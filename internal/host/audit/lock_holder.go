package audit

import (
	"fmt"
	"io"

	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

type lockLogWriterState struct {
	confirmedOffset int64
	needNewline     bool
}

func (s *FileSink) runLockHolder(readyCh chan<- error) error {
	defer close(s.doneCh)
	readySent := false
	signalReady := func(err error) {
		if !readySent {
			readySent = true
			readyCh <- err
		}
	}
	err := s.fs.WithRoot(s.rootDir, func(root ports.RootHandle) error {
		return s.holdProcessLockInRoot(root, signalReady)
	})
	signalReady(err)
	return err
}

func (s *FileSink) holdProcessLockInRoot(root ports.RootHandle, signalReady func(error)) error {
	var cleanShutdown bool
	acquired, err := root.TryWithLockedFile(s.lockDest, ports.LockExclusive, true, auditFilePerm, func(lf ports.LockedFile) error {
		st, stErr := lf.Stat()
		if stErr != nil {
			signalReady(stErr)
			return stErr
		}
		if st.Size() > 0 {
			// 严禁静默截断尚未完成崩溃对账的非空残留 .lock 文件（防止误复用 ProcessInstanceID 擦除未闭合记录）。
			unreconciledErr := fmt.Errorf("%w: 进程锁文件 %q 包含未对账残留记录，请先执行崩溃对账或使用新的 ProcessInstanceID", ports.ErrAlreadyExists, s.lockDest.String())
			signalReady(unreconciledErr)
			return unreconciledErr
		}
		if rErr := truncateAndRewind(lf); rErr != nil {
			signalReady(rErr)
			return rErr
		}
		signalReady(nil)
		cleanShutdown = true
		return s.serveLockCommands(lf)
	})
	if err != nil {
		signalReady(err)
		return err
	}
	if !acquired {
		signalReady(ports.ErrLockBusy)
		return nil
	}
	if !cleanShutdown || !s.cleanClose.Load() {
		return nil
	}
	// 仅在活跃集合归零的正常关闭路径，经 osfs.RemoveLockedFileSafely 按三平台安全协议删除锁文件；
	// 若仍有未闭合操作（cleanClose==false），故意保留已解锁且含活跃条目的 .lock 供下次启动崩溃对账补写 AbortedByCrash。
	if _, rmErr := osfs.RemoveLockedFileSafely(root, s.lockDest); rmErr != nil {
		return rmErr
	}
	return nil
}

func (s *FileSink) serveLockCommands(lf ports.LockedFile) error {
	state := &lockLogWriterState{}
	for {
		select {
		case cmd := <-s.cmdCh:
			cmd.reply <- applyLockCommand(lf, cmd, state)
		case <-s.closeCh:
			if s.cleanClose.Load() {
				// 活跃集合为空的正常关闭：持独占锁态截断清空并归零偏移刷盘，随后退出闭包解锁删除。
				return truncateAndRewind(lf)
			}
			// 仍有未闭合操作（如 Halted 熔断退出）：绝不截断 .lock，仅同步刷盘后退出闭包释放内核锁。
			return lf.Sync()
		}
	}
}

// applyLockCommand 以严格行帧边界向进程 .lock 追加单条 +opID / -opID 记录；
// 遇部分写入或刷盘失败时立即按 confirmedOffset 回滚 Truncate+Seek，若回滚本身也失败则置 needNewline，
// 确保下一次写入始终位于独立行首，绝不把后续有效 +<opID> 拼接到残留半行尾部导致崩溃对账丢失。
func applyLockCommand(lf ports.LockedFile, cmd lockCommand, st *lockLogWriterState) error {
	line := formatLockLogFrame(cmd, st.needNewline)
	if err := writeAll(lf, line); err != nil {
		rollbackLockFrame(lf, st)
		return fmt.Errorf("%w: 写入进程锁日志失败: %w", ports.ErrAuditWriteFailed, err)
	}
	if cmd.kind == lockCmdUnstage && cmd.truncateAfter {
		// 严格遵循 §4 #4：仅在活跃集合归零后执行 Truncate(0) 并紧跟 Seek(0, io.SeekStart)，防稀疏 NUL 空洞。
		if err := truncateAndRewind(lf); err != nil {
			rollbackLockFrame(lf, st)
			return fmt.Errorf("%w: 排空后截断重置进程锁失败: %w", ports.ErrAuditWriteFailed, err)
		}
		st.confirmedOffset = 0
		st.needNewline = false
		return nil
	}
	if err := lf.Sync(); err != nil {
		rollbackLockFrame(lf, st)
		return fmt.Errorf("%w: 刷盘进程锁日志失败: %w", ports.ErrAuditWriteFailed, err)
	}
	st.confirmedOffset += int64(len(line))
	st.needNewline = false
	return nil
}

func formatLockLogFrame(cmd lockCommand, leadingNewline bool) []byte {
	prefix := byte('-')
	if cmd.kind == lockCmdStage {
		prefix = '+'
	}
	opStr := cmd.opID.String()
	buf := make([]byte, 0, len(opStr)+3)
	if leadingNewline {
		buf = append(buf, '\n')
	}
	buf = append(buf, prefix)
	buf = append(buf, opStr...)
	return append(buf, '\n')
}

func rollbackLockFrame(lf ports.LockedFile, st *lockLogWriterState) {
	if err := lf.Truncate(st.confirmedOffset); err != nil {
		st.needNewline = true
		return
	}
	if _, err := lf.Seek(st.confirmedOffset, io.SeekStart); err != nil {
		st.needNewline = true
		return
	}
	if err := lf.Sync(); err != nil {
		st.needNewline = true
		return
	}
	st.needNewline = false
}

func truncateAndRewind(lf ports.LockedFile) error {
	if err := lf.Truncate(0); err != nil {
		return err
	}
	if _, err := lf.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return lf.Sync()
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
