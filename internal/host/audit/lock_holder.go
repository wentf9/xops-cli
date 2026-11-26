package audit

import (
	"fmt"
	"io"

	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

type lockLogWriterState struct {
	confirmedOffset int64
	offsetKnown     bool
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
	// holdProcessLockInRoot 已在进入主循环前完成 truncateAndRewind，因此初始已确认偏移精确锚定在 0。
	state := &lockLogWriterState{confirmedOffset: 0, offsetKnown: true}
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

// applyLockCommand 以严格行帧边界向进程 .lock 追加单条 +opID / -opID 记录：
//   - 若前次故障或排空截断导致偏移未知（!offsetKnown），先以 Seek(0, io.SeekEnd) 重新锚定真实 EOF
//     并同步修正文件游标，杜绝 confirmedOffset 失步导致后续回滚误截断已确认记录；
//   - 遇写入或刷盘失败时立即按 confirmedOffset 回滚 Truncate+Seek+Sync，若回滚自身失败则标记
//     offsetKnown=false 且 needNewline=true，确保后续有效 +<opID> 始终从独立行首落盘。
func applyLockCommand(lf ports.LockedFile, cmd lockCommand, st *lockLogWriterState) error {
	if err := reanchorLockOffset(lf, st); err != nil {
		return err
	}
	line := formatLockLogFrame(cmd, st.needNewline)
	if err := writeAll(lf, line); err != nil {
		rollbackLockFrame(lf, st)
		return fmt.Errorf("%w: 写入进程锁日志失败: %w", ports.ErrAuditWriteFailed, err)
	}
	if cmd.kind == lockCmdUnstage && cmd.truncateAfter {
		return compactLockAfterDrain(lf, st)
	}
	if err := lf.Sync(); err != nil {
		rollbackLockFrame(lf, st)
		return fmt.Errorf("%w: 刷盘进程锁日志失败: %w", ports.ErrAuditWriteFailed, err)
	}
	st.confirmedOffset += int64(len(line))
	st.offsetKnown = true
	st.needNewline = false
	return nil
}

func reanchorLockOffset(lf ports.LockedFile, st *lockLogWriterState) error {
	if st.offsetKnown {
		return nil
	}
	pos, err := lf.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("%w: 重新锚定进程锁文件偏移失败: %w", ports.ErrAuditWriteFailed, err)
	}
	st.confirmedOffset = pos
	st.offsetKnown = true
	if pos == 0 {
		st.needNewline = false
	}
	return nil
}

// compactLockAfterDrain 严格遵循 §4 #4 在活跃集合归零后截断并归零偏移：
// 将 Truncate(0) 与 Seek/Sync 明确拆离——仅当 Truncate(0) 自身失败时才按原 confirmedOffset 回滚；
// 一旦 Truncate(0) 已成功，文件已归零，绝不可再 Truncate(oldOffset) 产生 NUL 稀疏零填充。
func compactLockAfterDrain(lf ports.LockedFile, st *lockLogWriterState) error {
	if err := lf.Truncate(0); err != nil {
		rollbackLockFrame(lf, st)
		return fmt.Errorf("%w: 排空后截断进程锁失败: %w", ports.ErrAuditWriteFailed, err)
	}
	st.confirmedOffset = 0
	if _, err := lf.Seek(0, io.SeekStart); err != nil {
		st.offsetKnown = false
		st.needNewline = true
		return fmt.Errorf("%w: 排空截断后重置进程锁偏移失败: %w", ports.ErrAuditWriteFailed, err)
	}
	if err := lf.Sync(); err != nil {
		st.offsetKnown = false
		st.needNewline = true
		return fmt.Errorf("%w: 排空截断后刷盘进程锁失败: %w", ports.ErrAuditWriteFailed, err)
	}
	st.offsetKnown = true
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
		st.offsetKnown = false
		st.needNewline = true
		return
	}
	if _, err := lf.Seek(st.confirmedOffset, io.SeekStart); err != nil {
		st.offsetKnown = false
		st.needNewline = true
		return
	}
	if err := lf.Sync(); err != nil {
		st.offsetKnown = false
		st.needNewline = true
		return
	}
	st.offsetKnown = true
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
