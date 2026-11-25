package audit

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

type lockCmdKind uint8

const (
	lockCmdStage lockCmdKind = iota + 1
	lockCmdUnstage
)

type lockCommand struct {
	kind          lockCmdKind
	opID          security.OperationID
	truncateAfter bool
	reply         chan error
}

// FileSink 实现 ports.AuditSink，借助 core/conc.Nursery 监督的单一锁持有协程，
// 在完全不逃逸 ports.LockedFile 借用闭包的前提下长期持有 ~/.xops/run/<ProcessInstanceID>.lock
// 内核独占锁，并以只追加协议（+opID / -opID，仅活跃集合归零时 Truncate(0)+Seek(0,SeekStart)）记录活跃操作。
//
//xops:opaque
//xops:failclosed
type FileSink struct {
	fs          ports.ScopedRootFS
	rootDir     pathalg.LocalDir
	auditFile   pathalg.LocalRootedDest
	lockDest    pathalg.LocalRootedDest
	procID      ports.ProcessInstanceID
	nursery     *conc.Nursery
	cmdCh       chan lockCommand
	closeCh     chan struct{}
	doneCh      chan struct{}
	rwMu        sync.RWMutex
	stageMu     sync.Mutex
	active      map[security.OperationID]struct{}
	truncations atomic.Uint64
	valid       bool
	closed      bool
}

// NewFileSink 确保目录结构存在（遵循 INV-A4，经 EnsureRoot(0o700) 校验/创建 Owner-Only DACL 根目录）、
// 以非阻塞独占锁抢占 run/<ProcessID>.lock 并返回可用的 FileSink。
func NewFileSink(spec SinkSpec) (*FileSink, error) {
	if spec.ScopedFS == nil || !spec.RootDir.IsValid() || !spec.ProcessID.IsValid() {
		return nil, fmt.Errorf("%w: ScopedFS、RootDir 或 ProcessID 无效", ports.ErrInvalidArgument)
	}
	auditDest, runDest, err := resolveAuditPaths(spec.AuditFile, spec.RunDir)
	if err != nil {
		return nil, err
	}
	lockName, err := spec.ProcessID.LockFileName()
	if err != nil {
		return nil, err
	}
	lockDest, err := runDest.JoinComponent(lockName.String())
	if err != nil {
		return nil, err
	}
	if err := ensureAuditDirectories(spec.ScopedFS, spec.RootDir, runDest); err != nil {
		return nil, err
	}
	return startLockedFileSink(spec.ScopedFS, spec.RootDir, auditDest, lockDest, spec.ProcessID)
}

// NewFileSinkFromEntropy 从显式熵源生成 ProcessInstanceID 并构造 FileSink。
func NewFileSinkFromEntropy(fsPort ports.ScopedRootFS, rootDir pathalg.LocalDir, entropy ports.Entropy) (*FileSink, error) {
	procID, err := ports.NewProcessInstanceIDFrom(entropy)
	if err != nil {
		return nil, err
	}
	return NewFileSink(SinkSpec{ScopedFS: fsPort, RootDir: rootDir, ProcessID: procID})
}

func ensureAuditDirectories(fsPort ports.ScopedRootFS, rootDir pathalg.LocalDir, runDest pathalg.LocalRootedDest) error {
	if err := fsPort.EnsureRoot(rootDir, runDirPerm); err != nil {
		return err
	}
	return fsPort.WithRoot(rootDir, func(root ports.RootHandle) error {
		return root.MkdirAll(runDest, runDirPerm)
	})
}

func startLockedFileSink(fsPort ports.ScopedRootFS, rootDir pathalg.LocalDir, auditDest, lockDest pathalg.LocalRootedDest, procID ports.ProcessInstanceID) (*FileSink, error) {
	n, err := conc.NewNursery(context.Background())
	if err != nil {
		return nil, err
	}
	s := &FileSink{
		fs:        fsPort,
		rootDir:   rootDir,
		auditFile: auditDest,
		lockDest:  lockDest,
		procID:    procID,
		nursery:   n,
		cmdCh:     make(chan lockCommand),
		closeCh:   make(chan struct{}),
		doneCh:    make(chan struct{}),
		active:    make(map[security.OperationID]struct{}),
		valid:     true,
	}
	readyCh := make(chan error, 1)
	if gErr := n.Go(func(context.Context) error {
		return s.runLockHolder(readyCh)
	}); gErr != nil {
		_ = n.Close()
		return nil, gErr
	}
	if initErr := <-readyCh; initErr != nil {
		_ = n.Wait()
		return nil, initErr
	}
	return s, nil
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
	if !cleanShutdown {
		return nil
	}
	// 此时 TryWithLockedFile 已释放锁并关闭文件句柄，经 osfs.RemoveLockedFileSafely 按三平台安全协议删除锁文件，
	// 若并发 FileReconciler 恰已接管该空锁文件则和平让出并忽略 ErrNotFound，彻底规避 Windows 共享冲突。
	if _, rmErr := osfs.RemoveLockedFileSafely(root, s.lockDest); rmErr != nil {
		return rmErr
	}
	return nil
}

func (s *FileSink) serveLockCommands(lf ports.LockedFile) error {
	for {
		select {
		case cmd := <-s.cmdCh:
			cmd.reply <- applyLockCommand(lf, cmd)
		case <-s.closeCh:
			// 正常关闭路径：仍在持独占锁态截断清空并归零偏移刷盘，随后退出闭包解锁关闭。
			return truncateAndRewind(lf)
		}
	}
}

func applyLockCommand(lf ports.LockedFile, cmd lockCommand) error {
	prefix := byte('-')
	if cmd.kind == lockCmdStage {
		prefix = '+'
	}
	line := append(append([]byte{prefix}, cmd.opID.String()...), '\n')
	if err := writeAll(lf, line); err != nil {
		return fmt.Errorf("%w: 写入进程锁日志失败: %w", ports.ErrAuditWriteFailed, err)
	}
	if cmd.kind == lockCmdUnstage && cmd.truncateAfter {
		// 严格遵循 §4 #4：仅在活跃集合归零后执行 Truncate(0) 并紧跟 Seek(0, io.SeekStart)，防稀疏 NUL 空洞。
		if err := truncateAndRewind(lf); err != nil {
			return fmt.Errorf("%w: 排空后截断重置进程锁失败: %w", ports.ErrAuditWriteFailed, err)
		}
		return nil
	}
	if err := lf.Sync(); err != nil {
		return fmt.Errorf("%w: 刷盘进程锁日志失败: %w", ports.ErrAuditWriteFailed, err)
	}
	return nil
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

// ProcessInstanceID 返回当前 FileSink 绑定的进程实例标识；零值接收者返回无效零值。
func (s *FileSink) ProcessInstanceID() ports.ProcessInstanceID {
	if s == nil || !s.valid {
		return zeroVal[ports.ProcessInstanceID]()
	}
	return s.procID
}

// LockTruncations 返回因活跃操作集合归零触发 Truncate(0)+Seek(0) 的累计次数（供观测与测试断言）。
func (s *FileSink) LockTruncations() uint64 {
	if s == nil || !s.valid {
		return 0
	}
	return s.truncations.Load()
}

// StageOperation 以只追加协议向当前进程 .lock 文件写入 "+<opID>\n" 并同步刷盘，登记活跃未闭合操作。
func (s *FileSink) StageOperation(ctx context.Context, opID security.OperationID) error {
	if err := s.checkOpArgs(ctx, opID); err != nil {
		return err
	}
	s.rwMu.RLock()
	defer s.rwMu.RUnlock()
	if s.closed {
		return ports.ErrClosed
	}
	s.stageMu.Lock()
	defer s.stageMu.Unlock()
	if _, exists := s.active[opID]; exists {
		return nil
	}
	if err := s.sendLockCmd(lockCommand{kind: lockCmdStage, opID: opID, reply: make(chan error, 1)}); err != nil {
		return err
	}
	s.active[opID] = struct{}{}
	return nil
}

// UnstageOperation 以只追加协议向 .lock 写入 "-<opID>\n"；仅当活跃操作集合由此归零时执行截断与偏移归零。
func (s *FileSink) UnstageOperation(ctx context.Context, opID security.OperationID) error {
	if err := s.checkOpArgs(ctx, opID); err != nil {
		return err
	}
	s.rwMu.RLock()
	defer s.rwMu.RUnlock()
	if s.closed {
		return ports.ErrClosed
	}
	s.stageMu.Lock()
	defer s.stageMu.Unlock()
	if _, exists := s.active[opID]; !exists {
		return nil
	}
	willBeEmpty := len(s.active) == 1
	if err := s.sendLockCmd(lockCommand{kind: lockCmdUnstage, opID: opID, truncateAfter: willBeEmpty, reply: make(chan error, 1)}); err != nil {
		return err
	}
	delete(s.active, opID)
	if willBeEmpty {
		s.truncations.Add(1)
	}
	return nil
}

func (s *FileSink) sendLockCmd(cmd lockCommand) error {
	select {
	case s.cmdCh <- cmd:
	case <-s.doneCh:
		return ports.ErrClosed
	}
	select {
	case err := <-cmd.reply:
		return err
	case <-s.doneCh:
		return ports.ErrClosed
	}
}

// Record 以规范 json/v2 Deterministic(true) 序列化 entry 并在跨进程旁路锁 audit.jsonl.lock 保护下同步追加落盘。
// 当 AuditPhaseFinalized 写入失败时，按 ADR-008 返回 *ports.AuditPostWriteError 以触发上层 Halted 熔断。
func (s *FileSink) Record(ctx context.Context, entry ports.AuditEntry) error {
	if err := s.checkRecordArgs(ctx, entry); err != nil {
		return err
	}
	s.rwMu.RLock()
	defer s.rwMu.RUnlock()
	if s.closed {
		return ports.ErrClosed
	}
	rawJSON, err := entry.CanonicalJSON()
	if err != nil {
		return fmt.Errorf("%w: %w", ports.ErrInvalidAuditEntry, err)
	}
	if err := s.appendAuditLineLocked(ctx, rawJSON); err != nil {
		return wrapAuditRecordError(entry, err)
	}
	return nil
}

func (s *FileSink) appendAuditLineLocked(ctx context.Context, rawJSON []byte) error {
	return s.fs.WithRoot(s.rootDir, func(root ports.RootHandle) error {
		return osfs.WithSidecarLock(ctx, root, s.auditFile, ports.LockExclusive, auditFilePerm, func(ports.LockedFile) error {
			return root.AppendLine(s.auditFile, auditFilePerm, rawJSON)
		})
	})
}

func wrapAuditRecordError(entry ports.AuditEntry, cause error) error {
	if entry.Phase() == ports.AuditPhaseFinalized {
		if pw, err := ports.NewAuditPostWriteError(entry.OperationID(), cause); err == nil {
			return pw
		}
		return fmt.Errorf("%w: %w", ports.ErrAuditPostWrite, cause)
	}
	return fmt.Errorf("%w: %w", ports.ErrAuditWriteFailed, cause)
}

// Close 幂等清空并释放进程级 .lock 内核锁、按三平台安全协议删除锁文件，并等待锁持有协程彻底退出。
func (s *FileSink) Close() error {
	if s == nil || !s.valid {
		return fmt.Errorf("%w: FileSink 未初始化", ports.ErrInvalidArgument)
	}
	s.rwMu.Lock()
	if s.closed {
		s.rwMu.Unlock()
		return nil
	}
	s.closed = true
	close(s.closeCh)
	s.rwMu.Unlock()
	return s.nursery.Wait()
}

func (s *FileSink) checkOpArgs(ctx context.Context, opID security.OperationID) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || !s.valid {
		return fmt.Errorf("%w: FileSink 未初始化", ports.ErrInvalidArgument)
	}
	if !opID.IsValid() {
		return fmt.Errorf("%w: OperationID 无效", ports.ErrInvalidArgument)
	}
	return nil
}

func (s *FileSink) checkRecordArgs(ctx context.Context, entry ports.AuditEntry) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || !s.valid {
		return fmt.Errorf("%w: FileSink 未初始化", ports.ErrInvalidArgument)
	}
	if !entry.IsValid() {
		return ports.ErrInvalidAuditEntry
	}
	return nil
}
