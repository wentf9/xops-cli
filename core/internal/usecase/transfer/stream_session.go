package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/ports"
)

// managedTransferSession 承载托管于连接池 SlotMap 的跨请求 10 GiB 流式传输会话（ADR-009 / ADR-016）。
// 仅经 pool.RegisterLeaseHandleWith[plan.KindTransfer] 构造，持有可撤销钉选 TransportConn（零 borrowed 逃逸），
// 并由 conc.CtxMutex 串行化分片/提交/中止操作；撤销时仅关闭 SFTP 与钉选视图，绝不误关共享底层连接。
type managedTransferSession struct {
	mu                                  *conc.CtxMutex
	conn                                ports.TransportConn
	rfs                                 ports.RemoteFSPort
	revokeCtx                           context.Context
	state                               fsm.TransferState
	meta                                fsm.TransferMeta
	remoteSource, remoteStagePath       algebraic.Option[pathalg.RemotePath]
	localRoot                           algebraic.Option[pathalg.LocalDir]
	localStageDest                      algebraic.Option[pathalg.LocalRootedDest]
	renameSpec                          ports.RemoteRenameSpec
	modTime                             algebraic.Option[time.Time]
	perm                                fs.FileMode
	noClobber, applyPerm, preserveTimes bool
	hasher                              hash.Hash // 连续流式加速哈希；崩溃恢复后置 nil 强制全量回读校验
	startedAt                           time.Time
	valid                               bool
	closed                              atomic.Bool
	closeOnce                           sync.Once
	closeErr                            error
}

// IsValid / Close 实现 pool.ManagedResource 契约。
func (m *managedTransferSession) IsValid() bool {
	return m != nil && m.valid && !m.closed.Load() && m.conn != nil && m.rfs != nil && m.mu != nil && m.meta.IsValid()
}
func (m *managedTransferSession) Close() error {
	if m == nil || !m.valid {
		return nil
	}
	m.closed.Store(true)
	m.closeOnce.Do(func() { m.closeErr = errors.Join(closeIfNonNil(m.rfs), closeIfNonNil(m.conn)) })
	return m.closeErr
}
func closeIfNonNil(c io.Closer) error {
	if c == nil {
		return nil
	}
	return c.Close()
}
func (m *managedTransferSession) snapshotIfMatches(targetID security.OperationID) (TransferStatusSnapshot, bool) {
	meta := fsm.TransferMetaOf(m.state)
	if !meta.TransferID().Equal(targetID) {
		return TransferStatusSnapshot{}, false
	}
	off, chunks := transferProgressOf(m.state)
	return TransferStatusSnapshot{TransferID: meta.TransferID(), LiveHandle: true, Meta: meta, StateKind: m.state.Kind(), IsTerminal: m.state.IsTerminal(), Offset: off, ChunkCount: chunks}, true
}
func (s *Service) buildManagedTransferSession(revokeCtx context.Context, conn ports.TransportConn, req StartTransferRequest, defaultPerm fs.FileMode, renameSpec ports.RemoteRenameSpec, resumedState fsm.TransferState, freshStart bool, startedAt time.Time) (sess *managedTransferSession, effs []fsm.TransferEffect, evs []fsm.TransferEvent, err error) {
	rfs, err := conn.OpenRemoteFS(revokeCtx)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() {
		if err != nil {
			_ = rfs.Close()
		}
	}()
	totalBytes, modTime, perm, err := inspectStreamDownloadSource(revokeCtx, rfs, req, defaultPerm)
	if err != nil {
		return nil, nil, nil, err
	}
	meta, st, effs, evs, err := initOrResumeTransferFSM(req, totalBytes, resumedState, freshStart)
	if err != nil {
		return nil, nil, nil, err
	}
	remoteStage, localStage, err := computeStreamStagePaths(meta)
	if err != nil {
		return nil, nil, nil, err
	}
	return &managedTransferSession{
		mu: conc.NewCtxMutex(), conn: conn, rfs: rfs, revokeCtx: revokeCtx, state: st, meta: meta,
		remoteSource: req.RemoteSource, remoteStagePath: remoteStage, localRoot: req.LocalRoot, localStageDest: localStage,
		renameSpec: renameSpec, modTime: modTime, perm: perm, noClobber: req.NoClobber,
		applyPerm: req.Perm.IsSome(), preserveTimes: req.PreserveTimes, hasher: pickIf(freshStart, sha256.New(), nil), startedAt: startedAt, valid: true,
	}, effs, evs, nil
}
func inspectStreamDownloadSource(ctx context.Context, rfs ports.RemoteFSPort, req StartTransferRequest, defaultPerm fs.FileMode) (uint64, algebraic.Option[time.Time], fs.FileMode, error) {
	if req.Dest.Direction() != fsm.TransferDirectionDownload {
		return req.TotalBytes, req.ModTime, defaultPerm, nil
	}
	rs, ok := req.RemoteSource.Get()
	if !ok {
		return 0, req.ModTime, defaultPerm, fmt.Errorf("%w: 下载缺少 RemoteSource", ErrInvalidRequest)
	}
	st, err := rfs.Stat(ctx, rs)
	if err != nil || !st.IsRegular() {
		return 0, req.ModTime, defaultPerm, pickIf[error](err != nil, err, pickIf(st.IsDir(), ports.ErrRemoteIsDir, ports.ErrNotRegularFile))
	}
	size := uint64(st.Size())
	if size > fsm.MaxTransferBytes || (req.TotalBytes > 0 && req.TotalBytes != size) {
		return 0, req.ModTime, defaultPerm, pickIf[error](size > fsm.MaxTransferBytes, fmt.Errorf("%w: 远端大小 %d 超限", fsm.ErrTransferSizeExceeded, size), fmt.Errorf("%w: 声明大小与远端不符", ErrInvalidRequest))
	}
	mt := pickIf(req.PreserveTimes && req.ModTime.IsNone() && isValidRFC3339Time(st.ModTime()), algebraic.Some(st.ModTime()), req.ModTime)
	return size, mt, pickIf(req.Perm.IsNone() && st.Perm() != 0, sanitizeLocalDownloadPerm(st.Perm()), defaultPerm), nil
}
func initOrResumeTransferFSM(req StartTransferRequest, totalBytes uint64, resumedState fsm.TransferState, freshStart bool) (fsm.TransferMeta, fsm.TransferState, []fsm.TransferEffect, []fsm.TransferEvent, error) {
	if !freshStart {
		if resumedState == nil || !resumedState.IsValid() {
			return zeroVal[fsm.TransferMeta](), nil, nil, nil, fsm.ErrInvalidState
		}
		return fsm.TransferMetaOf(resumedState), resumedState, nil, nil, nil
	}
	tid, _ := req.TransferID.Get()
	meta, e1 := fsm.NewTransferMeta(fsm.TransferMetaSpec{TransferID: tid, Dest: req.Dest, TotalBytes: totalBytes, ExpectedDigest: req.ExpectedDigest, JournalVersion: req.JournalVersion, Generation: req.Generation})
	initSt, e2 := fsm.NewTransferState(meta)
	if err := firstErr(e1, e2); err != nil {
		return zeroVal[fsm.TransferMeta](), nil, nil, nil, err
	}
	nextSt, effs, evs, err := fsm.TransitionTransfer(initSt, fsm.TransferInputStart())
	return meta, nextSt, effs, evs, err
}
func computeStreamStagePaths(meta fsm.TransferMeta) (rpOpt algebraic.Option[pathalg.RemotePath], lpOpt algebraic.Option[pathalg.LocalRootedDest], err error) {
	sum := sha256.Sum256([]byte("xops.stream.transfer.v2\x00" + meta.Direction().String() + ":" + meta.TransferID().String() + ":g" + strconv.FormatUint(meta.Generation(), 10)))
	token := fmt.Sprintf("%x", sum[:12])
	if meta.Direction() == fsm.TransferDirectionUpload {
		if dst, ok := meta.Dest().Remote().Get(); ok {
			rp, rErr := makeRemoteStagePath(dst, token)
			return algebraic.Some(rp), lpOpt, rErr
		}
		return rpOpt, lpOpt, fmt.Errorf("%w: 缺少 RemotePath", ErrInvalidRequest)
	}
	if dst, ok := meta.Dest().Local().Get(); ok {
		lp, lErr := makeLocalStageDest(dst, token)
		return rpOpt, algebraic.Some(lp), lErr
	}
	return rpOpt, lpOpt, fmt.Errorf("%w: 缺少 LocalRootedDest", ErrInvalidRequest)
}

// verifyStagedDigest 计算完整暂存文件 SHA-256（下载重读本机 ScopedRootFS，上传恢复后经 SFTP ReadChunk 回读）。
func (s *Service) verifyStagedDigest(ctx context.Context, sess *managedTransferSession) (security.Digest, error) {
	totalBytes := sess.meta.TotalBytes()
	if totalBytes == 0 {
		return security.DigestBytes(nil), nil
	}
	if sess.meta.Direction() == fsm.TransferDirectionDownload {
		lr, okR := sess.localRoot.Get()
		stageDest, okS := sess.localStageDest.Get()
		if s.scopedFS == nil || !okR || !okS {
			return zeroVal[security.Digest](), pickIf[error](s.scopedFS == nil, ErrScopedFSUnavailable, fmt.Errorf("%w: 缺少 LocalRoot/暂存路径", ErrInvalidRequest))
		}
		var dig security.Digest
		err := s.scopedFS.WithRoot(lr, func(root ports.RootHandle) (hErr error) {
			dig, hErr = hashLocalStagedFile(root, stageDest, int64(totalBytes))
			return hErr
		})
		return dig, err
	}
	if sess.hasher != nil {
		return digestFromHash(sess.hasher), nil
	}
	return hashRemoteTransferStage(ctx, sess.rfs, sess.remoteStagePath, totalBytes, s.defaultChunkSize)
}
func hashRemoteTransferStage(ctx context.Context, rfs ports.RemoteFSPort, stageOpt algebraic.Option[pathalg.RemotePath], totalBytes uint64, chunkSize int64) (security.Digest, error) {
	stagePath, ok := stageOpt.Get()
	if !ok {
		return zeroVal[security.Digest](), fmt.Errorf("%w: 缺少远端暂存路径", ErrInvalidRequest)
	}
	if st, err := rfs.Lstat(ctx, stagePath); err != nil || !st.IsRegular() || uint64(st.Size()) != totalBytes {
		return zeroVal[security.Digest](), pickIf[error](err != nil, err, fmt.Errorf("%w: 远端暂存大小 %d 与预期 %d 不符", io.ErrUnexpectedEOF, st.Size(), totalBytes))
	}
	h := sha256.New()
	for offset := int64(0); uint64(offset) < totalBytes; {
		data, err := readRemoteChunkExact(ctx, rfs, stagePath, offset, min(chunkSize, int64(totalBytes)-offset))
		if err != nil {
			return zeroVal[security.Digest](), err
		}
		_, _ = h.Write(data)
		offset += int64(len(data))
	}
	return digestFromHash(h), nil
}

// executeAtomicTransferCommit 显式区分本机 ScopedRootFS 原子 Rename 与远端 SFTP v3 RenameAtomic 边界。
func (s *Service) executeAtomicTransferCommit(ctx context.Context, sess *managedTransferSession) (fsm.DurabilityStatus, string, error) {
	if sess.meta.Direction() == fsm.TransferDirectionDownload {
		return s.commitLocalScopedTransfer(sess)
	}
	return s.commitRemoteSFTPTransfer(ctx, sess)
}

//xops:syncclosure
func (s *Service) applyPostCommitModTime(sess *managedTransferSession, fn func(time.Time) error) {
	if mt, ok := sess.modTime.Get(); sess.preserveTimes && ok && isValidRFC3339Time(mt) {
		if cErr := fn(mt); cErr != nil {
			s.emitDiagnostic(algebraic.Some(sess.meta.TransferID()), events.SeverityWarn, "post_commit_chtimes_failed", cErr.Error(), nil)
		}
	}
}
func (s *Service) commitLocalScopedTransfer(sess *managedTransferSession) (fsm.DurabilityStatus, string, error) {
	lr, okR := sess.localRoot.Get()
	stageDest, okS := sess.localStageDest.Get()
	finalDest, okF := sess.meta.Dest().Local().Get()
	if s.scopedFS == nil || !okR || !okS || !okF {
		return fsm.DurabilityNotApplied, "invalid_local_commit", pickIf[error](s.scopedFS == nil, ErrScopedFSUnavailable, ErrInvalidRequest)
	}
	preRejected := false
	if err := s.scopedFS.WithRoot(lr, func(root ports.RootHandle) error {
		var rErr error
		if preRejected, rErr = renameLocalStageAtomic(root, stageDest, finalDest, sess.meta.TotalBytes(), sess.perm, sess.noClobber); rErr != nil {
			return rErr
		}
		s.applyPostCommitModTime(sess, func(mt time.Time) error { return root.Chtimes(finalDest, mt, mt) })
		return nil
	}); err != nil {
		return pickIf(preRejected || isDeterministicNotAppliedErr(err), fsm.DurabilityNotApplied, fsm.DurabilityOutcomeUnknown), err.Error(), err
	}
	return fsm.DurabilityCommitted, "local_root_atomic_rename", nil
}
func renameLocalStageAtomic(root ports.RootHandle, stageDest, finalDest pathalg.LocalRootedDest, totalBytes uint64, perm fs.FileMode, noClobber bool) (bool, error) {
	if err := firstErr(ensureParentLocalDir(root, finalDest), checkLocalNoClobber(root, finalDest, noClobber)); err != nil {
		return true, err
	}
	if totalBytes == 0 {
		if _, err := root.WriteChunk(stageDest, 0, bytes.NewReader(nil), 0, sanitizeLocalDownloadPerm(perm)); err != nil {
			return true, err
		}
	}
	return false, root.Rename(stageDest, finalDest)
}
func (s *Service) commitRemoteSFTPTransfer(ctx context.Context, sess *managedTransferSession) (fsm.DurabilityStatus, string, error) {
	stagePath, okS := sess.remoteStagePath.Get()
	finalPath, okF := sess.meta.Dest().Remote().Get()
	if !okS || !okF {
		return fsm.DurabilityNotApplied, "invalid_remote_commit", ErrInvalidRequest
	}
	if err := prepareRemoteStageForCommit(ctx, sess, stagePath); err != nil {
		return fsm.DurabilityNotApplied, err.Error(), err
	}
	if err := sess.rfs.RenameAtomic(ctx, stagePath, finalPath, sess.renameSpec); err != nil {
		return pickIf(isDeterministicNotAppliedErr(err), fsm.DurabilityNotApplied, fsm.DurabilityOutcomeUnknown), err.Error(), err
	}
	s.applyPostCommitModTime(sess, func(mt time.Time) error { return sess.rfs.Chtimes(ctx, finalPath, mt, mt) })
	return fsm.DurabilityCommitted, "remote_sftp_atomic_rename", nil
}
func prepareRemoteStageForCommit(ctx context.Context, sess *managedTransferSession, stagePath pathalg.RemotePath) error {
	if sess.meta.TotalBytes() == 0 {
		if err := sess.rfs.WriteChunk(ctx, stagePath, 0, bytes.NewReader(nil), 0); err != nil {
			return err
		}
	}
	if sess.applyPerm {
		return sess.rfs.Chmod(ctx, stagePath, sess.perm)
	}
	return nil
}
func isDeterministicNotAppliedErr(err error) bool {
	return errors.Is(err, ports.ErrAlreadyExists) || errors.Is(err, ports.ErrRemoteAnchorMismatch) ||
		errors.Is(err, ports.ErrRemoteIsDir) || errors.Is(err, ports.ErrNotRegularFile) ||
		errors.Is(err, ports.ErrSymlinkRejected) || errors.Is(err, ports.ErrPermissionDenied) ||
		errors.Is(err, ports.ErrInvalidArgument) || errors.Is(err, ports.ErrNotFound)
}
func (s *Service) removeLocalBestEffort(lrOpt algebraic.Option[pathalg.LocalDir], destOpt algebraic.Option[pathalg.LocalRootedDest]) {
	lr, okR := lrOpt.Get()
	dest, okD := destOpt.Get()
	if s.scopedFS != nil && okR && lr.IsValid() && okD && dest.IsValid() {
		_ = s.scopedFS.WithRoot(lr, func(root ports.RootHandle) error { return root.Remove(dest) })
	}
}
func (s *Service) cleanupTransferStaging(ctx context.Context, sess *managedTransferSession) {
	if sess.meta.Direction() == fsm.TransferDirectionUpload {
		if stagePath, ok := sess.remoteStagePath.Get(); ok && sess.rfs != nil {
			_ = sess.rfs.Remove(context.WithoutCancel(ctx), stagePath)
		}
		return
	}
	s.removeLocalBestEffort(sess.localRoot, sess.localStageDest)
}
func transferProgressOf(st fsm.TransferState) (offset, chunks uint64) {
	if st == nil || !st.IsValid() {
		return 0, 0
	}
	switch v := st.(type) {
	case *fsm.TransferStreaming:
		return v.Offset(), v.ChunkCount()
	case *fsm.TransferVerifying:
		return fsm.TransferMetaOf(st).TotalBytes(), v.ChunkCount()
	case *fsm.TransferCommitting, *fsm.TransferCommitted:
		return fsm.TransferMetaOf(st).TotalBytes(), 0
	case *fsm.TransferInitialized, *fsm.TransferAborted, *fsm.TransferUncertainCommit:
		return 0, 0
	default:
		return 0, 0
	}
}
