package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

type chunkBuf struct {
	offset int64
	data   []byte
}

type uploadExecParams struct {
	finalDest, stagePath                           pathalg.RemotePath
	renameSpec                                     ports.RemoteRenameSpec
	perm                                           fs.FileMode
	applyPerm, preserveMode, preserveTimes, resume bool
	modTime                                        algebraic.Option[time.Time]
	chunkSize                                      int64
	concurrency                                    int
	expectedDigest                                 algebraic.Option[security.Digest]
	transferID                                     security.OperationID
	startedAt                                      time.Time
}

// SCPUpload 执行受 core/conc.Nursery 有界并发监督的并行分片 SCP 上传：
// 显式区分 OperatorReadFS（缺席 Fail-Closed）与 ScopedRootFS，严守 INV-B4 单次目录展开与 Lstat 悬空软链检查。
func (s *Service) SCPUpload(ctx context.Context, req SCPUploadRequest) (SCPUploadResult, error) {
	defer closeStreamIfNonNil(req.OperationStream)
	hop, params, err := s.validateSCPUploadRequest(ctx, req)
	if err != nil {
		return SCPUploadResult{}, err
	}
	spec := authOpSpec{base: req.CallBase, targetHop: hop, tool: "scp", action: "upload", paths: []pathalg.RemotePath{req.RemoteDest}, defaultRisk: security.RiskModerate, summary: "scp upload -> " + req.RemoteDest.String(), canonicalize: true}
	return runAuthorizedRemoteFS[security.CapTransfer](ctx, s, spec, func(opCtx context.Context, auth gate.Authorized[security.CapTransfer], rfs ports.RemoteFSPort, emitter *transferEmitter) (SCPUploadResult, error) {
		finalDest, err := resolveRemoteUploadDest(opCtx, rfs, req.RemoteDest, req.Source.BaseName(), req.ExpandIntoDir, req.NoClobber)
		if err != nil {
			return SCPUploadResult{}, err
		}
		token, err := s.stageToken("xops.scp.upload.v1", finalDest.String(), req.Resume)
		if err != nil {
			return SCPUploadResult{}, err
		}
		if params.stagePath, err = makeRemoteStagePath(finalDest, token); err != nil {
			return SCPUploadResult{}, err
		}
		params.finalDest, params.transferID, params.startedAt = finalDest, auth.OperationID(), s.clock.Now().UTC().Round(0)
		return s.openSourceAndUpload(opCtx, rfs, emitter, req.Source, params)
	})
}

func (s *Service) validateSCPUploadRequest(ctx context.Context, req SCPUploadRequest) (hop plan.HopSpec, params uploadExecParams, err error) {
	if hop, err = s.validateRemotePathOp(ctx, req.CallBase, req.RemoteDest); err != nil {
		return hop, params, err
	}
	switch {
	case !req.Source.IsValid():
		return hop, params, fmt.Errorf("%w: LocalUploadSource 无效", ErrInvalidRequest)
	case req.Source.Kind() == LocalUploadSourceOperator && s.operatorReadFS == nil:
		return hop, params, ErrOperatorReadUnavailable
	case req.Source.Kind() == LocalUploadSourceScoped && s.scopedFS == nil:
		return hop, params, ErrScopedFSUnavailable
	}
	e1 := validateOptionalUploadAttrs(req.ModTime, req.ExpectedDigest)
	cs, conc, e2 := s.resolveChunkAndConcurrency(req.ChunkSize, req.Concurrency)
	perm, e3 := resolvePerm(req.Perm, defaultRemoteFilePerm)
	renameSpec, e4 := ports.NewRemoteRenameSpec(ports.RemoteRenameSpecInput{NoClobber: req.NoClobber})
	if err = firstErr(e1, e2, e3, e4); err != nil {
		return hop, params, err
	}
	return hop, uploadExecParams{
		renameSpec: renameSpec, perm: perm, applyPerm: req.PreserveMode || req.Perm.IsSome(),
		preserveMode: req.PreserveMode && req.Perm.IsNone(), modTime: req.ModTime, preserveTimes: req.PreserveTimes,
		resume: req.Resume, chunkSize: cs, concurrency: conc, expectedDigest: req.ExpectedDigest,
	}, nil
}
func validateOptionalUploadAttrs(modTime algebraic.Option[time.Time], expDig algebraic.Option[security.Digest]) error {
	if mt, ok := modTime.Get(); ok && !isValidRFC3339Time(mt) {
		return fmt.Errorf("%w: ModTime 必须为有效 RFC 3339 非零时刻", ErrInvalidRequest)
	}
	if dig, ok := expDig.Get(); ok && !dig.IsValid() {
		return fmt.Errorf("%w: ExpectedDigest 无效", ErrInvalidRequest)
	}
	return nil
}

// resolveRemoteUploadDest 严守 INV-B4：至多一次远端容器目录展开，经 Lstat 识别悬空软链与目录冲突。
func resolveRemoteUploadDest(ctx context.Context, rfs ports.RemoteFSPort, dest pathalg.RemotePath, sourceBase string, expandIntoDir, noClobber bool) (pathalg.RemotePath, error) {
	exists, isDir, err := inspectRemoteUploadTarget(ctx, rfs, dest)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), err
	}
	if exists && isDir {
		if !expandIntoDir {
			return zeroVal[pathalg.RemotePath](), fmt.Errorf("%w: 禁止覆写远端目录 %s", ports.ErrRemoteIsDir, dest)
		}
		if dest, err = joinRemoteBase(dest, sourceBase); err != nil {
			return zeroVal[pathalg.RemotePath](), err
		}
		if exists, isDir, err = inspectRemoteUploadTarget(ctx, rfs, dest); err != nil || (exists && isDir) {
			return zeroVal[pathalg.RemotePath](), pickIf[error](err != nil, err, fmt.Errorf("%w: 展开目标 %s 为目录（禁止二次展开）", ports.ErrRemoteIsDir, dest))
		}
	}
	if exists && noClobber {
		return zeroVal[pathalg.RemotePath](), fmt.Errorf("%w: 远端目标 %s 已存在（含悬空软链）", ports.ErrAlreadyExists, dest)
	}
	return dest, nil
}
func inspectRemoteUploadTarget(ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath) (exists, isDir bool, err error) {
	lstat, err := rfs.Lstat(ctx, p)
	if errors.Is(err, ports.ErrNotFound) {
		return false, false, nil
	}
	if err != nil || lstat.IsDir() || !lstat.IsSymlink() {
		return err == nil, err == nil && lstat.IsDir(), err
	}
	st, err := rfs.Stat(ctx, p)
	if errors.Is(err, ports.ErrNotFound) {
		return true, false, nil // 悬空软链按非目录已存在条目参与 NoClobber 检查
	}
	return true, err == nil && st.IsDir(), err
}
func (s *Service) openSourceAndUpload(ctx context.Context, rfs ports.RemoteFSPort, emitter *transferEmitter, src LocalUploadSource, params uploadExecParams) (res SCPUploadResult, err error) {
	if src.kind == LocalUploadSourceOperator {
		err = s.operatorReadFS.WithOperatorRead(ctx, src.operatorPath, src.symlinkPolicy, func(r ports.BoundedReadHandle, size int64) (uErr error) {
			res, uErr = uploadFromBoundedReader(ctx, rfs, emitter, r, size, params)
			return uErr
		})
		return res, err
	}
	limits, err := ports.NewReadLimits(int64(fsm.MaxTransferBytes))
	if err != nil {
		return SCPUploadResult{}, err
	}
	err = s.scopedFS.WithRoot(src.scopedRoot, func(root ports.RootHandle) error {
		if info, sErr := root.Stat(src.scopedPath); sErr == nil && info.IsValid() {
			if params.preserveTimes && params.modTime.IsNone() && isValidRFC3339Time(info.ModTime()) {
				params.modTime = algebraic.Some(info.ModTime())
			}
			if params.preserveMode && info.Perm() != 0 {
				params.perm = info.Perm()
			}
		}
		return root.WithReadRegular(src.scopedPath, limits, func(r ports.BoundedReadHandle, size int64) (uErr error) {
			res, uErr = uploadFromBoundedReader(ctx, rfs, emitter, r, size, params)
			return uErr
		})
	})
	return res, err
}

// uploadFromBoundedReader 同步消费借用句柄 r 并经 conc.RunWait 扇出并发 WriteChunk（r 绝不逃逸至 n.Go）。
func uploadFromBoundedReader(ctx context.Context, rfs ports.RemoteFSPort, emitter *transferEmitter, r ports.BoundedReadHandle, size int64, params uploadExecParams) (SCPUploadResult, error) {
	if size < 0 || uint64(size) > fsm.MaxTransferBytes {
		return SCPUploadResult{}, fmt.Errorf("%w: 本地文件大小 %d 超出 10 GiB 上限", fsm.ErrTransferSizeExceeded, size)
	}
	resumeOffset, err := calcResumeOffset(size, params.chunkSize, params.resume, func() (int64, bool, error) {
		st, sErr := rfs.Lstat(ctx, params.stagePath)
		return st.Size(), st.IsRegular(), sErr
	}, func() error { return rfs.Remove(ctx, params.stagePath) })
	if err != nil {
		return SCPUploadResult{}, err
	}
	committed := false
	defer func() {
		if !committed && !params.resume {
			_ = rfs.Remove(context.WithoutCancel(ctx), params.stagePath)
		}
	}()
	digest, chunksUploaded, err := streamUploadChunks(ctx, rfs, emitter, r, size, resumeOffset, params)
	if err != nil {
		return SCPUploadResult{}, err
	}
	if expDig, ok := params.expectedDigest.Get(); ok && !expDig.Equal(digest) {
		_ = rfs.Remove(context.WithoutCancel(ctx), params.stagePath)
		return SCPUploadResult{}, fmt.Errorf("%w: 上传源摘要与 ExpectedDigest 不一致", ErrDigestMismatch)
	}
	preserved, err := commitUploadedStage(ctx, rfs, params)
	if err != nil {
		return SCPUploadResult{}, err
	}
	committed = true
	return SCPUploadResult{RemotePath: params.finalDest, BytesTransferred: size, ResumedBytes: resumeOffset, ChunksTransferred: chunksUploaded, Digest: digest, ModTimePreserved: preserved}, nil
}
func commitUploadedStage(ctx context.Context, rfs ports.RemoteFSPort, params uploadExecParams) (bool, error) {
	if params.applyPerm {
		if err := rfs.Chmod(ctx, params.stagePath, params.perm); err != nil {
			return false, err
		}
	}
	if err := rfs.RenameAtomic(ctx, params.stagePath, params.finalDest, params.renameSpec); err != nil {
		return false, err
	}
	if mt, ok := params.modTime.Get(); params.preserveTimes && ok {
		err := rfs.Chtimes(ctx, params.finalDest, mt, mt)
		return err == nil, err
	}
	return false, nil
}

//xops:syncclosure
func calcResumeOffset(totalSize, chunkSize int64, resume bool, statFn func() (int64, bool, error), rmFn func() error) (int64, error) {
	if !resume || totalSize == 0 {
		return 0, nil
	}
	curSize, isReg, err := statFn()
	if err != nil {
		return 0, pickIf[error](errors.Is(err, ports.ErrNotFound), nil, err)
	}
	if isReg && curSize >= 0 && curSize <= totalSize {
		return (curSize / chunkSize) * chunkSize, nil
	}
	if rmErr := rmFn(); rmErr != nil && !errors.Is(rmErr, ports.ErrNotFound) {
		return 0, rmErr
	}
	return 0, nil
}
func streamUploadChunks(ctx context.Context, rfs ports.RemoteFSPort, emitter *transferEmitter, r ports.BoundedReadHandle, size, resumeOffset int64, params uploadExecParams) (security.Digest, int64, error) {
	if size == 0 {
		return security.DigestBytes(nil), 0, rfs.WriteChunk(ctx, params.stagePath, 0, bytes.NewReader(nil), 0)
	}
	hasher := sha256.New()
	var writtenBytes, chunksDone atomic.Int64
	writtenBytes.Store(resumeOffset)
	jobsCh := make(chan chunkBuf, params.concurrency)
	runErr := conc.RunWait(ctx, func(wCtx context.Context, n *conc.Nursery) error {
		for range params.concurrency {
			if err := n.Go(func(c context.Context) error {
				return runUploadWorker(c, rfs, emitter, jobsCh, size, params, &writtenBytes, &chunksDone)
			}); err != nil {
				close(jobsCh)
				return err
			}
		}
		err := produceUploadJobs(wCtx, r, hasher, size, resumeOffset, params.chunkSize, jobsCh)
		close(jobsCh)
		return err
	})
	if runErr != nil {
		return zeroVal[security.Digest](), 0, runErr
	}
	return digestFromHash(hasher), chunksDone.Load(), nil
}
func produceUploadJobs(ctx context.Context, r ports.BoundedReadHandle, hasher io.Writer, size, resumeOffset, chunkSize int64, jobsCh chan<- chunkBuf) error {
	for offset := int64(0); offset < size; {
		buf := make([]byte, min(chunkSize, size-offset))
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		_, _ = hasher.Write(buf)
		if offset >= resumeOffset {
			select {
			case jobsCh <- chunkBuf{offset: offset, data: buf}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		offset += int64(len(buf))
	}
	return nil
}
func runUploadWorker(ctx context.Context, rfs ports.RemoteFSPort, emitter *transferEmitter, jobsCh <-chan chunkBuf, totalSize int64, params uploadExecParams, writtenBytes, chunksDone *atomic.Int64) error {
	for job := range jobsCh {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := rfs.WriteChunk(ctx, params.stagePath, job.offset, bytes.NewReader(job.data), int64(len(job.data))); err != nil {
			return err
		}
		done, chunks := writtenBytes.Add(int64(len(job.data))), chunksDone.Add(1)
		emitter.emitProgress(ctx, params.transferID, fsm.TransferDirectionUpload, uint64(done), uint64(totalSize), uint64(chunks), params.startedAt, "uploading")
	}
	return nil
}
