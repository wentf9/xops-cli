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
	req                  SCPUploadRequest
	finalDest, stagePath pathalg.RemotePath
	renameSpec           ports.RemoteRenameSpec
	perm                 fs.FileMode
	applyPerm            bool
	chunkSize            int64
	concurrency          int
	transferID           security.OperationID
	startedAt            time.Time
}

// SCPUpload 执行受 core/conc.Nursery 有界并发监督的并行分片 SCP 上传：
// 显式区分 OperatorReadFS（缺席 Fail-Closed）与 ScopedRootFS，严守 INV-B4 单次目录展开、
// Lstat 悬空软链检查、ExpandIntoDir Round-2 保护闭环及续传逐片内容核验防稀疏空洞/换源损坏。
func (s *Service) SCPUpload(ctx context.Context, req SCPUploadRequest) (SCPUploadResult, error) {
	defer closeStreamIfNonNil(req.OperationStream)
	hop, params, err := s.validateSCPUploadRequest(ctx, req)
	if err != nil {
		return SCPUploadResult{}, err
	}
	spec := authOpSpec{base: req.CallBase, targetHop: hop, tool: "scp", action: "upload", paths: []pathalg.RemotePath{req.RemoteDest}, expandBase: pickIf(req.ExpandIntoDir, req.Source.BaseName(), ""), defaultRisk: security.RiskModerate, summary: "scp upload -> " + req.RemoteDest.String(), canonicalize: true}
	return runAuthorizedRemoteFS[security.CapTransfer](ctx, s, spec, func(opCtx context.Context, auth gate.Authorized[security.CapTransfer], rfs ports.RemoteFSPort, emitter *transferEmitter) (SCPUploadResult, error) {
		finalDest, err := resolveRemoteUploadDest(opCtx, rfs, req.RemoteDest, req.Source.BaseName(), req.ExpandIntoDir, req.NoClobber)
		if err == nil {
			err = verifyRemotePathAuthorized(opCtx, s.enforceStrictPaths(), rfs, auth.Binding(), finalDest)
		}
		if err == nil {
			var token string
			if token, err = s.stageToken("xops.scp.upload.v1", finalDest.String(), req.Resume); err == nil {
				params.stagePath, err = joinRemoteBase(finalDest.Dir(), ".xops-stage-"+token+".part")
			}
		}
		if err != nil {
			return SCPUploadResult{}, err
		}
		params.finalDest, params.transferID, params.startedAt = finalDest, auth.OperationID(), s.clock.Now().UTC().Round(0)
		return s.openSourceAndUpload(opCtx, rfs, emitter, params)
	})
}
func (s *Service) validateSCPUploadRequest(ctx context.Context, req SCPUploadRequest) (hop plan.HopSpec, params uploadExecParams, err error) {
	if hop, err = s.validateRemotePathOp(ctx, req.CallBase, req.RemoteDest); err != nil {
		return hop, params, err
	}
	if !req.Source.IsValid() || (req.Source.Kind() == LocalUploadSourceOperator && s.operatorReadFS == nil) || (req.Source.Kind() == LocalUploadSourceScoped && s.scopedFS == nil) {
		return hop, params, pickIf[error](!req.Source.IsValid(), fmt.Errorf("%w: LocalUploadSource 无效", ErrInvalidRequest), pickIf[error](req.Source.Kind() == LocalUploadSourceOperator, ErrOperatorReadUnavailable, ErrScopedFSUnavailable))
	}
	e1 := validateOptionalUploadAttrs(req.ModTime, req.ExpectedDigest)
	cs, conc, e2 := s.resolveChunkAndConcurrency(req.ChunkSize, req.Concurrency)
	perm, e3 := resolvePerm(req.Perm, defaultRemoteFilePerm)
	renameSpec, e4 := ports.NewRemoteRenameSpec(ports.RemoteRenameSpecInput{NoClobber: req.NoClobber})
	return hop, uploadExecParams{req: req, renameSpec: renameSpec, perm: perm, applyPerm: req.PreserveMode || req.Perm.IsSome(), chunkSize: cs, concurrency: conc}, firstErr(e1, e2, e3, e4)
}
func validateOptionalUploadAttrs(modTime algebraic.Option[time.Time], expDig algebraic.Option[security.Digest]) error {
	mt, okM := modTime.Get()
	dig, okD := expDig.Get()
	return firstErr(pickIf[error](okM && !isValidRFC3339Time(mt), fmt.Errorf("%w: ModTime 必须为有效 RFC 3339 非零时刻", ErrInvalidRequest), nil), pickIf[error](okD && !dig.IsValid(), fmt.Errorf("%w: ExpectedDigest 无效", ErrInvalidRequest), nil))
}

// resolveRemoteUploadDest 严守 INV-B4：至多一次远端容器目录展开，经 Lstat 识别悬空软链与目录冲突。
func resolveRemoteUploadDest(ctx context.Context, rfs ports.RemoteFSPort, dest pathalg.RemotePath, sourceBase string, expandIntoDir, noClobber bool) (pathalg.RemotePath, error) {
	exists, isDir, err := inspectRemoteUploadTarget(ctx, rfs, dest)
	if err == nil && exists && isDir {
		if !expandIntoDir {
			return zeroVal[pathalg.RemotePath](), fmt.Errorf("%w: 禁止覆写远端目录 %s", ports.ErrRemoteIsDir, dest)
		}
		if dest, err = joinRemoteBase(dest, sourceBase); err == nil {
			exists, isDir, err = inspectRemoteUploadTarget(ctx, rfs, dest)
		}
		if err == nil && exists && isDir {
			return zeroVal[pathalg.RemotePath](), fmt.Errorf("%w: 展开目标 %s 为目录（禁止二次展开）", ports.ErrRemoteIsDir, dest)
		}
	}
	return dest, firstErr(err, pickIf[error](exists && noClobber, fmt.Errorf("%w: 远端目标 %s 已存在（含悬空软链）", ports.ErrAlreadyExists, dest), nil))
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
	return true, err == nil && st.IsDir(), pickIf[error](errors.Is(err, ports.ErrNotFound), nil, err)
}
func (s *Service) openSourceAndUpload(ctx context.Context, rfs ports.RemoteFSPort, emitter *transferEmitter, params uploadExecParams) (res SCPUploadResult, err error) {
	src := params.req.Source
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
			if params.req.PreserveTimes && params.req.ModTime.IsNone() && isValidRFC3339Time(info.ModTime()) {
				params.req.ModTime = algebraic.Some(info.ModTime())
			}
			if params.req.PreserveMode && params.req.Perm.IsNone() && info.Perm() != 0 {
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
	resumeOffset, err := calcResumeOffset(size, params.chunkSize, params.req.Resume, func() (int64, bool, error) {
		st, sErr := rfs.Lstat(ctx, params.stagePath)
		return st.Size(), st.IsRegular(), sErr
	}, func() error { return rfs.Remove(ctx, params.stagePath) })
	if err != nil {
		return SCPUploadResult{}, err
	}
	committed := false
	defer func() {
		if !committed && !params.req.Resume {
			_ = rfs.Remove(context.WithoutCancel(ctx), params.stagePath)
		}
	}()
	digest, verifiedResumed, chunksUploaded, err := streamUploadChunks(ctx, rfs, emitter, r, size, resumeOffset, params)
	if err != nil {
		return SCPUploadResult{}, err
	}
	if expDig, ok := params.req.ExpectedDigest.Get(); ok && !expDig.Equal(digest) {
		_ = rfs.Remove(context.WithoutCancel(ctx), params.stagePath)
		return SCPUploadResult{}, fmt.Errorf("%w: 上传源摘要与 ExpectedDigest 不一致", ErrDigestMismatch)
	}
	preserved, err := commitUploadedStage(ctx, rfs, params)
	committed = err == nil
	return pickIf(err == nil, SCPUploadResult{RemotePath: params.finalDest, BytesTransferred: size, ResumedBytes: verifiedResumed, ChunksTransferred: chunksUploaded, Digest: digest, ModTimePreserved: preserved}, SCPUploadResult{}), err
}
func commitUploadedStage(ctx context.Context, rfs ports.RemoteFSPort, params uploadExecParams) (bool, error) {
	var err error
	if params.applyPerm {
		err = rfs.Chmod(ctx, params.stagePath, params.perm)
	}
	if err == nil {
		err = rfs.RenameAtomic(ctx, params.stagePath, params.finalDest, params.renameSpec)
	}
	if err != nil {
		return false, err
	}
	if mt, ok := params.req.ModTime.Get(); params.req.PreserveTimes && ok {
		err = rfs.Chtimes(ctx, params.finalDest, mt, mt)
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
	rmErr := rmFn()
	return 0, pickIf[error](rmErr != nil && !errors.Is(rmErr, ports.ErrNotFound), rmErr, nil)
}
func streamUploadChunks(ctx context.Context, rfs ports.RemoteFSPort, emitter *transferEmitter, r ports.BoundedReadHandle, size, resumeOffset int64, params uploadExecParams) (security.Digest, int64, int64, error) {
	if size == 0 {
		_ = rfs.Remove(ctx, params.stagePath)
		return security.DigestBytes(nil), 0, 0, rfs.WriteChunk(ctx, params.stagePath, 0, bytes.NewReader(nil), 0)
	}
	hasher, jobsCh := sha256.New(), make(chan chunkBuf, params.concurrency)
	var writtenBytes, chunksDone, verifiedResumed atomic.Int64
	runErr := conc.RunWait(ctx, func(wCtx context.Context, n *conc.Nursery) error {
		for range params.concurrency {
			if err := n.Go(func(c context.Context) error {
				return runUploadWorker(c, rfs, emitter, jobsCh, size, params, &writtenBytes, &chunksDone)
			}); err != nil {
				close(jobsCh)
				return err
			}
		}
		err := produceUploadJobs(wCtx, rfs, r, hasher, size, resumeOffset, params, jobsCh, &writtenBytes, &verifiedResumed)
		close(jobsCh)
		return err
	})
	return pickIf(runErr == nil, digestFromHash(hasher), zeroVal[security.Digest]()), verifiedResumed.Load(), chunksDone.Load(), runErr
}

// produceUploadJobs 按序读取本地源并计算全量摘要；对 resumeOffset 以内分片逐片回读比对远端暂存内容，
// 发现稀疏零空洞或换源失配立即重传，彻底杜绝 Resume 静默数据损坏。
func produceUploadJobs(ctx context.Context, rfs ports.RemoteFSPort, r ports.BoundedReadHandle, hasher io.Writer, size, resumeOffset int64, params uploadExecParams, jobsCh chan<- chunkBuf, writtenBytes, verifiedResumed *atomic.Int64) error {
	for offset := int64(0); offset < size; offset += params.chunkSize {
		if err := ctx.Err(); err != nil {
			return err
		}
		buf := make([]byte, min(params.chunkSize, size-offset))
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		_, _ = hasher.Write(buf)
		n := int64(len(buf))
		if offset < resumeOffset {
			if existing, err := readRemoteChunkExact(ctx, rfs, params.stagePath, offset, n); err == nil && bytes.Equal(existing, buf) {
				writtenBytes.Add(n)
				verifiedResumed.Add(n)
				continue
			}
		}
		if err := sendOrDone(ctx, jobsCh, chunkBuf{offset: offset, data: buf}); err != nil {
			return err
		}
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

// 以下为 SCP / 流式下载共享的本地 ScopedRootFS 原子落盘与软链覆写辅助函数。
func hashLocalStagedFile(root ports.RootHandle, stageDest pathalg.LocalRootedDest, expectedSize int64) (security.Digest, error) {
	limits, err := ports.NewReadLimits(max(expectedSize, 1))
	h := sha256.New()
	if err == nil {
		err = root.WithReadRegular(stageDest, limits, func(r ports.BoundedReadHandle, size int64) error {
			if size != expectedSize {
				return fmt.Errorf("%w: 本地暂存大小 %d 与预期 %d 不符", io.ErrUnexpectedEOF, size, expectedSize)
			}
			_, copyErr := io.Copy(h, r)
			return copyErr
		})
	}
	return pickIf(err == nil, digestFromHash(h), zeroVal[security.Digest]()), err
}
func ensureParentLocalDir(root ports.RootHandle, dest pathalg.LocalRootedDest) error {
	if parent, ok := dest.Parent(); ok {
		return root.MkdirAll(parent, defaultDirPerm)
	}
	return nil
}
func checkLocalNoClobber(root ports.RootHandle, dest pathalg.LocalRootedDest, noClobber bool) error {
	if !noClobber {
		return nil
	}
	_, err := root.Lstat(dest)
	return pickIf[error](err == nil, fmt.Errorf("%w: 本地目标 %s 已存在", ports.ErrAlreadyExists, dest), pickIf[error](errors.Is(err, ports.ErrNotFound), nil, err))
}
func createLocalSymlink(root ports.RootHandle, dest pathalg.LocalRootedDest, target string, noClobber bool) error {
	if st, err := root.Lstat(dest); err == nil {
		if noClobber || st.IsDir() {
			return pickIf(noClobber, fmt.Errorf("%w: 本地目标 %s 已存在", ports.ErrAlreadyExists, dest), fmt.Errorf("%w: 禁止以软链覆写已有目录 %s", ports.ErrRemoteIsDir, dest))
		}
		if rmErr := root.Remove(dest); rmErr != nil {
			return rmErr
		}
	} else if !errors.Is(err, ports.ErrNotFound) {
		return err
	}
	return root.CreateSymlink(dest, target)
}
func sanitizeLocalDownloadPerm(remotePerm fs.FileMode) fs.FileMode {
	return pickIf(remotePerm.Perm() != 0, remotePerm.Perm()|0o600, defaultLocalStagePerm)
}
