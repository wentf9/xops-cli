package transfer

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/usecase/transfer/remotecanon"
	"github.com/wentf9/xops-cli/core/ports"
)

type (
	chunkBuf struct {
		offset int64
		data   []byte
	}
	uploadExecParams struct {
		req                   SCPUploadRequest
		finalDest, stagePath  pathalg.RemotePath
		renameSpec            ports.RemoteRenameSpec
		perm                  fs.FileMode
		applyPerm             bool
		chunkSize             int64
		concurrency, maxFiles int
		maxBytes              uint64
		transferID            security.OperationID
		startedAt             time.Time
	}
	plannedUploadDir struct {
		remote  pathalg.RemotePath
		perm    fs.FileMode
		modTime time.Time
	}
	plannedUploadFile struct {
		plannedUploadDir
		local pathalg.LocalRootedDest
	}
	recursiveUploadPlan struct {
		dirs                 []plannedUploadDir
		files                []plannedUploadFile
		allLocal             []pathalg.LocalRootedDest
		totalBytes, maxBytes uint64
		maxFiles             int
	}
)

// SCPUpload 执行受 core/conc.Nursery 有界并发监督的并行分片 SCP 上传（单文件或基于 ScopedRootFS 的递归目录上传）：
// 显式区分 OperatorReadFS（缺席 Fail-Closed）与 ScopedRootFS，收口于单次 gate.WithAuthorized[CapTransfer] 与单次 pool.WithLease，
// 严守 INV-B4 单次目录展开、SymlinkPolicy、MaxFiles/MaxTotalBytes、Lstat 悬空软链检查及续传逐片内容核验。
func (s *Service) SCPUpload(ctx context.Context, req SCPUploadRequest) (SCPUploadResult, error) {
	defer closeStream(req.OperationStream)
	hop, params, err := s.validateSCPUploadRequest(ctx, req)
	if err != nil {
		return SCPUploadResult{}, err
	}
	spec := authOpSpec{
		base: req.CallBase, targetHop: hop, tool: "scp", action: "upload",
		paths: pickIf(req.Recursive, nil, []pathalg.RemotePath{req.RemoteDest}), recursivePaths: pickIf(req.Recursive, []pathalg.RemotePath{req.RemoteDest}, nil),
		expandBase: pickIf(req.ExpandIntoDir, req.Source.BaseName(), ""), defaultRisk: security.RiskModerate,
		summary: "scp upload -> " + req.RemoteDest.String(), canonicalize: true,
	}
	return runAuthorizedRemoteFS[security.CapTransfer](ctx, s, spec, func(opCtx context.Context, auth gate.Authorized[security.CapTransfer], rfs ports.RemoteFSPort, emitter *transferEmitter) (SCPUploadResult, error) {
		params.transferID, params.startedAt = auth.OperationID(), s.clock.Now().UTC().Round(0)
		if req.Recursive {
			return s.executeRecursiveSCPUpload(opCtx, auth.Binding(), rfs, emitter, params)
		}
		return s.executeSingleSCPUpload(opCtx, auth.Binding(), rfs, emitter, params)
	})
}
func (s *Service) executeSingleSCPUpload(ctx context.Context, binding security.OperationBinding, rfs ports.RemoteFSPort, emitter *transferEmitter, params uploadExecParams) (SCPUploadResult, error) {
	req := params.req
	finalDest, err := remotecanon.ResolveUploadTarget(ctx, rfs, req.RemoteDest, req.Source.BaseName(), req.ExpandIntoDir, req.NoClobber, false, ErrInvalidRequest)
	if err == nil {
		err = remotecanon.VerifyPathAuthorized(ctx, s.strictPaths(), rfs, binding, finalDest, canonSentinels())
	}
	if err == nil {
		params.stagePath, err = s.buildUploadStagePath(finalDest, req.Resume)
	}
	if err != nil {
		return SCPUploadResult{}, err
	}
	params.finalDest = finalDest
	return s.openSourceAndUpload(ctx, rfs, emitter, params)
}
func (s *Service) buildUploadStagePath(finalDest pathalg.RemotePath, resume bool) (pathalg.RemotePath, error) {
	token, err := s.stageToken("xops.scp.upload.v1", finalDest.String(), resume)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), err
	}
	return remotecanon.JoinRemoteBase(finalDest.Dir(), ".xops-stage-"+token+".part", ErrInvalidRequest)
}
func resolveRecursiveLimits(maxFiles int, maxBytes uint64) (int, uint64, error) {
	if maxFiles < 0 || maxFiles > maxRecursiveFilesLimit {
		return 0, 0, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldRange, domi18n.Str("field", "MaxFiles"), domi18n.Int("value", maxFiles), domi18n.Int("min", 0), domi18n.Int("max", maxRecursiveFilesLimit))
	}
	if maxBytes > fsm.MaxTransferBytes {
		return 0, 0, domi18n.EF(fsm.ErrTransferSizeExceeded, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "MaxTotalBytes"), domi18n.Uint64("size", maxBytes), domi18n.Uint64("limit", fsm.MaxTransferBytes))
	}
	return pickIf(maxFiles == 0, defaultMaxRecursiveFiles, maxFiles), pickIf(maxBytes == 0, fsm.MaxTransferBytes, maxBytes), nil
}
func (s *Service) validateSCPUploadRequest(ctx context.Context, req SCPUploadRequest) (hop plan.HopSpec, params uploadExecParams, err error) {
	if hop, err = s.validateRemotePathOp(ctx, req.CallBase, req.RemoteDest); err != nil {
		return hop, params, err
	}
	if !req.Source.IsValid() || (req.Source.Kind() == LocalUploadSourceOperator && s.operatorReadFS == nil) || (req.Source.Kind() == LocalUploadSourceScoped && s.scopedFS == nil) {
		return hop, params, pickIf[error](!req.Source.IsValid(), domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "LocalUploadSource")), pickIf[error](req.Source.Kind() == LocalUploadSourceOperator, ErrOperatorReadUnavailable, ErrScopedFSUnavailable))
	}
	maxFiles, maxBytes, e0 := validateRecursiveUploadParams(req)
	e1 := validateOptionalUploadAttrs(req.ModTime, req.ExpectedDigest)
	cs, conc, e2 := s.resolveChunkAndConcurrency(req.ChunkSize, req.Concurrency)
	perm, e3 := resolvePerm(req.Perm, defaultRemoteFilePerm)
	renameSpec, e4 := ports.NewRemoteRenameSpec(ports.RemoteRenameSpecInput{NoClobber: req.NoClobber})
	return hop, uploadExecParams{req: req, renameSpec: renameSpec, perm: perm, applyPerm: req.PreserveMode || req.Perm.IsSome(), chunkSize: cs, concurrency: conc, maxFiles: maxFiles, maxBytes: maxBytes}, firstErr(e0, e1, e2, e3, e4)
}
func validateRecursiveUploadParams(req SCPUploadRequest) (int, uint64, error) {
	if !req.Recursive {
		return defaultMaxRecursiveFiles, fsm.MaxTransferBytes, nil
	}
	if req.Source.Kind() != LocalUploadSourceScoped {
		return 0, 0, domi18n.WrapS(ErrInvalidRequest, ports.ErrUnsupported, domi18n.KeyCommonNotSupported, domi18n.Str("feature", "recursive_operator_upload"))
	}
	if !req.SymlinkPolicy.IsValid() || req.SymlinkPolicy != pathalg.SymlinkReject {
		return 0, 0, domi18n.WrapSentinel(ErrSymlinkPolicyDenied, domi18n.Wrap(ports.ErrSymlinkRejected, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "SymlinkPolicy"), domi18n.Str("value", req.SymlinkPolicy.String())), ports.ErrSymlinkRejected)
	}
	return resolveRecursiveLimits(req.MaxFiles, req.MaxTotalBytes)
}
func validateOptionalUploadAttrs(modTime algebraic.Option[time.Time], expDig algebraic.Option[security.Digest]) error {
	mt, okM := modTime.Get()
	dig, okD := expDig.Get()
	return firstErr(pickIf[error](okM && !validRFC3339(mt), domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "ModTime")), nil), pickIf[error](okD && !dig.IsValid(), domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "ExpectedDigest")), nil))
}
func (s *Service) openSourceAndUpload(ctx context.Context, rfs ports.RemoteFSPort, emitter *transferEmitter, params uploadExecParams) (res SCPUploadResult, err error) {
	src := params.req.Source
	if src.kind == LocalUploadSourceOperator {
		return res, s.operatorReadFS.WithOperatorRead(ctx, src.operatorPath, src.symlinkPolicy, func(r ports.BoundedReadHandle, size int64) error {
			res, err = uploadFromBoundedReader(ctx, rfs, emitter, r, size, params)
			return err
		})
	}
	limits, err := ports.NewReadLimits(int64(fsm.MaxTransferBytes))
	if err != nil {
		return res, err
	}
	return res, s.scopedFS.WithRoot(src.scopedRoot, func(root ports.RootHandle) error {
		if info, sErr := root.Stat(src.scopedPath); sErr == nil && info.IsValid() {
			applyScopedFileAttrs(&params, info.Perm(), info.ModTime())
		}
		return root.WithReadRegular(src.scopedPath, limits, func(r ports.BoundedReadHandle, size int64) error {
			res, err = uploadFromBoundedReader(ctx, rfs, emitter, r, size, params)
			return err
		})
	})
}

// uploadFromBoundedReader 同步消费借用句柄 r 并经 conc.RunWait 扇出并发 WriteChunk（r 绝不逃逸至 n.Go）。
func uploadFromBoundedReader(ctx context.Context, rfs ports.RemoteFSPort, emitter *transferEmitter, r ports.BoundedReadHandle, size int64, params uploadExecParams) (SCPUploadResult, error) {
	if size < 0 || uint64(size) > fsm.MaxTransferBytes {
		return SCPUploadResult{}, domi18n.EF(fsm.ErrTransferSizeExceeded, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "local_file"), domi18n.Int64("size", size), domi18n.Uint64("limit", fsm.MaxTransferBytes))
	}
	resumeOffset, err := calcResumeOffset(size, params.chunkSize, params.req.Resume, func() (int64, bool, error) {
		st, sErr := rfs.Lstat(ctx, params.stagePath)
		return st.Size(), st.IsRegular(), sErr
	}, func() error { return rfs.Remove(ctx, params.stagePath) })
	if err != nil {
		return SCPUploadResult{}, err
	}
	committed, dropStage := false, false
	defer func() {
		if (!committed && !params.req.Resume) || dropStage {
			_ = rfs.Remove(context.WithoutCancel(ctx), params.stagePath)
		}
	}()
	digest, verifiedResumed, chunksUploaded, err := streamUploadChunks(ctx, rfs, emitter, r, size, resumeOffset, params)
	if err != nil {
		return SCPUploadResult{}, err
	}
	if expDig, ok := params.req.ExpectedDigest.Get(); ok && !expDig.Equal(digest) {
		dropStage = true
		return SCPUploadResult{}, domi18n.EF(ErrDigestMismatch, domi18n.KeyCommonMismatch, domi18n.Str("field", "sha256"), domi18n.Str("expected", expDig.String()), domi18n.Str("actual", digest.String()))
	}
	preserved, err := commitUploadedStage(ctx, rfs, params)
	committed = err == nil
	return pickIf(err == nil, SCPUploadResult{RemotePath: params.finalDest, FilesUploaded: 1, BytesTransferred: size, ResumedBytes: verifiedResumed, ChunksTransferred: chunksUploaded, Digest: digest, ModTimePreserved: preserved}, SCPUploadResult{}), err
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
		if n := int64(len(buf)); offset < resumeOffset {
			if existing, err := remotecanon.ReadChunkExact(ctx, rfs, params.stagePath, offset, n); err == nil && bytes.Equal(existing, buf) {
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

// executeRecursiveSCPUpload 在单一 WithRoot 与单一已授权 RemoteFSPort 租约内执行沙箱源递归目录（或单文件）上传：
// 写前完整遍历并校验 SymlinkPolicy、MaxFiles、MaxTotalBytes 与跨平台路径碰撞，严守 INV-B4 单次容器目录展开与自底向上 mtime 保留。
func (s *Service) executeRecursiveSCPUpload(ctx context.Context, binding security.OperationBinding, rfs ports.RemoteFSPort, emitter *transferEmitter, params uploadExecParams) (out SCPUploadResult, err error) {
	src, isRegular, regSize := params.req.Source, false, int64(0)
	err = s.scopedFS.WithRoot(src.scopedRoot, func(root ports.RootHandle) error {
		lstat, sErr := root.Lstat(src.scopedPath)
		if sErr != nil {
			return sErr
		}
		switch {
		case lstat.IsSymlink():
			return domi18n.WrapS(ErrSymlinkPolicyDenied, ports.ErrSymlinkRejected, domi18n.KeyUCTransferSymlinkPol, domi18n.Str("policy", params.req.SymlinkPolicy.String()), domi18n.BoundStr("path", src.scopedPath.String()))
		case lstat.IsRegular():
			isRegular, regSize = true, lstat.Size()
			return nil
		case lstat.IsDir():
			out, sErr = s.uploadScopedDirectoryTree(ctx, binding, rfs, root, emitter, lstat, params)
			return sErr
		default:
			return domi18n.EF(ports.ErrNotRegularFile, domi18n.KeyCommonPathForbidden, domi18n.BoundStr("path", src.scopedPath.String()), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyUCTransferReasonNotRegular)))
		}
	})
	if err != nil || !isRegular {
		return out, err
	}
	if uint64(regSize) > params.maxBytes {
		return out, domi18n.EF(fsm.ErrTransferSizeExceeded, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "local_file"), domi18n.Int64("size", regSize), domi18n.Uint64("limit", params.maxBytes))
	}
	return s.executeSingleSCPUpload(ctx, binding, rfs, emitter, params)
}
func applyScopedFileAttrs(params *uploadExecParams, perm fs.FileMode, modTime time.Time) {
	if params.req.PreserveTimes && params.req.ModTime.IsNone() && validRFC3339(modTime) {
		params.req.ModTime = algebraic.Some(modTime)
	}
	if params.req.PreserveMode && params.req.Perm.IsNone() && perm != 0 {
		params.perm = perm
	}
}
func (s *Service) uploadScopedDirectoryTree(ctx context.Context, binding security.OperationBinding, rfs ports.RemoteFSPort, root ports.RootHandle, emitter *transferEmitter, rootStat ports.LocalFileInfo, params uploadExecParams) (SCPUploadResult, error) {
	req, pl := params.req, &recursiveUploadPlan{maxFiles: params.maxFiles, maxBytes: params.maxBytes}
	rootRemote, err := remotecanon.ResolveUploadTarget(ctx, rfs, req.RemoteDest, req.Source.BaseName(), req.ExpandIntoDir, req.NoClobber, true, ErrInvalidRequest)
	if err == nil {
		err = remotecanon.VerifyPathAuthorized(ctx, s.strictPaths(), rfs, binding, rootRemote, canonSentinels())
	}
	if err == nil {
		err = walkLocalUploadTree(ctx, root, req.Source.scopedPath, rootStat, rootRemote, req.PreserveMode, pl)
	}
	if err != nil {
		return SCPUploadResult{}, err
	}
	if cErr := pathalg.CheckPathCollisions(pl.allLocal); cErr != nil {
		return SCPUploadResult{}, domi18n.WrapSentinel(ErrSymlinkPolicyDenied, cErr)
	}
	out := SCPUploadResult{RemotePath: rootRemote}
	if err = s.createRemoteUploadDirs(ctx, binding, rfs, pl.dirs, &out); err != nil {
		return out, err
	}
	limits, err := ports.NewReadLimits(int64(fsm.MaxTransferBytes))
	for i := 0; err == nil && i < len(pl.files); i++ {
		err = s.uploadOnePlannedFile(ctx, binding, rfs, root, emitter, pl.files[i], limits, params, &out)
	}
	if err == nil && req.PreserveTimes {
		err = applyDirTimesOrdered(pl.dirs, func(a, b plannedUploadDir) int {
			return cmp.Or(cmp.Compare(strings.Count(b.remote.String(), "/"), strings.Count(a.remote.String(), "/")), a.remote.Compare(b.remote))
		}, func(d plannedUploadDir) time.Time { return d.modTime }, func(d plannedUploadDir, mt time.Time) error { return rfs.Chtimes(ctx, d.remote, mt, mt) }, &out.ModTimePreserved)
	}
	return out, err
}
func walkLocalUploadTree(ctx context.Context, root ports.RootHandle, localDir pathalg.LocalRootedDest, dirStat ports.LocalFileInfo, remoteDir pathalg.RemotePath, preserveMode bool, pl *recursiveUploadPlan) error {
	if err := ctx.Err(); err != nil || len(pl.allLocal) >= pl.maxFiles {
		return pickIf[error](err != nil, err, domi18n.EF(ports.ErrLimitExceeded, domi18n.KeyCommonCountLimit, domi18n.Str("kind", "upload_entries"), domi18n.Int("count", len(pl.allLocal)), domi18n.Int("limit", pl.maxFiles)))
	}
	pl.dirs, pl.allLocal = append(pl.dirs, plannedUploadDir{remote: remoteDir, perm: pickIf(preserveMode && dirStat.Perm() != 0, dirStat.Perm(), defaultDirPerm), modTime: dirStat.ModTime()}), append(pl.allLocal, localDir)
	entries, err := root.ReadDir(algebraic.Some(localDir))
	if err != nil {
		return err
	}
	slices.SortFunc(entries, func(a, b ports.LocalDirEntry) int { return cmp.Compare(a.Name(), b.Name()) })
	for _, ent := range entries {
		if err := walkLocalUploadEntry(ctx, root, localDir, remoteDir, ent, preserveMode, pl); err != nil {
			return err
		}
	}
	return nil
}
func walkLocalUploadEntry(ctx context.Context, root ports.RootHandle, localDir pathalg.LocalRootedDest, remoteDir pathalg.RemotePath, ent ports.LocalDirEntry, preserveMode bool, pl *recursiveUploadPlan) error {
	if len(pl.allLocal) >= pl.maxFiles {
		return domi18n.EF(ports.ErrLimitExceeded, domi18n.KeyCommonCountLimit, domi18n.Str("kind", "upload_entries"), domi18n.Int("count", len(pl.allLocal)), domi18n.Int("limit", pl.maxFiles))
	}
	childLocal, e1 := localDir.JoinComponent(ent.Name())
	rName, e2 := pathalg.ParseRemoteName(ent.Name())
	childRemote, e3 := remoteDir.Join(rName)
	if err := firstErr(e1, e2, e3); err != nil {
		return err
	}
	childStat, err := root.Lstat(childLocal)
	if err != nil {
		return err
	}
	switch {
	case childStat.IsSymlink():
		return domi18n.WrapS(ErrSymlinkPolicyDenied, ports.ErrSymlinkRejected, domi18n.KeyUCTransferSymlinkPol, domi18n.Str("policy", pathalg.SymlinkReject.String()), domi18n.BoundStr("path", childLocal.String()))
	case childStat.IsDir():
		return walkLocalUploadTree(ctx, root, childLocal, childStat, childRemote, preserveMode, pl)
	case childStat.IsRegular():
		if uint64(childStat.Size()) > pl.maxBytes-pl.totalBytes {
			return domi18n.EF(fsm.ErrTransferSizeExceeded, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "upload_total"), domi18n.Uint64("size", pl.totalBytes+uint64(childStat.Size())), domi18n.Uint64("limit", pl.maxBytes))
		}
		pl.totalBytes, pl.files, pl.allLocal = pl.totalBytes+uint64(childStat.Size()), append(pl.files, plannedUploadFile{plannedUploadDir: plannedUploadDir{remote: childRemote, perm: childStat.Perm(), modTime: childStat.ModTime()}, local: childLocal}), append(pl.allLocal, childLocal)
		return nil
	default:
		return domi18n.EF(ports.ErrNotRegularFile, domi18n.KeyCommonPathForbidden, domi18n.BoundStr("path", childLocal.String()), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyUCTransferReasonNotRegular)))
	}
}
func (s *Service) createRemoteUploadDirs(ctx context.Context, binding security.OperationBinding, rfs ports.RemoteFSPort, dirs []plannedUploadDir, out *SCPUploadResult) error {
	for _, d := range dirs {
		if err := remotecanon.VerifyPathAuthorized(ctx, s.strictPaths(), rfs, binding, d.remote, canonSentinels()); err != nil {
			return err
		}
		if exists, isDir, err := remotecanon.InspectUploadTarget(ctx, rfs, d.remote); err != nil || (exists && !isDir) {
			return pickIf[error](err != nil, err, domi18n.EF(ports.ErrAlreadyExists, domi18n.KeyCommonPathForbidden, domi18n.BoundStr("path", d.remote.String()), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyUCTransferReasonExistsNonDir))))
		}
		if err := rfs.MkdirAll(ctx, d.remote, d.perm); err != nil {
			return err
		}
		out.DirsCreated++
	}
	return nil
}
func (s *Service) uploadOnePlannedFile(ctx context.Context, binding security.OperationBinding, rfs ports.RemoteFSPort, root ports.RootHandle, emitter *transferEmitter, f plannedUploadFile, limits ports.ReadLimits, base uploadExecParams, out *SCPUploadResult) error {
	if exists, isDir, err := remotecanon.InspectUploadTarget(ctx, rfs, f.remote); err != nil || (exists && (isDir || base.req.NoClobber)) {
		return pickIf[error](err != nil, err, pickIf(isDir, domi18n.EF(ports.ErrRemoteIsDir, domi18n.KeyCommonPathForbidden, domi18n.BoundStr("path", f.remote.String()), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyUCTransferReasonTargetIsDir))), domi18n.EF(ports.ErrAlreadyExists, domi18n.KeyCommonPathForbidden, domi18n.BoundStr("path", f.remote.String()), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyUCTransferReasonAlreadyExist)))))
	}
	if err := remotecanon.VerifyPathAuthorized(ctx, s.strictPaths(), rfs, binding, f.remote, canonSentinels()); err != nil {
		return err
	}
	stagePath, err := s.buildUploadStagePath(f.remote, base.req.Resume)
	if err != nil {
		return err
	}
	fp := base
	fp.finalDest, fp.stagePath, fp.req.ExpectedDigest, fp.req.ModTime = f.remote, stagePath, algebraic.None[security.Digest](), algebraic.None[time.Time]()
	applyScopedFileAttrs(&fp, f.perm, f.modTime)
	return root.WithReadRegular(f.local, limits, func(r ports.BoundedReadHandle, size int64) error {
		res, uErr := uploadFromBoundedReader(ctx, rfs, emitter, r, size, fp)
		if uErr == nil {
			out.FilesUploaded, out.BytesTransferred, out.ResumedBytes, out.ChunksTransferred, out.ModTimePreserved = out.FilesUploaded+1, out.BytesTransferred+res.BytesTransferred, out.ResumedBytes+res.ResumedBytes, out.ChunksTransferred+res.ChunksTransferred, out.ModTimePreserved || res.ModTimePreserved
		}
		return uErr
	})
}
