package transfer

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"io/fs"
	"slices"
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
	downloadFileSpec struct {
		req                   SCPDownloadRequest
		authBinding           security.OperationBinding
		remoteStat            ports.RemoteFileStat
		chunkSize             int64
		concurrency, maxFiles int
		maxBytes              uint64
		transferID            security.OperationID
		startedAt             time.Time
	}
	plannedDir struct {
		local   pathalg.LocalRootedDest
		modTime time.Time
	}
	plannedFile struct {
		remote pathalg.RemotePath
		local  pathalg.LocalRootedDest
		stat   ports.RemoteFileStat
	}
	plannedSymlink struct {
		local  pathalg.LocalRootedDest
		target string
	}
	recursiveDownloadPlan struct {
		dirs                 []plannedDir
		files                []plannedFile
		symlinks             []plannedSymlink
		allDests             []pathalg.LocalRootedDest
		totalBytes, maxBytes uint64
		maxFiles             int
		visited              map[string]struct{}
	}
)

// SCPDownload 执行受 core/conc.Nursery 监督的并行分片 SCP 下载（单文件或递归目录），
// 全程仅依赖 ScopedRootFS（零 OperatorReadFS 依赖），采用有界滑动窗口按序落盘杜绝 Resume 稀疏空洞，
// 严守 INV-B1..B3 并支持 Chtimes mtime 保留。
func (s *Service) SCPDownload(ctx context.Context, req SCPDownloadRequest) (SCPDownloadResult, error) {
	defer closeStream(req.OperationStream)
	hop, baseSpec, err := s.validateSCPDownloadRequest(ctx, req)
	if err != nil {
		return SCPDownloadResult{}, err
	}
	spec := authOpSpec{base: req.CallBase, targetHop: hop, tool: "scp", action: "download", paths: pickIf(req.Recursive, nil, []pathalg.RemotePath{req.RemoteSource}), recursivePaths: pickIf(req.Recursive, []pathalg.RemotePath{req.RemoteSource}, nil), defaultRisk: security.RiskSafe, summary: "scp download " + req.RemoteSource.String(), canonicalize: true}
	return runAuthorizedRemoteFS[security.CapTransfer](ctx, s, spec, func(opCtx context.Context, auth gate.Authorized[security.CapTransfer], rfs ports.RemoteFSPort, emitter *transferEmitter) (SCPDownloadResult, error) {
		baseSpec.authBinding, baseSpec.transferID, baseSpec.startedAt = auth.Binding(), auth.OperationID(), s.clock.Now().UTC().Round(0)
		return s.executeSCPDownload(opCtx, rfs, emitter, baseSpec)
	})
}
func (s *Service) validateSCPDownloadRequest(ctx context.Context, req SCPDownloadRequest) (hop plan.HopSpec, spec downloadFileSpec, err error) {
	if hop, err = s.validateRemotePathOp(ctx, req.CallBase, req.RemoteSource); err != nil || s.scopedFS == nil {
		return hop, spec, pickIf[error](err != nil, err, ErrScopedFSUnavailable)
	}
	if dig, hasDig := req.ExpectedDigest.Get(); !req.LocalRoot.IsValid() || !req.LocalDest.IsValid() || (hasDig && !dig.IsValid()) {
		return hop, spec, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "LocalRoot/LocalDest/ExpectedDigest"))
	}
	if !req.SymlinkPolicy.IsValid() || req.SymlinkPolicy == pathalg.SymlinkFollowOperatorSource {
		return hop, spec, domi18n.WrapSentinel(ErrSymlinkPolicyDenied, domi18n.E(domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "SymlinkPolicy"), domi18n.Str("value", req.SymlinkPolicy.String())))
	}
	maxFiles, maxBytes, e1 := resolveRecursiveLimits(req.MaxFiles, req.MaxTotalBytes)
	cs, conc, e2 := s.resolveChunkAndConcurrency(req.ChunkSize, req.Concurrency)
	return hop, downloadFileSpec{req: req, chunkSize: cs, concurrency: conc, maxFiles: maxFiles, maxBytes: maxBytes}, firstErr(e1, e2)
}
func (s *Service) executeSCPDownload(ctx context.Context, rfs ports.RemoteFSPort, emitter *transferEmitter, spec downloadFileSpec) (out SCPDownloadResult, err error) {
	req := spec.req
	lstat, err := rfs.Lstat(ctx, req.RemoteSource)
	if err != nil {
		return out, err
	}
	switch lstat.FileType() {
	case ports.RemoteFileRegular:
		if uint64(lstat.Size()) > spec.maxBytes {
			return out, domi18n.EF(fsm.ErrTransferSizeExceeded, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "remote_file"), domi18n.Int64("size", lstat.Size()), domi18n.Uint64("limit", spec.maxBytes))
		}
		spec.remoteStat = lstat
		return out, s.scopedFS.WithRoot(req.LocalRoot, func(root ports.RootHandle) error {
			if e := ensureParentLocalDir(root, req.LocalDest); e != nil {
				return e
			}
			b, res, ch, dig, mod, dErr := s.downloadFileIntoRoot(ctx, rfs, root, emitter, spec)
			if dErr == nil {
				out = SCPDownloadResult{LocalDest: req.LocalDest, FilesDownloaded: 1, BytesTransferred: b, ResumedBytes: res, ChunksTransferred: ch, Digest: algebraic.Some(dig), ModTimePreserved: mod}
			}
			return dErr
		})
	case ports.RemoteFileSymlink:
		return s.downloadSingleSymlink(ctx, rfs, req)
	case ports.RemoteFileDir:
		if !req.Recursive {
			return out, domi18n.EF(ports.ErrRemoteIsDir, domi18n.KeyCommonPathForbidden, domi18n.BoundStr("path", req.RemoteSource.String()), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyUCTransferReasonRecursiveReq)))
		}
		spec.req.ExpectedDigest = algebraic.None[security.Digest]()
		return s.downloadDirectoryTree(ctx, rfs, emitter, lstat, spec)
	default:
		return out, domi18n.EF(ErrRemoteObjectUnsupported, domi18n.KeyUCTransferRemoteType, domi18n.BoundStr("path", req.RemoteSource.String()), domi18n.Str("kind", lstat.FileType().String()))
	}
}
func (s *Service) downloadSingleSymlink(ctx context.Context, rfs ports.RemoteFSPort, req SCPDownloadRequest) (SCPDownloadResult, error) {
	if req.SymlinkPolicy != pathalg.SymlinkContainedRelative {
		return SCPDownloadResult{}, domi18n.WrapS(ErrSymlinkPolicyDenied, ports.ErrSymlinkRejected, domi18n.KeyUCTransferSymlinkPol, domi18n.Str("policy", req.SymlinkPolicy.String()), domi18n.BoundStr("path", req.RemoteSource.String()))
	}
	target, err := rfs.ReadLink(ctx, req.RemoteSource)
	if err != nil {
		return SCPDownloadResult{}, err
	}
	if vErr := pathalg.ValidateContainedSymlink(target, req.LocalDest.Depth()-1); vErr != nil {
		return SCPDownloadResult{}, domi18n.WrapSentinel(ErrSymlinkPolicyDenied, vErr)
	}
	err = s.scopedFS.WithRoot(req.LocalRoot, func(root ports.RootHandle) error {
		if e := ensureParentLocalDir(root, req.LocalDest); e != nil {
			return e
		}
		return createLocalSymlink(root, req.LocalDest, target, req.NoClobber)
	})
	return pickIf(err == nil, SCPDownloadResult{LocalDest: req.LocalDest, SymlinksCreated: 1}, SCPDownloadResult{}), err
}

// downloadFileIntoRoot 经 conc.RunWait 并行拉取分片并在主同步回调按严格连续偏移写盘（0 borrowed 逃逸、0 稀疏空洞）。
func (s *Service) downloadFileIntoRoot(ctx context.Context, rfs ports.RemoteFSPort, root ports.RootHandle, emitter *transferEmitter, spec downloadFileSpec) (bytesN, resumedN, chunksN int64, dig security.Digest, modPres bool, err error) {
	req, st := spec.req, spec.remoteStat
	fileSize := st.Size()
	if err = checkLocalNoClobber(root, req.LocalDest, req.NoClobber); err != nil {
		return 0, 0, 0, dig, false, err
	}
	key := fmt.Sprintf("%s|%s|%d|%d|%d|%d", req.LocalDest, req.RemoteSource, fileSize, st.ModTime().UTC().UnixNano(), st.Anchor().Dev(), st.Anchor().Ino())
	token, err := s.stageToken("xops.scp.download.v2", key, req.Resume)
	var stageDest pathalg.LocalRootedDest
	var resumeOffset int64
	if err == nil {
		stageDest, err = makeLocalStageDest(req.LocalDest, token)
	}
	if err == nil {
		resumeOffset, err = calcResumeOffset(fileSize, spec.chunkSize, req.Resume, func() (int64, bool, error) { ls, sErr := root.Lstat(stageDest); return ls.Size(), ls.IsRegular(), sErr }, func() error { return root.Remove(stageDest) })
	}
	if err != nil {
		return 0, 0, 0, dig, false, err
	}
	committed, dropStage := false, false
	defer func() { removeLocalIf(root, stageDest, (!committed && !req.Resume) || dropStage) }()
	if chunksN, err = streamDownloadChunks(ctx, rfs, root, emitter, stageDest, fileSize, resumeOffset, spec); err == nil {
		dig, err = hashLocalStagedFile(root, stageDest, fileSize)
	}
	if err != nil {
		return 0, 0, 0, dig, false, err
	}
	if expDig, ok := req.ExpectedDigest.Get(); ok && !expDig.Equal(dig) {
		dropStage = true
		return 0, 0, 0, dig, false, domi18n.EF(ErrDigestMismatch, domi18n.KeyCommonMismatch, domi18n.Str("field", "sha256"), domi18n.Str("expected", expDig.String()), domi18n.Str("actual", dig.String()))
	}
	if err = remotecanon.VerifyDownloadSource(ctx, s.strictPaths(), rfs, spec.authBinding, req.RemoteSource, st.Anchor(), fileSize, st.ModTime(), canonSentinels()); err != nil {
		dropStage = true
		return 0, 0, 0, dig, false, err
	}
	if err = root.Rename(stageDest, req.LocalDest); err != nil {
		return 0, 0, 0, dig, false, err
	}
	committed = true
	if mt := st.ModTime(); req.PreserveTimes && validRFC3339(mt) {
		err = root.Chtimes(req.LocalDest, mt, mt)
		modPres = err == nil
	}
	return fileSize, resumeOffset, chunksN, dig, modPres, err
}
func removeLocalIf(root ports.RootHandle, p pathalg.LocalRootedDest, cond bool) {
	if cond {
		_ = root.Remove(p)
	}
}

// streamDownloadChunks 以有界滑动窗口（在途 <= workers）并行拉取远端分片，由消费者严格按连续偏移落盘，杜绝稀疏空洞与内存膨胀。
func streamDownloadChunks(ctx context.Context, rfs ports.RemoteFSPort, root ports.RootHandle, emitter *transferEmitter, stageDest pathalg.LocalRootedDest, fileSize, resumeOffset int64, spec downloadFileSpec) (int64, error) {
	stagePerm := sanitizeLocalDownloadPerm(spec.remoteStat.Perm())
	if fileSize <= resumeOffset {
		if fileSize == 0 {
			_ = root.Remove(stageDest)
			_, err := root.WriteChunk(stageDest, 0, bytes.NewReader(nil), 0, stagePerm)
			return 0, err
		}
		return 0, nil
	}
	totalChunks := (fileSize - resumeOffset + spec.chunkSize - 1) / spec.chunkSize
	workers := int(min(int64(spec.concurrency), totalChunks))
	slots, jobsCh, resultsCh := make(chan struct{}, workers), make(chan int64), make(chan chunkBuf, workers)
	return totalChunks, conc.RunWait(ctx, func(wCtx context.Context, n *conc.Nursery) error {
		if err := n.Go(func(c context.Context) error { return dispatchDownloadJobs(c, totalChunks, slots, jobsCh) }); err != nil {
			return err
		}
		for range workers {
			if err := n.Go(func(c context.Context) error {
				return runDownloadWorker(c, rfs, spec, resumeOffset, fileSize, jobsCh, resultsCh)
			}); err != nil {
				return err
			}
		}
		return consumeOrderedChunks(wCtx, root, emitter, stageDest, stagePerm, resumeOffset, fileSize, totalChunks, spec, slots, resultsCh)
	})
}
func dispatchDownloadJobs(ctx context.Context, totalChunks int64, slots chan<- struct{}, jobsCh chan<- int64) error {
	defer close(jobsCh)
	for idx := range totalChunks {
		if err := sendOrDone(ctx, slots, struct{}{}); err != nil {
			return err
		}
		if err := sendOrDone(ctx, jobsCh, idx); err != nil {
			return err
		}
	}
	return nil
}
func runDownloadWorker(ctx context.Context, rfs ports.RemoteFSPort, spec downloadFileSpec, resumeOffset, fileSize int64, jobsCh <-chan int64, resultsCh chan<- chunkBuf) error {
	for idx := range jobsCh {
		offset := resumeOffset + idx*spec.chunkSize
		if err := ctx.Err(); err != nil {
			return err
		}
		data, err := remotecanon.ReadChunkExact(ctx, rfs, spec.req.RemoteSource, offset, min(spec.chunkSize, fileSize-offset))
		if err != nil {
			return err
		}
		if err = sendOrDone(ctx, resultsCh, chunkBuf{offset: offset, data: data}); err != nil {
			return err
		}
	}
	return nil
}
func consumeOrderedChunks(ctx context.Context, root ports.RootHandle, emitter *transferEmitter, stageDest pathalg.LocalRootedDest, stagePerm fs.FileMode, resumeOffset, fileSize, totalChunks int64, spec downloadFileSpec, slots <-chan struct{}, resultsCh <-chan chunkBuf) error {
	nextOffset, writtenChunks, pending := resumeOffset, int64(0), make(map[int64][]byte, cap(slots))
	for writtenChunks < totalChunks {
		select {
		case chunk := <-resultsCh:
			pending[chunk.offset] = chunk.data
			for data, ok := pending[nextOffset]; ok; data, ok = pending[nextOffset] {
				delete(pending, nextOffset)
				n, err := root.WriteChunk(stageDest, nextOffset, bytes.NewReader(data), int64(len(data)), stagePerm)
				if err != nil || n != int64(len(data)) {
					return pickIf[error](err != nil, err, io.ErrShortWrite)
				}
				nextOffset, writtenChunks = nextOffset+n, writtenChunks+1
				<-slots
				emitter.emitProgress(ctx, spec.transferID, fsm.TransferDirectionDownload, uint64(nextOffset), uint64(fileSize), uint64(writtenChunks), spec.startedAt, "downloading")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// applyDirTimesOrdered 通用自底向上目录时间戳回填（供递归上传与下载共享，确保父目录 mtime 不被子项写入冲刷）。
//
//xops:syncclosure
func applyDirTimesOrdered[T any](dirs []T, cmpFn func(a, b T) int, modTimeFn func(T) time.Time, setTime func(T, time.Time) error, preserved *bool) error {
	ordered := slices.Clone(dirs)
	slices.SortFunc(ordered, cmpFn)
	for _, d := range ordered {
		if mt := modTimeFn(d); validRFC3339(mt) {
			if err := setTime(d, mt); err != nil {
				return err
			}
			*preserved = true
		}
	}
	return nil
}

// downloadDirectoryTree 两阶段执行递归目录下载：先构造全图计划并校验跨平台碰撞与软链封闭性，再单次 WithRoot 落盘并自底向上回填目录 mtime。
func (s *Service) downloadDirectoryTree(ctx context.Context, rfs ports.RemoteFSPort, emitter *transferEmitter, rootStat ports.RemoteFileStat, baseSpec downloadFileSpec) (SCPDownloadResult, error) {
	req, pl := baseSpec.req, &recursiveDownloadPlan{maxFiles: baseSpec.maxFiles, maxBytes: baseSpec.maxBytes, visited: make(map[string]struct{})}
	if err := walkRemoteDirTree(ctx, rfs, req.RemoteSource, rootStat, req.LocalDest, req.SymlinkPolicy, pl); err != nil {
		return SCPDownloadResult{}, err
	}
	if err := validateRecursivePlan(pl); err != nil {
		return SCPDownloadResult{}, err
	}
	out := SCPDownloadResult{LocalDest: req.LocalDest}
	return out, s.scopedFS.WithRoot(req.LocalRoot, func(root ports.RootHandle) (e error) {
		if e = createPlannedDirsAndSymlinks(root, pl.dirs, nil, req.NoClobber, &out); e == nil {
			e = s.downloadPlannedFiles(ctx, rfs, root, emitter, pl.files, baseSpec, &out)
		}
		if e == nil {
			e = createPlannedDirsAndSymlinks(root, nil, pl.symlinks, req.NoClobber, &out)
		}
		if e == nil && req.PreserveTimes {
			e = applyDirTimesOrdered(pl.dirs, func(a, b plannedDir) int {
				return cmp.Or(cmp.Compare(b.local.Depth(), a.local.Depth()), a.local.Compare(b.local))
			},
				func(d plannedDir) time.Time { return d.modTime }, func(d plannedDir, mt time.Time) error { return root.Chtimes(d.local, mt, mt) }, &out.ModTimePreserved)
		}
		return e
	})
}
func walkRemoteDirTree(ctx context.Context, rfs ports.RemoteFSPort, remoteDir pathalg.RemotePath, dirStat ports.RemoteFileStat, localDir pathalg.LocalRootedDest, symPolicy pathalg.SymlinkPolicy, pl *recursiveDownloadPlan) error {
	if err := ctx.Err(); err != nil || len(pl.allDests) >= pl.maxFiles {
		return pickIf[error](err != nil, err, domi18n.EF(ports.ErrLimitExceeded, domi18n.KeyCommonCountLimit, domi18n.Str("kind", "download_entries"), domi18n.Int("count", len(pl.allDests)), domi18n.Int("limit", pl.maxFiles)))
	}
	visitKey := pickIf(dirStat.Anchor().HasDevIno(), fmt.Sprintf("%d:%d", dirStat.Anchor().Dev(), dirStat.Anchor().Ino()), remoteDir.String())
	if _, seen := pl.visited[visitKey]; seen {
		return domi18n.EF(ErrInvalidRequest, domi18n.KeyUCTransferRemoteCycle, domi18n.BoundStr("path", remoteDir.String()))
	}
	pl.visited[visitKey], pl.dirs, pl.allDests = struct{}{}, append(pl.dirs, plannedDir{local: localDir, modTime: dirStat.ModTime()}), append(pl.allDests, localDir)
	entries, err := rfs.ReadDir(ctx, remoteDir)
	if err != nil {
		return err
	}
	slices.SortFunc(entries, func(a, b ports.RemoteDirEntry) int { return a.Name().Compare(b.Name()) })
	for _, ent := range entries {
		if err := walkRemoteEntry(ctx, rfs, remoteDir, localDir, ent, symPolicy, pl); err != nil {
			return err
		}
	}
	return nil
}
func walkRemoteEntry(ctx context.Context, rfs ports.RemoteFSPort, remoteDir pathalg.RemotePath, localDir pathalg.LocalRootedDest, ent ports.RemoteDirEntry, symPolicy pathalg.SymlinkPolicy, pl *recursiveDownloadPlan) error {
	if len(pl.allDests) >= pl.maxFiles {
		return domi18n.EF(ports.ErrLimitExceeded, domi18n.KeyCommonCountLimit, domi18n.Str("kind", "download_entries"), domi18n.Int("count", len(pl.allDests)), domi18n.Int("limit", pl.maxFiles))
	}
	childRemote, e1 := remoteDir.Join(ent.Name())
	childLocal, e2 := localDir.JoinRemoteName(ent.Name())
	if err := firstErr(e1, e2); err != nil {
		return err
	}
	childStat, err := rfs.Lstat(ctx, childRemote)
	if err != nil {
		return err
	}
	switch childStat.FileType() {
	case ports.RemoteFileDir:
		return walkRemoteDirTree(ctx, rfs, childRemote, childStat, childLocal, symPolicy, pl)
	case ports.RemoteFileRegular:
		if uint64(childStat.Size()) > pl.maxBytes-pl.totalBytes {
			return domi18n.EF(fsm.ErrTransferSizeExceeded, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "download_total"), domi18n.Uint64("size", pl.totalBytes+uint64(childStat.Size())), domi18n.Uint64("limit", pl.maxBytes))
		}
		pl.totalBytes, pl.files, pl.allDests = pl.totalBytes+uint64(childStat.Size()), append(pl.files, plannedFile{remote: childRemote, local: childLocal, stat: childStat}), append(pl.allDests, childLocal)
		return nil
	case ports.RemoteFileSymlink:
		if symPolicy != pathalg.SymlinkContainedRelative {
			return domi18n.WrapS(ErrSymlinkPolicyDenied, ports.ErrSymlinkRejected, domi18n.KeyUCTransferSymlinkPol, domi18n.Str("policy", symPolicy.String()), domi18n.BoundStr("path", childRemote.String()))
		}
		target, rErr := rfs.ReadLink(ctx, childRemote)
		if rErr == nil {
			pl.symlinks, pl.allDests = append(pl.symlinks, plannedSymlink{local: childLocal, target: target}), append(pl.allDests, childLocal)
		}
		return rErr
	default:
		return domi18n.EF(ErrRemoteObjectUnsupported, domi18n.KeyUCTransferRemoteType, domi18n.BoundStr("path", childRemote.String()), domi18n.Str("kind", childStat.FileType().String()))
	}
}
func validateRecursivePlan(pl *recursiveDownloadPlan) error {
	err := pathalg.CheckPathCollisions(pl.allDests)
	if err == nil && len(pl.symlinks) > 0 {
		bindings := make([]pathalg.SymlinkBinding, 0, len(pl.symlinks))
		for _, sl := range pl.symlinks {
			b, bErr := pathalg.NewSymlinkBinding(sl.local, sl.target)
			if bErr != nil {
				return domi18n.WrapSentinel(ErrSymlinkPolicyDenied, bErr)
			}
			bindings = append(bindings, b)
		}
		err = pathalg.ValidateContainedSymlinkSet(bindings)
	}
	return pickIf[error](err != nil, domi18n.WrapSentinel(ErrSymlinkPolicyDenied, err), nil)
}
func createPlannedDirsAndSymlinks(root ports.RootHandle, dirs []plannedDir, symlinks []plannedSymlink, noClobber bool, out *SCPDownloadResult) error {
	for _, d := range dirs {
		if err := root.MkdirAll(d.local, defaultDirPerm); err != nil {
			return err
		}
		out.DirsCreated++
	}
	for _, sl := range symlinks {
		if err := createLocalSymlink(root, sl.local, sl.target, noClobber); err != nil {
			return err
		}
		out.SymlinksCreated++
	}
	return nil
}
func (s *Service) downloadPlannedFiles(ctx context.Context, rfs ports.RemoteFSPort, root ports.RootHandle, emitter *transferEmitter, files []plannedFile, baseSpec downloadFileSpec, out *SCPDownloadResult) error {
	for _, f := range files {
		spec := baseSpec
		spec.req.RemoteSource, spec.remoteStat, spec.req.LocalDest, spec.req.Resume = f.remote, f.stat, f.local, false
		b, res, ch, _, mod, fErr := s.downloadFileIntoRoot(ctx, rfs, root, emitter, spec)
		if fErr != nil {
			return fErr
		}
		out.FilesDownloaded, out.BytesTransferred, out.ResumedBytes, out.ChunksTransferred, out.ModTimePreserved = out.FilesDownloaded+1, out.BytesTransferred+b, out.ResumedBytes+res, out.ChunksTransferred+ch, out.ModTimePreserved || mod
	}
	return nil
}
