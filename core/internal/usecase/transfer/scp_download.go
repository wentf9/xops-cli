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
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

type (
	downloadFileSpec struct {
		req         SCPDownloadRequest
		remoteStat  ports.RemoteFileStat
		chunkSize   int64
		concurrency int
		maxFiles    int
		maxBytes    uint64
		transferID  security.OperationID
		startedAt   time.Time
	}
	fileDownloadOutcome struct {
		bytes, resumed, chunks int64
		digest                 security.Digest
		modTimePreserved       bool
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
	defer closeStreamIfNonNil(req.OperationStream)
	hop, baseSpec, err := s.validateSCPDownloadRequest(ctx, req)
	if err != nil {
		return SCPDownloadResult{}, err
	}
	spec := authOpSpec{base: req.CallBase, targetHop: hop, tool: "scp", action: "download", paths: pickIf(req.Recursive, nil, []pathalg.RemotePath{req.RemoteSource}), recursivePaths: pickIf(req.Recursive, []pathalg.RemotePath{req.RemoteSource}, nil), defaultRisk: security.RiskSafe, summary: "scp download " + req.RemoteSource.String(), canonicalize: true}
	return runAuthorizedRemoteFS[security.CapTransfer](ctx, s, spec, func(opCtx context.Context, auth gate.Authorized[security.CapTransfer], rfs ports.RemoteFSPort, emitter *transferEmitter) (SCPDownloadResult, error) {
		baseSpec.transferID, baseSpec.startedAt = auth.OperationID(), s.clock.Now().UTC().Round(0)
		return s.executeSCPDownload(opCtx, rfs, emitter, baseSpec)
	})
}
func (s *Service) validateSCPDownloadRequest(ctx context.Context, req SCPDownloadRequest) (hop plan.HopSpec, spec downloadFileSpec, err error) {
	if hop, err = s.validateRemotePathOp(ctx, req.CallBase, req.RemoteSource); err != nil || s.scopedFS == nil {
		return hop, spec, pickIf[error](err != nil, err, ErrScopedFSUnavailable)
	}
	if dig, hasDig := req.ExpectedDigest.Get(); !req.LocalRoot.IsValid() || !req.LocalDest.IsValid() || req.MaxFiles < 0 || req.MaxFiles > maxRecursiveFilesLimit || (hasDig && !dig.IsValid()) {
		return hop, spec, fmt.Errorf("%w: LocalRoot/LocalDest/MaxFiles/ExpectedDigest 无效", ErrInvalidRequest)
	}
	if !req.SymlinkPolicy.IsValid() || req.SymlinkPolicy == pathalg.SymlinkFollowOperatorSource || req.MaxTotalBytes > fsm.MaxTransferBytes {
		return hop, spec, pickIf[error](req.MaxTotalBytes > fsm.MaxTransferBytes, fmt.Errorf("%w: MaxTotalBytes 超出 10 GiB 上限", fsm.ErrTransferSizeExceeded), fmt.Errorf("%w: 下载仅允许 SymlinkReject 或 SymlinkContainedRelative", ErrSymlinkPolicyDenied))
	}
	cs, conc, err := s.resolveChunkAndConcurrency(req.ChunkSize, req.Concurrency)
	return hop, downloadFileSpec{req: req, chunkSize: cs, concurrency: conc, maxFiles: pickIf(req.MaxFiles == 0, defaultMaxRecursiveFiles, req.MaxFiles), maxBytes: pickIf(req.MaxTotalBytes == 0, fsm.MaxTransferBytes, req.MaxTotalBytes)}, err
}
func (s *Service) executeSCPDownload(ctx context.Context, rfs ports.RemoteFSPort, emitter *transferEmitter, spec downloadFileSpec) (SCPDownloadResult, error) {
	req := spec.req
	lstat, err := rfs.Lstat(ctx, req.RemoteSource)
	if err != nil {
		return SCPDownloadResult{}, err
	}
	switch lstat.FileType() {
	case ports.RemoteFileRegular:
		if uint64(lstat.Size()) > spec.maxBytes {
			return SCPDownloadResult{}, fmt.Errorf("%w: 远端文件大小 %d 超限 %d", fsm.ErrTransferSizeExceeded, lstat.Size(), spec.maxBytes)
		}
		spec.remoteStat = lstat
		var out SCPDownloadResult
		err = s.scopedFS.WithRoot(req.LocalRoot, func(root ports.RootHandle) error {
			if e := ensureParentLocalDir(root, req.LocalDest); e != nil {
				return e
			}
			f, dErr := s.downloadFileIntoRoot(ctx, rfs, root, emitter, spec)
			if dErr == nil {
				out = SCPDownloadResult{LocalDest: req.LocalDest, FilesDownloaded: 1, BytesTransferred: f.bytes, ResumedBytes: f.resumed, ChunksTransferred: f.chunks, Digest: algebraic.Some(f.digest), ModTimePreserved: f.modTimePreserved}
			}
			return dErr
		})
		return out, err
	case ports.RemoteFileSymlink:
		return s.downloadSingleSymlink(ctx, rfs, req)
	case ports.RemoteFileDir:
		if !req.Recursive {
			return SCPDownloadResult{}, fmt.Errorf("%w: 远端路径 %s 为目录（需启用 Recursive）", ports.ErrRemoteIsDir, req.RemoteSource)
		}
		spec.req.ExpectedDigest = algebraic.None[security.Digest]()
		return s.downloadDirectoryTree(ctx, rfs, emitter, lstat, spec)
	default:
		return SCPDownloadResult{}, fmt.Errorf("%w: 拒绝下载特殊对象 %s (%s)", ErrRemoteObjectUnsupported, req.RemoteSource, lstat.FileType())
	}
}
func (s *Service) downloadSingleSymlink(ctx context.Context, rfs ports.RemoteFSPort, req SCPDownloadRequest) (SCPDownloadResult, error) {
	if req.SymlinkPolicy != pathalg.SymlinkContainedRelative {
		return SCPDownloadResult{}, fmt.Errorf("%w: %w: 策略 %s 禁止下载软链", ErrSymlinkPolicyDenied, ports.ErrSymlinkRejected, req.SymlinkPolicy)
	}
	target, err := rfs.ReadLink(ctx, req.RemoteSource)
	if err == nil {
		if vErr := pathalg.ValidateContainedSymlink(target, req.LocalDest.Depth()-1); vErr != nil {
			err = fmt.Errorf("%w: %w", ErrSymlinkPolicyDenied, vErr)
		}
	}
	if err == nil {
		err = s.scopedFS.WithRoot(req.LocalRoot, func(root ports.RootHandle) error {
			if e := ensureParentLocalDir(root, req.LocalDest); e != nil {
				return e
			}
			return createLocalSymlink(root, req.LocalDest, target, req.NoClobber)
		})
	}
	return pickIf(err == nil, SCPDownloadResult{LocalDest: req.LocalDest, SymlinksCreated: 1}, SCPDownloadResult{}), err
}

// downloadFileIntoRoot 经 conc.RunWait 并行拉取分片并在主同步回调按严格连续偏移写盘（0 borrowed 逃逸、0 稀疏空洞）。
func (s *Service) downloadFileIntoRoot(ctx context.Context, rfs ports.RemoteFSPort, root ports.RootHandle, emitter *transferEmitter, spec downloadFileSpec) (out fileDownloadOutcome, err error) {
	req, fileSize := spec.req, spec.remoteStat.Size()
	stageKey := fmt.Sprintf("%s|%s|%d|%d|%d|%d", req.LocalDest, req.RemoteSource, fileSize, spec.remoteStat.ModTime().UTC().UnixNano(), spec.remoteStat.Anchor().Dev(), spec.remoteStat.Anchor().Ino())
	var token string
	if err = checkLocalNoClobber(root, req.LocalDest, req.NoClobber); err == nil {
		token, err = s.stageToken("xops.scp.download.v2", stageKey, req.Resume)
	}
	stageDest, resumeOffset := zeroVal[pathalg.LocalRootedDest](), int64(0)
	if err == nil {
		stageDest, err = makeLocalStageDest(req.LocalDest, token)
	}
	if err == nil {
		resumeOffset, err = calcResumeOffset(fileSize, spec.chunkSize, req.Resume, func() (int64, bool, error) { st, sErr := root.Lstat(stageDest); return st.Size(), st.IsRegular(), sErr }, func() error { return root.Remove(stageDest) })
	}
	if err != nil {
		return out, err
	}
	committed := false
	defer func() {
		if !committed && !req.Resume {
			_ = root.Remove(stageDest)
		}
	}()
	chunks, err := streamDownloadChunks(ctx, rfs, root, emitter, stageDest, fileSize, resumeOffset, spec)
	dig := zeroVal[security.Digest]()
	if err == nil {
		dig, err = hashLocalStagedFile(root, stageDest, fileSize)
	}
	if err != nil {
		return out, err
	}
	if expDig, ok := req.ExpectedDigest.Get(); ok && !expDig.Equal(dig) {
		_ = root.Remove(stageDest)
		return out, fmt.Errorf("%w: 下载摘要不匹配", ErrDigestMismatch)
	}
	if err = root.Rename(stageDest, req.LocalDest); err != nil {
		return out, err
	}
	committed, out = true, fileDownloadOutcome{bytes: fileSize, resumed: resumeOffset, chunks: chunks, digest: dig}
	if mt := spec.remoteStat.ModTime(); req.PreserveTimes && isValidRFC3339Time(mt) {
		err = root.Chtimes(req.LocalDest, mt, mt)
		out.modTimePreserved = err == nil
	}
	return out, err
}

// streamDownloadChunks 以有界滑动窗口（在途 <= workers）并行拉取远端分片，由消费者严格按连续偏移落盘，杜绝稀疏空洞与内存膨胀。
func streamDownloadChunks(ctx context.Context, rfs ports.RemoteFSPort, root ports.RootHandle, emitter *transferEmitter, stageDest pathalg.LocalRootedDest, fileSize, resumeOffset int64, spec downloadFileSpec) (int64, error) {
	stagePerm := sanitizeLocalDownloadPerm(spec.remoteStat.Perm())
	if fileSize == 0 {
		_ = root.Remove(stageDest)
		_, err := root.WriteChunk(stageDest, 0, bytes.NewReader(nil), 0, stagePerm)
		return 0, err
	}
	if fileSize <= resumeOffset {
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
		if err := ctx.Err(); err != nil {
			return err
		}
		offset := resumeOffset + idx*spec.chunkSize
		data, err := readRemoteChunkExact(ctx, rfs, spec.req.RemoteSource, offset, min(spec.chunkSize, fileSize-offset))
		if err == nil {
			err = sendOrDone(ctx, resultsCh, chunkBuf{offset: offset, data: data})
		}
		if err != nil {
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
	err := s.scopedFS.WithRoot(req.LocalRoot, func(root ports.RootHandle) (e error) {
		if e = createPlannedDirsAndSymlinks(root, pl.dirs, nil, req.NoClobber, &out); e == nil {
			e = s.downloadPlannedFiles(ctx, rfs, root, emitter, pl.files, baseSpec, &out)
		}
		if e == nil {
			e = createPlannedDirsAndSymlinks(root, nil, pl.symlinks, req.NoClobber, &out)
		}
		if e == nil && req.PreserveTimes {
			var preservedDir bool
			preservedDir, e = applyDirTimesBottomUp(root, pl.dirs)
			out.ModTimePreserved = out.ModTimePreserved || preservedDir
		}
		return e
	})
	return out, err
}
func walkRemoteDirTree(ctx context.Context, rfs ports.RemoteFSPort, remoteDir pathalg.RemotePath, dirStat ports.RemoteFileStat, localDir pathalg.LocalRootedDest, symPolicy pathalg.SymlinkPolicy, pl *recursiveDownloadPlan) error {
	if err := ctx.Err(); err != nil || len(pl.allDests) >= pl.maxFiles {
		return pickIf[error](err != nil, err, fmt.Errorf("%w: 递归下载对象数超限 %d", ports.ErrLimitExceeded, pl.maxFiles))
	}
	visitKey := pickIf(dirStat.Anchor().HasDevIno(), fmt.Sprintf("%d:%d", dirStat.Anchor().Dev(), dirStat.Anchor().Ino()), remoteDir.String())
	if _, seen := pl.visited[visitKey]; seen {
		return fmt.Errorf("%w: 检测到远端目录环路 %s", ErrInvalidRequest, remoteDir)
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
		return fmt.Errorf("%w: 递归下载对象数超限 %d", ports.ErrLimitExceeded, pl.maxFiles)
	}
	childRemote, e1 := remoteDir.Join(ent.Name())
	childLocal, e2 := localDir.JoinRemoteName(ent.Name())
	var childStat ports.RemoteFileStat
	err := firstErr(e1, e2)
	if err == nil {
		childStat, err = rfs.Lstat(ctx, childRemote)
	}
	if err != nil {
		return err
	}
	switch childStat.FileType() {
	case ports.RemoteFileDir:
		return walkRemoteDirTree(ctx, rfs, childRemote, childStat, childLocal, symPolicy, pl)
	case ports.RemoteFileRegular:
		if uint64(childStat.Size()) > pl.maxBytes-pl.totalBytes {
			return fmt.Errorf("%w: 递归下载总大小超限 %d", fsm.ErrTransferSizeExceeded, pl.maxBytes)
		}
		pl.totalBytes, pl.files, pl.allDests = pl.totalBytes+uint64(childStat.Size()), append(pl.files, plannedFile{remote: childRemote, local: childLocal, stat: childStat}), append(pl.allDests, childLocal)
		return nil
	case ports.RemoteFileSymlink:
		if symPolicy != pathalg.SymlinkContainedRelative {
			return fmt.Errorf("%w: %w: 策略 %s 禁止软链 %s", ErrSymlinkPolicyDenied, ports.ErrSymlinkRejected, symPolicy, childRemote)
		}
		target, rErr := rfs.ReadLink(ctx, childRemote)
		if rErr != nil {
			return rErr
		}
		pl.symlinks, pl.allDests = append(pl.symlinks, plannedSymlink{local: childLocal, target: target}), append(pl.allDests, childLocal)
		return nil
	default:
		return fmt.Errorf("%w: 远端路径 %s 为不受支持类型 %s", ErrRemoteObjectUnsupported, childRemote, childStat.FileType())
	}
}
func validateRecursivePlan(pl *recursiveDownloadPlan) error {
	if err := pathalg.CheckPathCollisions(pl.allDests); err != nil {
		return fmt.Errorf("%w: %w", ErrSymlinkPolicyDenied, err)
	}
	if len(pl.symlinks) == 0 {
		return nil
	}
	bindings := make([]pathalg.SymlinkBinding, 0, len(pl.symlinks))
	for _, sl := range pl.symlinks {
		b, err := pathalg.NewSymlinkBinding(sl.local, sl.target)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSymlinkPolicyDenied, err)
		}
		bindings = append(bindings, b)
	}
	if err := pathalg.ValidateContainedSymlinkSet(bindings); err != nil {
		return fmt.Errorf("%w: %w", ErrSymlinkPolicyDenied, err)
	}
	return nil
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
		r, fErr := s.downloadFileIntoRoot(ctx, rfs, root, emitter, spec)
		if fErr != nil {
			return fErr
		}
		out.FilesDownloaded, out.BytesTransferred, out.ResumedBytes, out.ChunksTransferred, out.ModTimePreserved = out.FilesDownloaded+1, out.BytesTransferred+r.bytes, out.ResumedBytes+r.resumed, out.ChunksTransferred+r.chunks, out.ModTimePreserved || r.modTimePreserved
	}
	return nil
}
func applyDirTimesBottomUp(root ports.RootHandle, dirs []plannedDir) (bool, error) {
	ordered := slices.Clone(dirs)
	slices.SortFunc(ordered, func(a, b plannedDir) int {
		return cmp.Or(cmp.Compare(b.local.Depth(), a.local.Depth()), a.local.Compare(b.local))
	})
	preserved := false
	for _, d := range ordered {
		if isValidRFC3339Time(d.modTime) {
			if err := root.Chtimes(d.local, d.modTime, d.modTime); err != nil {
				return false, err
			}
			preserved = true
		}
	}
	return preserved, nil
}
