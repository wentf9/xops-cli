package transfer

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
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

type downloadFileSpec struct {
	remoteSrc                        pathalg.RemotePath
	remoteStat                       ports.RemoteFileStat
	localDest                        pathalg.LocalRootedDest
	noClobber, resume, preserveTimes bool
	chunkSize                        int64
	concurrency, maxFiles            int
	maxBytes                         uint64
	expectedDigest                   algebraic.Option[security.Digest]
	transferID                       security.OperationID
	startedAt                        time.Time
}

// SCPDownload 执行受 core/conc.Nursery 监督的并行分片 SCP 下载（单文件或递归目录），
// 全程仅依赖 ScopedRootFS（零 OperatorReadFS 依赖），严守 INV-B1..B3 并支持 Chtimes mtime 保留。
func (s *Service) SCPDownload(ctx context.Context, req SCPDownloadRequest) (SCPDownloadResult, error) {
	defer closeStreamIfNonNil(req.OperationStream)
	hop, baseSpec, err := s.validateSCPDownloadRequest(ctx, req)
	if err != nil {
		return SCPDownloadResult{}, err
	}
	spec := authOpSpec{
		base: req.CallBase, targetHop: hop, tool: "scp", action: "download",
		paths:          pickIf(req.Recursive, nil, []pathalg.RemotePath{req.RemoteSource}),
		recursivePaths: pickIf(req.Recursive, []pathalg.RemotePath{req.RemoteSource}, nil),
		defaultRisk:    security.RiskSafe, summary: "scp download " + req.RemoteSource.String(), canonicalize: true,
	}
	return runAuthorizedRemoteFS[security.CapTransfer](ctx, s, spec, func(opCtx context.Context, auth gate.Authorized[security.CapTransfer], rfs ports.RemoteFSPort, emitter *transferEmitter) (SCPDownloadResult, error) {
		baseSpec.transferID, baseSpec.startedAt = auth.OperationID(), s.clock.Now().UTC().Round(0)
		return s.executeSCPDownload(opCtx, rfs, emitter, req, baseSpec)
	})
}

func (s *Service) validateSCPDownloadRequest(ctx context.Context, req SCPDownloadRequest) (hop plan.HopSpec, spec downloadFileSpec, err error) {
	if hop, err = s.validateRemotePathOp(ctx, req.CallBase, req.RemoteSource); err != nil {
		return hop, spec, err
	}
	switch {
	case s.scopedFS == nil:
		return hop, spec, ErrScopedFSUnavailable
	case !req.LocalRoot.IsValid() || !req.LocalDest.IsValid() || req.MaxFiles < 0 || req.MaxFiles > maxRecursiveFilesLimit:
		return hop, spec, fmt.Errorf("%w: LocalRoot/LocalDest/MaxFiles 无效", ErrInvalidRequest)
	case !req.SymlinkPolicy.IsValid() || req.SymlinkPolicy == pathalg.SymlinkFollowOperatorSource:
		return hop, spec, fmt.Errorf("%w: 下载仅允许 SymlinkReject 或 SymlinkContainedRelative", ErrSymlinkPolicyDenied)
	case req.MaxTotalBytes > fsm.MaxTransferBytes:
		return hop, spec, fmt.Errorf("%w: MaxTotalBytes 超出 10 GiB 上限", fsm.ErrTransferSizeExceeded)
	}
	if dig, ok := req.ExpectedDigest.Get(); ok && !dig.IsValid() {
		return hop, spec, fmt.Errorf("%w: ExpectedDigest 无效", ErrInvalidRequest)
	}
	cs, conc, err := s.resolveChunkAndConcurrency(req.ChunkSize, req.Concurrency)
	return hop, downloadFileSpec{
		remoteSrc: req.RemoteSource, localDest: req.LocalDest, noClobber: req.NoClobber,
		resume: req.Resume, preserveTimes: req.PreserveTimes, chunkSize: cs, concurrency: conc,
		maxFiles: pickIf(req.MaxFiles == 0, defaultMaxRecursiveFiles, req.MaxFiles),
		maxBytes: pickIf(req.MaxTotalBytes == 0, fsm.MaxTransferBytes, req.MaxTotalBytes), expectedDigest: req.ExpectedDigest,
	}, err
}

type fileDownloadOutcome struct {
	bytes, resumed, chunks int64
	digest                 security.Digest
	modTimePreserved       bool
}

func (s *Service) executeSCPDownload(ctx context.Context, rfs ports.RemoteFSPort, emitter *transferEmitter, req SCPDownloadRequest, spec downloadFileSpec) (SCPDownloadResult, error) {
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
			if err := ensureParentLocalDir(root, req.LocalDest); err != nil {
				return err
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
		spec.expectedDigest = algebraic.None[security.Digest]()
		return s.downloadDirectoryTree(ctx, rfs, emitter, req, lstat, spec)
	default:
		return SCPDownloadResult{}, fmt.Errorf("%w: 拒绝下载特殊对象 %s (%s)", ErrRemoteObjectUnsupported, req.RemoteSource, lstat.FileType())
	}
}
func (s *Service) downloadSingleSymlink(ctx context.Context, rfs ports.RemoteFSPort, req SCPDownloadRequest) (SCPDownloadResult, error) {
	if req.SymlinkPolicy != pathalg.SymlinkContainedRelative {
		return SCPDownloadResult{}, fmt.Errorf("%w: %w: 策略 %s 禁止下载软链", ErrSymlinkPolicyDenied, ports.ErrSymlinkRejected, req.SymlinkPolicy)
	}
	target, err := rfs.ReadLink(ctx, req.RemoteSource)
	if err != nil {
		return SCPDownloadResult{}, err
	}
	if err = pathalg.ValidateContainedSymlink(target, req.LocalDest.Depth()-1); err != nil {
		return SCPDownloadResult{}, fmt.Errorf("%w: %w", ErrSymlinkPolicyDenied, err)
	}
	err = s.scopedFS.WithRoot(req.LocalRoot, func(root ports.RootHandle) error {
		if err := firstErr(ensureParentLocalDir(root, req.LocalDest), checkLocalNoClobber(root, req.LocalDest, req.NoClobber)); err != nil {
			return err
		}
		return root.CreateSymlink(req.LocalDest, target)
	})
	return pickIf(err == nil, SCPDownloadResult{LocalDest: req.LocalDest, SymlinksCreated: 1}, SCPDownloadResult{}), err
}

// downloadFileIntoRoot 经 conc.RunWait 并行拉取分片并在主同步回调经借用 root 落盘（0 borrowed 逃逸）。
func (s *Service) downloadFileIntoRoot(ctx context.Context, rfs ports.RemoteFSPort, root ports.RootHandle, emitter *transferEmitter, spec downloadFileSpec) (out fileDownloadOutcome, err error) {
	if err = checkLocalNoClobber(root, spec.localDest, spec.noClobber); err != nil {
		return out, err
	}
	token, err := s.stageToken("xops.scp.download.v1", spec.localDest.String(), spec.resume)
	if err != nil {
		return out, err
	}
	stageDest, err := makeLocalStageDest(spec.localDest, token)
	if err != nil {
		return out, err
	}
	fileSize := spec.remoteStat.Size()
	resumeOffset, err := calcResumeOffset(fileSize, spec.chunkSize, spec.resume, func() (int64, bool, error) {
		st, sErr := root.Lstat(stageDest)
		return st.Size(), st.IsRegular(), sErr
	}, func() error { return root.Remove(stageDest) })
	if err != nil {
		return out, err
	}
	committed := false
	defer func() {
		if !committed && !spec.resume {
			_ = root.Remove(stageDest)
		}
	}()
	chunks, err := streamDownloadChunks(ctx, rfs, root, emitter, stageDest, fileSize, resumeOffset, spec)
	if err != nil {
		return out, err
	}
	dig, err := hashLocalStagedFile(root, stageDest, fileSize)
	if err != nil {
		return out, err
	}
	if expDig, ok := spec.expectedDigest.Get(); ok && !expDig.Equal(dig) {
		_ = root.Remove(stageDest)
		return out, fmt.Errorf("%w: 下载摘要不匹配", ErrDigestMismatch)
	}
	if err = root.Rename(stageDest, spec.localDest); err != nil {
		return out, err
	}
	committed, out = true, fileDownloadOutcome{bytes: fileSize, resumed: resumeOffset, chunks: chunks, digest: dig}
	if mt := spec.remoteStat.ModTime(); spec.preserveTimes && isValidRFC3339Time(mt) {
		cErr := root.Chtimes(spec.localDest, mt, mt)
		out.modTimePreserved = cErr == nil
		return out, cErr
	}
	return out, nil
}
func streamDownloadChunks(ctx context.Context, rfs ports.RemoteFSPort, root ports.RootHandle, emitter *transferEmitter, stageDest pathalg.LocalRootedDest, fileSize, resumeOffset int64, spec downloadFileSpec) (int64, error) {
	stagePerm := sanitizeLocalDownloadPerm(spec.remoteStat.Perm())
	if fileSize == 0 {
		_, err := root.WriteChunk(stageDest, 0, bytes.NewReader(nil), 0, stagePerm)
		return 0, err
	}
	if fileSize-resumeOffset <= 0 {
		return 0, nil
	}
	totalChunks := (fileSize - resumeOffset + spec.chunkSize - 1) / spec.chunkSize
	workers := int(min(int64(spec.concurrency), totalChunks))
	var nextChunk atomic.Int64
	resultsCh := make(chan chunkBuf, workers)
	err := conc.RunWait(ctx, func(wCtx context.Context, n *conc.Nursery) error {
		for range workers {
			if gErr := n.Go(func(c context.Context) error {
				return runDownloadWorker(c, rfs, spec, resumeOffset, fileSize, totalChunks, &nextChunk, resultsCh)
			}); gErr != nil {
				return gErr
			}
		}
		return consumeDownloadedChunks(wCtx, root, emitter, stageDest, stagePerm, resumeOffset, fileSize, totalChunks, spec, resultsCh)
	})
	return totalChunks, err
}
func runDownloadWorker(ctx context.Context, rfs ports.RemoteFSPort, spec downloadFileSpec, resumeOffset, fileSize, totalChunks int64, nextChunk *atomic.Int64, resultsCh chan<- chunkBuf) error {
	for idx := nextChunk.Add(1) - 1; idx < totalChunks; idx = nextChunk.Add(1) - 1 {
		if err := ctx.Err(); err != nil {
			return err
		}
		offset := resumeOffset + idx*spec.chunkSize
		data, err := readRemoteChunkExact(ctx, rfs, spec.remoteSrc, offset, min(spec.chunkSize, fileSize-offset))
		if err != nil {
			return err
		}
		select {
		case resultsCh <- chunkBuf{offset: offset, data: data}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
func consumeDownloadedChunks(ctx context.Context, root ports.RootHandle, emitter *transferEmitter, stageDest pathalg.LocalRootedDest, stagePerm fs.FileMode, resumeOffset, fileSize, totalChunks int64, spec downloadFileSpec, resultsCh <-chan chunkBuf) error {
	writtenTotal := resumeOffset
	for received := range totalChunks {
		select {
		case chunk := <-resultsCh:
			n, err := root.WriteChunk(stageDest, chunk.offset, bytes.NewReader(chunk.data), int64(len(chunk.data)), stagePerm)
			if err != nil || n != int64(len(chunk.data)) {
				return pickIf[error](err != nil, err, io.ErrShortWrite)
			}
			writtenTotal += n
			emitter.emitProgress(ctx, spec.transferID, fsm.TransferDirectionDownload, uint64(writtenTotal), uint64(fileSize), uint64(received+1), spec.startedAt, "downloading")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
func hashLocalStagedFile(root ports.RootHandle, stageDest pathalg.LocalRootedDest, expectedSize int64) (security.Digest, error) {
	limits, err := ports.NewReadLimits(max(expectedSize, 1))
	if err != nil {
		return zeroVal[security.Digest](), err
	}
	h := sha256.New()
	if err = root.WithReadRegular(stageDest, limits, func(r ports.BoundedReadHandle, size int64) error {
		if size != expectedSize {
			return fmt.Errorf("%w: 本地暂存大小 %d 与预期 %d 不符", io.ErrUnexpectedEOF, size, expectedSize)
		}
		_, copyErr := io.Copy(h, r)
		return copyErr
	}); err != nil {
		return zeroVal[security.Digest](), err
	}
	return digestFromHash(h), nil
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
	if _, err := root.Lstat(dest); err != nil {
		return pickIf[error](errors.Is(err, ports.ErrNotFound), nil, err)
	}
	return fmt.Errorf("%w: 本地目标 %s 已存在", ports.ErrAlreadyExists, dest)
}
func sanitizeLocalDownloadPerm(remotePerm fs.FileMode) fs.FileMode {
	return pickIf(remotePerm.Perm() != 0, remotePerm.Perm()|0o600, defaultLocalStagePerm)
}

type (
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

// downloadDirectoryTree 两阶段执行递归目录下载：先构造全图计划并校验跨平台碰撞与软链封闭性，再单次 WithRoot 落盘并自底向上回填目录 mtime。
func (s *Service) downloadDirectoryTree(ctx context.Context, rfs ports.RemoteFSPort, emitter *transferEmitter, req SCPDownloadRequest, rootStat ports.RemoteFileStat, baseSpec downloadFileSpec) (SCPDownloadResult, error) {
	pl := &recursiveDownloadPlan{maxFiles: baseSpec.maxFiles, maxBytes: baseSpec.maxBytes, visited: make(map[string]struct{})}
	if err := walkRemoteDirTree(ctx, rfs, req.RemoteSource, rootStat, req.LocalDest, req.SymlinkPolicy, pl); err != nil {
		return SCPDownloadResult{}, err
	}
	if err := validateRecursivePlan(pl); err != nil {
		return SCPDownloadResult{}, err
	}
	out := SCPDownloadResult{LocalDest: req.LocalDest}
	err := s.scopedFS.WithRoot(req.LocalRoot, func(root ports.RootHandle) error {
		if err := createPlannedDirsAndSymlinks(root, pl.dirs, nil, req.NoClobber, &out); err != nil {
			return err
		}
		if err := s.downloadPlannedFiles(ctx, rfs, root, emitter, pl.files, baseSpec, &out); err != nil {
			return err
		}
		if err := createPlannedDirsAndSymlinks(root, nil, pl.symlinks, req.NoClobber, &out); err != nil {
			return err
		}
		if !req.PreserveTimes {
			return nil
		}
		preservedDir, cErr := applyDirTimesBottomUp(root, pl.dirs)
		out.ModTimePreserved = out.ModTimePreserved || preservedDir
		return cErr
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
	if e1 != nil || e2 != nil {
		return pickIf(e1 != nil, e1, e2)
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
			return fmt.Errorf("%w: 递归下载总大小超限 %d", fsm.ErrTransferSizeExceeded, pl.maxBytes)
		}
		pl.totalBytes += uint64(childStat.Size())
		pl.files, pl.allDests = append(pl.files, plannedFile{remote: childRemote, local: childLocal, stat: childStat}), append(pl.allDests, childLocal)
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
		if err := checkLocalNoClobber(root, sl.local, noClobber); err != nil {
			return err
		}
		if err := root.CreateSymlink(sl.local, sl.target); err != nil {
			return err
		}
		out.SymlinksCreated++
	}
	return nil
}
func (s *Service) downloadPlannedFiles(ctx context.Context, rfs ports.RemoteFSPort, root ports.RootHandle, emitter *transferEmitter, files []plannedFile, baseSpec downloadFileSpec, out *SCPDownloadResult) error {
	for _, f := range files {
		spec := baseSpec
		spec.remoteSrc, spec.remoteStat, spec.localDest, spec.resume = f.remote, f.stat, f.local, false
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
