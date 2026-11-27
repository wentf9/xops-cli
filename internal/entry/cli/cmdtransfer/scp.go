package cmdtransfer

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

type scpArgs struct {
	common         clikit.CommonFlags
	cliOpts        option.OptionLayer
	srcRaw         string
	dstRaw         string
	recursive      bool
	preserve       bool
	expandIntoDir  bool
	noClobber      bool
	resume         bool
	symlinkPolicy  pathalg.SymlinkPolicy
	localRoot      algebraic.Option[pathalg.LocalDir]
	perm           algebraic.Option[fs.FileMode]
	chunkSize      int64
	concurrency    int
	maxFiles       int
	maxTotalBytes  uint64
	expectedDigest algebraic.Option[security.Digest]
}

type scpUploadView struct {
	OK                bool               `json:"ok"`
	Direction         string             `json:"direction"`
	Target            string             `json:"target"`
	RemotePath        pathalg.RemotePath `json:"remote_path"`
	FilesUploaded     int                `json:"files_uploaded"`
	DirsCreated       int                `json:"dirs_created"`
	BytesTransferred  int64              `json:"bytes_transferred"`
	ResumedBytes      int64              `json:"resumed_bytes,omitzero"`
	ChunksTransferred int64              `json:"chunks_transferred"`
	Digest            string             `json:"digest,omitzero"`
	ModTimePreserved  bool               `json:"mod_time_preserved,omitzero"`
}

type scpDownloadView struct {
	OK                bool                              `json:"ok"`
	Direction         string                            `json:"direction"`
	Target            string                            `json:"target"`
	LocalRoot         pathalg.LocalDir                  `json:"local_root"`
	LocalDest         pathalg.LocalRootedDest           `json:"local_dest"`
	FilesDownloaded   int                               `json:"files_downloaded"`
	DirsCreated       int                               `json:"dirs_created"`
	SymlinksCreated   int                               `json:"symlinks_created,omitzero"`
	BytesTransferred  int64                             `json:"bytes_transferred"`
	ResumedBytes      int64                             `json:"resumed_bytes,omitzero"`
	ChunksTransferred int64                             `json:"chunks_transferred"`
	Digest            algebraic.Option[security.Digest] `json:"digest,omitzero"`
	ModTimePreserved  bool                              `json:"mod_time_preserved,omitzero"`
}

// RunSCP 执行 `xops scp`，依据源与目标的 `host:path` 归属分派至 engine.SCPUpload 或 engine.SCPDownload。
func RunSCP(ctx context.Context, rt *clikit.Runtime, args []string) int {
	parsed, err := parseSCPArgs(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.Global.JSON, err)
	}
	if parsed.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, SCPHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(parsed.common.JSON)
	srcHost, srcRemote, srcIsRemote := splitSCPEndpoint(parsed.srcRaw)
	dstHost, dstRemote, dstIsRemote := splitSCPEndpoint(parsed.dstRaw)
	if srcIsRemote == dstIsRemote {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: scp 源与目标必须一端为本地路径、另一端为 [user@]host:<remote_path>", clikit.ErrUsage))
	}
	initOpts := rt.EffectiveInitOptions(parsed.common.ConfigFile, parsed.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitSSHError, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireTransferClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		if dstIsRemote {
			return runSCPUpload(ctx, rt, client, parsed, parsed.srcRaw, dstHost, dstRemote, jsonOut)
		}
		return runSCPDownload(ctx, rt, client, parsed, srcHost, srcRemote, parsed.dstRaw, jsonOut)
	})
}

func runSCPUpload(ctx context.Context, rt *clikit.Runtime, client clikit.TransferClient, parsed scpArgs, localRaw, targetHost, remoteRaw string, jsonOut bool) int {
	srcSpec, err := buildUploadSource(parsed, localRaw)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	remotePath, err := pathalg.ParseRemotePath(remoteRaw)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: 远端目标路径 %q 非法: %w", clikit.ErrUsage, remoteRaw, err))
	}
	res, err := client.SCPUpload(ctx, engine.SCPUploadRequest{
		RemoteCall: engine.RemoteCall{
			TargetInput: engine.TargetInput{TargetSpec: targetHost, CLIOptions: parsed.cliOpts},
		},
		Source:         srcSpec,
		RemoteDest:     remotePath,
		Recursive:      parsed.recursive,
		ExpandIntoDir:  parsed.expandIntoDir,
		NoClobber:      parsed.noClobber,
		Resume:         parsed.resume,
		PreserveMode:   parsed.preserve,
		PreserveTimes:  parsed.preserve,
		SymlinkPolicy:  parsed.symlinkPolicy,
		Perm:           parsed.perm,
		ChunkSize:      parsed.chunkSize,
		Concurrency:    parsed.concurrency,
		MaxFiles:       parsed.maxFiles,
		MaxTotalBytes:  parsed.maxTotalBytes,
		ExpectedDigest: parsed.expectedDigest,
	})
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	view := scpUploadView{
		OK:                true,
		Direction:         "upload",
		Target:            targetHost,
		RemotePath:        res.RemotePath,
		FilesUploaded:     res.FilesUploaded,
		DirsCreated:       res.DirsCreated,
		BytesTransferred:  res.BytesTransferred,
		ResumedBytes:      res.ResumedBytes,
		ChunksTransferred: res.ChunksTransferred,
		Digest:            res.Digest.String(),
		ModTimePreserved:  res.ModTimePreserved,
	}
	return rt.WriteResult(jsonOut, view, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "uploaded %d file(s), %d bytes -> %s:%s\n", res.FilesUploaded, res.BytesTransferred, targetHost, res.RemotePath)
	})
}

func runSCPDownload(ctx context.Context, rt *clikit.Runtime, client clikit.TransferClient, parsed scpArgs, targetHost, remoteRaw, localRaw string, jsonOut bool) int {
	remotePath, err := pathalg.ParseRemotePath(remoteRaw)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: 远端源路径 %q 非法: %w", clikit.ErrUsage, remoteRaw, err))
	}
	localRoot, localDest, err := resolveDownloadTarget(rt, parsed.localRoot, localRaw, remotePath)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	res, err := client.SCPDownload(ctx, engine.SCPDownloadRequest{
		RemoteCall: engine.RemoteCall{
			TargetInput: engine.TargetInput{TargetSpec: targetHost, CLIOptions: parsed.cliOpts},
		},
		RemoteSource:   remotePath,
		LocalRoot:      localRoot,
		LocalDest:      localDest,
		Recursive:      parsed.recursive,
		NoClobber:      parsed.noClobber,
		Resume:         parsed.resume,
		PreserveTimes:  parsed.preserve,
		SymlinkPolicy:  parsed.symlinkPolicy,
		ChunkSize:      parsed.chunkSize,
		Concurrency:    parsed.concurrency,
		MaxFiles:       parsed.maxFiles,
		MaxTotalBytes:  parsed.maxTotalBytes,
		ExpectedDigest: parsed.expectedDigest,
	})
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	view := scpDownloadView{
		OK:                true,
		Direction:         "download",
		Target:            targetHost,
		LocalRoot:         localRoot,
		LocalDest:         res.LocalDest,
		FilesDownloaded:   res.FilesDownloaded,
		DirsCreated:       res.DirsCreated,
		SymlinksCreated:   res.SymlinksCreated,
		BytesTransferred:  res.BytesTransferred,
		ResumedBytes:      res.ResumedBytes,
		ChunksTransferred: res.ChunksTransferred,
		Digest:            res.Digest,
		ModTimePreserved:  res.ModTimePreserved,
	}
	return rt.WriteResult(jsonOut, view, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "downloaded %d file(s), %d bytes -> %s/%s\n", res.FilesDownloaded, res.BytesTransferred, localRoot, res.LocalDest)
	})
}

func buildUploadSource(parsed scpArgs, localRaw string) (src engine.LocalUploadSource, err error) {
	if root, ok := parsed.localRoot.Get(); ok {
		rel, pErr := pathalg.ParseLocalRootedDest(localRaw)
		if pErr != nil {
			return src, fmt.Errorf("%w: --local-root 模式下本地源必须为沙箱相对路径: %w", clikit.ErrUsage, pErr)
		}
		return engine.NewScopedUploadSource(root, rel)
	}
	srcPath, pErr := pathalg.ParseLocalSourcePath(localRaw)
	if pErr != nil {
		return src, fmt.Errorf("%w: 本地源路径 %q 非法: %w", clikit.ErrUsage, localRaw, pErr)
	}
	return engine.NewOperatorUploadSource(srcPath, parsed.symlinkPolicy)
}

func resolveDownloadTarget(rt *clikit.Runtime, rootOpt algebraic.Option[pathalg.LocalDir], localRaw string, remotePath pathalg.RemotePath) (root pathalg.LocalDir, dest pathalg.LocalRootedDest, err error) {
	if fixedRoot, ok := rootOpt.Get(); ok {
		return resolveRootedDownload(fixedRoot, localRaw, remotePath)
	}
	trimmed := strings.TrimSpace(localRaw)
	if trimmed == "." || trimmed == "./" {
		wd, wErr := resolveWorkDirOrDot(rt)
		if wErr != nil {
			return root, dest, wErr
		}
		return resolveRootedDownload(wd, ".", remotePath)
	}
	src, pErr := pathalg.ParseLocalSourcePath(trimmed)
	if pErr != nil {
		return root, dest, fmt.Errorf("%w: 本地目标路径 %q 非法: %w", clikit.ErrUsage, localRaw, pErr)
	}
	if src.IsAbs() {
		d, dErr := pathalg.ParseLocalRootedDest(src.Base())
		if dErr != nil {
			return root, dest, fmt.Errorf("%w: 本地目标文件名 %q 非法: %w", clikit.ErrUsage, src.Base(), dErr)
		}
		return src.Dir(), d, nil
	}
	wd, wErr := resolveWorkDirOrDot(rt)
	if wErr != nil {
		return root, dest, wErr
	}
	d, dErr := pathalg.ParseLocalRootedDest(src.String())
	if dErr != nil {
		return root, dest, fmt.Errorf("%w: 本地相对路径 %q 非法: %w", clikit.ErrUsage, src.String(), dErr)
	}
	return wd, d, nil
}

func resolveRootedDownload(fixedRoot pathalg.LocalDir, localRaw string, remotePath pathalg.RemotePath) (root pathalg.LocalDir, dest pathalg.LocalRootedDest, err error) {
	relRaw, rErr := resolveLocalRelName(localRaw, remotePath)
	if rErr != nil {
		return root, dest, rErr
	}
	d, dErr := pathalg.ParseLocalRootedDest(relRaw)
	if dErr != nil {
		return root, dest, fmt.Errorf("%w: 本地目标相对路径 %q 非法: %w", clikit.ErrUsage, localRaw, dErr)
	}
	return fixedRoot, d, nil
}

func resolveLocalRelName(localRaw string, remotePath pathalg.RemotePath) (string, error) {
	relRaw := strings.TrimSpace(localRaw)
	if relRaw != "." && relRaw != "./" {
		return relRaw, nil
	}
	base, ok := remotePath.Base()
	if !ok {
		return "", fmt.Errorf("%w: 远端路径 %q 无文件名组件，无法推导本地目标名", clikit.ErrUsage, remotePath)
	}
	return base.String(), nil
}

func resolveWorkDirOrDot(rt *clikit.Runtime) (pathalg.LocalDir, error) {
	if rt.Hooks.ResolveWorkDir != nil {
		return rt.Hooks.ResolveWorkDir()
	}
	return pathalg.ParseLocalDir(".")
}
