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
	"github.com/wentf9/xops-cli/internal/i18n"
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
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if parsed.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, SCPHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(parsed.common.JSON)
	srcHost, srcRemote, srcIsRemote := splitSCPEndpoint(parsed.srcRaw)
	dstHost, dstRemote, dstIsRemote := splitSCPEndpoint(parsed.dstRaw)
	if srcIsRemote == dstIsRemote {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.EF(clikit.ErrUsage, i18n.KeyCLISCPEndpointMismatch))
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
	srcSpec, err := buildUploadSource(rt, parsed, localRaw)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	remotePath, err := pathalg.ParseRemotePath(remoteRaw)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidField, i18n.Str("field", "remote destination path"), i18n.BoundStr("value", remoteRaw)))
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
	loc := rt.Loc()
	return rt.WriteResult(jsonOut, view, func(w io.Writer) {
		_, _ = fmt.Fprintln(w, loc.T(
			i18n.KeyCLISCPUploaded,
			i18n.Int("files", res.FilesUploaded),
			i18n.Int64("bytes", res.BytesTransferred),
			i18n.BoundStr("target", targetHost),
			i18n.BoundStr("path", res.RemotePath.String()),
		))
	})
}

func runSCPDownload(ctx context.Context, rt *clikit.Runtime, client clikit.TransferClient, parsed scpArgs, targetHost, remoteRaw, localRaw string, jsonOut bool) int {
	if parsed.symlinkPolicy == pathalg.SymlinkFollowOperatorSource {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.EF(clikit.ErrUsage, i18n.KeyCLISCPDownloadSymlinkPolicy))
	}
	remotePath, err := pathalg.ParseRemotePath(remoteRaw)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidField, i18n.Str("field", "remote source path"), i18n.BoundStr("value", remoteRaw)))
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
	loc := rt.Loc()
	return rt.WriteResult(jsonOut, view, func(w io.Writer) {
		_, _ = fmt.Fprintln(w, loc.T(
			i18n.KeyCLISCPDownloaded,
			i18n.Int("files", res.FilesDownloaded),
			i18n.Int64("bytes", res.BytesTransferred),
			i18n.BoundStr("root", localRoot.String()),
			i18n.BoundStr("dest", res.LocalDest.String()),
		))
	})
}

func buildUploadSource(rt *clikit.Runtime, parsed scpArgs, localRaw string) (src engine.LocalUploadSource, err error) {
	if parsed.recursive && parsed.symlinkPolicy != pathalg.SymlinkReject {
		return src, i18n.EF(clikit.ErrUsage, i18n.KeyCLISCPRecursiveSymlinkPolicy)
	}
	if root, ok := parsed.localRoot.Get(); ok {
		rel, pErr := pathalg.ParseLocalRootedDest(normalizeLocalRootedRel(localRaw))
		if pErr != nil {
			return src, i18n.WrapS(clikit.ErrUsage, pErr, i18n.KeyCLISCPLocalRootRelative)
		}
		return engine.NewScopedUploadSource(root, rel)
	}
	// 对齐 core/internal/usecase/transfer/scp_upload.go:validateRecursiveUploadParams：
	// 递归目录上传强制使用 ScopedRootFS 沙箱源，未显式指定 --local-root 时自动解析父目录为沙箱根。
	if parsed.recursive {
		root, rel, rErr := resolveScopedRecursiveUploadSource(rt, localRaw)
		if rErr != nil {
			return src, rErr
		}
		return engine.NewScopedUploadSource(root, rel)
	}
	srcPath, pErr := pathalg.ParseLocalSourcePath(localRaw)
	if pErr != nil {
		return src, i18n.WrapS(clikit.ErrUsage, pErr, i18n.KeyCLIInvalidField, i18n.Str("field", "local source path"), i18n.BoundStr("value", localRaw))
	}
	return engine.NewOperatorUploadSource(srcPath, parsed.symlinkPolicy)
}

func resolveScopedRecursiveUploadSource(rt *clikit.Runtime, localRaw string) (root pathalg.LocalDir, rel pathalg.LocalRootedDest, err error) {
	trimmed := strings.TrimSpace(localRaw)
	if trimmed == "." || trimmed == "./" {
		wd, wErr := resolveWorkDirOrDot(rt)
		if wErr != nil {
			return root, rel, wErr
		}
		wdSrc, pErr := pathalg.ParseLocalSourcePath(wd.String())
		if pErr != nil || !wdSrc.IsAbs() {
			return root, rel, i18n.EF(clikit.ErrUsage, i18n.KeyCLISCPRecursiveDotAbs)
		}
		d, dErr := pathalg.ParseLocalRootedDest(wdSrc.Base())
		if dErr != nil {
			return root, rel, i18n.WrapS(clikit.ErrUsage, dErr, i18n.KeyCLIInvalidField, i18n.Str("field", "local relative path"), i18n.BoundStr("value", wdSrc.Base()))
		}
		return wdSrc.Dir(), d, nil
	}
	srcPath, pErr := pathalg.ParseLocalSourcePath(trimmed)
	if pErr != nil {
		return root, rel, i18n.WrapS(clikit.ErrUsage, pErr, i18n.KeyCLIInvalidField, i18n.Str("field", "local source path"), i18n.BoundStr("value", localRaw))
	}
	if srcPath.IsAbs() {
		d, dErr := pathalg.ParseLocalRootedDest(srcPath.Base())
		if dErr != nil {
			return root, rel, i18n.WrapS(clikit.ErrUsage, dErr, i18n.KeyCLIInvalidField, i18n.Str("field", "local directory name"), i18n.BoundStr("value", srcPath.Base()))
		}
		return srcPath.Dir(), d, nil
	}
	wd, wErr := resolveWorkDirOrDot(rt)
	if wErr != nil {
		return root, rel, wErr
	}
	d, dErr := pathalg.ParseLocalRootedDest(normalizeLocalRootedRel(srcPath.String()))
	if dErr != nil {
		return root, rel, i18n.WrapS(clikit.ErrUsage, dErr, i18n.KeyCLIInvalidField, i18n.Str("field", "local relative path"), i18n.BoundStr("value", localRaw))
	}
	return wd, d, nil
}

func normalizeLocalRootedRel(raw string) string {
	s := strings.ReplaceAll(strings.TrimSpace(raw), `\`, "/")
	for strings.HasPrefix(s, "./") {
		s = strings.TrimPrefix(s, "./")
	}
	return strings.TrimSuffix(s, "/")
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
		return root, dest, i18n.WrapS(clikit.ErrUsage, pErr, i18n.KeyCLIInvalidField, i18n.Str("field", "local destination path"), i18n.BoundStr("value", localRaw))
	}
	if src.IsAbs() {
		d, dErr := pathalg.ParseLocalRootedDest(src.Base())
		if dErr != nil {
			return root, dest, i18n.WrapS(clikit.ErrUsage, dErr, i18n.KeyCLIInvalidField, i18n.Str("field", "local destination filename"), i18n.BoundStr("value", src.Base()))
		}
		return src.Dir(), d, nil
	}
	wd, wErr := resolveWorkDirOrDot(rt)
	if wErr != nil {
		return root, dest, wErr
	}
	d, dErr := pathalg.ParseLocalRootedDest(normalizeLocalRootedRel(src.String()))
	if dErr != nil {
		return root, dest, i18n.WrapS(clikit.ErrUsage, dErr, i18n.KeyCLIInvalidField, i18n.Str("field", "local relative path"), i18n.BoundStr("value", src.String()))
	}
	return wd, d, nil
}

func resolveRootedDownload(fixedRoot pathalg.LocalDir, localRaw string, remotePath pathalg.RemotePath) (root pathalg.LocalDir, dest pathalg.LocalRootedDest, err error) {
	relRaw, rErr := resolveLocalRelName(localRaw, remotePath)
	if rErr != nil {
		return root, dest, rErr
	}
	d, dErr := pathalg.ParseLocalRootedDest(normalizeLocalRootedRel(relRaw))
	if dErr != nil {
		return root, dest, i18n.WrapS(clikit.ErrUsage, dErr, i18n.KeyCLIInvalidField, i18n.Str("field", "local destination relative path"), i18n.BoundStr("value", localRaw))
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
		return "", i18n.EF(clikit.ErrUsage, i18n.KeyCLISCPNoRemoteBase, i18n.BoundStr("path", remotePath.String()))
	}
	return base.String(), nil
}

func resolveWorkDirOrDot(rt *clikit.Runtime) (pathalg.LocalDir, error) {
	if rt.Hooks.ResolveWorkDir != nil {
		return rt.Hooks.ResolveWorkDir()
	}
	return pathalg.ParseLocalDir(".")
}
