package sftpshell

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/internal/i18n"
)

type transferFlags struct {
	recursive bool
	noClobber bool
	resume    bool
	preserve  bool
	args      []string
}

func parseTransferFlags(cmd string, args []string) (transferFlags, error) {
	var f transferFlags
	for _, arg := range args {
		switch arg {
		case "-r", "-R", "--recursive":
			f.recursive = true
		case "-n", "--no-clobber":
			f.noClobber = true
		case "--resume":
			f.resume = true
		case "-p", "--preserve":
			f.preserve = true
		default:
			if strings.HasPrefix(arg, "-") {
				return transferFlags{}, i18n.EF(ErrSyntax, i18n.KeySFTPUnknownOption,
					i18n.Str("cmd", cmd),
					i18n.BoundStr("option", arg),
				)
			}
			f.args = append(f.args, arg)
		}
	}
	return f, nil
}

func (s *Shell) cmdPut(ctx context.Context, args []string) error {
	f, err := parseTransferFlags("put", args)
	if err != nil {
		return err
	}
	if len(f.args) < 1 || len(f.args) > 2 {
		return i18n.EF(ErrSyntax, i18n.KeySFTPUsage, i18n.Str("usage", "put [-r] [-n] [--resume] [-p] <local-path> [remote-path]"))
	}
	src, baseName, err := s.buildUploadSource(f.args[0], f.recursive)
	if err != nil {
		return err
	}
	remoteDest, expandDir, err := s.resolvePutRemoteDest(f.args, baseName)
	if err != nil {
		return err
	}
	var res engine.SCPUploadResult
	err = s.runWithProgressStream(ctx, func(runCtx context.Context, stream *events.OperationStream) error {
		var uErr error
		res, uErr = s.eng.SCPUpload(runCtx, engine.SCPUploadRequest{
			RemoteCall:    s.remoteCall(stream),
			Source:        src,
			RemoteDest:    remoteDest,
			Recursive:     f.recursive,
			ExpandIntoDir: expandDir,
			NoClobber:     f.noClobber,
			Resume:        f.resume,
			PreserveMode:  f.preserve,
			PreserveTimes: f.preserve,
			SymlinkPolicy: s.uploadSymlinkPolicy(f.recursive),
		})
		return uErr
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(s.stdout, "%s\n", s.loc.T(i18n.KeySFTPOutputUploaded,
		i18n.BoundStr("src", f.args[0]),
		i18n.BoundStr("dest", res.RemotePath.String()),
		i18n.Int("files", res.FilesUploaded),
		i18n.Int64("bytes", res.BytesTransferred),
	))
	return nil
}

// buildUploadSource 按模式与递归标志构造满足 core/engine.SCPUpload 不变量的上传源：
//   - ScopedLocalOnly=true：始终锚定于不可变 sandboxRoot（ScopedUploadSource）；
//   - 递归目录上传（put -r）：即便在默认操作员模式也构造 ScopedUploadSource（Engine 仅允许 *os.Root 遍历目录树）；
//   - 单文件操作员上传：构造 OperatorUploadSource。
func (s *Shell) buildUploadSource(rawLocal string, recursive bool) (engine.LocalUploadSource, string, error) {
	if s.scopedLocalOnly {
		rel, err := resolveScopedUploadTarget(s.sandboxSub, rawLocal)
		if err != nil {
			return zeroVal[engine.LocalUploadSource](), "", err
		}
		src, err := engine.NewScopedUploadSource(s.sandboxRoot, rel)
		return src, rel.Base(), err
	}
	srcPath, err := resolveLocalUploadPath(s.localDir, rawLocal)
	if err != nil {
		return zeroVal[engine.LocalUploadSource](), "", err
	}
	if recursive {
		relBase, err := pathalg.ParseLocalRootedDest(srcPath.Base())
		if err != nil {
			return zeroVal[engine.LocalUploadSource](), "", err
		}
		src, err := engine.NewScopedUploadSource(srcPath.Dir(), relBase)
		return src, relBase.Base(), err
	}
	src, err := engine.NewOperatorUploadSource(srcPath, s.symlinkPolicy)
	return src, srcPath.Base(), err
}

func (s *Shell) uploadSymlinkPolicy(recursive bool) pathalg.SymlinkPolicy {
	if recursive && s.symlinkPolicy == pathalg.SymlinkFollowOperatorSource {
		return pathalg.SymlinkReject
	}
	return s.symlinkPolicy
}

func (s *Shell) downloadSymlinkPolicy() pathalg.SymlinkPolicy {
	if s.symlinkPolicy == pathalg.SymlinkFollowOperatorSource {
		return pathalg.SymlinkReject
	}
	return s.symlinkPolicy
}

func (s *Shell) resolvePutRemoteDest(args []string, localBase string) (pathalg.RemotePath, bool, error) {
	if len(args) == 2 {
		dest, err := resolveRemotePath(s.remoteDir, args[1])
		return dest, true, err
	}
	name, err := pathalg.ParseRemoteName(localBase)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), false, err
	}
	dest, err := s.remoteDir.Join(name)
	return dest, false, err
}

func (s *Shell) cmdGet(ctx context.Context, args []string) error {
	f, err := parseTransferFlags("get", args)
	if err != nil {
		return err
	}
	if len(f.args) < 1 || len(f.args) > 2 {
		return i18n.EF(ErrSyntax, i18n.KeySFTPUsage, i18n.Str("usage", "get [-r] [-n] [--resume] [-p] <remote-path> [local-path]"))
	}
	remoteSrc, err := resolveRemotePath(s.remoteDir, f.args[0])
	if err != nil {
		return err
	}
	localArg := ""
	if len(f.args) == 2 {
		localArg = f.args[1]
	}
	localRoot, localDest, err := resolveLocalDownloadTarget(s.localDir, s.sandboxRoot, s.sandboxSub, s.scopedLocalOnly, remoteSrc, localArg)
	if err != nil {
		return err
	}
	var res engine.SCPDownloadResult
	err = s.runWithProgressStream(ctx, func(runCtx context.Context, stream *events.OperationStream) error {
		var dErr error
		res, dErr = s.eng.SCPDownload(runCtx, engine.SCPDownloadRequest{
			RemoteCall:    s.remoteCall(stream),
			RemoteSource:  remoteSrc,
			LocalRoot:     localRoot,
			LocalDest:     localDest,
			Recursive:     f.recursive,
			NoClobber:     f.noClobber,
			Resume:        f.resume,
			PreserveTimes: f.preserve,
			SymlinkPolicy: s.downloadSymlinkPolicy(),
		})
		return dErr
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(s.stdout, "%s\n", s.loc.T(i18n.KeySFTPOutputDownloaded,
		i18n.BoundStr("src", remoteSrc.String()),
		i18n.BoundStr("dest", res.LocalDest.String()),
		i18n.Int("files", res.FilesDownloaded),
		i18n.Int64("bytes", res.BytesTransferred),
	))
	return nil
}

func (s *Shell) cmdCat(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return i18n.EF(ErrSyntax, i18n.KeySFTPUsage, i18n.Str("usage", "cat <remote-path>"))
	}
	target, err := resolveRemotePath(s.remoteDir, args[0])
	if err != nil {
		return err
	}
	res, err := s.eng.ReadRemoteFile(ctx, engine.RemoteFileReadRequest{
		RemoteCall: s.remoteCall(nil),
		Path:       target,
		MaxBytes:   defaultMaxReadBytes,
	})
	if err != nil {
		return err
	}
	_, _ = s.stdout.Write(res.Content)
	if len(res.Content) > 0 && res.Content[len(res.Content)-1] != '\n' {
		_, _ = s.stdout.Write([]byte("\n"))
	}
	return nil
}

func (s *Shell) cmdWrite(ctx context.Context, args []string) error {
	noClobber, createParents, positional, err := parseWriteArgs(args)
	if err != nil {
		return err
	}
	if len(positional) < 2 {
		return i18n.EF(ErrSyntax, i18n.KeySFTPUsage, i18n.Str("usage", "write [-n] [-p] [--] <remote-path> <content>"))
	}
	target, err := resolveRemotePath(s.remoteDir, positional[0])
	if err != nil {
		return err
	}
	content := strings.Join(positional[1:], " ")
	res, err := s.eng.WriteRemoteFile(ctx, engine.RemoteFileWriteRequest{
		RemoteCall:    s.remoteCall(nil),
		Path:          target,
		Content:       []byte(content),
		NoClobber:     noClobber,
		CreateParents: createParents,
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(s.stdout, "%s\n", s.loc.T(i18n.KeySFTPOutputWrote,
		i18n.BoundStr("path", target.String()),
		i18n.Int64("bytes", res.BytesWritten),
	))
	return nil
}

// parseWriteArgs 仅在遇到首个位置参数或 "--" 之前解析 -n/-p 选项，避免正文内容中的 "-n"/"-p" 被误删。
func parseWriteArgs(args []string) (noClobber, createParents bool, positional []string, err error) {
	parsingFlags := true
	for _, arg := range args {
		if !parsingFlags {
			positional = append(positional, arg)
			continue
		}
		switch arg {
		case "--":
			parsingFlags = false
		case "-n", "--no-clobber":
			noClobber = true
		case "-p", "--parents":
			createParents = true
		default:
			if strings.HasPrefix(arg, "-") {
				return false, false, nil, i18n.EF(ErrSyntax, i18n.KeySFTPUnknownOption,
					i18n.Str("cmd", "write"),
					i18n.BoundStr("option", arg),
				)
			}
			parsingFlags = false
			positional = append(positional, arg)
		}
	}
	return noClobber, createParents, positional, nil
}

func (s *Shell) cmdRename(ctx context.Context, args []string) error {
	noClobber := false
	var positional []string
	for _, arg := range args {
		switch arg {
		case "-n", "--no-clobber":
			noClobber = true
		default:
			if strings.HasPrefix(arg, "-") {
				return i18n.EF(ErrSyntax, i18n.KeySFTPUnknownOption,
					i18n.Str("cmd", "mv/rename"),
					i18n.BoundStr("option", arg),
				)
			}
			positional = append(positional, arg)
		}
	}
	if len(positional) != 2 {
		return i18n.EF(ErrSyntax, i18n.KeySFTPUsage, i18n.Str("usage", "mv [-n] <old-path> <new-path>"))
	}
	oldPath, err := resolveRemotePath(s.remoteDir, positional[0])
	if err != nil {
		return err
	}
	newPath, err := resolveRemotePath(s.remoteDir, positional[1])
	if err != nil {
		return err
	}
	return s.eng.RenameRemoteFile(ctx, engine.RemoteRenameRequest{
		RemoteCall: s.remoteCall(nil),
		OldPath:    oldPath,
		NewPath:    newPath,
		NoClobber:  noClobber,
	})
}

func (s *Shell) cmdMkdir(ctx context.Context, args []string) error {
	var perm algebraic.Option[fs.FileMode]
	var positional []string
	for i := 0; i < len(args); i++ {
		if args[i] == "-m" || args[i] == "--mode" {
			if i+1 >= len(args) {
				return i18n.EF(ErrSyntax, i18n.KeySFTPMkdirMissingMode)
			}
			i++
			p, err := parseOctalPerm(args[i])
			if err != nil {
				return err
			}
			perm = algebraic.Some(p)
			continue
		}
		if strings.HasPrefix(args[i], "-") {
			return i18n.EF(ErrSyntax, i18n.KeySFTPUnknownOption,
				i18n.Str("cmd", "mkdir"),
				i18n.BoundStr("option", args[i]),
			)
		}
		positional = append(positional, args[i])
	}
	if len(positional) != 1 {
		return i18n.EF(ErrSyntax, i18n.KeySFTPUsage, i18n.Str("usage", "mkdir [-m <octal>] <remote-path>"))
	}
	target, err := resolveRemotePath(s.remoteDir, positional[0])
	if err != nil {
		return err
	}
	return s.eng.MkdirRemoteAll(ctx, engine.RemotePathOpRequest{
		RemoteCall: s.remoteCall(nil),
		Path:       target,
		Perm:       perm,
	})
}

func (s *Shell) cmdRemove(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return i18n.EF(ErrSyntax, i18n.KeySFTPUsage, i18n.Str("usage", "rm <remote-path>"))
	}
	target, err := resolveRemotePath(s.remoteDir, args[0])
	if err != nil {
		return err
	}
	return s.eng.RemoveRemoteFile(ctx, engine.RemotePathOpRequest{
		RemoteCall: s.remoteCall(nil),
		Path:       target,
	})
}

func (s *Shell) cmdRemoveDir(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return i18n.EF(ErrSyntax, i18n.KeySFTPUsage, i18n.Str("usage", "rmdir <remote-path>"))
	}
	target, err := resolveRemotePath(s.remoteDir, args[0])
	if err != nil {
		return err
	}
	return s.eng.RemoveRemoteDir(ctx, engine.RemotePathOpRequest{
		RemoteCall: s.remoteCall(nil),
		Path:       target,
	})
}

func (s *Shell) cmdChmod(ctx context.Context, args []string) error {
	if len(args) != 2 {
		return i18n.EF(ErrSyntax, i18n.KeySFTPUsage, i18n.Str("usage", "chmod <octal-mode> <remote-path>"))
	}
	perm, err := parseOctalPerm(args[0])
	if err != nil {
		return err
	}
	target, err := resolveRemotePath(s.remoteDir, args[1])
	if err != nil {
		return err
	}
	return s.eng.ChmodRemote(ctx, engine.RemotePathOpRequest{
		RemoteCall: s.remoteCall(nil),
		Path:       target,
		Perm:       algebraic.Some(perm),
	})
}

func (s *Shell) cmdChtimes(ctx context.Context, args []string) error {
	var atime, mtime time.Time
	var pathRaw string
	switch len(args) {
	case 2:
		t, err := parseTimestamp(args[0])
		if err != nil {
			return err
		}
		atime, mtime, pathRaw = t, t, args[1]
	case 3:
		var err error
		if atime, err = parseTimestamp(args[0]); err != nil {
			return err
		}
		if mtime, err = parseTimestamp(args[1]); err != nil {
			return err
		}
		pathRaw = args[2]
	default:
		return i18n.EF(ErrSyntax, i18n.KeySFTPUsage, i18n.Str("usage", "chtimes <mtime> <remote-path> | chtimes <atime> <mtime> <remote-path>"))
	}
	target, err := resolveRemotePath(s.remoteDir, pathRaw)
	if err != nil {
		return err
	}
	return s.eng.ChtimesRemote(ctx, engine.RemotePathOpRequest{
		RemoteCall: s.remoteCall(nil),
		Path:       target,
		Atime:      atime,
		Mtime:      mtime,
	})
}

// runWithProgressStream 在 core/conc.Nursery（RunWait）监督下为传输操作挂载隔离 OperationStream，
// 确保进度消费协程在传输返回、出错或被单命令取消后 100% 确定性排空（0 裸 go、0 goroutine 泄漏）。
//
//xops:syncclosure
func (s *Shell) runWithProgressStream(ctx context.Context, fn func(context.Context, *events.OperationStream) error) error {
	stream, err := s.eng.NewOperationStream(ctx, s.streamBuffer)
	if err != nil {
		return err
	}
	if stream == nil {
		return fn(ctx, nil)
	}
	return conc.RunWait(ctx, func(wCtx context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(pCtx context.Context) error {
			return s.consumeTransferProgress(pCtx, stream)
		}); gErr != nil {
			stream.Close()
			return gErr
		}
		defer stream.Close()
		return fn(wCtx, stream)
	})
}

func (s *Shell) consumeTransferProgress(ctx context.Context, stream *events.OperationStream) error {
	for {
		ev, ok, err := stream.Next(ctx)
		if err != nil || !ok {
			return nil
		}
		if !s.showProgress {
			continue
		}
		if tp, ok := ev.(*events.TransferProgressEvent); ok && tp.IsValid() {
			_, _ = fmt.Fprintf(s.stderr, "%s\n", s.loc.T(i18n.KeySFTPOutputProgress,
				i18n.BoundStr("stage", tp.Stage()),
				i18n.Uint64("transferred", tp.BytesTransferred()),
				i18n.Uint64("total", tp.TotalBytes()),
			))
		}
	}
}
