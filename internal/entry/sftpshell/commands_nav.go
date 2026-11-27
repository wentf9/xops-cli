package sftpshell

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/engine"
)

func (s *Shell) cmdPWD(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("%w: pwd 不接受参数", ErrSyntax)
	}
	_, _ = fmt.Fprintf(s.stdout, "%s\n", s.remoteDir.String())
	return nil
}

func (s *Shell) cmdCD(ctx context.Context, args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("%w: 用法: cd [remote-path]", ErrSyntax)
	}
	target := s.homeRemoteDir
	if len(args) == 1 {
		var err error
		if target, err = resolveRemotePath(s.remoteDir, args[0]); err != nil {
			return err
		}
	}
	realPath, err := s.eng.RealPathRemote(ctx, engine.RemotePathOpRequest{
		RemoteCall: s.remoteCall(nil),
		Path:       target,
	})
	if err != nil {
		return err
	}
	st, err := s.eng.StatRemoteFile(ctx, engine.RemoteStatRequest{
		RemoteCall:     s.remoteCall(nil),
		Path:           realPath,
		FollowSymlinks: true,
	})
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("远端路径 %s 不是目录 (%s)", realPath.String(), st.FileType().String())
	}
	s.remoteDir = realPath
	return nil
}

func (s *Shell) cmdLS(ctx context.Context, args []string) error {
	longFmt, showAll, pathArg, err := parseListFlags(args)
	if err != nil {
		return err
	}
	target := s.remoteDir
	if pathArg != "" {
		if target, err = resolveRemotePath(s.remoteDir, pathArg); err != nil {
			return err
		}
	}
	res, err := s.eng.ListRemoteDir(ctx, engine.RemotePathOpRequest{
		RemoteCall: s.remoteCall(nil),
		Path:       target,
	})
	if err != nil {
		return err
	}
	entries := slices.Clone(res.Entries)
	slices.SortFunc(entries, func(a, b engine.RemoteDirEntry) int { return a.Name().Compare(b.Name()) })
	for _, e := range entries {
		name := e.Name().String()
		if !showAll && strings.HasPrefix(name, ".") {
			continue
		}
		if longFmt {
			_, _ = fmt.Fprintf(s.stdout, "%s %10d %s %s\n", formatRemoteEntryMode(e), e.Size(), formatMTime(e.ModTime()), formatRemoteEntryName(e))
		} else {
			_, _ = fmt.Fprintf(s.stdout, "%s\n", formatRemoteEntryName(e))
		}
	}
	return nil
}

func (s *Shell) cmdLPWD(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("%w: lpwd 不接受参数", ErrSyntax)
	}
	_, _ = fmt.Fprintf(s.stdout, "%s\n", s.localDir.String())
	return nil
}

func (s *Shell) cmdLCD(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("%w: 用法: lcd <local-path>", ErrSyntax)
	}
	nextDir, err := resolveLocalDir(s.localDir, args[0])
	if err != nil {
		return err
	}
	if s.localFS != nil {
		ok, err := s.localFS.IsDir(ctx, nextDir)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("本地路径 %s 不是目录或不存在", nextDir.String())
		}
	}
	s.localDir = nextDir
	return nil
}

func (s *Shell) cmdLLS(ctx context.Context, args []string) error {
	longFmt, showAll, pathArg, err := parseListFlags(args)
	if err != nil {
		return err
	}
	if s.localFS == nil {
		return fmt.Errorf("%w: 当前环境未注入 LocalFS，无法列举本地目录", engine.ErrUnsupported)
	}
	target := s.localDir
	if pathArg != "" {
		if target, err = resolveLocalDir(s.localDir, pathArg); err != nil {
			return err
		}
	}
	entries, err := s.localFS.ReadDir(ctx, target)
	if err != nil {
		return err
	}
	sorted := slices.Clone(entries)
	slices.SortFunc(sorted, func(a, b LocalDirEntry) int { return cmp.Compare(a.Name, b.Name) })
	for _, e := range sorted {
		if !showAll && strings.HasPrefix(e.Name, ".") {
			continue
		}
		display := e.Name
		if e.IsDir {
			display += "/"
		}
		if longFmt {
			_, _ = fmt.Fprintf(s.stdout, "%s %10d %s %s\n", e.Mode.String(), e.Size, formatMTime(e.ModTime), display)
		} else {
			_, _ = fmt.Fprintf(s.stdout, "%s\n", display)
		}
	}
	return nil
}

func (s *Shell) cmdStat(ctx context.Context, args []string, followDefault bool) error {
	follow := followDefault
	var positional []string
	for _, arg := range args {
		switch arg {
		case "-L", "--follow":
			follow = true
		default:
			if strings.HasPrefix(arg, "-") {
				return fmt.Errorf("%w: stat 未知选项 %q", ErrSyntax, arg)
			}
			positional = append(positional, arg)
		}
	}
	if len(positional) != 1 {
		return fmt.Errorf("%w: 用法: stat [-L] <remote-path>", ErrSyntax)
	}
	target, err := resolveRemotePath(s.remoteDir, positional[0])
	if err != nil {
		return err
	}
	st, err := s.eng.StatRemoteFile(ctx, engine.RemoteStatRequest{
		RemoteCall:     s.remoteCall(nil),
		Path:           target,
		FollowSymlinks: follow,
	})
	if err != nil {
		return err
	}
	anchor := st.Anchor()
	anchorStr := anchor.FileType().String()
	if anchor.HasDevIno() {
		anchorStr = fmt.Sprintf("%s(dev=%d,ino=%d)", anchor.FileType().String(), anchor.Dev(), anchor.Ino())
	}
	_, _ = fmt.Fprintf(s.stdout, "Path: %s\nType: %s\nMode: %s (%#04o)\nSize: %d\nModTime: %s\nAnchor: %s\n",
		st.Path().String(), st.FileType().String(), st.Mode().String(), st.Perm(), st.Size(), formatMTime(st.ModTime()), anchorStr)
	return nil
}

func (s *Shell) cmdRealPath(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("%w: 用法: realpath <remote-path>", ErrSyntax)
	}
	target, err := resolveRemotePath(s.remoteDir, args[0])
	if err != nil {
		return err
	}
	resolved, err := s.eng.RealPathRemote(ctx, engine.RemotePathOpRequest{
		RemoteCall: s.remoteCall(nil),
		Path:       target,
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(s.stdout, "%s\n", resolved.String())
	return nil
}

func (s *Shell) cmdReadLink(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("%w: 用法: readlink <remote-path>", ErrSyntax)
	}
	target, err := resolveRemotePath(s.remoteDir, args[0])
	if err != nil {
		return err
	}
	linkTarget, err := s.eng.ReadLinkRemote(ctx, engine.RemotePathOpRequest{
		RemoteCall: s.remoteCall(nil),
		Path:       target,
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(s.stdout, "%s\n", linkTarget)
	return nil
}

func (s *Shell) cmdHelp(args []string) error {
	if len(args) == 0 {
		_, _ = io.WriteString(s.stdout, shellHelpSummary())
		return nil
	}
	if detail, ok := shellHelpTopic(strings.ToLower(args[0])); ok {
		_, _ = fmt.Fprintf(s.stdout, "%s\n", detail)
		return nil
	}
	return fmt.Errorf("%w: 未知帮助主题 %q", ErrSyntax, args[0])
}

func parseListFlags(args []string) (longFmt, showAll bool, pathArg string, err error) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			for _, ch := range arg[1:] {
				switch ch {
				case 'l':
					longFmt = true
				case 'a':
					showAll = true
				default:
					return false, false, "", fmt.Errorf("%w: 未知列表选项 -%c", ErrSyntax, ch)
				}
			}
			continue
		}
		if pathArg != "" {
			return false, false, "", fmt.Errorf("%w: ls/lls 仅支持至多一个路径参数", ErrSyntax)
		}
		pathArg = arg
	}
	return longFmt, showAll, pathArg, nil
}

func formatRemoteEntryMode(e engine.RemoteDirEntry) string {
	if e.Mode() != 0 {
		return e.Mode().String()
	}
	switch e.FileType() {
	case engine.RemoteFileDir:
		return "drwxr-xr-x"
	case engine.RemoteFileSymlink:
		return "lrwxrwxrwx"
	default:
		return "-rw-r--r--"
	}
}

func formatRemoteEntryName(e engine.RemoteDirEntry) string {
	name := e.Name().String()
	switch e.FileType() {
	case engine.RemoteFileDir:
		return name + "/"
	case engine.RemoteFileSymlink:
		return name + "@"
	default:
		return name
	}
}

func formatMTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func shellHelpSummary() string {
	return `SFTP Shell Commands:
  Navigation:
    pwd                         Print remote working directory
    cd [remote-path]            Change remote working directory (default: initial remote dir)
    ls [-l] [-a] [remote-path]  List remote directory contents
    lpwd                        Print local working directory
    lcd <local-path>            Change local working directory
    lls [-l] [-a] [local-path]  List local directory contents (requires LocalFS)

  Transfer & Atomic File Operations:
    put [-r] [-n] [--resume] [-p] <local> [remote]  Upload local file/dir to remote
    get [-r] [-n] [--resume] [-p] <remote> [local]  Download remote file/dir to local
    cat <remote-path>                               Read remote file contents
    write [-n] [-p] <remote-path> <content>         Atomically write text to remote file
    mv [-n] <old-path> <new-path>                   Atomically rename remote path (alias: rename)
    mkdir [-m <octal>] <remote-path>                Create remote directory (and parents)
    rm <remote-path>                                Remove remote file or symlink
    rmdir <remote-path>                             Remove empty remote directory

  Metadata & Inspection:
    chmod <octal-mode> <remote-path>                Change remote file permissions (0001..0777)
    chtimes <mtime> <remote-path>                   Update remote atime/mtime (or <atime> <mtime> <path>)
    stat [-L] <remote-path>                         Inspect remote metadata & FSTAT anchor (alias: lstat)
    realpath <remote-path>                          Resolve canonical remote path
    readlink <remote-path>                          Read remote symlink target

  Control:
    help [command]              Show help
    exit / quit / bye           Close SFTP shell
`
}

func shellHelpTopic(topic string) (string, bool) {
	switch topic {
	case "put":
		return "put [-r] [-n|--no-clobber] [--resume] [-p|--preserve] <local-path> [remote-path]: upload via SCPUpload with progress streaming", true
	case "get":
		return "get [-r] [-n|--no-clobber] [--resume] [-p|--preserve] <remote-path> [local-path]: download into sandboxed local directory via SCPDownload", true
	case "mv", "rename":
		return "mv [-n|--no-clobber] <old-path> <new-path>: atomic SFTP v3 posix-rename@openssh.com", true
	case "chmod":
		return "chmod <octal-mode> <remote-path>: set POSIX permission bits in 0001..0777", true
	case "chtimes":
		return "chtimes <mtime> <remote-path> | chtimes <atime> <mtime> <remote-path>: set RFC3339 or Unix epoch timestamps", true
	case "write":
		return "write [-n|--no-clobber] [-p|--parents] <remote-path> <text>: atomically write UTF-8 text to remote file", true
	case "stat", "lstat":
		return "stat [-L|--follow] <remote-path> / lstat <remote-path>: display type, mode, size, mtime, and FSTAT anchor", true
	case "cd", "pwd", "ls", "lpwd", "lcd", "lls", "mkdir", "rm", "rmdir", "cat", "realpath", "readlink", "exit", "quit", "bye":
		return fmt.Sprintf("command %q: run 'help' to see full command reference", topic), true
	default:
		return "", false
	}
}
