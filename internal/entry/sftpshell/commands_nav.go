package sftpshell

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/i18n"
)

func (s *Shell) cmdPWD(args []string) error {
	if len(args) > 0 {
		return i18n.EF(ErrSyntax, i18n.KeySFTPNoArgsAllowed, i18n.Str("cmd", "pwd"))
	}
	_, _ = fmt.Fprintf(s.stdout, "%s\n", s.remoteDir.String())
	return nil
}

func (s *Shell) cmdCD(ctx context.Context, args []string) error {
	if len(args) > 1 {
		return i18n.EF(ErrSyntax, i18n.KeySFTPUsage, i18n.Str("usage", "cd [remote-path]"))
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
		return i18n.E(i18n.KeySFTPRemoteNotDir,
			i18n.BoundStr("path", realPath.String()),
			i18n.Str("type", st.FileType().String()),
		)
	}
	s.remoteDir = realPath
	return nil
}

func (s *Shell) cmdLS(ctx context.Context, args []string) error {
	longFmt, showAll, pathArg, err := parseListFlags("ls", args)
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
		return i18n.EF(ErrSyntax, i18n.KeySFTPNoArgsAllowed, i18n.Str("cmd", "lpwd"))
	}
	_, _ = fmt.Fprintf(s.stdout, "%s\n", s.localDir.String())
	return nil
}

func (s *Shell) cmdLCD(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return i18n.EF(ErrSyntax, i18n.KeySFTPUsage, i18n.Str("usage", "lcd <local-path>"))
	}
	nextDir, nextSub, err := s.resolveLocalDirArg(args[0])
	if err != nil {
		return err
	}
	if s.localFS != nil {
		ok, err := s.localFS.IsDir(ctx, nextDir)
		if err != nil {
			return err
		}
		if !ok {
			return i18n.E(i18n.KeySFTPLocalNotDir, i18n.BoundStr("path", nextDir.String()))
		}
	}
	s.localDir = nextDir
	if s.scopedLocalOnly {
		s.sandboxSub = nextSub
	}
	return nil
}

func (s *Shell) resolveLocalDirArg(raw string) (pathalg.LocalDir, []string, error) {
	if s.scopedLocalOnly {
		nextSub, err := resolveScopedLocalSegments(s.sandboxSub, raw)
		if err != nil {
			return zeroVal[pathalg.LocalDir](), nil, err
		}
		nextDir, err := joinLocalDirSegments(s.sandboxRoot, nextSub)
		return nextDir, nextSub, err
	}
	nextDir, err := resolveLocalDir(s.localDir, raw)
	return nextDir, nil, err
}

func (s *Shell) cmdLLS(ctx context.Context, args []string) error {
	longFmt, showAll, pathArg, err := parseListFlags("lls", args)
	if err != nil {
		return err
	}
	if s.localFS == nil {
		return i18n.EF(engine.ErrUnsupported, i18n.KeySFTPLocalFSUnavailable)
	}
	target := s.localDir
	if pathArg != "" {
		if target, _, err = s.resolveLocalDirArg(pathArg); err != nil {
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
				return i18n.EF(ErrSyntax, i18n.KeySFTPUnknownOption,
					i18n.Str("cmd", "stat"),
					i18n.BoundStr("option", arg),
				)
			}
			positional = append(positional, arg)
		}
	}
	if len(positional) != 1 {
		return i18n.EF(ErrSyntax, i18n.KeySFTPUsage, i18n.Str("usage", "stat [-L] <remote-path>"))
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
	_, _ = fmt.Fprintf(s.stdout, "%s\n", s.loc.T(i18n.KeySFTPOutputStat,
		i18n.BoundStr("path", st.Path().String()),
		i18n.Str("type", st.FileType().String()),
		i18n.Str("mode", st.Mode().String()),
		i18n.Str("perm", fmt.Sprintf("%#04o", st.Perm())),
		i18n.Int64("size", st.Size()),
		i18n.Str("mtime", formatMTime(st.ModTime())),
		i18n.BoundStr("anchor", anchorStr),
	))
	return nil
}

func (s *Shell) cmdRealPath(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return i18n.EF(ErrSyntax, i18n.KeySFTPUsage, i18n.Str("usage", "realpath <remote-path>"))
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
		return i18n.EF(ErrSyntax, i18n.KeySFTPUsage, i18n.Str("usage", "readlink <remote-path>"))
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
		_, _ = io.WriteString(s.stdout, s.loc.T(i18n.KeySFTPHelpSummary))
		return nil
	}
	if detail, ok := s.shellHelpTopic(strings.ToLower(args[0])); ok {
		_, _ = fmt.Fprintf(s.stdout, "%s\n", detail)
		return nil
	}
	return i18n.EF(ErrSyntax, i18n.KeySFTPUnknownHelpTopic, i18n.BoundStr("topic", args[0]))
}

func parseListFlags(cmd string, args []string) (longFmt, showAll bool, pathArg string, err error) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			for _, ch := range arg[1:] {
				switch ch {
				case 'l':
					longFmt = true
				case 'a':
					showAll = true
				default:
					return false, false, "", i18n.EF(ErrSyntax, i18n.KeySFTPUnknownOption,
						i18n.Str("cmd", cmd),
						i18n.BoundStr("option", "-"+string(ch)),
					)
				}
			}
			continue
		}
		if pathArg != "" {
			return false, false, "", i18n.EF(ErrSyntax, i18n.KeySFTPListTooManyPaths)
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

func (s *Shell) shellHelpTopic(topic string) (string, bool) {
	switch topic {
	case "put":
		return s.loc.T(i18n.KeySFTPHelpPut), true
	case "get":
		return s.loc.T(i18n.KeySFTPHelpGet), true
	case "mv", "rename":
		return s.loc.T(i18n.KeySFTPHelpMV), true
	case "chmod":
		return s.loc.T(i18n.KeySFTPHelpChmod), true
	case "chtimes":
		return s.loc.T(i18n.KeySFTPHelpChtimes), true
	case "write":
		return s.loc.T(i18n.KeySFTPHelpWrite), true
	case "stat":
		return s.loc.T(i18n.KeySFTPHelpStat), true
	case "lstat":
		return s.loc.T(i18n.KeySFTPHelpLstat), true
	case "cd", "pwd", "ls", "lpwd", "lcd", "lls", "mkdir", "rm", "rmdir", "cat", "realpath", "readlink", "exit", "quit", "bye":
		return s.loc.T(i18n.KeySFTPHelpGeneric, i18n.BoundStr("cmd", topic)), true
	default:
		return "", false
	}
}
