package cmdtransfer

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

type sftpArgs struct {
	sub            string
	common         clikit.CommonFlags
	cliOpts        option.OptionLayer
	initialDir     string
	followSymlinks bool
	noClobber      bool
	createParents  bool
	replaceAll     bool
	prune          bool
	maxBytes       int64
	perm           algebraic.Option[fs.FileMode]
	localRoot      algebraic.Option[pathalg.LocalDir]
	filePath       string
	symlinkPolicy  pathalg.SymlinkPolicy
	oldText        string
	newText        string
	pos            []string
}

// RunSFTP 执行 `xops sftp`：支持交互式 SFTP Shell（经 AppConfig.RunSFTPShell 回调注入）及全部单步远端 SFTP 子命令。
func RunSFTP(ctx context.Context, rt *clikit.Runtime, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, _ = io.WriteString(rt.Stdout, SFTPHelpText())
		return clikit.ExitOK
	}
	parsed, err := parseSFTPArgs(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if parsed.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, SFTPHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(parsed.common.JSON)
	if parsed.sub == "" {
		return runSFTPInteractive(ctx, rt, parsed, jsonOut)
	}
	initOpts := rt.EffectiveInitOptions(parsed.common.ConfigFile, parsed.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitSSHError, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireTransferClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		return dispatchSFTPOp(ctx, rt, client, parsed, jsonOut)
	})
}

func runSFTPInteractive(ctx context.Context, rt *clikit.Runtime, parsed sftpArgs, jsonOut bool) int {
	if jsonOut {
		return rt.Fail(clikit.ExitUsage, true, fmt.Errorf("%w: 交互式 SFTP Shell 不支持 --json 输出，请使用单步 sftp 子命令", clikit.ErrUsage))
	}
	if len(parsed.pos) != 1 || strings.TrimSpace(parsed.pos[0]) == "" {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: 交互式 sftp 需要恰好 1 个目标主机参数", clikit.ErrUsage))
	}
	if rt.Hooks.RunSFTPShell == nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, fmt.Errorf("%w: 未注入 RunSFTPShell 回调，无法启动交互式 SFTP Shell", clikit.ErrNotConfigured))
	}
	targetSpec := strings.TrimSpace(parsed.pos[0])
	initialDir := parsed.initialDir
	if hostPart, dirPart, isRemote := splitSCPEndpoint(targetSpec); isRemote {
		targetSpec = hostPart
		if initialDir == "" {
			initialDir = dirPart
		}
	}
	req := clikit.SFTPShellStartRequest{
		InitOptions: rt.EffectiveInitOptions(parsed.common.ConfigFile, parsed.common.Policy),
		TargetSpec:  targetSpec,
		CLIOptions:  parsed.cliOpts,
		InitialDir:  initialDir,
		Stdin:       rt.Stdin,
		Stdout:      rt.Stdout,
		Stderr:      rt.Stderr,
	}
	if err := rt.Hooks.RunSFTPShell(ctx, req); err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	return clikit.ExitOK
}

func isSFTPSubcommand(tok string) bool {
	switch tok {
	case "ls", "stat", "cat", "read", "write", "patch", "mkdir", "mv", "rename", "rm", "rmdir", "chmod", "realpath", "readlink", "recover":
		return true
	default:
		return false
	}
}

func parseSFTPArgs(args []string) (sftpArgs, error) {
	out := sftpArgs{
		cliOpts:       option.UnsetOptionLayer(),
		symlinkPolicy: pathalg.SymlinkReject,
	}
	rest := args
	if isSFTPSubcommand(args[0]) {
		out.sub = args[0]
		rest = args[1:]
	}
	cur := clikit.NewFlagCursor(rest)
	for cur.HasNext() {
		tok := cur.Peek()
		if tok == "--" {
			cur.Next()
			out.pos = append(out.pos, cur.Rest()...)
			break
		}
		if tok == "-h" || tok == "--help" {
			out.common.ShowHelp = true
			return out, nil
		}
		if !strings.HasPrefix(tok, "-") || tok == "-" {
			out.pos = append(out.pos, cur.Next())
			continue
		}
		if err := parseSFTPFlag(cur, &out); err != nil {
			return sftpArgs{}, err
		}
		if out.common.ShowHelp {
			return out, nil
		}
	}
	if err := out.cliOpts.Validate(); err != nil {
		return sftpArgs{}, fmt.Errorf("%w: CLI 选项层校验失败: %w", clikit.ErrUsage, err)
	}
	return out, nil
}

func parseSFTPFlag(cur *clikit.FlagCursor, out *sftpArgs) error {
	if strings.HasPrefix(cur.Peek(), "--") {
		return parseSFTPLongFlag(cur, out)
	}
	tok := cur.Next()
	return parseSFTPShortCluster(cur, tok[1:], out)
}

func parseSFTPShortCluster(cur *clikit.FlagCursor, cluster string, out *sftpArgs) error {
	if cluster == "" {
		return nil
	}
	ch := cluster[0]
	rest := cluster[1:]
	switch ch {
	case 'h':
		if rest != "" {
			return fmt.Errorf("%w: sftp 未知短选项 -%s", clikit.ErrUsage, cluster)
		}
		out.common.ShowHelp = true
		return nil
	case 'P':
		val, err := cur.ConsumeShortArg('P', rest)
		if err != nil {
			return err
		}
		return clikit.ApplyOptionKV(&out.cliOpts, "Port", val, "-P")
	case 'p', 'l', 'i', 'J', 'o', 'F':
		_, err := clikit.ApplyCommonSSHShortOption(cur, ch, rest, &out.cliOpts, &out.common.ConfigFile)
		return err
	default:
		r, _ := utf8.DecodeRuneInString(cluster)
		return fmt.Errorf("%w: sftp 未知短选项 -%c", clikit.ErrUsage, r)
	}
}

func parseSFTPLongFlag(cur *clikit.FlagCursor, out *sftpArgs) error {
	if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &out.common); err != nil || consumed {
		return err
	}
	tok := cur.Next()
	name, inlineVal, hasEq := clikit.SplitLongFlag(tok)
	if handled, err := parseSFTPBoolFlag(name, inlineVal, hasEq, out); handled || err != nil {
		return err
	}
	return parseSFTPValueFlag(cur, name, inlineVal, hasEq, tok, out)
}

func parseSFTPBoolFlag(name, inlineVal string, hasEq bool, out *sftpArgs) (bool, error) {
	switch name {
	case "follow-symlinks":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.followSymlinks = v
		return true, err
	case "no-clobber":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.noClobber = v
		return true, err
	case "create-parents":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.createParents = v
		return true, err
	case "all":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.replaceAll = v
		return true, err
	case "prune":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.prune = v
		return true, err
	default:
		return false, nil
	}
}

func parseSFTPValueFlag(cur *clikit.FlagCursor, name, inlineVal string, hasEq bool, rawTok string, out *sftpArgs) error {
	switch name {
	case "dir":
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		out.initialDir = raw
		return err
	case "max-bytes":
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return err
		}
		out.maxBytes, err = clikit.ParseNonNegInt64("--max-bytes", raw)
		return err
	case "perm":
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return err
		}
		mode, err := clikit.ParseOctalPerm("--perm", raw)
		if err == nil {
			out.perm = algebraic.Some(mode)
		}
		return err
	case "local-root":
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return err
		}
		d, err := pathalg.ParseLocalDir(raw)
		if err != nil {
			return fmt.Errorf("%w: --local-root 非法: %w", clikit.ErrUsage, err)
		}
		out.localRoot = algebraic.Some(d)
		return nil
	case "file":
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		out.filePath = raw
		return err
	case "symlink-policy":
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return err
		}
		p, err := pathalg.ParseSymlinkPolicy(raw)
		if err != nil {
			return fmt.Errorf("%w: --symlink-policy 非法: %w", clikit.ErrUsage, err)
		}
		out.symlinkPolicy = p
		return nil
	case "old":
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		out.oldText = raw
		return err
	case "new":
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		out.newText = raw
		return err
	default:
		return fmt.Errorf("%w: sftp 未知长选项 %q", clikit.ErrUsage, rawTok)
	}
}

func sftpRemoteCall(target string, cliOpts option.OptionLayer) engine.RemoteCall {
	return engine.RemoteCall{
		TargetInput: engine.TargetInput{TargetSpec: target, CLIOptions: cliOpts},
	}
}
