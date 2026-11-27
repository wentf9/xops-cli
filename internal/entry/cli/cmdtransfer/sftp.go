package cmdtransfer

import (
	"context"
	"io"
	"io/fs"
	"strings"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
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
	prefix, rest, err := clikit.ConsumeSubcommandPrefix(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(prefix.JSON || clikit.HasJSONFlagForCommand("sftp", args)), err)
	}
	rt = rt.WithPrefix(prefix)
	if prefix.ShowHelp || len(rest) == 0 || rest[0] == "help" {
		_, _ = io.WriteString(rt.Stdout, SFTPHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	parsed, err := parseSFTPArgs(rest)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlagForCommand("sftp", rest)), err)
	}
	if parsed.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, SFTPHelpText(rt.Loc()))
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
		return rt.Fail(clikit.ExitUsage, true, i18n.EF(clikit.ErrUsage, i18n.KeyCLIInteractiveNoJSON, i18n.Str("mode", "sftp")))
	}
	if len(parsed.pos) != 1 || strings.TrimSpace(parsed.pos[0]) == "" {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.EF(clikit.ErrUsage, i18n.KeyCLIArgCountExact, i18n.Str("cmd", "sftp"), i18n.Int("count", 1), i18n.Str("usage", "<target>")))
	}
	if rt.Hooks.RunSFTPShell == nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, i18n.EF(clikit.ErrNotConfigured, i18n.KeyCLIHookNotConfigured, i18n.Str("hook", "RunSFTPShell")))
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
		Locale:      rt.EffectiveLocale(),
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

// parseSFTPArgs 在跳过全部前置通用标志与 SSH 选项（-P/-p/-l/-i/-J/-o/-F 等）后的首个非选项位置词上识别 SFTP 子命令，
// 防止 `xops sftp --lang zh ls web /tmp` 或 `xops sftp -P 2222 ls web /tmp` 静默误路由为拨号名为 "ls" 的交互主机；
// 显式 `--` 之后的全部参数均按普通位置参数保留，不触发子命令识别。
func parseSFTPArgs(args []string) (sftpArgs, error) {
	out := sftpArgs{
		cliOpts:       option.UnsetOptionLayer(),
		symlinkPolicy: pathalg.SymlinkReject,
	}
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		done, err := parseSFTPToken(cur, &out)
		if err != nil {
			return sftpArgs{}, err
		}
		if out.common.ShowHelp {
			return out, nil
		}
		if done {
			break
		}
	}
	if err := out.cliOpts.Validate(); err != nil {
		return sftpArgs{}, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidOptionLayer)
	}
	return out, nil
}

func parseSFTPToken(cur *clikit.FlagCursor, out *sftpArgs) (bool, error) {
	tok := cur.Peek()
	if tok == "--" {
		cur.Next()
		out.pos = append(out.pos, cur.Rest()...)
		return true, nil
	}
	if tok == "-h" || tok == "--help" {
		out.common.ShowHelp = true
		return true, nil
	}
	if !strings.HasPrefix(tok, "-") || tok == "-" {
		return consumeSFTPPositional(cur.Next(), out), nil
	}
	return false, parseSFTPFlag(cur, out)
}

func consumeSFTPPositional(tok string, out *sftpArgs) bool {
	if out.sub == "" && len(out.pos) == 0 {
		if tok == "help" {
			out.common.ShowHelp = true
			return true
		}
		if isSFTPSubcommand(tok) {
			out.sub = tok
			return false
		}
	}
	out.pos = append(out.pos, tok)
	return false
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
			return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownShortFlag, i18n.BoundStr("flag", cluster))
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
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownShortFlag, i18n.BoundStr("flag", string(r)))
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
			return i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--local-root"), i18n.BoundStr("value", raw))
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
			return i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--symlink-policy"), i18n.BoundStr("value", raw))
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
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownLongFlag, i18n.BoundStr("flag", rawTok))
	}
}

func sftpRemoteCall(target string, cliOpts option.OptionLayer) engine.RemoteCall {
	return engine.RemoteCall{
		TargetInput: engine.TargetInput{TargetSpec: target, CLIOptions: cliOpts},
	}
}
