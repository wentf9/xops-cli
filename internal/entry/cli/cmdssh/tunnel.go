package cmdssh

import (
	"context"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

type tunnelArgs struct {
	common   clikit.CommonFlags
	cliOpts  option.OptionLayer
	target   string
	forwards []engine.ForwardSpec
	rawTUNs  []string
	tunMode  engine.TUNMode
}

// RunTunnel 执行 `xops tunnel`（别名 `forward`），支持 start / local / remote / dynamic / tun 及 OpenSSH -L/-R/-D/-w 风格。
func RunTunnel(ctx context.Context, rt *clikit.Runtime, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, _ = io.WriteString(rt.Stdout, TunnelHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	parsed, err := parseTunnelArgs(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if parsed.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, TunnelHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(parsed.common.JSON)
	initOpts := rt.EffectiveInitOptions(parsed.common.ConfigFile, parsed.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitSSHError, jsonOut, func(runner clikit.SessionRunner) (exitCode int) {
		client, err := requireSSHClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitSSHError, jsonOut, err)
		}
		rc := engine.RemoteCall{
			TargetInput: engine.TargetInput{TargetSpec: parsed.target, CLIOptions: parsed.cliOpts},
		}
		infos, err := startForwards(ctx, client, rc, parsed.forwards)
		if err != nil {
			return rt.Fail(clikit.ExitSSHError, jsonOut, err)
		}
		defer func() { reportCleanupError(rt, stopForwards(ctx, client, infos), &exitCode) }()
		announceActiveSession(rt, jsonOut, parsed.target, infos, nil)
		if err := waitForwards(ctx, infos, nil); err != nil {
			return failAfterAnnounce(rt, jsonOut, err)
		}
		return clikit.ExitOK
	})
}

func parseTunnelArgs(args []string) (tunnelArgs, error) {
	sub := ""
	rest := args
	switch args[0] {
	case "start", "local", "remote", "dynamic", "tun":
		sub = args[0]
		rest = args[1:]
	}
	out := tunnelArgs{
		cliOpts: option.UnsetOptionLayer(),
		tunMode: engine.TUNModePointToPoint,
	}
	cur := clikit.NewFlagCursor(rest)
	var pos []string
	for cur.HasNext() {
		tok := cur.Peek()
		if tok == "--" {
			cur.Next()
			pos = append(pos, cur.Rest()...)
			break
		}
		if tok == "-h" || tok == "--help" {
			out.common.ShowHelp = true
			return out, nil
		}
		if !strings.HasPrefix(tok, "-") || tok == "-" {
			pos = append(pos, cur.Next())
			continue
		}
		if err := parseTunnelFlag(cur, &out); err != nil {
			return tunnelArgs{}, err
		}
		if out.common.ShowHelp {
			return out, nil
		}
	}
	return finalizeTunnelArgs(sub, pos, out)
}

func parseTunnelFlag(cur *clikit.FlagCursor, out *tunnelArgs) error {
	if strings.HasPrefix(cur.Peek(), "--") {
		if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &out.common); err != nil || consumed {
			return err
		}
		tok := cur.Next()
		name, inlineVal, hasEq := clikit.SplitLongFlag(tok)
		if name == "tun-mode" {
			raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
			if err != nil {
				return err
			}
			m, err := engine.ParseTUNMode(raw)
			if err != nil {
				return i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--tun-mode"), i18n.BoundStr("value", raw))
			}
			out.tunMode = m
			return nil
		}
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownLongFlag, i18n.BoundStr("flag", tok))
	}
	tok := cur.Next()
	return parseTunnelShortCluster(cur, tok[1:], out)
}

func parseTunnelShortCluster(cur *clikit.FlagCursor, cluster string, out *tunnelArgs) error {
	if cluster == "" {
		return nil
	}
	ch := cluster[0]
	rest := cluster[1:]
	if ok, err := clikit.ApplyCommonSSHShortOption(cur, ch, rest, &out.cliOpts, &out.common.ConfigFile); ok || err != nil {
		return err
	}
	switch ch {
	case 'h':
		if rest != "" {
			return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownShortFlag, i18n.BoundStr("flag", cluster))
		}
		out.common.ShowHelp = true
		return nil
	case 'L', 'R', 'D', 'w':
		val, err := cur.ConsumeShortArg(ch, rest)
		if err != nil {
			return err
		}
		return applyTunnelShortForward(ch, val, out)
	default:
		r, _ := utf8.DecodeRuneInString(cluster)
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownShortFlag, i18n.BoundStr("flag", string(r)))
	}
}

func applyTunnelShortForward(ch byte, val string, out *tunnelArgs) error {
	switch ch {
	case 'L':
		return appendParsedFwd(engine.ForwardLocal, val, &out.forwards)
	case 'R':
		return appendParsedFwd(engine.ForwardRemote, val, &out.forwards)
	case 'D':
		return appendParsedFwd(engine.ForwardDynamic, val, &out.forwards)
	case 'w':
		out.rawTUNs = append(out.rawTUNs, val)
		return nil
	default:
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownShortFlag, i18n.Str("flag", string(ch)))
	}
}

func appendParsedFwd(dir engine.ForwardDirection, val string, dst *[]engine.ForwardSpec) error {
	spec, err := clikit.ParseForwardFlagSpec(dir, val)
	if err != nil {
		return err
	}
	*dst = append(*dst, spec)
	return nil
}

func finalizeTunnelArgs(sub string, pos []string, out tunnelArgs) (tunnelArgs, error) {
	if err := applyTunnelSubcommandPositionals(sub, pos, &out); err != nil {
		return tunnelArgs{}, err
	}
	for _, rawTUN := range out.rawTUNs {
		spec, err := clikit.ParseTUNForwardSpec(out.tunMode, rawTUN)
		if err != nil {
			return tunnelArgs{}, err
		}
		out.forwards = append(out.forwards, spec)
	}
	if strings.TrimSpace(out.target) == "" {
		return tunnelArgs{}, i18n.EF(clikit.ErrUsage, i18n.KeyCLISSHMissingTarget)
	}
	if len(out.forwards) == 0 {
		return tunnelArgs{}, i18n.EF(clikit.ErrUsage, i18n.KeyCLITunnelRequiresForward)
	}
	if err := out.cliOpts.Validate(); err != nil {
		return tunnelArgs{}, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidOptionLayer)
	}
	return out, nil
}

func applyTunnelSubcommandPositionals(sub string, pos []string, out *tunnelArgs) error {
	switch sub {
	case "", "start":
		if len(pos) != 1 {
			return i18n.EF(clikit.ErrUsage, i18n.KeyCLIArgCountExact, i18n.Str("cmd", strings.TrimSpace("tunnel "+sub)), i18n.Int("count", 1), i18n.Str("usage", "<target>"))
		}
		out.target = pos[0]
		return nil
	case "local", "remote":
		if len(pos) != 2 {
			return i18n.EF(clikit.ErrUsage, i18n.KeyCLIArgCountExact, i18n.Str("cmd", "tunnel "+sub), i18n.Int("count", 2), i18n.Str("usage", "<target> <bind:target>"))
		}
		out.target = pos[0]
		dir := engine.ForwardLocal
		if sub == "remote" {
			dir = engine.ForwardRemote
		}
		return appendParsedFwd(dir, pos[1], &out.forwards)
	case "dynamic":
		if len(pos) != 2 {
			return i18n.EF(clikit.ErrUsage, i18n.KeyCLIArgCountExact, i18n.Str("cmd", "tunnel dynamic"), i18n.Int("count", 2), i18n.Str("usage", "<target> <[bind:]port>"))
		}
		out.target = pos[0]
		return appendParsedFwd(engine.ForwardDynamic, pos[1], &out.forwards)
	case "tun":
		if len(pos) != 2 {
			return i18n.EF(clikit.ErrUsage, i18n.KeyCLIArgCountExact, i18n.Str("cmd", "tunnel tun"), i18n.Int("count", 2), i18n.Str("usage", "<target> <local[:remote]>"))
		}
		out.target = pos[0]
		out.rawTUNs = append(out.rawTUNs, pos[1])
		return nil
	default:
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownSubcommand, i18n.Str("cmd", "tunnel"), i18n.BoundStr("sub", sub))
	}
}
