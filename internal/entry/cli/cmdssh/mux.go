package cmdssh

import (
	"context"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

type muxArgs struct {
	sub        string
	common     clikit.CommonFlags
	cliOpts    option.OptionLayer
	target     string
	socketPath string
	daemon     bool
	forwards   []engine.ForwardSpec
	rawTUNs    []string
	tunMode    engine.TUNMode
}

type muxResponseView struct {
	OK        bool   `json:"ok"`
	Action    string `json:"action"`
	Alive     bool   `json:"alive"`
	MasterPID uint32 `json:"master_pid,omitzero"`
	Detail    string `json:"detail,omitzero"`
}

// RunMux 执行 `xops mux` 子命令族：start / check(status) / forward / cancel / exit / stop / proxy / daemon。
func RunMux(ctx context.Context, rt *clikit.Runtime, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, _ = io.WriteString(rt.Stdout, MuxHelpText())
		return clikit.ExitOK
	}
	parsed, err := parseMuxArgs(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if parsed.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, MuxHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(parsed.common.JSON)
	if parsed.sub == "daemon" || (parsed.sub == "start" && parsed.daemon) {
		return runMuxDaemon(ctx, rt, parsed, jsonOut)
	}
	initOpts := rt.EffectiveInitOptions(parsed.common.ConfigFile, parsed.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitSSHError, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireSSHClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitSSHError, jsonOut, err)
		}
		return dispatchMuxAction(ctx, rt, client, parsed, jsonOut)
	})
}

func runMuxDaemon(ctx context.Context, rt *clikit.Runtime, parsed muxArgs, jsonOut bool) int {
	if rt.Hooks.RunMuxDaemon == nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, fmt.Errorf("%w: 未注入 RunMuxDaemon 回调，无法启动 ControlPersist 守护进程", clikit.ErrNotConfigured))
	}
	sockOpt, err := parseOptionalControlSocket(parsed.socketPath)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	req := clikit.MuxDaemonStartRequest{
		InitOptions: rt.EffectiveInitOptions(parsed.common.ConfigFile, parsed.common.Policy),
		TargetSpec:  parsed.target,
		CLIOptions:  parsed.cliOpts,
		Forwards:    parsed.forwards,
		SocketPath:  sockOpt,
		Stdout:      rt.Stdout,
		Stderr:      rt.Stderr,
	}
	if err := rt.Hooks.RunMuxDaemon(ctx, req); err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	return clikit.ExitOK
}

func dispatchMuxAction(ctx context.Context, rt *clikit.Runtime, client clikit.SSHClient, parsed muxArgs, jsonOut bool) int {
	rc := engine.RemoteCall{
		TargetInput: engine.TargetInput{TargetSpec: parsed.target, CLIOptions: parsed.cliOpts},
	}
	if parsed.sub == "start" {
		return runMuxStartForeground(ctx, rt, client, rc, parsed, jsonOut)
	}
	sockOpt, err := parseOptionalControlSocket(parsed.socketPath)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	act, err := muxSubcommandToAction(parsed.sub)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	req := engine.MuxControlRequest{RemoteCall: rc, SocketPath: sockOpt, Action: act}
	if act == engine.MuxActionProxy {
		if err := client.RunMuxProxy(ctx, req, toReadCloser(rt.Stdin), rt.Stdout); err != nil {
			return rt.Fail(clikit.ExitSSHError, jsonOut, err)
		}
		return clikit.ExitOK
	}
	if act == engine.MuxActionForward || act == engine.MuxActionCancel {
		if len(parsed.forwards) != 1 {
			return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: mux %s 需要恰好一条转发规则（-L/-R/-D/-w）", clikit.ErrUsage, parsed.sub))
		}
		req.Forward = algebraic.Some(parsed.forwards[0])
	}
	var resp engine.MuxControlResponse
	if act == engine.MuxActionCheck {
		resp, err = client.ProbeMux(ctx, req)
	} else {
		resp, err = client.ControlMux(ctx, req)
	}
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	return renderMuxResponse(rt, jsonOut, act, resp)
}

func runMuxStartForeground(ctx context.Context, rt *clikit.Runtime, client clikit.SSHClient, rc engine.RemoteCall, parsed muxArgs, jsonOut bool) (exitCode int) {
	cm, err := client.StartControlMaster(ctx, engine.ControlMasterRequest{RemoteCall: rc})
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	defer func() { reportCleanupError(rt, stopControlMaster(ctx, client, cm), &exitCode) }()
	infos, err := startForwards(ctx, client, rc, parsed.forwards)
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	defer func() { reportCleanupError(rt, stopForwards(ctx, client, infos), &exitCode) }()
	announceActiveSession(rt, jsonOut, parsed.target, infos, &cm)
	if err := waitForwards(ctx, infos, &cm); err != nil {
		return failAfterAnnounce(rt, jsonOut, err)
	}
	return clikit.ExitOK
}

func muxSubcommandToAction(sub string) (engine.MuxControlAction, error) {
	switch sub {
	case "check", "status":
		return engine.MuxActionCheck, nil
	case "forward":
		return engine.MuxActionForward, nil
	case "cancel":
		return engine.MuxActionCancel, nil
	case "exit":
		return engine.MuxActionExit, nil
	case "stop":
		return engine.MuxActionStop, nil
	case "proxy":
		return engine.MuxActionProxy, nil
	default:
		return engine.MuxActionInvalid, fmt.Errorf("%w: 未知 mux 子命令 %q", clikit.ErrUsage, sub)
	}
}

func renderMuxResponse(rt *clikit.Runtime, jsonOut bool, action engine.MuxControlAction, resp engine.MuxControlResponse) int {
	ok := action != engine.MuxActionCheck || resp.Alive()
	code := clikit.ExitOK
	if !ok {
		code = clikit.ExitSSHError
	}
	view := muxResponseView{
		OK:        ok,
		Action:    action.String(),
		Alive:     resp.Alive(),
		MasterPID: resp.MasterPID(),
		Detail:    resp.Detail(),
	}
	if rt.WriteResult(jsonOut, view, func(w io.Writer) {
		if resp.Alive() {
			_, _ = fmt.Fprintf(w, "mux %s: master running (pid=%d) %s\n", action, resp.MasterPID(), strings.TrimSpace(resp.Detail()))
			return
		}
		if action == engine.MuxActionCheck {
			_, _ = fmt.Fprintf(w, "mux %s: master not running %s\n", action, strings.TrimSpace(resp.Detail()))
			return
		}
		_, _ = fmt.Fprintf(w, "mux %s: ok %s\n", action, strings.TrimSpace(resp.Detail()))
	}) != clikit.ExitOK {
		return clikit.ExitGeneral
	}
	return code
}

func parseMuxArgs(args []string) (muxArgs, error) {
	out := muxArgs{
		sub:     args[0],
		cliOpts: option.UnsetOptionLayer(),
		tunMode: engine.TUNModePointToPoint,
	}
	cur := clikit.NewFlagCursor(args[1:])
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
		if err := parseMuxFlag(cur, &out); err != nil {
			return muxArgs{}, err
		}
		if out.common.ShowHelp {
			return out, nil
		}
	}
	return finalizeMuxArgs(pos, out)
}

func parseMuxFlag(cur *clikit.FlagCursor, out *muxArgs) error {
	if strings.HasPrefix(cur.Peek(), "--") {
		if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &out.common); err != nil || consumed {
			return err
		}
		tok := cur.Next()
		name, inlineVal, hasEq := clikit.SplitLongFlag(tok)
		switch name {
		case "socket":
			raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
			if err != nil {
				return err
			}
			out.socketPath = raw
			return clikit.ApplyOptionKV(&out.cliOpts, "ControlPath", raw, "--socket")
		case "daemon":
			v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
			out.daemon = v
			return err
		case "tun-mode":
			raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
			if err != nil {
				return err
			}
			m, err := engine.ParseTUNMode(raw)
			if err != nil {
				return fmt.Errorf("%w: --tun-mode 非法: %w", clikit.ErrUsage, err)
			}
			out.tunMode = m
			return nil
		default:
			return fmt.Errorf("%w: mux 未知长选项 %q", clikit.ErrUsage, tok)
		}
	}
	tok := cur.Next()
	return parseMuxShortCluster(cur, tok[1:], out)
}

func parseMuxShortCluster(cur *clikit.FlagCursor, cluster string, out *muxArgs) error {
	for i := 0; i < len(cluster); i++ {
		ch := cluster[i]
		if ok, err := clikit.ApplyCommonSSHShortOption(cur, ch, cluster[i+1:], &out.cliOpts, &out.common.ConfigFile); ok || err != nil {
			return err
		}
		switch ch {
		case 'h':
			out.common.ShowHelp = true
			return nil
		case 'f':
			out.daemon = true
		case 'S':
			val, err := cur.ConsumeShortArg('S', cluster[i+1:])
			if err != nil {
				return err
			}
			out.socketPath = val
			return clikit.ApplyOptionKV(&out.cliOpts, "ControlPath", val, "-S")
		case 'L', 'R', 'D', 'w':
			val, err := cur.ConsumeShortArg(ch, cluster[i+1:])
			if err != nil {
				return err
			}
			return applyMuxShortForward(ch, val, out)
		default:
			r, _ := utf8.DecodeRuneInString(cluster[i:])
			return fmt.Errorf("%w: mux 未知短选项 -%c", clikit.ErrUsage, r)
		}
	}
	return nil
}

func applyMuxShortForward(ch byte, val string, out *muxArgs) error {
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
		return fmt.Errorf("%w: 不支持的转发标志 -%c", clikit.ErrUsage, ch)
	}
}

func finalizeMuxArgs(pos []string, out muxArgs) (muxArgs, error) {
	switch out.sub {
	case "start", "check", "status", "forward", "cancel", "exit", "stop", "proxy", "daemon":
	default:
		return muxArgs{}, fmt.Errorf("%w: 未知 mux 子命令 %q", clikit.ErrUsage, out.sub)
	}
	for _, rawTUN := range out.rawTUNs {
		spec, err := clikit.ParseTUNForwardSpec(out.tunMode, rawTUN)
		if err != nil {
			return muxArgs{}, err
		}
		out.forwards = append(out.forwards, spec)
	}
	if len(pos) != 1 || strings.TrimSpace(pos[0]) == "" {
		return muxArgs{}, fmt.Errorf("%w: mux %s 需要恰好 1 个目标主机参数", clikit.ErrUsage, out.sub)
	}
	out.target = strings.TrimSpace(pos[0])
	if (out.sub == "start" || out.sub == "daemon") && !out.cliOpts.Control().Master().IsSet() {
		if err := clikit.ApplyOptionKV(&out.cliOpts, "ControlMaster", "yes", "mux "+out.sub); err != nil {
			return muxArgs{}, err
		}
	}
	if err := out.cliOpts.Validate(); err != nil {
		return muxArgs{}, fmt.Errorf("%w: CLI 选项层校验失败: %w", clikit.ErrUsage, err)
	}
	return out, nil
}
