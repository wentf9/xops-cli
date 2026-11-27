package cmdssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

// RunSSH 执行 `xops ssh` 全量路径：交互/命令会话、-O 多路复用控制、-M/-N 隧道常驻与 -f 守护移交。
func RunSSH(ctx context.Context, rt *clikit.Runtime, args []string) int {
	parsed, err := ParseSSHArgs(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if parsed.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, SSHHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(parsed.JSON)
	if parsed.StdioForward.IsSome() {
		return rt.Fail(clikit.ExitSSHError, jsonOut, fmt.Errorf("%w: -W host:port stdio 转发暂未在引擎门面开放，请使用 -J ProxyJump 或 -O proxy", engine.ErrUnsupported))
	}
	if parsed.Background {
		return runSSHBackground(ctx, rt, parsed, jsonOut)
	}
	initOpts := rt.EffectiveInitOptions(parsed.ConfigFile, parsed.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitSSHError, jsonOut, func(runner clikit.SessionRunner) int {
		return dispatchSSHRunner(ctx, rt, runner, parsed, jsonOut)
	})
}

func runSSHBackground(ctx context.Context, rt *clikit.Runtime, parsed SSHCommandArgs, jsonOut bool) int {
	if rt.Hooks.RunMuxDaemon == nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, fmt.Errorf("%w: 未注入 RunMuxDaemon 回调，无法执行 -f 后台驻留", clikit.ErrNotConfigured))
	}
	sockOpt, err := parseOptionalControlSocket(parsed.ControlSocket)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	req := clikit.MuxDaemonStartRequest{
		InitOptions: rt.EffectiveInitOptions(parsed.ConfigFile, parsed.Policy),
		TargetSpec:  parsed.TargetSpec,
		CLIOptions:  parsed.CLIOptions,
		Forwards:    parsed.Forwards,
		SocketPath:  sockOpt,
		Stdout:      rt.Stdout,
		Stderr:      rt.Stderr,
	}
	if err := rt.Hooks.RunMuxDaemon(ctx, req); err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	return clikit.ExitOK
}

func dispatchSSHRunner(ctx context.Context, rt *clikit.Runtime, runner clikit.SessionRunner, parsed SSHCommandArgs, jsonOut bool) int {
	if parsed.MuxAction.IsValid() {
		return runSSHMuxControl(ctx, rt, runner, parsed, jsonOut)
	}
	if parsed.NoCommand {
		return runSSHNoCommand(ctx, rt, runner, parsed, jsonOut)
	}
	if len(parsed.Forwards) > 0 || parsed.MasterCount > 0 {
		return runSSHWithSessionExtensions(ctx, rt, runner, parsed, jsonOut)
	}
	return runPlainSSHSession(ctx, rt, runner, parsed, jsonOut)
}

func runSSHMuxControl(ctx context.Context, rt *clikit.Runtime, runner clikit.SessionRunner, parsed SSHCommandArgs, jsonOut bool) int {
	client, err := requireSSHClient(runner)
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	sockOpt, err := parseOptionalControlSocket(parsed.ControlSocket)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	req := engine.MuxControlRequest{
		RemoteCall: engine.RemoteCall{
			TargetInput: engine.TargetInput{TargetSpec: parsed.TargetSpec, CLIOptions: parsed.CLIOptions},
		},
		SocketPath: sockOpt,
		Action:     parsed.MuxAction,
	}
	if parsed.MuxAction == engine.MuxActionProxy {
		if err := client.RunMuxProxy(ctx, req, toReadCloser(rt.Stdin), rt.Stdout); err != nil {
			return rt.Fail(clikit.ExitSSHError, jsonOut, err)
		}
		return clikit.ExitOK
	}
	if parsed.MuxAction == engine.MuxActionCheck {
		resp, pErr := client.ProbeMux(ctx, req)
		if pErr != nil {
			return rt.Fail(clikit.ExitSSHError, jsonOut, pErr)
		}
		return renderMuxResponse(rt, jsonOut, parsed.MuxAction, resp)
	}
	if parsed.MuxAction == engine.MuxActionForward || parsed.MuxAction == engine.MuxActionCancel {
		if len(parsed.Forwards) != 1 {
			return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: -O %s 需要恰好一条转发规则（-L/-R/-D/-w）", clikit.ErrUsage, parsed.MuxAction))
		}
		req.Forward = algebraic.Some(parsed.Forwards[0])
	}
	resp, err := client.ControlMux(ctx, req)
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	return renderMuxResponse(rt, jsonOut, parsed.MuxAction, resp)
}

func runSSHNoCommand(ctx context.Context, rt *clikit.Runtime, runner clikit.SessionRunner, parsed SSHCommandArgs, jsonOut bool) (exitCode int) {
	if len(parsed.Forwards) == 0 && parsed.MasterCount == 0 {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: -N 模式至少需要 -M 或一条转发规则（-L/-R/-D/-w）", clikit.ErrUsage))
	}
	client, err := requireSSHClient(runner)
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	rc := engine.RemoteCall{
		TargetInput: engine.TargetInput{TargetSpec: parsed.TargetSpec, CLIOptions: parsed.CLIOptions},
	}
	var masterPtr *engine.ControlMasterInfo
	if parsed.MasterCount > 0 {
		cm, mErr := client.StartControlMaster(ctx, engine.ControlMasterRequest{RemoteCall: rc})
		if mErr != nil {
			return rt.Fail(clikit.ExitSSHError, jsonOut, mErr)
		}
		masterPtr = &cm
		defer func() { reportCleanupError(rt, stopControlMaster(ctx, client, cm), &exitCode) }()
	}
	infos, err := startForwards(ctx, client, rc, parsed.Forwards)
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	defer func() { reportCleanupError(rt, stopForwards(ctx, client, infos), &exitCode) }()
	announceActiveSession(rt, jsonOut, parsed.TargetSpec, infos, masterPtr)
	if err := waitForwards(ctx, infos, masterPtr); err != nil {
		return failAfterAnnounce(rt, jsonOut, err)
	}
	return clikit.ExitOK
}

func runSSHWithSessionExtensions(ctx context.Context, rt *clikit.Runtime, runner clikit.SessionRunner, parsed SSHCommandArgs, jsonOut bool) (exitCode int) {
	client, err := requireSSHClient(runner)
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	rc := engine.RemoteCall{
		TargetInput: engine.TargetInput{TargetSpec: parsed.TargetSpec, CLIOptions: parsed.CLIOptions},
	}
	if parsed.MasterCount > 0 {
		cm, mErr := client.StartControlMaster(ctx, engine.ControlMasterRequest{RemoteCall: rc})
		if mErr != nil {
			return rt.Fail(clikit.ExitSSHError, jsonOut, mErr)
		}
		defer func() { reportCleanupError(rt, stopControlMaster(ctx, client, cm), &exitCode) }()
	}
	infos, err := startForwards(ctx, client, rc, parsed.Forwards)
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	defer func() { reportCleanupError(rt, stopForwards(ctx, client, infos), &exitCode) }()
	return runPlainSSHSession(ctx, rt, runner, parsed, jsonOut)
}

func runPlainSSHSession(ctx context.Context, rt *clikit.Runtime, runner clikit.SessionRunner, parsed SSHCommandArgs, jsonOut bool) int {
	if jsonOut && len(parsed.CommandArgs) == 0 {
		return rt.Fail(clikit.ExitUsage, true, fmt.Errorf("%w: 交互式 SSH Shell 不支持 --json 输出，请提供远端命令", clikit.ErrUsage))
	}
	var outBuf, errBuf bytes.Buffer
	stdout, stderr := rt.Stdout, rt.Stderr
	if jsonOut {
		stdout, stderr = &outBuf, &errBuf
	}
	outcome, runErr := runner.RunSSH(ctx, engine.RunSSHRequest{
		TargetSpec:  parsed.TargetSpec,
		CLIOptions:  parsed.CLIOptions,
		CommandArgs: parsed.CommandArgs,
		Stdin:       rt.Stdin,
		Stdout:      stdout,
		Stderr:      stderr,
		RequestTTY:  parsed.RequestTTY,
	})
	if jsonOut {
		view, code, _ := clikit.BuildExecOutcomeView(outcome, runErr, outBuf.String(), errBuf.String())
		if mErr := clikit.WriteJSON(rt.Stdout, view); mErr != nil {
			rt.WriteErr("marshal json failed: " + mErr.Error())
			return clikit.ExitGeneral
		}
		return code
	}
	code, diag, _ := clikit.MapOutcomeToExit(outcome, runErr)
	if diag != "" {
		rt.WriteErr(diag)
	}
	return code
}

func parseOptionalControlSocket(raw string) (algebraic.Option[pathalg.LocalSourcePath], error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.EqualFold(trimmed, "none") {
		return algebraic.None[pathalg.LocalSourcePath](), nil
	}
	p, err := pathalg.ParseLocalSourcePath(trimmed)
	if err != nil {
		return algebraic.None[pathalg.LocalSourcePath](), fmt.Errorf("%w: 控制套接字路径 %q 非法: %w", clikit.ErrUsage, raw, err)
	}
	return algebraic.Some(p), nil
}

func toReadCloser(r io.Reader) io.ReadCloser {
	if rc, ok := r.(io.ReadCloser); ok {
		return rc
	}
	if r == nil {
		return io.NopCloser(strings.NewReader(""))
	}
	return io.NopCloser(r)
}

func stopControlMaster(ctx context.Context, client clikit.SSHClient, cm engine.ControlMasterInfo) error {
	if !cm.IsValid() || cm.ReusedExisting() {
		return nil
	}
	h, ok := cm.Handle().Get()
	if !ok || !h.IsValid() {
		return nil
	}
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultCleanupTimeout)
	defer cancel()
	if err := client.StopControlMaster(stopCtx, h); err != nil && !errors.Is(err, engine.ErrHandleNotFound) {
		return err
	}
	return nil
}

type activeTunnelSummary struct {
	OK         bool                `json:"ok"`
	Target     string              `json:"target"`
	MasterSock string              `json:"master_socket,omitzero"`
	Forwards   []forwardRecordView `json:"forwards,omitzero"`
}

type forwardRecordView struct {
	Direction  engine.ForwardDirection `json:"direction"`
	BindAddr   string                  `json:"bind_addr"`
	TargetAddr string                  `json:"target_addr,omitzero"`
}

func announceActiveSession(rt *clikit.Runtime, jsonOut bool, target string, infos []engine.ForwardInfo, master *engine.ControlMasterInfo) {
	summary := activeTunnelSummary{OK: true, Target: target}
	if master != nil && master.IsValid() {
		summary.MasterSock = master.SocketPath().String()
	}
	for _, info := range infos {
		if !info.IsValid() {
			continue
		}
		summary.Forwards = append(summary.Forwards, forwardRecordView{
			Direction:  info.Spec().Direction(),
			BindAddr:   info.BoundAddr(),
			TargetAddr: info.Spec().TargetAddr(),
		})
	}
	_ = rt.WriteResult(jsonOut, summary, func(w io.Writer) {
		if summary.MasterSock != "" {
			_, _ = fmt.Fprintf(w, "control master active: %s\n", summary.MasterSock)
		}
		for _, f := range summary.Forwards {
			_, _ = fmt.Fprintf(w, "forward [%s] listening on %s -> %s\n", f.Direction, f.BindAddr, f.TargetAddr)
		}
	})
}
