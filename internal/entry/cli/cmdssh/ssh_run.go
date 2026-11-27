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
	"github.com/wentf9/xops-cli/internal/i18n"
)

// RunSSH 执行 `xops ssh` 全量路径：交互/命令会话、-O 多路复用控制、-M/-N 隧道常驻与 -f 守护移交。
func RunSSH(ctx context.Context, rt *clikit.Runtime, args []string) int {
	parsed, err := ParseSSHArgs(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if parsed.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, SSHHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(parsed.JSON)
	if parsed.StdioForward.IsSome() {
		return rt.Fail(clikit.ExitSSHError, jsonOut, i18n.EF(engine.ErrUnsupported, i18n.KeyCLISSHStdioFwdUnsupported))
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
		return rt.Fail(clikit.ExitSSHError, jsonOut, i18n.EF(clikit.ErrNotConfigured, i18n.KeyCLIHookNotConfigured, i18n.Str("hook", "RunMuxDaemon")))
	}
	sockOpt, err := parseOptionalControlSocket(parsed.ControlSocket)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	req := clikit.MuxDaemonStartRequest{
		InitOptions: rt.EffectiveInitOptions(parsed.ConfigFile, parsed.Policy),
		Locale:      rt.EffectiveLocale(),
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
			return rt.Fail(clikit.ExitUsage, jsonOut, i18n.EF(clikit.ErrUsage, i18n.KeyCLIMuxRequiresSingleForward, i18n.Str("action", parsed.MuxAction.String())))
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
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.EF(clikit.ErrUsage, i18n.KeyCLISSHNoCmdRequiresForward))
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
		return rt.Fail(clikit.ExitUsage, true, i18n.EF(clikit.ErrUsage, i18n.KeyCLIInteractiveNoJSON, i18n.Str("mode", "ssh")))
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
	loc := rt.Loc()
	if jsonOut {
		view, code, _ := clikit.BuildExecOutcomeViewLocalized(loc, outcome, runErr, outBuf.String(), errBuf.String())
		if mErr := clikit.WriteJSON(rt.Stdout, view); mErr != nil {
			rt.WriteErr(loc.T(i18n.KeyCLIMarshalJSONFailed, i18n.BoundStr("err", loc.RenderError(mErr))))
			return clikit.ExitGeneral
		}
		return code
	}
	code, diag, _ := clikit.MapOutcomeToExitLocalized(loc, outcome, runErr)
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
		return algebraic.None[pathalg.LocalSourcePath](), i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidField, i18n.Str("field", "control socket path"), i18n.BoundStr("value", raw))
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
	loc := rt.Loc()
	_ = rt.WriteResult(jsonOut, summary, func(w io.Writer) {
		if summary.MasterSock != "" {
			_, _ = fmt.Fprintln(w, loc.T(i18n.KeyCLISSHMasterActive, i18n.BoundStr("socket", summary.MasterSock)))
		}
		for _, f := range summary.Forwards {
			_, _ = fmt.Fprintln(w, loc.T(i18n.KeyCLISSHForwardListening, i18n.Str("direction", f.Direction.String()), i18n.BoundStr("bind", f.BindAddr), i18n.BoundStr("target", f.TargetAddr)))
		}
	})
}
