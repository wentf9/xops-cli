package cli_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli"
)

// fakeSessionRunner 供 internal/entry/cli 进程内确定性单元测试捕获强类型 RunSSHRequest 与停机序。
type fakeSessionRunner struct {
	runFn   func(ctx context.Context, req engine.RunSSHRequest) (execution.ExecutionOutcome, error)
	closeFn func(ctx context.Context) error

	gotReq    engine.RunSSHRequest
	runCalls  int
	closed    bool
	closeSeq  *[]string
	closeName string
}

func (f *fakeSessionRunner) RunSSH(ctx context.Context, req engine.RunSSHRequest) (execution.ExecutionOutcome, error) {
	f.runCalls++
	f.gotReq = req
	if f.runFn != nil {
		return f.runFn(ctx, req)
	}
	out, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	return out, nil
}

func (f *fakeSessionRunner) Close(ctx context.Context) error {
	f.closed = true
	if f.closeSeq != nil && f.closeName != "" {
		*f.closeSeq = append(*f.closeSeq, f.closeName)
	}
	if f.closeFn != nil {
		return f.closeFn(ctx)
	}
	return nil
}

func mustNewApp(t *testing.T, info cli.BuildInfo, factory cli.EngineFactory, stdin io.Reader) (*cli.App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	app, err := cli.NewApp(cli.AppConfig{
		BuildInfo:     info,
		EngineFactory: factory,
		Stdin:         stdin,
		Stdout:        &stdout,
		Stderr:        &stderr,
	})
	if err != nil {
		t.Fatalf("NewApp 失败: %v", err)
	}
	return app, &stdout, &stderr
}

func TestApp_ZeroValueAndConfigValidation(t *testing.T) {
	defer goleak.VerifyNone(t)

	var zeroApp cli.App
	if code := zeroApp.Run(context.Background(), []string{"version"}); code == 0 {
		t.Fatalf("未初始化零值 App 必须失败关闭返回非零退出码，实际=%d", code)
	}
	var out, errBuf bytes.Buffer
	dummyFactory := func(context.Context, cli.EngineInitOptions) (cli.EngineHandle, error) {
		return cli.EngineHandle{}, errors.New("unused")
	}
	if _, err := cli.NewApp(cli.AppConfig{Stdout: &out, Stderr: &errBuf}); !errors.Is(err, cli.ErrInvalidConfig) {
		t.Fatalf("缺少 EngineFactory 应返回 ErrInvalidConfig，实际=%v", err)
	}
	if _, err := cli.NewApp(cli.AppConfig{EngineFactory: dummyFactory, Stderr: &errBuf}); !errors.Is(err, cli.ErrInvalidConfig) {
		t.Fatalf("缺少 Stdout 应返回 ErrInvalidConfig，实际=%v", err)
	}
	if _, err := cli.NewApp(cli.AppConfig{EngineFactory: dummyFactory, Stdout: &out}); !errors.Is(err, cli.ErrInvalidConfig) {
		t.Fatalf("缺少 Stderr 应返回 ErrInvalidConfig，实际=%v", err)
	}
	negDur := algebraic.FromStdDuration(-1)
	if _, err := cli.NewApp(cli.AppConfig{
		EngineFactory:   dummyFactory,
		Stdout:          &out,
		Stderr:          &errBuf,
		ShutdownTimeout: algebraic.Some(negDur),
	}); !errors.Is(err, cli.ErrInvalidConfig) {
		t.Fatalf("负数 ShutdownTimeout 应返回 ErrInvalidConfig，实际=%v", err)
	}
}

func TestApp_VersionAndHelpNeverInitializeEngine(t *testing.T) {
	defer goleak.VerifyNone(t)

	factoryCalled := 0
	factory := func(context.Context, cli.EngineInitOptions) (cli.EngineHandle, error) {
		factoryCalled++
		return cli.EngineHandle{}, errors.New("engine factory must not be called")
	}
	info := cli.BuildInfo{
		Version:   "v2.5.0-test",
		Commit:    "abc1234",
		BuildTime: "2026-11-25T12:00:00Z",
		GoVersion: "go1.27.0",
		Platform:  "linux/amd64",
	}

	assertVersionOutput(t, info, factory)
	assertHelpInvocations(t, info, factory)
	assertUsageErrorInvocations(t, info, factory)

	if factoryCalled != 0 {
		t.Fatalf("version/help/非法参数场景绝不应触发 EngineFactory，实际调用=%d", factoryCalled)
	}
}

func assertVersionOutput(t *testing.T, info cli.BuildInfo, factory cli.EngineFactory) {
	t.Helper()
	app, stdout, stderr := mustNewApp(t, info, factory, nil)
	if code := app.Run(context.Background(), []string{"version"}); code != 0 {
		t.Fatalf("xops version 退出码应为 0，实际=%d stderr=%q", code, stderr.String())
	}
	got := stdout.String()
	for _, want := range []string{"v2.5.0-test", "abc1234", "2026-11-25T12:00:00Z", "go1.27.0 (linux/amd64)"} {
		if !strings.Contains(got, want) {
			t.Fatalf("xops version 输出缺少 %q，实际=%q", want, got)
		}
	}
	appZero, outZero, _ := mustNewApp(t, cli.BuildInfo{}, factory, nil)
	if code := appZero.Run(context.Background(), []string{"version"}); code != 0 {
		t.Fatalf("空 BuildInfo xops version 退出码应为 0，实际=%d", code)
	}
	if !strings.Contains(outZero.String(), "xops version dev\ncommit: unknown\nbuilt:  unknown\ngo:     unknown\n") {
		t.Fatalf("零值 BuildInfo 回退格式不符: %q", outZero.String())
	}
}

func assertHelpInvocations(t *testing.T, info cli.BuildInfo, factory cli.EngineFactory) {
	t.Helper()
	helpCases := [][]string{
		nil,
		{"--help"},
		{"help", "ssh"},
		{"help", "version"},
		{"version", "--help"},
		{"ssh", "-h"},
		{"ssh", "--help"},
	}
	for _, args := range helpCases {
		a, out, errB := mustNewApp(t, info, factory, nil)
		if code := a.Run(context.Background(), args); code != 0 {
			t.Fatalf("help 命令 %v 应返回 0，实际=%d stderr=%q", args, code, errB.String())
		}
		if out.Len() == 0 {
			t.Fatalf("help 命令 %v 输出不应为空", args)
		}
	}
}

func assertUsageErrorInvocations(t *testing.T, info cli.BuildInfo, factory cli.EngineFactory) {
	t.Helper()
	badCases := [][]string{
		{"unknown-cmd"},
		{"version", "extra"},
		{"ssh"},
		{"ssh", "-z", "host"},
		{"ssh", "--bogus", "host"},
		{"ssh", "-o", "UnknownKey=1", "host"},
	}
	for _, badArgs := range badCases {
		a, _, errB := mustNewApp(t, info, factory, nil)
		if code := a.Run(context.Background(), badArgs); code != 2 {
			t.Fatalf("非法用法 %v 应返回退出码 2，实际=%d", badArgs, code)
		}
		if errB.Len() == 0 {
			t.Fatalf("非法用法 %v 应向 stderr 输出诊断信息", badArgs)
		}
	}
}

func TestParseSSHArgs_AllOpenSSHFlagsAndSeparator(t *testing.T) {
	defer goleak.VerifyNone(t)

	parsed, err := cli.ParseSSHArgs([]string{
		"-p", "2222",
		"-l", "deploy",
		"-i", "/home/alice/my keys/id_ed25519",
		"-i/home/alice/.ssh/id_ecdsa",
		"-J", "bastion1:2201,jump@bastion2",
		"-o", "StrictHostKeyChecking=accept-new",
		"-oBatchMode=yes",
		"-o", "SendEnv LANG LC_ALL LC_TIME",
		"-o", "SendEnv -LC_TIME",
		"-tt",
		"-F", "/tmp/custom_ssh_config",
		"--",
		"app.internal",
		"echo", "-n", "--raw-flag",
	})
	if err != nil {
		t.Fatalf("ParseSSHArgs 失败: %v", err)
	}
	assertParsedSSHBase(t, parsed)
	assertParsedSSHTier1Options(t, parsed.CLIOptions)
}

func assertParsedSSHBase(t *testing.T, parsed cli.SSHCommandArgs) {
	t.Helper()
	if parsed.TargetSpec != "app.internal" {
		t.Fatalf("TargetSpec=%q，期望 app.internal", parsed.TargetSpec)
	}
	if !slices.Equal(parsed.CommandArgs, []string{"echo", "-n", "--raw-flag"}) {
		t.Fatalf("CommandArgs=%v，远端命令参数未被完整透传", parsed.CommandArgs)
	}
	if parsed.RequestTTY != engine.RequestTTYForce {
		t.Fatalf("RequestTTY=%v，期望 RequestTTYForce", parsed.RequestTTY)
	}
	if parsed.ConfigFile != "/tmp/custom_ssh_config" {
		t.Fatalf("ConfigFile=%q，期望 /tmp/custom_ssh_config", parsed.ConfigFile)
	}
}

func assertParsedSSHTier1Options(t *testing.T, layer option.OptionLayer) {
	t.Helper()
	if port, ok := layer.Port().Get(); !ok || port != 2222 {
		t.Fatalf("Port=(%d,%v)，期望 (2222,true)", port, ok)
	}
	if user, ok := layer.User().Get(); !ok || user.String() != "deploy" {
		t.Fatalf("User=(%q,%v)，期望 (deploy,true)", user, ok)
	}
	wantKeys := []string{"/home/alice/my keys/id_ed25519", "/home/alice/.ssh/id_ecdsa"}
	if gotKeys := layer.IdentityFiles().RawItems(); !slices.Equal(gotKeys, wantKeys) {
		t.Fatalf("IdentityFiles=%v，期望 %v", gotKeys, wantKeys)
	}
	if shkc, ok := layer.StrictHostKeyChecking().Get(); !ok || shkc != option.StrictHostKeyCheckingAcceptNew {
		t.Fatalf("StrictHostKeyChecking=(%v,%v)，期望 accept-new", shkc, ok)
	}
	if bm, ok := layer.BatchMode().Get(); !ok || !bm {
		t.Fatalf("BatchMode=(%v,%v)，期望 true", bm, ok)
	}
	jump, ok := layer.Proxy().(*option.ProxyJumpChain)
	if !ok || !jump.IsValid() || len(jump.Hops().Slice()) != 2 {
		t.Fatalf("ProxyJump 未正确解析: %#v", layer.Proxy())
	}
	filtered := layer.SendEnv().Filter(map[string]string{
		"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "LC_TIME": "en_US", "OTHER": "x",
	})
	if filtered["LANG"] != "C.UTF-8" || filtered["LC_ALL"] != "C.UTF-8" || filtered["LC_TIME"] != "" || filtered["OTHER"] != "" {
		t.Fatalf("SendEnv 折叠结果异常: %v", filtered)
	}
}

func TestParseSSHArgs_TTYModesAndErrors(t *testing.T) {
	defer goleak.VerifyNone(t)

	cases := []struct {
		name    string
		args    []string
		wantTTY engine.RequestTTYMode
		wantErr bool
	}{
		{name: "default_unset", args: []string{"host"}, wantTTY: engine.RequestTTYUnset},
		{name: "single_t", args: []string{"-t", "host"}, wantTTY: engine.RequestTTYYes},
		{name: "double_t_separate", args: []string{"-t", "-t", "host"}, wantTTY: engine.RequestTTYForce},
		{name: "double_t_clustered", args: []string{"-tt", "host"}, wantTTY: engine.RequestTTYForce},
		{name: "disable_T", args: []string{"-T", "host"}, wantTTY: engine.RequestTTYNo},
		{name: "t_then_T", args: []string{"-t", "-T", "host"}, wantTTY: engine.RequestTTYNo},
		{name: "T_then_t", args: []string{"-T", "-t", "host"}, wantTTY: engine.RequestTTYYes},
		{name: "T_then_tt", args: []string{"-T", "-tt", "host"}, wantTTY: engine.RequestTTYForce},
		{name: "combined_tp", args: []string{"-tp", "2200", "host"}, wantTTY: engine.RequestTTYYes},
		{name: "attached_p", args: []string{"-p2200", "host"}, wantTTY: engine.RequestTTYUnset},
		{name: "missing_p_arg", args: []string{"-p"}, wantErr: true},
		{name: "invalid_port", args: []string{"-p", "70000", "host"}, wantErr: true},
		{name: "empty_F", args: []string{"-F", "   ", "host"}, wantErr: true},
		{name: "empty_target", args: []string{"--", "   "}, wantErr: true},
		{name: "bad_option", args: []string{"-o", "Port=notaport", "host"}, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cli.ParseSSHArgs(tc.args)
			if tc.wantErr {
				if !errors.Is(err, cli.ErrUsage) {
					t.Fatalf("期望 ErrUsage，实际 err=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("未预期错误: %v", err)
			}
			if got.RequestTTY != tc.wantTTY {
				t.Fatalf("RequestTTY=%v，期望 %v", got.RequestTTY, tc.wantTTY)
			}
		})
	}
}

func TestParseSSHArgs_UTF8UnknownShortFlag(t *testing.T) {
	defer goleak.VerifyNone(t)

	for _, rawArgs := range [][]string{{"-中", "host"}, {"-t中", "host"}} {
		_, err := cli.ParseSSHArgs(rawArgs)
		if !errors.Is(err, cli.ErrUsage) || !strings.Contains(err.Error(), "-中") {
			t.Fatalf("UTF-8 未知短选项 %v 应返回包含 -中 的 ErrUsage，实际=%v", rawArgs, err)
		}
	}
}

type exitMappingCase struct {
	name           string
	outcome        execution.ExecutionOutcome
	runErr         error
	closeErr       error
	wantCode       int
	wantStderrPart string
}

func TestApp_SSHExitCodeMappingAndShutdown(t *testing.T) {
	defer goleak.VerifyNone(t)

	okZero, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	exit42, _ := execution.NewOutcomeCompleted(execution.NewExitCode(42), false)
	exit256, _ := execution.NewOutcomeCompleted(execution.NewExitCode(256), false)
	exit257, _ := execution.NewOutcomeCompleted(execution.NewExitCode(257), false)
	exitNeg1, _ := execution.NewOutcomeCompleted(execution.NewExitCode(-1), false)
	sigTerm, _ := execution.NewExitSignal("TERM", false, "terminated")
	outSigTerm, _ := execution.NewOutcomeCompleted(sigTerm, false)
	sigCustom, _ := execution.NewExitSignal("CUSTOMSIG", true, "")
	outSigCustom, _ := execution.NewOutcomeCompleted(sigCustom, false)
	outExitUnknown, _ := execution.NewOutcomeCompleted(execution.NewExitUnknown("missing exit-status"), false)
	outNotStarted, _ := execution.NewOutcomeNotStarted(execution.StartPhaseDial, "dial_failed", "connection refused")
	outUnknown, _ := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, "transport_lost", "broken pipe")

	cases := []exitMappingCase{
		{name: "completed_zero", outcome: okZero, wantCode: 0},
		{name: "completed_42", outcome: exit42, wantCode: 42},
		{name: "completed_256_never_wraps_zero", outcome: exit256, wantCode: 1},
		{name: "completed_257_masked_low_byte", outcome: exit257, wantCode: 1},
		{name: "completed_neg1_masked_255", outcome: exitNeg1, wantCode: 255},
		{name: "completed_zero_with_audit_error_failclosed", outcome: okZero, runErr: engine.ErrEngineHalted, wantCode: 255, wantStderrPart: "Halted"},
		{name: "completed_signal_term", outcome: outSigTerm, wantCode: 143, wantStderrPart: "signal TERM"},
		{name: "completed_signal_unknown_nonzero", outcome: outSigCustom, wantCode: 255, wantStderrPart: "CUSTOMSIG"},
		{name: "completed_exit_unknown", outcome: outExitUnknown, wantCode: 255, wantStderrPart: "missing exit-status"},
		{name: "not_started", outcome: outNotStarted, runErr: errors.New("dial tcp refused"), wantCode: 255, wantStderrPart: "dial tcp refused"},
		{name: "outcome_unknown", outcome: outUnknown, runErr: errors.New("eof"), wantCode: 255, wantStderrPart: "outcome unknown"},
		{name: "nil_outcome_error", outcome: nil, runErr: errors.New("boom"), wantCode: 255, wantStderrPart: "boom"},
		{name: "close_error_failclosed", outcome: okZero, closeErr: errors.New("audit flush failed"), wantCode: 1, wantStderrPart: "audit flush failed"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runExitMappingCase(t, tc)
		})
	}
}

func runExitMappingCase(t *testing.T, tc exitMappingCase) {
	t.Helper()
	var gotOpts cli.EngineInitOptions
	var closeCalled bool
	runner := &fakeSessionRunner{
		runFn: func(context.Context, engine.RunSSHRequest) (execution.ExecutionOutcome, error) {
			return tc.outcome, tc.runErr
		},
	}
	factory := func(_ context.Context, opts cli.EngineInitOptions) (cli.EngineHandle, error) {
		gotOpts = opts
		return cli.EngineHandle{
			Runner: runner,
			Close: func(closeCtx context.Context) error {
				closeCalled = true
				if closeCtx.Err() != nil {
					t.Errorf("关闭上下文不应已取消: %v", closeCtx.Err())
				}
				return tc.closeErr
			},
		}, nil
	}
	app, _, stderr := mustNewApp(t, cli.BuildInfo{}, factory, strings.NewReader("in"))
	code := app.Run(context.Background(), []string{"ssh", "-F", "/tmp/my.cfg", "-p", "2202", "alice@127.0.0.1", "uptime"})
	if code != tc.wantCode {
		t.Fatalf("退出码=%d，期望=%d stderr=%q", code, tc.wantCode, stderr.String())
	}
	if !closeCalled {
		t.Fatalf("必须调用 EngineHandle.Close 完成资源关闭")
	}
	if gotOpts.OpenSSHConfigFile != "/tmp/my.cfg" {
		t.Fatalf("OpenSSHConfigFile=%q，期望 /tmp/my.cfg", gotOpts.OpenSSHConfigFile)
	}
	if tc.wantStderrPart != "" && !strings.Contains(stderr.String(), tc.wantStderrPart) {
		t.Fatalf("stderr=%q 未包含 %q", stderr.String(), tc.wantStderrPart)
	}
}
