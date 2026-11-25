package execution

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
)

func TestLaunchProfileMatrixAndCodec(t *testing.T) {
	assertDefaultLaunchProfile(t)
	assertValidLaunchProfiles(t)
	assertInvalidLaunchProfiles(t)
}

func assertDefaultLaunchProfile(t *testing.T) {
	t.Helper()
	if (LaunchProfile{}).IsValid() || (LaunchProfile{}).IsPOSIXBourne() {
		t.Fatal("零值 LaunchProfile 必须失败关闭")
	}
	def := DefaultServerLaunchProfile()
	if !def.IsValid() || def.Interpreter() != InterpreterServer || def.Dialect() != DialectUnknown || def.LoginMode() != LoginModeInherit {
		t.Fatalf("默认 server 配置异常: %#v", def)
	}
	if def.IsPOSIXBourne() {
		t.Fatal("server + DialectUnknown 不得满足 POSIX Bourne 校验")
	}
	if err := def.ValidatePOSIXBourne(); !errors.Is(err, ErrNotPOSIXBourne) {
		t.Fatalf("期望 ErrNotPOSIXBourne，实际=%v", err)
	}
}

func assertValidLaunchProfiles(t *testing.T) {
	t.Helper()
	validCases := []struct {
		name  string
		spec  LaunchProfileSpec
		posix bool
	}{
		{"server_posix", LaunchProfileSpec{algebraic.Some(DialectPOSIX), InterpreterServer, LoginModeInherit}, true},
		{"server_raw", LaunchProfileSpec{algebraic.Some(DialectRaw), InterpreterServer, LoginModeInherit}, false},
		{"sh_disabled", LaunchProfileSpec{algebraic.Some(DialectPOSIX), InterpreterSH, LoginModeDisabled}, true},
		{"bash_login", LaunchProfileSpec{algebraic.Some(DialectPOSIX), InterpreterBash, LoginModeLogin}, true},
		{"zsh_inherit", LaunchProfileSpec{algebraic.Some(DialectPOSIX), InterpreterZsh, LoginModeInherit}, true},
		{"pwsh_cmd", LaunchProfileSpec{algebraic.Some(DialectCmd), InterpreterPwsh, LoginModeDisabled}, false},
		{"ps_posix", LaunchProfileSpec{algebraic.Some(DialectPOSIX), InterpreterPowerShell, LoginModeInherit}, false},
		{"cmd_cmd", LaunchProfileSpec{algebraic.Some(DialectCmd), InterpreterCmd, LoginModeDisabled}, false},
	}
	for _, tc := range validCases {
		p, err := NewLaunchProfile(tc.spec)
		if err != nil {
			t.Fatalf("%s: 期望有效，实际失败: %v", tc.name, err)
		}
		if p.IsPOSIXBourne() != tc.posix {
			t.Fatalf("%s: IsPOSIXBourne=%v, want=%v", tc.name, p.IsPOSIXBourne(), tc.posix)
		}
		assertLaunchProfileRoundTrip(t, tc.name, p)
	}
}

func assertLaunchProfileRoundTrip(t *testing.T, name string, p LaunchProfile) {
	t.Helper()
	raw, err := jsonv2.Marshal(p, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("%s: Marshal 失败: %v", name, err)
	}
	var dec LaunchProfile
	if err := jsonv2.Unmarshal(raw, &dec); err != nil || !dec.Equal(p) {
		t.Fatalf("%s: JSON 往返失败: err=%v dec=%#v", name, err, dec)
	}
}

func assertInvalidLaunchProfiles(t *testing.T) {
	t.Helper()
	invalidCases := []LaunchProfileSpec{
		{algebraic.None[LaunchDialect](), InterpreterBash, LoginModeDisabled},
		{algebraic.Some(DialectPOSIX), InterpreterServer, LoginModeDisabled},
		{algebraic.Some(DialectPOSIX), InterpreterSH, LoginModeLogin},
		{algebraic.Some(DialectCmd), InterpreterBash, LoginModeDisabled},
		{algebraic.Some(DialectRaw), InterpreterPwsh, LoginModeDisabled},
		{algebraic.Some(DialectPowerShell), InterpreterPowerShell, LoginModeLogin},
		{algebraic.Some(DialectPowerShell), InterpreterCmd, LoginModeDisabled},
		{algebraic.Some(DialectPOSIX), InterpreterCmd, LoginModeDisabled},
		{algebraic.Some(DialectUnknown), InterpreterServer, LoginModeInherit},
	}
	for i, spec := range invalidCases {
		if _, err := NewLaunchProfile(spec); err == nil {
			t.Fatalf("invalidCases[%d] 期望拒绝，却构造成功: %#v", i, spec)
		}
	}
	var p LaunchProfile
	for _, badJSON := range []string{`null`, `{}`, `{"interpreter":"sh"}`, `{"login":"disabled"}`, `{"launch_dialect":"posix","interpreter":"sh","login":"login"}`} {
		if err := jsonv2.Unmarshal([]byte(badJSON), &p); err == nil || p.IsValid() {
			t.Fatalf("非法 JSON %s 期望失败关闭，实际 err=%v valid=%v", badJSON, err, p.IsValid())
		}
	}
}

func TestCommandPlanRenderDigestAndRedaction(t *testing.T) {
	if (CommandPlan{}).IsValid() {
		t.Fatal("零值 CommandPlan 必须无效")
	}
	if _, err := (CommandPlan{}).Digest(); !errors.Is(err, ErrInvalidCommandPlan) {
		t.Fatalf("零值 Digest 期望 ErrInvalidCommandPlan，实际=%v", err)
	}
	wd, err := pathalg.ParseAbsRemotePath("/srv/app dir/it's")
	if err != nil {
		t.Fatalf("ParseAbsRemotePath 失败: %v", err)
	}
	bashProf, err := POSIXLaunchProfile(InterpreterBash, LoginModeLogin)
	if err != nil {
		t.Fatalf("POSIXLaunchProfile 失败: %v", err)
	}
	plan := mustCommandPlan(t, CommandPlanSpec{
		Kind: PlanKindCommand, Profile: bashProf,
		Argv:    []string{"curl", "-H", "Authorization: Bearer super-secret-token", "--password=topsecret", "--token", "spaced-secret-val", "https://example.invalid"},
		WorkDir: algebraic.Some(wd), Env: map[string]string{"DB_PASS": "hunter2", "APP_ENV": "prod"},
		Timeout: algebraic.Some(algebraic.FromStdDuration(30 * time.Second)), MaxOutputBytes: algebraic.Some[uint64](1024 * 64), PTY: true,
	})
	assertPlanRenderAndSummary(t, plan)
	assertPlanDigestAndRoundTrip(t, plan, bashProf, wd)
}

func mustCommandPlan(t *testing.T, spec CommandPlanSpec) CommandPlan {
	t.Helper()
	p, err := NewCommandPlan(spec)
	if err != nil {
		t.Fatalf("NewCommandPlan 失败: %v", err)
	}
	return p
}

func assertPlanRenderAndSummary(t *testing.T, plan CommandPlan) {
	t.Helper()
	rendered, err := plan.RenderCommand()
	if err != nil {
		t.Fatalf("RenderCommand 失败: %v", err)
	}
	if !strings.HasPrefix(rendered, "bash -l -c '") || !strings.Contains(rendered, "cd -- ") ||
		!strings.Contains(rendered, "|| exit $?; export APP_ENV=") {
		t.Fatalf("POSIX 渲染格式不符合预期: %s", rendered)
	}
	if _, hasStdin := plan.StdinPayload(); hasStdin {
		t.Fatal("PlanKindCommand 不应返回 StdinPayload")
	}
	summary := plan.RedactedSummary()
	if strings.Contains(summary, "hunter2") || strings.Contains(summary, "super-secret-token") ||
		strings.Contains(summary, "topsecret") || strings.Contains(summary, "spaced-secret-val") {
		t.Fatalf("脱敏摘要泄露敏感内容: %s", summary)
	}
	if !strings.Contains(summary, "env=[APP_ENV,DB_PASS]") || !strings.Contains(summary, "[REDACTED]") {
		t.Fatalf("脱敏摘要缺少键名或 [REDACTED] 占位: %s", summary)
	}
}

func assertPlanDigestAndRoundTrip(t *testing.T, plan CommandPlan, bashProf LaunchProfile, wd pathalg.RemotePath) {
	t.Helper()
	d1, err := plan.Digest()
	if err != nil {
		t.Fatalf("Digest 失败: %v", err)
	}
	planSame := mustCommandPlan(t, CommandPlanSpec{
		Kind: PlanKindCommand, Profile: bashProf,
		Argv:    []string{"curl", "-H", "Authorization: Bearer super-secret-token", "--password=topsecret", "--token", "spaced-secret-val", "https://example.invalid"},
		WorkDir: algebraic.Some(wd), Env: map[string]string{"APP_ENV": "prod", "DB_PASS": "hunter2"},
		Timeout: algebraic.Some(algebraic.FromStdDuration(30 * time.Second)), MaxOutputBytes: algebraic.Some[uint64](1024 * 64), PTY: true,
	})
	if d2, err := planSame.Digest(); err != nil || !d1.Equal(d2) {
		t.Fatalf("等价计划摘要不一致: d1=%s d2=%s err=%v", d1, d2, err)
	}
	planDiff := mustCommandPlan(t, CommandPlanSpec{
		Kind: PlanKindCommand, Profile: bashProf,
		Argv:    []string{"curl", "-H", "Authorization: Bearer super-secret-token", "--password=topsecret", "--token", "spaced-secret-val", "https://example.invalid"},
		WorkDir: algebraic.Some(wd), Env: map[string]string{"APP_ENV": "prod", "DB_PASS": "hunter3"},
		Timeout: algebraic.Some(algebraic.FromStdDuration(30 * time.Second)), MaxOutputBytes: algebraic.Some[uint64](1024 * 64), PTY: true,
	})
	if d3, err := planDiff.Digest(); err != nil || d1.Equal(d3) {
		t.Fatalf("修改环境变量值后摘要未变化: d1=%s d3=%s", d1, d3)
	}
	raw, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON 失败: %v", err)
	}
	var decoded CommandPlan
	if err := jsonv2.Unmarshal(raw, &decoded); err != nil || !decoded.Equal(plan) {
		t.Fatalf("CommandPlan JSON 往返失败: err=%v equal=%v", err, decoded.Equal(plan))
	}
}

func TestCommandPlanValidationAndDialects(t *testing.T) {
	// server raw 模式原样输出，拒绝 cwd/env/argv
	rawProf, err := NewLaunchProfile(LaunchProfileSpec{algebraic.Some(DialectRaw), InterpreterServer, LoginModeInherit})
	if err != nil {
		t.Fatalf("rawProf 构造失败: %v", err)
	}
	pRaw, err := NewCommandPlan(CommandPlanSpec{Kind: PlanKindCommand, Profile: rawProf, Command: "show version | include IOS"})
	if err != nil {
		t.Fatalf("raw plan 构造失败: %v", err)
	}
	if out, err := pRaw.RenderCommand(); err != nil || out != "show version | include IOS" {
		t.Fatalf("raw 渲染未原样保留: out=%q err=%v", out, err)
	}
	wd, _ := pathalg.ParseAbsRemotePath("/tmp")
	if _, err := NewCommandPlan(CommandPlanSpec{Kind: PlanKindCommand, Profile: rawProf, Command: "ls", WorkDir: algebraic.Some(wd)}); !errors.Is(err, ErrUnsupportedExecutionCombination) {
		t.Fatalf("raw + cwd 期望 ErrUnsupportedExecutionCombination，实际=%v", err)
	}

	assertScriptStdinAndLimits(t, wd)
	assertCmdRenderingAndQuoting(t, wd)

	// 非法环境变量名、Cf/Bidi、NUL、空命令、同时提供 Command+Argv、脚本用 server/cmd/PTY、MaxOutput=0
	shProf, _ := POSIXLaunchProfile(InterpreterSH, LoginModeDisabled)
	cmdProf, _ := NewLaunchProfile(LaunchProfileSpec{algebraic.Some(DialectCmd), InterpreterCmd, LoginModeDisabled})
	badSpecs := []CommandPlanSpec{
		{Kind: PlanKindCommand, Profile: shProf},
		{Kind: PlanKindCommand, Profile: shProf, Command: "echo", Argv: []string{"echo"}},
		{Kind: PlanKindScript, Profile: DefaultServerLaunchProfile(), Command: "echo hi"},
		{Kind: PlanKindScript, Profile: cmdProf, Command: "echo hi"},
		{Kind: PlanKindScript, Profile: shProf, Command: "echo hi", PTY: true},
		{Kind: PlanKindScript, Profile: shProf, Argv: []string{"echo"}},
		{Kind: PlanKindCommand, Profile: shProf, Command: "echo\x00hi"},
		{Kind: PlanKindCommand, Profile: shProf, Command: "echo \u202ehi"},
		{Kind: PlanKindCommand, Profile: shProf, Command: "echo", Env: map[string]string{"BAD=KEY": "1"}},
		{Kind: PlanKindCommand, Profile: shProf, Command: "echo", Env: map[string]string{"OK": "bad\x00val"}},
		{Kind: PlanKindCommand, Profile: shProf, Command: "echo", Env: map[string]string{"OK": "bidi\u202eval"}},
		{Kind: PlanKindCommand, Profile: shProf, Command: "echo", Timeout: algebraic.Some(algebraic.ZeroDuration())},
		{Kind: PlanKindCommand, Profile: shProf, Command: "echo", MaxOutputBytes: algebraic.Some[uint64](0)},
	}
	for i, spec := range badSpecs {
		if _, err := NewCommandPlan(spec); err == nil {
			t.Fatalf("badSpecs[%d] 期望失败关闭，却成功构造", i)
		}
	}
}

func assertScriptStdinAndLimits(t *testing.T, wd pathalg.RemotePath) {
	t.Helper()
	// 1. POSIX 脚本模式：RenderCommand 仅输出 bash -l -s，WorkDir/Env 前言与正文在 StdinPayload 内按序执行
	bashProf, _ := POSIXLaunchProfile(InterpreterBash, LoginModeLogin)
	pPOSIXScript := mustCommandPlan(t, CommandPlanSpec{
		Kind: PlanKindScript, Profile: bashProf, Command: "echo a; echo b",
		WorkDir: algebraic.Some(wd), Env: map[string]string{"K": "v"},
	})
	if out, err := pPOSIXScript.RenderCommand(); err != nil || out != "bash -l -s" {
		t.Fatalf("POSIX script RenderCommand 异常: out=%q err=%v", out, err)
	}
	stdin, ok := pPOSIXScript.StdinPayload()
	if !ok || !strings.HasPrefix(stdin, "cd -- '/tmp' || exit $?; export K='v' || exit $?;\necho a; echo b") {
		t.Fatalf("POSIX script StdinPayload 异常: ok=%v stdin=%q", ok, stdin)
	}

	// 2. PowerShell 命令模式使用 -EncodedCommand + -ErrorAction Stop，超 32767 字符上限失败关闭
	pwshProf, _ := NewLaunchProfile(LaunchProfileSpec{algebraic.Some(DialectCmd), InterpreterPwsh, LoginModeDisabled})
	pPSCmd := mustCommandPlan(t, CommandPlanSpec{
		Kind: PlanKindCommand, Profile: pwshProf, Command: "Get-Date",
		WorkDir: algebraic.Some(wd), Env: map[string]string{"XOPS_TAG": "it's ok"},
	})
	if out, err := pPSCmd.RenderCommand(); err != nil || !strings.HasPrefix(out, "pwsh -NoProfile -NonInteractive -EncodedCommand ") {
		t.Fatalf("pwsh command 渲染不符合预期: out=%q err=%v", out, err)
	}
	if _, ok := pPSCmd.StdinPayload(); ok {
		t.Fatal("pwsh PlanKindCommand 不应返回 StdinPayload")
	}
	psSrvProf, _ := NewLaunchProfile(LaunchProfileSpec{algebraic.Some(DialectPowerShell), InterpreterServer, LoginModeInherit})
	pPSSrv := mustCommandPlan(t, CommandPlanSpec{Kind: PlanKindCommand, Profile: psSrvProf, Command: "Get-Date", WorkDir: algebraic.Some(wd)})
	if out, err := pPSSrv.RenderCommand(); err != nil || !strings.Contains(out, "Set-Location -LiteralPath '/tmp' -ErrorAction Stop") {
		t.Fatalf("PowerShell WorkDir 必须携带 -ErrorAction Stop: out=%q err=%v", out, err)
	}
	bigCmd := strings.Repeat("a", 20000)
	if _, err := NewCommandPlan(CommandPlanSpec{Kind: PlanKindCommand, Profile: pwshProf, Command: bigCmd}); !errors.Is(err, ErrInvalidCommandPlan) {
		t.Fatalf("超长 PowerShell -EncodedCommand 期望 ErrInvalidCommandPlan，实际=%v", err)
	}

	// 3. PowerShell 脚本模式统一走 -Command - 与 StdinPayload（支持 >32K 载荷）
	pPSScript := mustCommandPlan(t, CommandPlanSpec{
		Kind: PlanKindScript, Profile: pwshProf, Command: bigCmd,
		WorkDir: algebraic.Some(wd), Env: map[string]string{"X": "1"},
	})
	if out, err := pPSScript.RenderCommand(); err != nil || out != "pwsh -NoProfile -NonInteractive -Command -" {
		t.Fatalf("pwsh script RenderCommand 异常: out=%q err=%v", out, err)
	}
	psStdin, ok := pPSScript.StdinPayload()
	if !ok || !strings.HasPrefix(psStdin, "Set-Location -LiteralPath '/tmp' -ErrorAction Stop; $env:X = '1'\n") {
		t.Fatalf("pwsh script StdinPayload 异常: ok=%v", ok)
	}

	// 4. 带位置参数的 POSIX 与 PowerShell 脚本：Argv 进入 RenderCommand/StdinPayload、Digest 与 JSON 往返。
	assertParameterizedScriptPlans(t, bashProf, pwshProf, wd)
}

func assertParameterizedScriptPlans(t *testing.T, bashProf, pwshProf LaunchProfile, wd pathalg.RemotePath) {
	t.Helper()
	pPOSIXArgs := mustCommandPlan(t, CommandPlanSpec{
		Kind: PlanKindScript, Profile: bashProf, Command: `echo "$1" "$2"`,
		Argv: []string{"--flag", "it's ok", ""}, WorkDir: algebraic.Some(wd),
	})
	if out, err := pPOSIXArgs.RenderCommand(); err != nil || out != `bash -l -s -- '--flag' 'it'\''s ok' ''` {
		t.Fatalf("POSIX 带参脚本 RenderCommand 异常: out=%q err=%v", out, err)
	}
	pPOSIXNoArgs := mustCommandPlan(t, CommandPlanSpec{
		Kind: PlanKindScript, Profile: bashProf, Command: `echo "$1" "$2"`, WorkDir: algebraic.Some(wd),
	})
	dWithArgs, _ := pPOSIXArgs.Digest()
	dNoArgs, _ := pPOSIXNoArgs.Digest()
	if dWithArgs.Equal(dNoArgs) {
		t.Fatal("脚本位置参数变化必须改变 CommandPlan.Digest")
	}
	rawJSON, err := pPOSIXArgs.CanonicalJSON()
	var rt CommandPlan
	if err != nil || jsonv2.Unmarshal(rawJSON, &rt) != nil || !rt.Equal(pPOSIXArgs) {
		t.Fatalf("POSIX 带参脚本 JSON 往返失败: err=%v", err)
	}

	pPSArgs := mustCommandPlan(t, CommandPlanSpec{
		Kind: PlanKindScript, Profile: pwshProf, Command: "Write-Output $args[0] # comment",
		Argv: []string{"it's ok", "hello world", ""}, WorkDir: algebraic.Some(wd), Env: map[string]string{"K": "v"},
	})
	if out, err := pPSArgs.RenderCommand(); err != nil || out != "pwsh -NoProfile -NonInteractive -Command -" {
		t.Fatalf("PowerShell 带参脚本 RenderCommand 异常: out=%q err=%v", out, err)
	}
	psStdin, ok := pPSArgs.StdinPayload()
	wantPS := "Set-Location -LiteralPath '/tmp' -ErrorAction Stop; $env:K = 'v'\n& {\nWrite-Output $args[0] # comment\n} 'it''s ok' 'hello world' ''"
	if !ok || psStdin != wantPS {
		t.Fatalf("PowerShell 带参脚本 StdinPayload 异常:\ngot:  %q\nwant: %q", psStdin, wantPS)
	}
	// PowerShell 脚本参数含弯单引号（U+2019）必须在构造期被 QuotePowerShell 失败关闭拦截。
	if _, err := NewCommandPlan(CommandPlanSpec{
		Kind: PlanKindScript, Profile: pwshProf, Command: "Write-Output $args[0]", Argv: []string{"bad\u2019quote"},
	}); !errors.Is(err, ErrInvalidShellQuote) {
		t.Fatalf("PowerShell 脚本参数含弯单引号应返回 ErrInvalidShellQuote，实际=%v", err)
	}
	// 脱敏摘要必须覆盖脚本文本与位置参数两侧的内联凭据。
	pSecretArg := mustCommandPlan(t, CommandPlanSpec{
		Kind: PlanKindScript, Profile: bashProf, Command: "echo ok", Argv: []string{"--token", "super-secret-arg"},
	})
	if sum := pSecretArg.RedactedSummary(); strings.Contains(sum, "super-secret-arg") || !strings.Contains(sum, "[REDACTED]") {
		t.Fatalf("脚本位置参数未脱敏: %s", sum)
	}
}

func assertCmdRenderingAndQuoting(t *testing.T, wd pathalg.RemotePath) {
	t.Helper()
	cmdProf, _ := NewLaunchProfile(LaunchProfileSpec{algebraic.Some(DialectCmd), InterpreterCmd, LoginModeDisabled})
	pCmd := mustCommandPlan(t, CommandPlanSpec{
		Kind: PlanKindCommand, Profile: cmdProf, Argv: []string{"echo", "a=b", "hello world"},
		WorkDir: algebraic.Some(wd), Env: map[string]string{"APP": "hello world"},
	})
	out, err := pCmd.RenderCommand()
	if err != nil || !strings.Contains(out, `cd /d /tmp || exit 1 && set "APP=hello world" && echo "a=b" "hello world"`) {
		t.Fatalf("cmd 渲染异常: out=%q err=%v", out, err)
	}
	// Server + DialectCmd 同样拒绝 \r/\n
	srvCmdProf, _ := NewLaunchProfile(LaunchProfileSpec{algebraic.Some(DialectCmd), InterpreterServer, LoginModeInherit})
	if _, err := NewCommandPlan(CommandPlanSpec{Kind: PlanKindCommand, Profile: srvCmdProf, Command: "echo a\necho b"}); !errors.Is(err, ErrInvalidShellQuote) {
		t.Fatalf("Server+DialectCmd 含换行期望 ErrInvalidShellQuote，实际=%v", err)
	}
	// QuoteCmdArg：等号触发引号；带空白/等号且以反斜杠结尾必须拒绝
	if q, err := QuoteCmdArg("k=v"); err != nil || q != `"k=v"` {
		t.Fatalf("QuoteCmdArg(k=v) 异常: q=%q err=%v", q, err)
	}
	if _, err := QuoteCmdArg(`C:\Program Files\`); !errors.Is(err, ErrInvalidShellQuote) {
		t.Fatalf("带空白且尾部反斜杠的 cmd 参数期望拒绝，实际=%v", err)
	}
}

func TestExecutionOutcomeAndRetryInvariant(t *testing.T) {
	if CanRetryOutcome(nil) || (&OutcomeNotStarted{}).CanRetry() || (&OutcomeCompleted{}).CanRetry() || (&OutcomeUnknown{}).CanRetry() {
		t.Fatal("nil 或零值 ExecutionOutcome 严禁允许重试")
	}
	// 验证 nil 具体指针访问器零 panic 且失败关闭
	var nilNS *OutcomeNotStarted
	var nilUnk *OutcomeUnknown
	var nilSig *ExitSignal
	var nilEU *ExitUnknown
	if nilNS.Phase() != StartPhaseUnknown || nilNS.Code() != "" || nilNS.Reason() != "" ||
		nilUnk.Phase() != ExecPhaseUnknown || nilUnk.Code() != "" || nilUnk.Reason() != "" ||
		nilSig.Signal() != "" || nilSig.Message() != "" || nilEU.Reason() != "" {
		t.Fatal("nil Outcome/ExitStatus 指针访问器必须安全返回零值")
	}
	outcomes := buildValidOutcomesForTest(t)
	assertOutcomeRoundTrips(t, outcomes)
	assertMalformedOutcomesRejected(t)
}

func buildValidOutcomesForTest(t *testing.T) []ExecutionOutcome {
	t.Helper()
	ns, err := NewOutcomeNotStarted(StartPhaseDial, "dial_timeout", "connect refused")
	if err != nil || !ns.CanRetry() || !CanRetryOutcome(ns) {
		t.Fatalf("有效 *OutcomeNotStarted 必须允许重试: err=%v", err)
	}
	comp0, err := NewOutcomeCompleted(NewExitCode(0), false)
	if err != nil || comp0.CanRetry() || CanRetryOutcome(comp0) || !comp0.Succeeded() {
		t.Fatalf("*OutcomeCompleted(0) 语义错误: err=%v", err)
	}
	sig, err := NewExitSignal("term", true, "terminated")
	if err != nil {
		t.Fatalf("NewExitSignal 失败: %v", err)
	}
	compSig, err := NewOutcomeCompleted(sig, true)
	if err != nil || compSig.CanRetry() || compSig.Succeeded() || !compSig.Truncated() {
		t.Fatalf("*OutcomeCompleted(signal) 语义错误: err=%v", err)
	}
	compUnk, err := NewOutcomeCompleted(NewExitUnknown("eof without exit-status"), false)
	if err != nil || compUnk.CanRetry() || compUnk.Succeeded() {
		t.Fatalf("*OutcomeCompleted(ExitUnknown) 不得视为成功或可重试: err=%v", err)
	}
	unk, err := NewOutcomeUnknown(ExecPhaseTransportLost, "broken_pipe", "connection reset")
	if err != nil || unk.CanRetry() || CanRetryOutcome(unk) {
		t.Fatalf("*OutcomeUnknown 严禁允许重试: err=%v", err)
	}
	return []ExecutionOutcome{ns, comp0, compSig, compUnk, unk}
}

func assertOutcomeRoundTrips(t *testing.T, outcomes []ExecutionOutcome) {
	t.Helper()
	for _, oc := range outcomes {
		var buf bytes.Buffer
		if err := MarshalOutcomeTo(jsontext.NewEncoder(&buf), oc); err != nil {
			t.Fatalf("MarshalOutcomeTo 失败: %v", err)
		}
		dec, err := UnmarshalOutcomeFrom(jsontext.NewDecoder(&buf))
		if err != nil || !EqualOutcome(dec, oc) {
			t.Fatalf("UnmarshalOutcomeFrom 往返失败: err=%v raw=%s", err, buf.String())
		}
	}
}

func assertMalformedOutcomesRejected(t *testing.T) {
	t.Helper()
	for _, bad := range []string{
		`null`, `{}`,
		`{"kind":"not_started"}`,
		`{"kind":"not_started","start_phase":"dial","truncated":true}`,
		`{"kind":"completed","exit_status":{"kind":"code"}}`,
		`{"kind":"completed","exit_status":{"kind":"code","code":0},"code":"extra"}`,
		`{"kind":"unknown","start_phase":"dial"}`,
	} {
		if _, err := UnmarshalOutcomeFrom(jsontext.NewDecoder(strings.NewReader(bad))); err == nil {
			t.Fatalf("非法 Outcome JSON %s 期望失败关闭", bad)
		}
	}
}
