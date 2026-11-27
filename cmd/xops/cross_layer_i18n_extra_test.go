package main

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/entry/cli"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/entry/sftpshell"
	"github.com/wentf9/xops-cli/internal/host/sys"
	"github.com/wentf9/xops-cli/internal/i18n"
)

func assertRealAuditHaltedAndOrphanedPGroupErrors(
	t *testing.T,
	ctx context.Context,
	enLoc, zhLoc *i18n.Localizer,
) {
	t.Helper()
	auditEv := buildCrossLayerAuditRecordEvent(t)

	// 1. 真实 AuditDispatcher 写入失败触发不可逆熔断（ErrAuditHalted），验证中文非零汉字与完整语义。
	writeFailDisp, err := events.NewAuditDispatcher(events.AuditDispatcherConfig{
		Writer: events.AuditWriterFunc(func(context.Context, *events.AuditRecordEvent) error {
			return ports.ErrAuditWriteFailed
		}),
		HaltOnWriteError: true,
	})
	if err != nil {
		t.Fatalf("NewAuditDispatcher(writeFail): %v", err)
	}
	if firstErr := writeFailDisp.Dispatch(ctx, auditEv); firstErr == nil {
		t.Fatal("期望首次 Dispatch 因写失败返回错误")
	}
	haltedWriteErr := writeFailDisp.Dispatch(ctx, auditEv)
	if !errors.Is(haltedWriteErr, events.ErrAuditHalted) {
		t.Fatalf("期望 events.ErrAuditHalted，实际=%v", haltedWriteErr)
	}

	// 2. 自定义熔断码（如外部故障码）同样完整保留 ErrAuditHalted 中英文熔断语义。
	customHaltDisp, err := events.NewAuditDispatcher(events.AuditDispatcherConfig{
		Writer: events.AuditWriterFunc(func(context.Context, *events.AuditRecordEvent) error { return nil }),
	})
	if err != nil {
		t.Fatalf("NewAuditDispatcher(customHalt): %v", err)
	}
	customHaltDisp.Halt("disk_full_io", nil)
	haltedReasonErr := customHaltDisp.Dispatch(ctx, auditEv)
	if !errors.Is(haltedReasonErr, events.ErrAuditHalted) {
		t.Fatalf("期望自定义熔断原因保留 events.ErrAuditHalted，实际=%v", haltedReasonErr)
	}

	// 3. 真实 ErrOrphanedProcessGroup（裸哨兵与系统调用失败复合链）完整保留孤儿进程组说明。
	orphanSyscallErr := domi18n.WrapSentinel(
		sys.ErrOrphanedProcessGroup,
		i18n.Wrap(ports.ErrPermissionDenied, i18n.KeyHostSysSyscallFailed, i18n.Str("call", "getsid(0)")),
	)
	if !errors.Is(orphanSyscallErr, sys.ErrOrphanedProcessGroup) {
		t.Fatalf("期望复合链保留 sys.ErrOrphanedProcessGroup，实际=%v", orphanSyscallErr)
	}

	// 4. MCP OutcomeUnknown 细节模板完整保留禁止自动重试警告（EN/ZH）。
	mcpOutcomeErr := domi18n.EF(
		engine.ErrOutcomeUnknown,
		domi18n.KeyMCPProtoOutcomeUnkReason,
		domi18n.BoundStr("code", "transport_lost"),
		domi18n.BoundStr("reason", "peer_eof"),
	)

	for _, tc := range []crossLayerErrorCheck{
		{
			name:     "events.AuditDispatcher/ErrAuditHalted(write-failed)",
			err:      haltedWriteErr,
			wantEn:   []string{"events: AuditDispatcher entered Halted state: synchronous audit write failed"},
			wantZh:   []string{"审计分发器（AuditDispatcher）已进入熔断态（Halted）：同步审计落盘写入失败"},
			forbidZh: []string{"events:", "entered Halted state", "synchronous audit write failed"},
		},
		{
			name:     "events.AuditDispatcher/ErrAuditHalted(custom-reason)",
			err:      haltedReasonErr,
			wantEn:   []string{"events: AuditDispatcher entered Halted state (disk_full_io)"},
			wantZh:   []string{"审计分发器（AuditDispatcher）已进入熔断态（Halted）（原因：disk_full_io）"},
			forbidZh: []string{"events:", "entered Halted state"},
		},
		{
			name:     "sys.ErrOrphanedProcessGroup(bare)",
			err:      sys.ErrOrphanedProcessGroup,
			wantEn:   []string{"sys: current process is in an orphaned process group or is a session leader; suspend is forbidden"},
			wantZh:   []string{"当前进程处于孤儿进程组或会话首进程，禁止执行挂起"},
			forbidZh: []string{"sys:", "orphaned process group", "suspend is forbidden"},
		},
		{
			name:     "sys.ErrOrphanedProcessGroup(syscall-wrapped)",
			err:      orphanSyscallErr,
			wantEn:   []string{"sys: current process is in an orphaned process group or is a session leader; suspend is forbidden", "getsid(0) failed"},
			wantZh:   []string{"当前进程处于孤儿进程组或会话首进程，禁止执行挂起", "系统调用 getsid(0) 失败"},
			forbidZh: []string{"sys:", "orphaned process group", "suspend is forbidden", "getsid(0) failed"},
		},
		{
			name:     "mcp.OutcomeUnknown(automatic-retry-forbidden)",
			err:      mcpOutcomeErr,
			wantEn:   []string{"mcp: remote execution outcome is unknown (transport_lost: peer_eof); automatic retry is forbidden"},
			wantZh:   []string{"远端执行终态未知（transport_lost：peer_eof），严禁自动重试"},
			forbidZh: []string{"mcp:", "outcome is unknown", "automatic retry is forbidden"},
		},
	} {
		assertRealBilingualParity(t, tc, enLoc, zhLoc)
	}
}

func buildCrossLayerAuditRecordEvent(t *testing.T) *events.AuditRecordEvent {
	t.Helper()
	tid, err := security.ParseTraceID("trace-cross-audit-01")
	if err != nil {
		t.Fatalf("ParseTraceID: %v", err)
	}
	opID, err := security.ParseOperationID("op-cross-audit-01")
	if err != nil {
		t.Fatalf("ParseOperationID: %v", err)
	}
	meta, err := events.NewEventMeta(events.EventMetaSpec{
		TraceID:     tid,
		OperationID: algebraic.Some(opID),
		OccurredAt:  time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC),
		Seq:         1,
	})
	if err != nil {
		t.Fatalf("NewEventMeta: %v", err)
	}
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute,
		Tool:       "terminal_exec",
		Action:     "run",
		NodeID:     "n1",
	})
	if err != nil {
		t.Fatalf("NewOperationBinding: %v", err)
	}
	ev, err := events.NewAuditRecordEvent(events.AuditRecordSpec{
		Meta:              meta,
		Stage:             events.AuditStageAuthorized,
		ProcessInstanceID: "proc-cross-01",
		Capability:        security.CapabilityExecute,
		Decision:          security.NewDecisionAllow("policy allow"),
		Risk:              security.RiskSafe,
		Binding:           algebraic.Some(binding),
		Duration:          algebraic.ZeroDuration(),
	})
	if err != nil {
		t.Fatalf("NewAuditRecordEvent: %v", err)
	}
	return ev
}

func assertRealNonLoopbackMCPServerError(
	t *testing.T,
	ctx context.Context,
	eng *engine.Engine,
	enLoc, zhLoc *i18n.Localizer,
) {
	t.Helper()
	mcpSrv, err := eng.NewMCPServer(engine.MCPConfig{})
	if err != nil {
		t.Fatalf("NewMCPServer: %v", err)
	}
	defer func() {
		if cErr := mcpSrv.Close(ctx); cErr != nil {
			t.Errorf("mcpSrv.Close: %v", cErr)
		}
	}()
	nonLoopErr := mcpSrv.ListenAndServeHTTP(ctx, "0.0.0.0:18080")
	if nonLoopErr == nil {
		t.Fatal("期望 ListenAndServeHTTP(0.0.0.0:18080) 拒绝非回环绑定")
	}
	assertRealBilingualParity(t, crossLayerErrorCheck{
		name:     "mcpruntime.ListenAndServeHTTP/ErrNonLoopbackAddress",
		err:      nonLoopErr,
		wantEn:   []string{"mcpruntime: refusing non-loopback HTTP listen address 0.0.0.0:18080 (only 127.0.0.1 / ::1 / localhost are allowed by default)"},
		wantZh:   []string{"拒绝绑定非回环 MCP HTTP 监听地址 0.0.0.0:18080（默认仅允许 127.0.0.1 / ::1 / localhost）"},
		forbidZh: []string{"mcpruntime:", "refusing non-loopback", "allowed by default"},
	}, enLoc, zhLoc)
}

func TestRunProcess_DoctorAndConfigImport_BilingualTextAndCanonicalJSON(t *testing.T) {
	defer goleak.VerifyNone(t)
	homeDir, xopsHome := setupIsolatedRootEnv(t)
	setProcessLocaleEnv(t, "en", "", "", "en_US.UTF-8")

	cfgPath := filepath.Join(filepath.FromSlash(xopsHome.String()), "config.yaml")
	cfgYAML := `version: 2
inventory:
  hosts:
    h-ok:
      address: 127.0.0.1
      port: 22
    h-unused:
      address: 127.0.0.2
      port: 22
  identities:
    i-ok:
      user: ops
      auth:
        kind: agent
    i-unused:
      user: audit
      auth:
        kind: agent
  nodes:
    n-ok:
      host: h-ok
      identity: i-ok
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("WriteFile(config.yaml): %v", err)
	}

	assertRunProcessDoctorBilingualAndJSON(t)
	assertRunProcessConfigImportBilingualAndJSON(t, homeDir)
	assertZeroRemainingLocks(t, xopsHome)
}

func assertRunProcessDoctorBilingualAndJSON(t *testing.T) {
	t.Helper()
	// 1. xops --lang zh doctor：中文标题、中文诊断正文、中文凭据库说明，零英文诊断句子泄露。
	codeZh, outZh, errZh := runCLIInProc("--lang", "zh", "--ssh-config", "none", "doctor")
	if codeZh != 0 || errZh != "" {
		t.Fatalf("zh doctor 失败: code=%d stderr=%q stdout=%q", codeZh, errZh, outZh)
	}
	assertChineseCleanText(t, "zh doctor text", outZh,
		[]string{
			"系统诊断",
			"资产清单：",
			"[提示] unused_host（h-unused）：该主机资产未被任何节点引用",
			"[提示] unused_identity（i-unused）：该身份资产未被任何节点引用",
			"[警告] vault_uninitialized：凭据库尚未初始化",
			"凭据库：",
		},
		[]string{
			"Host is not referenced",
			"Identity is not referenced",
			"vault is not initialized",
		},
	)

	// 2. xops --lang zh --json doctor：机器 JSON 契约保持 100% 规范纯英文，无汉字、无 json:"-" 字段。
	codeJSON, outJSON, errJSON := runCLIInProc("--lang", "zh", "--ssh-config", "none", "--json", "doctor")
	if codeJSON != 0 || errJSON != "" {
		t.Fatalf("zh --json doctor 失败: code=%d stderr=%q stdout=%q", codeJSON, errJSON, outJSON)
	}
	if strings.Contains(outJSON, `"Localized"`) || strings.Contains(outJSON, `"Cause"`) {
		t.Fatalf("doctor --json 不得序列化 json:\"-\" 字段:\n%s", outJSON)
	}
	assertEnglishCleanText(t, "zh doctor --json", outJSON, []string{
		"Host is not referenced by any Node",
		"Identity is not referenced by any Node",
		"vault is not initialized",
	})
	var parsed map[string]any
	if err := jsonv2.Unmarshal([]byte(outJSON), &parsed); err != nil {
		t.Fatalf("doctor --json 解析失败: %v\nraw=%s", err, outJSON)
	}
}

func assertRunProcessConfigImportBilingualAndJSON(t *testing.T, homeDir pathalg.LocalDir) {
	t.Helper()
	sshCfgFile := filepath.Join(filepath.FromSlash(homeDir.String()), "import_warn_i18n.cfg")
	sshCfgContent := `Include conf.d/*.conf
Match exec "true"
  User ignored

Host app-1
  HostName 10.0.0.1
  User ops
  IdentityFile ~/.ssh/%r_id
`
	if err := os.WriteFile(sshCfgFile, []byte(sshCfgContent), 0o600); err != nil {
		t.Fatalf("WriteFile(import_warn_i18n.cfg): %v", err)
	}

	// 1. xops --lang zh config import --plan：中文摘要与中文告警正文，零英文告警句泄露。
	codeZh, outZh, errZh := runCLIInProc(
		"--lang", "zh", "config", "import",
		"--format", "openssh", "--file", sshCfgFile,
		"--symlink-policy", "follow_operator_source", "--plan",
	)
	if codeZh != 0 || errZh != "" {
		t.Fatalf("zh config import --plan 失败: code=%d stderr=%q stdout=%q", codeZh, errZh, outZh)
	}
	assertChineseCleanText(t, "zh config import text", outZh,
		[]string{
			"预检计划",
			"[警告]",
			"纯流式导入已跳过 Include",
			"已忽略 Match exec 代码块",
			"直接导入已跳过不受支持的 IdentityFile 项",
		},
		[]string{
			"skipped in stream-only import",
			"Match exec block ignored",
			"skipped unsupported IdentityFile",
		},
	)

	// 2. xops --lang zh --json config import --plan：JSON 告警契约保持 100% 规范纯英文。
	codeJSON, outJSON, errJSON := runCLIInProc(
		"--lang", "zh", "--json", "config", "import",
		"--format", "openssh", "--file", sshCfgFile,
		"--symlink-policy", "follow_operator_source", "--plan",
	)
	if codeJSON != 0 || errJSON != "" {
		t.Fatalf("zh --json config import --plan 失败: code=%d stderr=%q stdout=%q", codeJSON, errJSON, outJSON)
	}
	assertEnglishCleanText(t, "zh config import --json", outJSON, []string{
		"skipped in stream-only import",
		"Match exec block ignored",
		"skipped unsupported IdentityFile",
	})
	var parsed map[string]any
	if err := jsonv2.Unmarshal([]byte(outJSON), &parsed); err != nil {
		t.Fatalf("config import --json 解析失败: %v\nraw=%s", err, outJSON)
	}
}

func TestHasRawPlaceholderInCmd_AlignedWithParamKey(t *testing.T) {
	positives := []string{
		"missing {host}",
		"missing {node.id}",
		"missing {retry-count}",
		"missing {0_a.b-c}",
	}
	for _, s := range positives {
		if !hasRawPlaceholderInCmd(s) {
			t.Errorf("hasRawPlaceholderInCmd(%q) = false, want true", s)
		}
	}
	negatives := []string{
		"no placeholder",
		"bad {.leading_dot}",
		"bad {-leading_dash}",
		"bad {}",
		"bad {a b}",
		"bad {" + strings.Repeat("a", domi18n.MaxParamKeyBytes+1) + "}",
	}
	for _, s := range negatives {
		if hasRawPlaceholderInCmd(s) {
			t.Errorf("hasRawPlaceholderInCmd(%q) = true, want false", s)
		}
	}
}

type challengeSFTPStub struct {
	sftpshell.TransferClient
	challengeErr error
}

func (c challengeSFTPStub) RealPathRemote(context.Context, engine.RemotePathOpRequest) (pathalg.RemotePath, error) {
	return pathalg.ParseRemotePath("/home/ops")
}

func (c challengeSFTPStub) WriteRemoteFile(context.Context, engine.RemoteFileWriteRequest) (engine.WriteFileResult, error) {
	return engine.WriteFileResult{}, c.challengeErr
}

func TestCrossLayer_ApprovalChallenge_CLIFailAndSFTPShellBilingual(t *testing.T) {
	defer goleak.VerifyNone(t)
	_, xopsHome := setupIsolatedRootEnv(t)

	cfgPath := filepath.Join(filepath.FromSlash(xopsHome.String()), "config.yaml")
	cfgYAML := `version: 2
policy:
  mcp_default: strict_agent
  guardrail:
    approval_threshold: dangerous
    no_elicit_fallback: challenge
    protected_paths:
      - /etc/**
    node_overrides:
      "prod-*":
        approval_threshold: dangerous
        decision_floor: need_approval
inventory:
  hosts:
    h1:
      address: 127.0.0.1
      port: 22
  identities:
    i1:
      user: ops
      auth:
        kind: agent
  nodes:
    n1:
      host: h1
      identity: i1
    prod-1:
      host: h1
      identity: i1
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("WriteFile(config.yaml): %v", err)
	}

	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	runApprovalChallengeCrossLayerSuite(t, context.Background(), cat, cat.For(domi18n.LocaleEn), cat.For(domi18n.LocaleZh))
	assertZeroRemainingLocks(t, xopsHome)
}

func runApprovalChallengeCrossLayerSuite(
	t *testing.T,
	ctx context.Context,
	cat *i18n.Catalog,
	enLoc, zhLoc *i18n.Localizer,
) {
	t.Helper()
	rt, err := wireRuntimeWithLocalizer(ctx, cli.EngineInitOptions{
		OpenSSHConfigFile: "none",
		Locale:            domi18n.LocaleZh,
	}, runtimeModeMCP, strings.NewReader(""), io.Discard, zhLoc)
	if err != nil {
		t.Fatalf("wireRuntimeWithLocalizer(MCP): %v", err)
	}
	defer func() {
		if cErr := rt.Close(ctx); cErr != nil {
			t.Errorf("rt.Close(MCP): %v", cErr)
		}
	}()

	// 触发两类真实 *gate.ApprovalChallengeError：风险阈值触发与节点覆盖策略触发。
	var execOut bytes.Buffer
	_, riskErr := rt.engine.Exec(ctx, engine.ExecRequest{
		TargetSpec: "n1",
		Command:    "uname -a",
		Risk:       algebraic.Some(security.RiskDangerous),
		Stdout:     &execOut,
	})
	_, nodeOverrideErr := rt.engine.Exec(ctx, engine.ExecRequest{
		TargetSpec: "prod-1",
		Command:    "uptime",
		Risk:       algebraic.Some(security.RiskSafe),
		Stdout:     &execOut,
	})

	cases := []struct {
		name         string
		err          error
		wantEnReason string
		wantZhReason string
	}{
		{
			name:         "risk-threshold",
			err:          riskErr,
			wantEnReason: "operation risk meets or exceeds approval threshold",
			wantZhReason: "操作风险达到或超过审批阈值",
		},
		{
			name:         "node-override",
			err:          nodeOverrideErr,
			wantEnReason: "node override requires explicit approval",
			wantZhReason: "节点策略覆盖要求显式审批",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertApprovalChallengeCrossLayerRendering(t, ctx, rt.engine, cat, enLoc, zhLoc, tc.err, tc.wantEnReason, tc.wantZhReason)
		})
	}
}

func assertApprovalChallengeCrossLayerRendering(
	t *testing.T,
	ctx context.Context,
	eng *engine.Engine,
	cat *i18n.Catalog,
	enLoc, zhLoc *i18n.Localizer,
	chErr error,
	wantEnReason, wantZhReason string,
) {
	t.Helper()
	if !errors.Is(chErr, engine.ErrApprovalRequired) {
		t.Fatalf("期望 engine.ErrApprovalRequired，实际=%v", chErr)
	}
	ch, ok := engine.ExtractApprovalChallenge(chErr)
	if !ok || !ch.IsValid() {
		t.Fatalf("ExtractApprovalChallenge 失败: ok=%v err=%v", ok, chErr)
	}
	if ch.Reason() != wantEnReason {
		t.Fatalf("ch.Reason() = %q，期望 %q", ch.Reason(), wantEnReason)
	}
	forbidZh := []string{
		"operation risk meets or exceeds approval threshold",
		"node override requires explicit approval",
		"operation touches protected path",
		"approval required",
		"protected path",
		"approval challenge required",
	}

	// 1. CLI clikit.Runtime.Fail --lang zh 文本模式：首行错误与第二行审批摘要 100% 中文且零英文原因泄露。
	var zhOut, zhErrBuf bytes.Buffer
	zhRT := &clikit.Runtime{Stdout: &zhOut, Stderr: &zhErrBuf, Catalog: cat, Localizer: zhLoc}
	if code := zhRT.Fail(clikit.ExitGeneral, false, chErr); code != clikit.ExitGeneral {
		t.Fatalf("zh Fail exitCode = %d", code)
	}
	zhLines := strings.Split(strings.TrimSpace(zhErrBuf.String()), "\n")
	if len(zhLines) != 2 {
		t.Fatalf("zh Fail 期望 2 行（首行错误+第二行审批摘要），实际 %d 行:\n%s", len(zhLines), zhErrBuf.String())
	}
	assertChineseCleanText(t, "cli Fail zh line1", zhLines[0], []string{"操作需要两阶段人工审批确认", wantZhReason}, forbidZh)
	assertChineseCleanText(t, "cli Fail zh line2", zhLines[1], []string{"需要人工审批：摘要=" + ch.EnvelopeDigest().String(), "原因=" + wantZhReason}, forbidZh)

	// 2. CLI clikit.Runtime.Fail --lang en 文本模式：与 ch.Reason() 100% 逐字同构。
	var enOut, enErrBuf bytes.Buffer
	enRT := &clikit.Runtime{Stdout: &enOut, Stderr: &enErrBuf, Catalog: cat, Localizer: enLoc}
	_ = enRT.Fail(clikit.ExitGeneral, false, chErr)
	enLines := strings.Split(strings.TrimSpace(enErrBuf.String()), "\n")
	if len(enLines) != 2 {
		t.Fatalf("en Fail 期望 2 行，实际 %d 行:\n%s", len(enLines), enErrBuf.String())
	}
	assertEnglishCleanText(t, "cli Fail en line1", enLines[0], []string{ch.Reason()})
	assertEnglishCleanText(t, "cli Fail en line2", enLines[1], []string{"approval required: digest=" + ch.EnvelopeDigest().String(), "reason=" + ch.Reason()})

	// 3. CLI clikit.Runtime.Fail --lang zh --json：error 中文化，但 approval_challenge.reason 保持规范纯英文。
	var jsonOut, jsonErrBuf bytes.Buffer
	zhJSONRT := &clikit.Runtime{Stdout: &jsonOut, Stderr: &jsonErrBuf, Catalog: cat, Localizer: zhLoc}
	_ = zhJSONRT.Fail(clikit.ExitGeneral, true, chErr)
	var env clikit.ErrorEnvelope
	if err := jsonv2.Unmarshal(jsonOut.Bytes(), &env); err != nil {
		t.Fatalf("Fail --json 反序列化失败: %v\nraw=%s", err, jsonOut.String())
	}
	if env.ErrorCode != "approval_required" || env.Challenge == nil {
		t.Fatalf("Fail --json 信封缺少 approval_challenge: %+v", env)
	}
	assertChineseCleanText(t, "cli Fail zh --json error", env.Error, []string{"操作需要两阶段人工审批确认", wantZhReason}, forbidZh)
	if env.Challenge.Reason != ch.Reason() {
		t.Fatalf("approval_challenge.reason = %q，期望规范英文 %q", env.Challenge.Reason, ch.Reason())
	}
	assertEnglishCleanText(t, "cli Fail zh --json challenge.reason", env.Challenge.Reason, []string{ch.Reason()})

	// 4. sftpshell formatCommandError 双语渲染（经真实 sftpshell.Run 触发）。
	assertSFTPShellChallengeRendering(t, ctx, eng, enLoc, zhLoc, chErr, ch, wantZhReason, forbidZh)
}

func assertSFTPShellChallengeRendering(
	t *testing.T,
	ctx context.Context,
	eng *engine.Engine,
	enLoc, zhLoc *i18n.Localizer,
	chErr error,
	ch engine.ApprovalChallenge,
	wantZhReason string,
	forbidZh []string,
) {
	t.Helper()
	stub := challengeSFTPStub{TransferClient: eng, challengeErr: chErr}

	var zhOut, zhErr bytes.Buffer
	if err := sftpshell.Run(ctx, sftpshell.Config{
		Engine: stub, TargetSpec: "n1",
		Stdin: strings.NewReader("write /etc/hosts payload\nquit\n"), Stdout: &zhOut, Stderr: &zhErr,
		Localizer: zhLoc,
	}); err != nil {
		t.Fatalf("sftpshell.Run(zh): %v", err)
	}
	wantSFTPZh := "sftp: 需要人工审批（" + wantZhReason + "，摘要=" + ch.EnvelopeDigest().String() + "）"
	assertChineseCleanText(t, "sftpshell zh stderr", zhErr.String(), []string{wantSFTPZh}, forbidZh)

	var enOut, enErr bytes.Buffer
	if err := sftpshell.Run(ctx, sftpshell.Config{
		Engine: stub, TargetSpec: "n1",
		Stdin: strings.NewReader("write /etc/hosts payload\nquit\n"), Stdout: &enOut, Stderr: &enErr,
		Localizer: enLoc,
	}); err != nil {
		t.Fatalf("sftpshell.Run(en): %v", err)
	}
	wantSFTPEn := "sftp: approval required (" + ch.Reason() + ", digest=" + ch.EnvelopeDigest().String() + ")"
	assertEnglishCleanText(t, "sftpshell en stderr", enErr.String(), []string{wantSFTPEn})
}
