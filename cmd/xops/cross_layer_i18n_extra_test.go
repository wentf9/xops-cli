package main

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
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
