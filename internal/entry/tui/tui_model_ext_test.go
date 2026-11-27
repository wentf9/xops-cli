package tui_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/internal/entry/tui"
)

func mustTestMeta(t *testing.T, withOp bool) events.EventMeta {
	t.Helper()
	tid, err := security.ParseTraceID("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("ParseTraceID: %v", err)
	}
	nid, err := inventory.ParseNodeID("web-01")
	if err != nil {
		t.Fatalf("ParseNodeID: %v", err)
	}
	spec := events.EventMetaSpec{
		TraceID:    tid,
		OccurredAt: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		NodeID:     algebraic.Some(nid),
	}
	if withOp {
		oid, err := security.ParseOperationID("fedcba9876543210fedcba9876543210")
		if err != nil {
			t.Fatalf("ParseOperationID: %v", err)
		}
		spec.OperationID = algebraic.Some(oid)
	}
	meta, err := events.NewEventMeta(spec)
	if err != nil {
		t.Fatalf("NewEventMeta: %v", err)
	}
	return meta
}

func mustOK[T any](t *testing.T, label string, fn func() (T, error)) T {
	t.Helper()
	v, err := fn()
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return v
}

func buildAll12Events(t *testing.T) []events.Event {
	t.Helper()
	opMeta := mustTestMeta(t, true)
	sysMeta := mustTestMeta(t, false)
	list := buildOpEvents(t, opMeta)
	return append(list, buildSystemEvents(t, sysMeta)...)
}

func buildOpEvents(t *testing.T, opMeta events.EventMeta) []events.Event {
	t.Helper()
	opID, _ := opMeta.OperationID().Get()
	stepID := mustOK(t, "ParseStepID", func() (playbook.StepID, error) { return playbook.ParseStepID("step-1") })
	unknownOut := mustOK(t, "NewOutcomeUnknown", func() (execution.ExecutionOutcome, error) {
		return execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, "timeout", "lost link")
	})
	env := buildTestApprovalEnvelope(t, opID, opMeta.OccurredAt())

	e1 := mustOK(t, "OperationStarted", func() (events.Event, error) {
		return events.NewOperationStartedEvent(events.OperationStartedSpec{Meta: opMeta, Capability: security.CapabilityExecute, Tool: "session", Action: "exec", Summary: "run uptime"})
	})
	e2 := mustOK(t, "OperationCompleted", func() (events.Event, error) {
		return events.NewOperationCompletedEvent(events.OperationCompletedSpec{Meta: opMeta, Capability: security.CapabilityExecute, Duration: algebraic.FromStdDuration(time.Second), Outcome: algebraic.Some(unknownOut), Succeeded: false, Code: "unknown", Message: "link lost"})
	})
	e3 := mustOK(t, "OutputChunk", func() (events.Event, error) {
		return events.NewOutputChunkEvent(events.OutputChunkSpec{Meta: opMeta, Stream: events.OutputStreamStdout, ChunkIndex: 1, Data: []byte("hello log")})
	})
	e4 := mustOK(t, "StepEvent", func() (events.Event, error) {
		return events.NewStepEvent(events.StepEventSpec{Meta: opMeta, StepID: stepID, Status: playbook.StepStatusSucceeded, Duration: algebraic.FromStdDuration(200 * time.Millisecond), Message: "done"})
	})
	e5 := mustOK(t, "FSMTransition", func() (events.Event, error) {
		return events.NewFSMTransitionEvent(events.FSMTransitionSpec{Meta: opMeta, Machine: events.FSMMachineTransfer, FromState: "init", ToState: "streaming", EventName: "start", Detail: "chunking"})
	})
	e6 := mustOK(t, "ApprovalChallenge", func() (events.Event, error) {
		return events.NewApprovalChallengeEvent(events.ApprovalChallengeSpec{Meta: opMeta, Envelope: env, Phase: fsm.ApprovalPhaseChallengeIssued, Reason: "high risk"})
	})
	e7 := mustOK(t, "TransferProgress", func() (events.Event, error) {
		return events.NewTransferProgressEvent(events.TransferProgressSpec{Meta: opMeta, TransferID: opID, Direction: fsm.TransferDirectionUpload, BytesTransferred: 512, TotalBytes: 1024, Stage: "upload"})
	})
	e8 := mustOK(t, "MetricSample", func() (events.Event, error) {
		return events.NewMetricSampleEvent(events.MetricSampleSpec{Meta: opMeta, MetricName: "cpu_percent", Unit: "pct", Value: 42.5, Interval: algebraic.FromStdDuration(time.Second), Labels: map[string]string{"core": "all"}})
	})
	e9 := mustOK(t, "AuditRecord", func() (events.Event, error) {
		return events.NewAuditRecordEvent(events.AuditRecordSpec{Meta: opMeta, Stage: events.AuditStageHalted, ProcessInstanceID: "proc-1", Capability: security.CapabilityExecute, Decision: security.NewDecisionDeny("halted"), Risk: security.RiskSafe, Reason: "enospc"})
	})
	return []events.Event{e1, e2, e3, e4, e5, e6, e7, e8, e9}
}

func buildSystemEvents(t *testing.T, sysMeta events.EventMeta) []events.Event {
	t.Helper()
	ep := mustOK(t, "ParseEndpoint", func() (netaddr.Endpoint, error) { return netaddr.ParseEndpoint("10.0.0.10:22") })
	e10 := mustOK(t, "PoolState", func() (events.Event, error) {
		return events.NewPoolStateEvent(events.PoolStateSpec{Meta: sysMeta, Action: events.PoolActionLeaseAcquired, Endpoint: algebraic.Some(ep), ActiveLeases: 2, Detail: "ok"})
	})
	e11 := mustOK(t, "Diagnostic", func() (events.Event, error) {
		return events.NewDiagnosticEvent(events.DiagnosticSpec{Meta: sysMeta, Scope: events.DiagnosticScopeTransport, Severity: events.SeverityWarn, Code: "slow_kex", Message: "retrying"})
	})
	e12 := mustOK(t, "BusDropped", func() (events.Event, error) {
		return events.NewBusDroppedEvent(events.BusDroppedSpec{Meta: sysMeta, Scope: events.DiagnosticScopeRuntime, DroppedTotal: 5, DroppedDelta: 2, Reason: "slow consumer"})
	})
	return []events.Event{e10, e11, e12}
}

func buildTestApprovalEnvelope(t *testing.T, opID security.OperationID, issuedAt time.Time) security.ApprovalEnvelope {
	t.Helper()
	binding := mustOK(t, "NewOperationBinding", func() (security.OperationBinding, error) {
		return security.NewOperationBinding(security.OperationBindingSpec{
			Capability: security.CapabilityExecute,
			Tool:       "session",
			Action:     "exec",
			NodeID:     "web-01",
			Parameters: map[string]string{"cmd": "uptime"},
		})
	})
	needApp := mustOK(t, "NewDecisionNeedApproval", func() (security.GuardrailDecision, error) {
		return security.NewDecisionNeedApproval(security.RiskDangerous, "high risk")
	})
	return mustOK(t, "NewApprovalEnvelope", func() (security.ApprovalEnvelope, error) {
		return security.NewApprovalEnvelope(security.ApprovalEnvelopeSpec{
			OperationID:  opID,
			Binding:      binding,
			Risk:         security.RiskDangerous,
			Decision:     needApp,
			ScopeSummary: "restart service",
			IssuedAt:     issuedAt,
			TTL:          algebraic.FromStdDuration(5 * time.Minute),
			Nonce:        [16]byte{1, 2, 3, 4},
		})
	})
}

func TestProjectEvent_All12VariantsAndFailClosed(t *testing.T) {
	if _, err := tui.ProjectEvent(nil); !errors.Is(err, tui.ErrInvalidEvent) {
		t.Fatalf("nil event 期望 ErrInvalidEvent，实际=%v", err)
	}
	var zeroEv *events.DiagnosticEvent
	if _, err := tui.ProjectEvent(zeroEv); !errors.Is(err, tui.ErrInvalidEvent) {
		t.Fatalf("typed-nil event 期望 ErrInvalidEvent，实际=%v", err)
	}

	m := tui.NewModel(tui.ModelOptions{InitialWidth: 120, InitialHeight: 40})
	for _, ev := range buildAll12Events(t) {
		msg, err := tui.ProjectEvent(ev)
		if err != nil {
			t.Fatalf("ProjectEvent(%s) 失败: %v", ev.Kind(), err)
		}
		updated, _ := m.Update(msg)
		m = updated.(tui.Model)
	}
	if !m.GateHalted() {
		t.Fatalf("AuditStageHalted 应单调锁存 GateHalted=true")
	}
	if !m.HasUnknownOutcome() {
		t.Fatalf("OutcomeUnknown 应单调锁存 HasUnknownOutcome=true")
	}
	if m.DroppedEvents() != 2 {
		t.Fatalf("DroppedEvents 期望 2，实际=%d", m.DroppedEvents())
	}
	if len(m.Operations()) == 0 || len(m.Logs()) == 0 {
		t.Fatalf("期望投影出操作与日志条目，ops=%d logs=%d", len(m.Operations()), len(m.Logs()))
	}

	updated, _ := m.Update(tea.KeyPressMsg{Code: '4', Text: "4"})
	m = updated.(tui.Model)
	view := m.View()
	if !strings.Contains(view.Content, "SECURITY GATE HALTED") || !strings.Contains(view.Content, "OutcomeUnknown") {
		t.Fatalf("视图缺少安全告警横幅:\n%s", view.Content)
	}
}

func TestModel_ViewSwitchingFilteringNavigationAndMetrics(t *testing.T) {
	hosts := buildSampleInventoryItems(t)
	m := tui.NewModel(tui.ModelOptions{InitialView: tui.ViewHosts, InitialWidth: 100, InitialHeight: 30, CanTakeover: true})
	var next tea.Model
	next, _ = m.Update(tui.InventoryLoadedMsg{Revision: "rev-9", Hosts: hosts})
	m = next.(tui.Model)

	if m.SelectedTarget() != "db-01" {
		t.Fatalf("首个选中节点期望 db-01，实际=%q", m.SelectedTarget())
	}
	next, _ = m.Update(tea.KeyPressMsg{Code: 'j', Text: "j"})
	m = next.(tui.Model)
	if m.SelectedTarget() != "web-01" {
		t.Fatalf("下移后期望 web-01，实际=%q", m.SelectedTarget())
	}

	// 进入筛选模式，输入 "db" 并回车确认
	for _, k := range []tea.KeyPressMsg{
		{Code: '/', Text: "/"},
		{Code: 'd', Text: "d"},
		{Code: 'b', Text: "b"},
		{Code: tea.KeyEnter},
	} {
		next, _ = m.Update(k)
		m = next.(tui.Model)
	}
	if m.FilterQuery() != "db" || m.SelectedTarget() != "db-01" {
		t.Fatalf("筛选失败: query=%q selected=%q", m.FilterQuery(), m.SelectedTarget())
	}

	// 视图切换 Tab / Shift+Tab / 2 / 3 / ?
	next, _ = m.Update(tea.KeyPressMsg{Code: '2', Text: "2"})
	m = next.(tui.Model)
	if m.ActiveView() != tui.ViewMetrics {
		t.Fatalf("期望 ViewMetrics，实际=%s", m.ActiveView())
	}
	next, _ = m.Update(tui.MetricsFrameMsg{
		Target: "db-01",
		Frame: engine.HostMetricsFrame{
			NodeID:     "db-01",
			Hostname:   "db-prod",
			CPUPercent: 33.5,
			MemPercent: 61.2,
			MemUsed:    4096,
			MemTotal:   8192,
			Uptime:     algebraic.FromStdDuration(3 * time.Hour),
			Disks:      []engine.DiskMetric{{Mount: "/", UsedPercent: 45.0}},
			Processes:  []engine.ProcessMetric{{PID: 101, User: "postgres", CPUPercent: 12.1, MemPercent: 20.5, Command: "postgres"}},
		},
	})
	m = next.(tui.Model)
	if !strings.Contains(m.View().Content, "db-prod") || !strings.Contains(m.View().Content, "postgres") {
		t.Fatalf("Metrics 视图缺少预期帧数据:\n%s", m.View().Content)
	}

	// 日志视图渲染与滚动
	next, _ = m.Update(tui.LogChunkMsg{Target: "db-01", Stream: events.OutputStreamStderr, Text: "line-1\nline-2\n"})
	m = next.(tui.Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: '3', Text: "3"})
	m = next.(tui.Model)
	if !strings.Contains(m.View().Content, "line-1") || !strings.Contains(m.View().Content, "line-2") {
		t.Fatalf("Logs 视图缺少日志行:\n%s", m.View().Content)
	}

	// 回到 Hosts 视图触发交互接管（Enter）
	next, _ = m.Update(tea.KeyPressMsg{Code: '1', Text: "1"})
	m = next.(tui.Model)
	var cmd tea.Cmd
	next, cmd = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(tui.Model)
	req, ok := m.PendingTakeover()
	if !ok || req.TargetSpec != "db-01" || cmd == nil {
		t.Fatalf("Enter 接管未触发: ok=%v req=%+v cmd=%v", ok, req, cmd)
	}
}

func buildSampleInventoryItems(t *testing.T) []tui.HostItem {
	t.Helper()
	h1ID, _ := inventory.ParseHostID("h-db")
	h2ID, _ := inventory.ParseHostID("h-web")
	ep1, _ := netaddr.ParseEndpoint("10.0.0.2:22")
	ep2, _ := netaddr.ParseEndpoint("10.0.0.3:22")
	h1, err := inventory.NewHost(inventory.HostSpec{ID: h1ID, Endpoint: ep1})
	if err != nil {
		t.Fatalf("NewHost h1: %v", err)
	}
	h2, err := inventory.NewHost(inventory.HostSpec{ID: h2ID, Endpoint: ep2})
	if err != nil {
		t.Fatalf("NewHost h2: %v", err)
	}
	idKey, _ := inventory.ParseIdentityID("ops")
	user, _ := option.ParseUsername("deploy")
	auth, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	if err != nil {
		t.Fatalf("NewAuthAgent: %v", err)
	}
	ident, err := inventory.NewIdentity(inventory.IdentitySpec{ID: idKey, User: user, Auth: auth})
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	n1ID, _ := inventory.ParseNodeID("db-01")
	n2ID, _ := inventory.ParseNodeID("web-01")
	tagProd, _ := inventory.ParseTag("prod")
	n1, err := inventory.NewNode(inventory.NodeSpec{ID: n1ID, HostRef: h1ID, IdentityRef: idKey, Tags: []inventory.Tag{tagProd}, Origin: inventory.NewOriginManaged()})
	if err != nil {
		t.Fatalf("NewNode n1: %v", err)
	}
	n2, err := inventory.NewNode(inventory.NodeSpec{ID: n2ID, HostRef: h2ID, IdentityRef: idKey, Origin: inventory.NewOriginManaged()})
	if err != nil {
		t.Fatalf("NewNode n2: %v", err)
	}
	return tui.BuildHostItemsFromEntities([]inventory.Host{h1, h2}, []inventory.Identity{ident}, []inventory.Node{n1, n2})
}

func TestModel_ViewKindCycleFilterEditSortScrollAndBanners(t *testing.T) {
	var zeroView tui.ViewKind
	if tui.ViewInvalid.IsValid() || !zeroView.IsZero() || zeroView.IsValid() {
		t.Fatalf("零值 ViewKind 必须失败关闭返回 invalid")
	}
	if tui.ViewHosts.Next() != tui.ViewMetrics || tui.ViewHosts.Prev() != tui.ViewHelp {
		t.Fatalf("ViewKind 环形切换异常: next=%v prev=%v", tui.ViewHosts.Next(), tui.ViewHosts.Prev())
	}

	m := tui.NewModel(tui.ModelOptions{InitialWidth: 100, InitialHeight: 24, MaxLogLines: 3})
	var next tea.Model
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyTab})
	m = next.(tui.Model)
	if m.ActiveView() != tui.ViewMetrics {
		t.Fatalf("Tab 后期望 ViewMetrics，实际=%v", m.ActiveView())
	}
	next, _ = m.Update(tea.KeyPressMsg{Code: 's', Text: "s"})
	m = next.(tui.Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: '?', Text: "?"})
	m = next.(tui.Model)
	if m.ActiveView() != tui.ViewHelp || !strings.Contains(m.View().Content, "Keybindings & Runtime Controls") {
		t.Fatalf("? 未切入帮助视图:\n%s", m.View().Content)
	}

	// 验证过滤编辑（backspace / esc 清空）与日志环形缓冲 + 滚动。
	for _, k := range []tea.KeyPressMsg{
		{Code: '/', Text: "/"}, {Code: 'a', Text: "a"}, {Code: 'b', Text: "b"},
		{Code: tea.KeyBackspace}, {Code: tea.KeyEscape},
	} {
		next, _ = m.Update(k)
		m = next.(tui.Model)
	}
	if m.FilterQuery() != "" {
		t.Fatalf("Esc 后筛选词应清空，实际=%q", m.FilterQuery())
	}
	next, _ = m.Update(tui.LogChunkMsg{Target: "web-01", Text: "l1\nl2\nl3\nl4\n"})
	m = next.(tui.Model)
	if len(m.Logs()) != 3 || m.Logs()[0].Data != "l2" {
		t.Fatalf("日志环形上限 3 裁剪异常: %+v", m.Logs())
	}
	next, _ = m.Update(tea.KeyPressMsg{Code: '3', Text: "3"})
	m = next.(tui.Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: 'G', Text: "G"})
	m = next.(tui.Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: 'g', Text: "g"})
	m = next.(tui.Model)
	next, _ = m.Update(tui.SystemBusDroppedMsg{Delta: 4, Total: 4})
	m = next.(tui.Model)
	next, _ = m.Update(tui.TakeoverResultMsg{Target: "web-01", Err: errors.New("ssh closed")})
	m = next.(tui.Model)
	if m.DroppedEvents() != 4 || !strings.Contains(m.View().Content, "ssh closed") {
		t.Fatalf("Drop 计数或 Takeover 错误横幅缺失: dropped=%d\n%s", m.DroppedEvents(), m.View().Content)
	}
}

func TestModel_MultiTickProjectionNoLogDuplicationAndNoDirectClobber(t *testing.T) {
	m := tui.NewModel(tui.ModelOptions{InitialWidth: 100, InitialHeight: 24, MaxLogLines: 10})
	ts := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	// 先投递一条直连 OperationStream 事件，验证后续 Projection 更新不会将其抹除。
	opMeta := mustTestMeta(t, true)
	started := mustOK(t, "OpStarted", func() (events.Event, error) {
		return events.NewOperationStartedEvent(events.OperationStartedSpec{
			Meta: opMeta, Capability: security.CapabilityInspect, Tool: "direct", Action: "ping", Summary: "direct op",
		})
	})
	directMsg := mustOK(t, "ProjectEvent", func() (tea.Msg, error) { return tui.ProjectEvent(started) })
	next, _ := m.Update(directMsg)
	m = next.(tui.Model)

	log0 := engine.LogEntry{TraceID: "t1", NodeID: "n1", Stream: events.OutputStreamStdout, ChunkIndex: 1, Data: "alpha\nbeta\n", OccurredAt: ts}
	log1 := engine.LogEntry{TraceID: "t1", NodeID: "n1", Stream: events.OutputStreamStdout, ChunkIndex: 2, Data: "gamma", OccurredAt: ts}
	log2 := engine.LogEntry{TraceID: "t1", NodeID: "n1", Stream: events.OutputStreamStderr, ChunkIndex: 3, Data: "delta", OccurredAt: ts}
	projOp := engine.OperationView{OperationID: "proj-op-1", Tool: "obs", Action: "metrics", Summary: "proj"}

	// v1 -> v2 -> v3 重复携带全量历史 snap.Logs()，绝不可产生任何重复行，且必须保留直连 op。
	for _, view := range []tui.ProjectionView{
		{Valid: true, Version: 1, TotalEvents: 1, Operations: []engine.OperationView{projOp}, Logs: []engine.LogEntry{log0}},
		{Valid: true, Version: 2, TotalEvents: 2, Operations: []engine.OperationView{projOp}, Logs: []engine.LogEntry{log0, log1}},
		{Valid: true, Version: 3, TotalEvents: 3, Operations: []engine.OperationView{projOp}, Logs: []engine.LogEntry{log0, log1}, Metrics: []engine.MetricPoint{{Key: "k1", Name: "cpu", Value: 50}}},
	} {
		next, _ = m.Update(tui.ProjectionViewMsg{View: view})
		m = next.(tui.Model)
	}
	wantLines := []string{"alpha", "beta", "gamma"}
	assertLogLinesEqual(t, m.Logs(), wantLines)
	if len(m.Operations()) != 2 || len(m.Metrics()) != 1 {
		t.Fatalf("Projection 与直连事件合并异常: ops=%d metrics=%d", len(m.Operations()), len(m.Metrics()))
	}

	// 陈旧版本 v2 必须被忽略；v4 环形淘汰 log0 后应准确反映 [gamma, delta]。
	next, _ = m.Update(tui.ProjectionViewMsg{View: tui.ProjectionView{Valid: true, Version: 2, Logs: []engine.LogEntry{log0}}})
	m = next.(tui.Model)
	assertLogLinesEqual(t, m.Logs(), wantLines)

	next, _ = m.Update(tui.ProjectionViewMsg{View: tui.ProjectionView{Valid: true, Version: 4, TotalEvents: 4, Logs: []engine.LogEntry{log1, log2}}})
	m = next.(tui.Model)
	assertLogLinesEqual(t, m.Logs(), []string{"gamma", "delta"})
}

func assertLogLinesEqual(t *testing.T, got []engine.LogEntry, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("日志行数失配: got=%d (%+v) want=%d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i].Data != want[i] {
			t.Fatalf("logs[%d].Data=%q，期望 %q", i, got[i].Data, want[i])
		}
	}
}

func TestModel_StandaloneHostTargetAndStreamSeqOrdering(t *testing.T) {
	hStandaloneID := mustOK(t, "ParseHostID", func() (inventory.HostID, error) { return inventory.ParseHostID("z-bare") })
	ep := mustOK(t, "ParseEndpoint", func() (netaddr.Endpoint, error) { return netaddr.ParseEndpoint("10.9.9.9:2222") })
	hStandalone := mustOK(t, "NewHost", func() (inventory.Host, error) {
		return inventory.NewHost(inventory.HostSpec{ID: hStandaloneID, Endpoint: ep})
	})
	hNodeID := mustOK(t, "ParseHostID", func() (inventory.HostID, error) { return inventory.ParseHostID("a-host") })
	ep2 := mustOK(t, "ParseEndpoint", func() (netaddr.Endpoint, error) { return netaddr.ParseEndpoint("10.0.0.1:22") })
	hNode := mustOK(t, "NewHost", func() (inventory.Host, error) {
		return inventory.NewHost(inventory.HostSpec{ID: hNodeID, Endpoint: ep2})
	})

	// 故意乱序输入两台独立主机，验证 BuildHostItemsFromEntities 确定性排序及独立主机 EffectiveTarget 解析为 Endpoint。
	items := tui.BuildHostItemsFromEntities([]inventory.Host{hStandalone, hNode}, nil, nil)
	if len(items) != 2 || items[0].NodeID != "a-host" || items[1].NodeID != "z-bare" {
		t.Fatalf("HostItem 未确定性排序: %+v", items)
	}
	if items[1].EffectiveTarget() != "10.9.9.9:2222" {
		t.Fatalf("独立 Host 目标应解析为 Endpoint，实际=%q", items[1].EffectiveTarget())
	}

	m := tui.NewModel(tui.ModelOptions{CanTakeover: true})
	var next tea.Model
	next, _ = m.Update(tui.InventoryLoadedMsg{Hosts: items})
	m = next.(tui.Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: 'j', Text: "j"})
	m = next.(tui.Model)
	if m.SelectedTarget() != "10.9.9.9:2222" {
		t.Fatalf("选中独立 Host 期望 SelectedTarget=10.9.9.9:2222，实际=%q", m.SelectedTarget())
	}

	// 验证旧流延迟到达的 idle 状态不会覆盖新序号流状态。
	next, _ = m.Update(tui.StreamStateMsg{Kind: tui.StreamKindMetrics, Target: "host-b", Active: true, Seq: 2})
	m = next.(tui.Model)
	next, _ = m.Update(tui.StreamStateMsg{Kind: tui.StreamKindMetrics, Target: "host-a", Active: false, Seq: 1})
	m = next.(tui.Model)
	if !m.MetricsActive() {
		t.Fatalf("陈旧序号 Seq=1 的 idle 消息不应覆盖 Seq=2 的活跃状态")
	}
}
