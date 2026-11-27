package tui_test

import (
	"bytes"
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/internal/entry/tui"
	"github.com/wentf9/xops-cli/internal/i18n"
	"go.uber.org/goleak"
)

func mustLoadCatalog(t *testing.T) *i18n.Catalog {
	t.Helper()
	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("i18n.LoadCatalog: %v", err)
	}
	return cat
}

func assertContainsAll(t *testing.T, label, got string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Fatalf("%s 缺少期望片段 %q\n实际输出:\n%s", label, want, got)
		}
	}
}

func assertContainsNone(t *testing.T, label, got string, forbidden ...string) {
	t.Helper()
	for _, bad := range forbidden {
		if strings.Contains(got, bad) {
			t.Fatalf("%s 不应包含旧语种片段 %q\n实际输出:\n%s", label, bad, got)
		}
	}
}

func pressKey(m tui.Model, msg tea.KeyPressMsg) tui.Model {
	next, _ := m.Update(msg)
	return next.(tui.Model)
}

func sendMsgToModel(m tui.Model, msg tea.Msg) tui.Model {
	next, _ := m.Update(msg)
	return next.(tui.Model)
}

func TestModel_BilingualDeferredRenderingAndLiveLocaleToggle(t *testing.T) {
	cat := mustLoadCatalog(t)
	var toggled []domi18n.Locale
	m := tui.NewModel(tui.ModelOptions{
		InitialView:    tui.ViewHosts,
		InitialWidth:   120,
		InitialHeight:  36,
		Catalog:        cat,
		Locale:         domi18n.LocaleEn,
		OnLocaleChange: func(loc domi18n.Locale) { toggled = append(toggled, loc) },
	})
	if m.Locale() != domi18n.LocaleEn {
		t.Fatalf("初始语种期望 LocaleEn，实际=%v", m.Locale())
	}

	// 注入全部可延迟渲染的复合运行期状态：主机清单、筛选词、安全熔断错误、未知终态、指标流帧、截断日志、四态操作与结构化错误。
	m = populateRichWorkbenchState(t, m)

	// 1. 英文态渲染全部 5 个视图，校验窗口标题、标签、横幅、过滤栏、帧详情、截断标签、操作徽章、帮助页与底栏。
	assertAllViewsInLocale(t, m, domi18n.LocaleEn)

	// 2. 按大写 L 瞬时热切至简体中文，校验 Locale、OnLocaleChange 回调以及 100% 视图元素即时重绘。
	m = pressKey(m, tea.KeyPressMsg{Code: 'L', Text: "L"})
	if m.Locale() != domi18n.LocaleZh {
		t.Fatalf("按 L 后语种期望 LocaleZh，实际=%v", m.Locale())
	}
	if !slices.Equal(toggled, []domi18n.Locale{domi18n.LocaleZh}) {
		t.Fatalf("OnLocaleChange 回调序列异常: got=%v", toggled)
	}
	assertAllViewsInLocale(t, m, domi18n.LocaleZh)

	// 3. 验证无 lastErr 时，状态栏的 language_switched / process_sort / inventory_loaded 消息也完全延迟渲染。
	m = sendMsgToModel(m, tui.InventoryLoadedMsg{Revision: "rev-2", Hosts: buildSampleInventoryItems(t)})
	assertContainsAll(t, "中文资产刷新状态", m.View().Content, "已加载 2 个目标（版本 rev-2）")
	m = pressKey(m, tea.KeyPressMsg{Code: 's', Text: "s"})
	assertContainsAll(t, "中文进程排序状态", m.View().Content, "进程排序方式：内存")

	// 4. 再按大写 L 切回英文，校验状态栏与全部视图回切英文且保留回调记录。
	m = pressKey(m, tea.KeyPressMsg{Code: 'L', Text: "L"})
	if m.Locale() != domi18n.LocaleEn {
		t.Fatalf("再次按 L 后期望回切 LocaleEn，实际=%v", m.Locale())
	}
	if !slices.Equal(toggled, []domi18n.Locale{domi18n.LocaleZh, domi18n.LocaleEn}) {
		t.Fatalf("二次切换 OnLocaleChange 回调异常: got=%v", toggled)
	}
	assertContainsAll(t, "英文语言切换状态", m.View().Content, "Language switched to English", "L lang")
	assertContainsNone(t, "英文态不得残留中文标签", m.View().Content, "界面语言已切换", "L 语言")
}

func populateRichWorkbenchState(t *testing.T, m tui.Model) tui.Model {
	t.Helper()
	m = sendMsgToModel(m, tui.InventoryLoadedMsg{Revision: "rev-7", Hosts: buildSampleInventoryItems(t)})
	// 设置非空筛选词（先进入编辑再按 Enter 应用）
	m = pressKey(m, tea.KeyPressMsg{Code: '/', Text: "/"})
	m = pressKey(m, tea.KeyPressMsg{Code: 'd', Text: "d"})
	m = pressKey(m, tea.KeyPressMsg{Code: 'b', Text: "b"})
	m = pressKey(m, tea.KeyPressMsg{Code: tea.KeyEnter})

	// 注入结构化熔断错误与未知终态四态操作
	m = sendMsgToModel(m, tui.HaltedStateMsg{Err: context.DeadlineExceeded})
	m = sendMsgToModel(m, tui.ProjectionViewMsg{View: tui.ProjectionView{
		Valid:             true,
		Version:           1,
		TotalEvents:       4,
		DroppedEvents:     1,
		ActiveStreams:     2,
		HasUnknownOutcome: true,
		Operations: []engine.OperationView{
			{OperationID: "op-running", Tool: "ssh", Action: "exec", NodeID: "db-01", Summary: "run"},
			{OperationID: "op-ok", Tool: "ssh", Action: "exec", NodeID: "db-01", Completed: true, Succeeded: true, Summary: "ok"},
			{OperationID: "op-fail", Tool: "ssh", Action: "exec", NodeID: "db-01", Completed: true, Succeeded: false, Summary: "fail"},
			{OperationID: "op-unknown", Tool: "ssh", Action: "exec", NodeID: "db-01", Completed: true, Unknown: true, Summary: "unk"},
		},
	}})

	// 注入指标流活跃态、完整主机帧（含磁盘与进程）及截断日志
	m = sendMsgToModel(m, tui.StreamStateMsg{Kind: tui.StreamKindMetrics, Target: "db-01", Active: true, Seq: 1})
	m = sendMsgToModel(m, tui.MetricsFrameMsg{
		Target: "db-01",
		Frame: engine.HostMetricsFrame{
			NodeID:     "db-01",
			Hostname:   "db-prod",
			CPUPercent: 41.2,
			Load1:      1.25,
			Load5:      0.95,
			Load15:     0.50,
			MemPercent: 72.5,
			MemUsed:    4096,
			MemTotal:   8192,
			Uptime:     algebraic.FromStdDuration(2 * time.Hour),
			Disks:      []engine.DiskMetric{{Mount: "/", UsedPercent: 60.5}},
			Processes:  []engine.ProcessMetric{{PID: 77, User: "postgres", CPUPercent: 15.0, MemPercent: 22.0, Command: "postgres"}},
		},
	})
	m = sendMsgToModel(m, tui.StreamStateMsg{Kind: tui.StreamKindLogs, Target: "db-01", Active: true, Seq: 1})
	m = sendMsgToModel(m, tui.LogChunkMsg{Target: "db-01", Stream: events.OutputStreamStdout, Text: "db log line", Truncated: true})
	// 注入结构化可本地化错误到 lastErr（验证切语种后立即重译）
	m = sendMsgToModel(m, tui.StreamStateMsg{Kind: tui.StreamKindLogs, Target: "db-01", Active: false, Seq: 2, Err: context.DeadlineExceeded})
	return m
}

func assertAllViewsInLocale(t *testing.T, m tui.Model, loc domi18n.Locale) {
	t.Helper()
	isZh := loc == domi18n.LocaleZh

	// Hosts 视图
	m = pressKey(m, tea.KeyPressMsg{Code: '1', Text: "1"})
	vHosts := m.View()
	if isZh {
		assertContainsAll(t, "ZH Hosts Title", vHosts.WindowTitle, "XOps v2 工作台 — 主机")
		assertContainsAll(t, "ZH Hosts View", vHosts.Content,
			"1:主机", "2:指标", "3:日志", "4:操作", "?:帮助",
			"事件=4 丢弃=1 活跃流=2",
			"安全门控已熔断：上下文已超时",
			"警告：检测到未知终态（OutcomeUnknown）— 严禁自动重试",
			"[过滤]：db",
			"主机与节点（1/2）版本=rev-7",
			"错误：日志流（db-01）：上下文已超时",
			"L 语言",
		)
	} else {
		assertContainsAll(t, "EN Hosts Title", vHosts.WindowTitle, "XOps v2 Workbench — Hosts")
		assertContainsAll(t, "EN Hosts View", vHosts.Content,
			"1:Hosts", "2:Metrics", "3:Logs", "4:Operations", "?:Help",
			"events=4 dropped=1 streams=2",
			"SECURITY GATE HALTED: context deadline exceeded",
			"WARNING: OutcomeUnknown detected — DO NOT auto-retry",
			"[filter]: db",
			"Hosts & Nodes (1/2) rev=rev-7",
			"ERR: logs stream (db-01): context deadline exceeded",
			"L lang",
		)
	}

	// Metrics 视图
	m = pressKey(m, tea.KeyPressMsg{Code: '2', Text: "2"})
	vMetrics := m.View()
	if isZh {
		assertContainsAll(t, "ZH Metrics Title", vMetrics.WindowTitle, "XOps v2 工作台 — 指标")
		assertContainsAll(t, "ZH Metrics View", vMetrics.Content,
			"主机指标 [流式传输中] 目标=db-01 排序=CPU",
			"主机：db-prod (db-01)", "负载：1.25 0.95 0.50", "内存：72.5%", "运行时长：2h0m0s",
			"磁盘占用：", "热门进程：",
		)
	} else {
		assertContainsAll(t, "EN Metrics Title", vMetrics.WindowTitle, "XOps v2 Workbench — Metrics")
		assertContainsAll(t, "EN Metrics View", vMetrics.Content,
			"Host Metrics [streaming] target=db-01 sort=cpu",
			"Host: db-prod (db-01)", "Load: 1.25 0.95 0.50", "Mem: 72.5%", "Uptime: 2h0m0s",
			"Disks:", "Top Processes:",
		)
	}

	// Logs 视图
	m = pressKey(m, tea.KeyPressMsg{Code: '3', Text: "3"})
	vLogs := m.View()
	if isZh {
		assertContainsAll(t, "ZH Logs Title", vLogs.WindowTitle, "XOps v2 工作台 — 日志")
		assertContainsAll(t, "ZH Logs View", vLogs.Content, "实时日志 [空闲] 目标=db-01 行数=1", "[已截断]")
	} else {
		assertContainsAll(t, "EN Logs Title", vLogs.WindowTitle, "XOps v2 Workbench — Logs")
		assertContainsAll(t, "EN Logs View", vLogs.Content, "Live Logs [idle] target=db-01 lines=1", "[truncated]")
	}

	// Operations 视图（清除筛选以展示全部 4 种状态徽章）
	m = pressKey(m, tea.KeyPressMsg{Code: '4', Text: "4"})
	vOps := m.View()
	if isZh {
		assertContainsAll(t, "ZH Ops Title", vOps.WindowTitle, "XOps v2 工作台 — 操作")
		assertContainsAll(t, "ZH Ops View", vOps.Content, "操作（4）| 连接池（0）| 诊断（0）", "运行中", "成功", "失败", "未知")
	} else {
		assertContainsAll(t, "EN Ops Title", vOps.WindowTitle, "XOps v2 Workbench — Operations")
		assertContainsAll(t, "EN Ops View", vOps.Content, "Operations (4) | Pool (0) | Diagnostics (0)", "RUNNING", "OK", "FAILED", "UNKNOWN")
	}

	// Help 视图
	m = pressKey(m, tea.KeyPressMsg{Code: '?', Text: "?"})
	vHelp := m.View()
	if isZh {
		assertContainsAll(t, "ZH Help Title", vHelp.WindowTitle, "XOps v2 工作台 — 帮助")
		assertContainsAll(t, "ZH Help View", vHelp.Content, "快捷键与运行期控制", "小写 l", "大写 L")
	} else {
		assertContainsAll(t, "EN Help Title", vHelp.WindowTitle, "XOps v2 Workbench — Help")
		assertContainsAll(t, "EN Help View", vHelp.Content, "Keybindings & Runtime Controls", "lowercase l", "uppercase L")
	}
}

func TestModel_FilterModeDoesNotHijackUppercaseL(t *testing.T) {
	calls := 0
	m := tui.NewModel(tui.ModelOptions{
		Locale:         domi18n.LocaleEn,
		OnLocaleChange: func(domi18n.Locale) { calls++ },
	})
	m = pressKey(m, tea.KeyPressMsg{Code: '/', Text: "/"})
	m = pressKey(m, tea.KeyPressMsg{Code: 'L', Text: "L"})
	m = pressKey(m, tea.KeyPressMsg{Code: 'o', Text: "o"})
	m = pressKey(m, tea.KeyPressMsg{Code: 'g', Text: "g"})

	if m.Locale() != domi18n.LocaleEn || calls != 0 {
		t.Fatalf("过滤编辑模式输入大写 L 不得触发语种切换: locale=%v calls=%d", m.Locale(), calls)
	}
	if m.FilterQuery() != "Log" {
		t.Fatalf("过滤词应追加大写 L: got=%q", m.FilterQuery())
	}
	assertContainsAll(t, "编辑态过滤栏", m.View().Content, "[filter (editing)]: Log")

	// 退出过滤编辑后再按 L，必须正常切换至中文。
	m = pressKey(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m = pressKey(m, tea.KeyPressMsg{Code: 'L', Text: "L"})
	if m.Locale() != domi18n.LocaleZh || calls != 1 {
		t.Fatalf("退出过滤后按 L 应切为 LocaleZh: locale=%v calls=%d", m.Locale(), calls)
	}
	assertContainsAll(t, "中文只读过滤栏", m.View().Content, "[过滤]：Log")
}

func TestModel_HaltedBannerVariantsAndFailClosedEdgeCases(t *testing.T) {
	// 1. HaltedStateMsg 空 Reason 与空 Err -> 回退本地化默认熔断原因。
	m := tui.NewModel(tui.ModelOptions{Locale: domi18n.LocaleEn})
	m = sendMsgToModel(m, tui.HaltedStateMsg{})
	assertContainsAll(t, "EN default halt", m.View().Content, "SECURITY GATE HALTED: audit post-write failure")
	m = pressKey(m, tea.KeyPressMsg{Code: 'L', Text: "L"})
	assertContainsAll(t, "ZH default halt", m.View().Content, "安全门控已熔断：审计落盘失败")

	// 2. 兼容仅传 Reason 字符串的场景。
	m = sendMsgToModel(m, tui.HaltedStateMsg{Reason: "disk full"})
	assertContainsAll(t, "ZH raw reason halt", m.View().Content, "安全门控已熔断：disk full")

	// 3. 无效 StreamKind 严格失败关闭（不污染状态与流活跃标志）。
	var zeroKind tui.StreamKind
	if zeroKind.IsValid() || !zeroKind.IsZero() || zeroKind.LabelKey().IsValid() {
		t.Fatalf("零值 StreamKind 必须失败关闭")
	}
	m = sendMsgToModel(m, tui.StreamStateMsg{Kind: zeroKind, Target: "x", Active: true, Seq: 9})
	if m.MetricsActive() || m.LogsActive() {
		t.Fatalf("无效 StreamKind 不得置位活跃流标志")
	}

	// 4. NaN/Inf 指标帧浮点安全降级，不破坏状态栏与视图渲染。
	m = sendMsgToModel(m, tui.MetricsFrameMsg{
		Target: "nan-box",
		Frame:  engine.HostMetricsFrame{NodeID: "nan-box", CPUPercent: math.NaN(), MemPercent: math.Inf(1)},
	})
	assertContainsAll(t, "NaN 安全降级", m.View().Content, "指标已更新（nan-box：CPU -% 内存 -%）")
}

func TestSentinels_StructuredErrorIDsAndCanonicalEnglish(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want domi18n.MessageID
	}{
		{"ErrNilContext", tui.ErrNilContext, i18n.KeyTUINilContext},
		{"ErrInvalidConfig", tui.ErrInvalidConfig, i18n.KeyTUIInvalidConfig},
		{"ErrInvalidEvent", tui.ErrInvalidEvent, i18n.KeyTUIInvalidEvent},
		{"ErrTerminalRestore", tui.ErrTerminalRestore, i18n.KeyTUITerminalRestore},
		{"ErrTakeoverDisabled", tui.ErrTakeoverDisabled, i18n.KeyTUITakeoverDisabled},
	}
	zhLoc := mustLoadCatalog(t).For(domi18n.LocaleZh)
	for _, tc := range cases {
		id, ok := domi18n.ErrorID(tc.err)
		if !ok || id != tc.want {
			t.Fatalf("%s ErrorID 失配: ok=%v got=%q want=%q", tc.name, ok, id, tc.want)
		}
		if strings.Contains(tc.err.Error(), "不能") || strings.Contains(tc.err.Error(), "无效") {
			t.Fatalf("%s.Error() 必须为规范英文: got=%q", tc.name, tc.err.Error())
		}
		if zh := zhLoc.RenderError(tc.err); zh == "" || zh == tc.err.Error() {
			t.Fatalf("%s 中文渲染异常: zh=%q en=%q", tc.name, zh, tc.err.Error())
		}
	}

	// 校验配置校验错误与终端恢复包装错误保留 errors.Is 与结构化 ErrorID。
	cfgErr := tui.Run(context.Background(), tui.Config{})
	if !errors.Is(cfgErr, tui.ErrInvalidConfig) {
		t.Fatalf("空 Config 应匹配 ErrInvalidConfig: %v", cfgErr)
	}
	if id, ok := domi18n.ErrorID(cfgErr); !ok || id != i18n.KeyTUIConfigNoSource {
		t.Fatalf("空 Config ErrorID 期望 KeyTUIConfigNoSource，实际 ok=%v id=%q", ok, id)
	}
}

func TestRun_LiveLocaleToggleFiresHookAndSurvivesTakeover_ZeroLeaks(t *testing.T) {
	defer goleak.VerifyNone(t)

	eng := newSampleFakeEngine(t)
	defer eng.bus.Close()

	var mu sync.Mutex
	var localeLog []domi18n.Locale
	localeSwitched := make(chan domi18n.Locale, 2)
	takeoverSeen := make(chan domi18n.Locale, 1)
	extMsgs := make(chan tea.Msg, 8)
	var out bytes.Buffer

	runErrCh := make(chan error, 1)
	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if err := n.Go(func(_ context.Context) error {
			runErrCh <- tui.Run(context.Background(), tui.Config{
				Engine:               eng,
				Output:               &out,
				DisableInput:         true,
				DisableRenderer:      true,
				DisableAltScreen:     true,
				DisableSignalHandler: true,
				InitialTarget:        "app-01",
				Locale:               domi18n.LocaleEn,
				ExternalMsgs:         extMsgs,
				OnLocaleChange: func(loc domi18n.Locale) {
					mu.Lock()
					localeLog = append(localeLog, loc)
					mu.Unlock()
					localeSwitched <- loc
				},
				OnTakeover: func(_ context.Context, _ tui.TakeoverRequest) error {
					mu.Lock()
					cur := domi18n.LocaleEn
					if len(localeLog) > 0 {
						cur = localeLog[len(localeLog)-1]
					}
					mu.Unlock()
					takeoverSeen <- cur
					return nil
				},
			})
			return nil
		}); err != nil {
			return err
		}

		<-eng.listCalledCh
		// Pass 1 按 L 切换为中文 -> 触发 Enter 接管 -> 确认接管期观测到中文 -> Pass 2 恢复后按 L 切回英文 -> 退出。
		extMsgs <- tea.KeyPressMsg{Code: 'L', Text: "L"}
		if got := <-localeSwitched; got != domi18n.LocaleZh {
			t.Errorf("Pass 1 按 L 期望切换至 LocaleZh，实际=%v", got)
		}
		extMsgs <- tea.KeyPressMsg{Code: tea.KeyEnter}
		if got := <-takeoverSeen; got != domi18n.LocaleZh {
			t.Errorf("接管回调期间期望同步为 LocaleZh，实际=%v", got)
		}
		<-eng.listCalledCh
		extMsgs <- tea.KeyPressMsg{Code: 'L', Text: "L"}
		if got := <-localeSwitched; got != domi18n.LocaleEn {
			t.Errorf("接管恢复后按 L 应从 LocaleZh 切回 LocaleEn，实际=%v", got)
		}
		extMsgs <- tea.KeyPressMsg{Code: 'q', Text: "q"}
		close(extMsgs)
		return nil
	})
	if err != nil {
		t.Fatalf("conc.RunWait: %v", err)
	}
	if runErr := <-runErrCh; runErr != nil {
		t.Fatalf("tui.Run 期望 nil，实际=%v", runErr)
	}
	mu.Lock()
	gotLog := slices.Clone(localeLog)
	mu.Unlock()
	if !slices.Equal(gotLog, []domi18n.Locale{domi18n.LocaleZh, domi18n.LocaleEn}) {
		t.Fatalf("Run 生命周期语种切换记录失配: got=%v", gotLog)
	}
}
