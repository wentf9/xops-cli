package tui_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/internal/entry/tui"
	"go.uber.org/goleak"
)

type fakeEngineClient struct {
	mu           sync.Mutex
	hosts        []inventory.Host
	idents       []inventory.Identity
	nodes        []inventory.Node
	rev          engine.Revision
	bus          *events.SystemBus
	halted       bool
	listCalledCh chan struct{}
	metricsStart chan string
	logsStart    chan string
	streamBlock  bool
	onMetrics    func(ctx context.Context, req engine.MetricsStreamRequest) (engine.MetricsStreamResult, error)
	onLogs       func(ctx context.Context, req engine.LogStreamRequest) (engine.LogStreamResult, error)
}

func (f *fakeEngineClient) ListHosts(_ context.Context, _ engine.InventoryQueryRequest) ([]inventory.Host, engine.Revision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listCalledCh != nil {
		select {
		case f.listCalledCh <- struct{}{}:
		default:
		}
	}
	return slices.Clone(f.hosts), f.rev, nil
}

func (f *fakeEngineClient) ListIdentities(_ context.Context, _ engine.InventoryQueryRequest) ([]inventory.Identity, engine.Revision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.idents), f.rev, nil
}

func (f *fakeEngineClient) ListNodes(_ context.Context, _ engine.InventoryQueryRequest) ([]inventory.Node, engine.Revision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.nodes), f.rev, nil
}

func (f *fakeEngineClient) NewProjection(_ context.Context, _ engine.ProjectionConfig) (*engine.Projection, error) {
	return nil, nil
}

func (f *fakeEngineClient) NewOperationStream(_ context.Context, buffer int) (*events.OperationStream, error) {
	tid, _ := security.ParseTraceID("0123456789abcdef0123456789abcdef")
	oid, _ := security.ParseOperationID("fedcba9876543210fedcba9876543210")
	return events.NewOperationStream(events.OperationStreamConfig{TraceID: tid, OperationID: oid, OperationBuffer: max(buffer, 16)})
}

func zeroVal[T any]() (z T) { return z }

func (f *fakeEngineClient) StreamMetrics(ctx context.Context, req engine.MetricsStreamRequest) (engine.MetricsStreamResult, error) {
	if f.metricsStart != nil {
		select {
		case f.metricsStart <- req.TargetSpec:
		default:
		}
	}
	if f.onMetrics != nil {
		return f.onMetrics(ctx, req)
	}
	if req.OnFrame != nil {
		req.OnFrame(engine.HostMetricsFrame{NodeID: req.TargetSpec, Hostname: req.TargetSpec, CPUPercent: 19.5, MemPercent: 40.0})
	}
	if f.streamBlock {
		<-ctx.Done()
		return zeroVal[engine.MetricsStreamResult](), ctx.Err()
	}
	return zeroVal[engine.MetricsStreamResult](), nil
}

func (f *fakeEngineClient) StreamLogs(ctx context.Context, req engine.LogStreamRequest) (engine.LogStreamResult, error) {
	if f.logsStart != nil {
		select {
		case f.logsStart <- req.TargetSpec:
		default:
		}
	}
	if f.onLogs != nil {
		return f.onLogs(ctx, req)
	}
	if req.Output != nil {
		_, _ = io.WriteString(req.Output, "streamed remote log line\n")
	}
	if f.streamBlock {
		<-ctx.Done()
		return zeroVal[engine.LogStreamResult](), ctx.Err()
	}
	return zeroVal[engine.LogStreamResult](), nil
}

func (f *fakeEngineClient) SystemBus() *events.SystemBus { return f.bus }
func (f *fakeEngineClient) IsHalted() bool               { return f.halted }
func (f *fakeEngineClient) HaltInfo() (engine.HaltInfo, bool) {
	return zeroVal[engine.HaltInfo](), false
}

type fakeProjectionSource struct {
	mu      sync.Mutex
	closed  bool
	waits   chan struct{}
	unblock chan struct{}
}

func (p *fakeProjectionSource) AttachOperationStream(_ *events.OperationStream) error { return nil }
func (p *fakeProjectionSource) Snapshot() engine.ProjectionSnapshot {
	return zeroVal[engine.ProjectionSnapshot]()
}
func (p *fakeProjectionSource) WaitUpdate(ctx context.Context, _ uint64) (engine.ProjectionSnapshot, error) {
	if p.waits != nil {
		select {
		case p.waits <- struct{}{}:
		default:
		}
	}
	select {
	case <-ctx.Done():
		return zeroVal[engine.ProjectionSnapshot](), ctx.Err()
	case <-p.unblock:
		return zeroVal[engine.ProjectionSnapshot](), errors.New("closed")
	}
}
func (p *fakeProjectionSource) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		close(p.unblock)
	}
	return nil
}

func newSampleFakeEngine(t *testing.T) *fakeEngineClient {
	t.Helper()
	hID, _ := inventory.ParseHostID("host-1")
	ep, _ := netaddr.ParseEndpoint("10.1.0.5:22")
	h, _ := inventory.NewHost(inventory.HostSpec{ID: hID, Endpoint: ep})
	idKey, _ := inventory.ParseIdentityID("admin")
	user, _ := option.ParseUsername("root")
	auth, _ := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	ident, _ := inventory.NewIdentity(inventory.IdentitySpec{ID: idKey, User: user, Auth: auth})
	nID, _ := inventory.ParseNodeID("app-01")
	n, _ := inventory.NewNode(inventory.NodeSpec{ID: nID, HostRef: hID, IdentityRef: idKey, Origin: inventory.NewOriginManaged()})
	rev, _ := engine.ParseRevision("rev-1")
	bus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: 16})
	if err != nil {
		t.Fatalf("NewSystemBus: %v", err)
	}
	return &fakeEngineClient{
		hosts:        []inventory.Host{h},
		idents:       []inventory.Identity{ident},
		nodes:        []inventory.Node{n},
		rev:          rev,
		bus:          bus,
		listCalledCh: make(chan struct{}, 4),
		metricsStart: make(chan string, 4),
		logsStart:    make(chan string, 4),
	}
}

func TestRun_ValidationFailClosed(t *testing.T) {
	var nilCtx context.Context
	if err := tui.Run(nilCtx, tui.Config{}); !errors.Is(err, tui.ErrNilContext) {
		t.Fatalf("nil ctx 期望 ErrNilContext，实际=%v", err)
	}
	if err := tui.Run(context.Background(), tui.Config{}); !errors.Is(err, tui.ErrInvalidConfig) {
		t.Fatalf("空 Config 期望 ErrInvalidConfig，实际=%v", err)
	}
	negDur := algebraic.FromStdDuration(-time.Second)
	if err := tui.Run(context.Background(), tui.Config{
		Engine:          newSampleFakeEngine(t),
		MetricsInterval: algebraic.Some(negDur),
	}); !errors.Is(err, tui.ErrInvalidConfig) {
		t.Fatalf("负 MetricsInterval 期望 ErrInvalidConfig，实际=%v", err)
	}
}

func TestRun_HeadlessProjectionSystemBusOperationStreamAndCtxCancel_ZeroLeaks(t *testing.T) {
	defer goleak.VerifyNone(t)

	eng := newSampleFakeEngine(t)
	defer eng.bus.Close()

	opStream, err := eng.NewOperationStream(context.Background(), 16)
	if err != nil {
		t.Fatalf("NewOperationStream: %v", err)
	}
	proj := &fakeProjectionSource{waits: make(chan struct{}, 2), unblock: make(chan struct{})}
	defer func() { _ = proj.Close() }()

	var mu sync.Mutex
	var eventsLog []string
	record := func(s string) {
		mu.Lock()
		eventsLog = append(eventsLog, s)
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var out bytes.Buffer
	runErrCh := make(chan error, 1)
	err = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if err := n.Go(func(_ context.Context) error {
			runErrCh <- tui.Run(ctx, tui.Config{
				Engine:               eng,
				Projection:           proj,
				SystemBus:            eng.bus,
				OperationStreams:     []*events.OperationStream{opStream},
				Output:               &out,
				DisableInput:         true,
				DisableRenderer:      true,
				DisableAltScreen:     true,
				DisableSignalHandler: true,
				TerminalHooks: tui.TerminalHooks{
					OnEnter:   func() error { record("enter"); return nil },
					OnRestore: func() error { record("restore"); return nil },
				},
			})
			return nil
		}); err != nil {
			return err
		}

		// 等待后台投影监听与资产刷新均就绪（零 time.Sleep）。
		<-proj.waits
		<-eng.listCalledCh

		// 向 OperationStream 投递事件并关闭验证确定性 EOF 排空。
		meta := mustTestMeta(t, true)
		started, _ := events.NewOperationStartedEvent(events.OperationStartedSpec{
			Meta: meta, Capability: security.CapabilityInspect, Tool: "inventory", Action: "list", Summary: "load",
		})
		_ = opStream.Emit(context.Background(), started)
		opStream.Close()

		// 取消父 ctx，验证 TUI 确定性退出、排空 Nursery 并恢复终端。
		cancel()
		return nil
	})
	if err != nil {
		t.Fatalf("conc.RunWait: %v", err)
	}
	if runErr := <-runErrCh; !errors.Is(runErr, context.Canceled) {
		t.Fatalf("ctx 取消期望返回 context.Canceled，实际=%v", runErr)
	}
	mu.Lock()
	gotHooks := slices.Clone(eventsLog)
	mu.Unlock()
	if !slices.Equal(gotHooks, []string{"enter", "restore"}) {
		t.Fatalf("终端生命周期钩子顺序错误: got=%v", gotHooks)
	}
}

func TestRun_NormalQuitAndCtrlCAndTakeoverRestore_ZeroLeaks(t *testing.T) {
	defer goleak.VerifyNone(t)

	eng := newSampleFakeEngine(t)
	eng.streamBlock = true
	defer eng.bus.Close()

	var mu sync.Mutex
	var hookSeq []string
	record := func(s string) {
		mu.Lock()
		hookSeq = append(hookSeq, s)
		mu.Unlock()
	}

	takeoverEntered := make(chan tui.TakeoverRequest, 1)
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
				ExternalMsgs:         extMsgs,
				TerminalHooks: tui.TerminalHooks{
					OnEnter:   func() error { record("enter"); return nil },
					OnRelease: func() error { record("release"); return nil },
					OnRestore: func() error { record("restore"); return nil },
				},
				OnTakeover: func(_ context.Context, req tui.TakeoverRequest) error {
					record("takeover:" + req.TargetSpec)
					takeoverEntered <- req
					return nil
				},
			})
			return nil
		}); err != nil {
			return err
		}

		// 等待首轮资产刷新后启动 metrics/logs 流、停止流、触发 Enter 接管，并在恢复后按 q 正常退出。
		<-eng.listCalledCh
		extMsgs <- tea.KeyPressMsg{Code: 'm', Text: "m"}
		if gotTarget := <-eng.metricsStart; gotTarget != "app-01" {
			t.Errorf("metrics 目标期望 app-01，实际=%q", gotTarget)
		}
		extMsgs <- tea.KeyPressMsg{Code: 'l', Text: "l"}
		if gotTarget := <-eng.logsStart; gotTarget != "app-01" {
			t.Errorf("logs 目标期望 app-01，实际=%q", gotTarget)
		}
		extMsgs <- tea.KeyPressMsg{Code: 'x', Text: "x"}
		extMsgs <- tea.KeyPressMsg{Code: '1', Text: "1"}
		extMsgs <- tea.KeyPressMsg{Code: tea.KeyEnter}
		req := <-takeoverEntered
		if req.TargetSpec != "app-01" {
			t.Errorf("接管目标期望 app-01，实际=%q", req.TargetSpec)
		}
		// 接管结束后自动重入 TUI 并再次触发刷新，发送 q 优雅退出。
		<-eng.listCalledCh
		extMsgs <- tea.KeyPressMsg{Code: 'q', Text: "q"}
		close(extMsgs)
		return nil
	})
	if err != nil {
		t.Fatalf("conc.RunWait: %v", err)
	}
	if runErr := <-runErrCh; runErr != nil {
		t.Fatalf("正常退出期望 nil，实际=%v", runErr)
	}
	mu.Lock()
	got := slices.Clone(hookSeq)
	mu.Unlock()
	want := []string{"enter", "release", "takeover:app-01", "enter", "restore"}
	if !slices.Equal(got, want) {
		t.Fatalf("终端接管与恢复钩子顺序失配: got=%v want=%v", got, want)
	}
}

func TestRun_CtrlCExitsCleanlyAndRestoresTerminal_ZeroLeaks(t *testing.T) {
	defer goleak.VerifyNone(t)

	bus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: 8})
	if err != nil {
		t.Fatalf("NewSystemBus: %v", err)
	}
	defer bus.Close()

	restored := false
	var out bytes.Buffer
	// 发送 ETX (0x03 = Ctrl+C) 触发 Bubble Tea v2 KeyPressMsg("ctrl+c") 优雅退出。
	err = tui.Run(context.Background(), tui.Config{
		SystemBus:            bus,
		Input:                strings.NewReader("\x03"),
		Output:               &out,
		DisableRenderer:      true,
		DisableAltScreen:     true,
		DisableSignalHandler: true,
		TerminalHooks: tui.TerminalHooks{
			OnRestore: func() error { restored = true; return nil },
		},
	})
	if err != nil {
		t.Fatalf("Ctrl+C 退出期望 nil，实际=%v", err)
	}
	if !restored {
		t.Fatalf("Ctrl+C 退出必须触发确定性终端恢复 OnRestore")
	}
}

func TestRun_TakeoverErrorAndCtxCancelStillRestoresTerminal_ZeroLeaks(t *testing.T) {
	defer goleak.VerifyNone(t)

	eng := newSampleFakeEngine(t)
	eng.halted = true
	defer eng.bus.Close()

	takeoverStarted := make(chan struct{}, 1)
	extMsgs := make(chan tea.Msg, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var hooks []string
	rec := func(s string) {
		mu.Lock()
		hooks = append(hooks, s)
		mu.Unlock()
	}

	runErrCh := make(chan error, 1)
	var out bytes.Buffer
	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if err := n.Go(func(_ context.Context) error {
			runErrCh <- tui.Run(ctx, tui.Config{
				Engine:               eng,
				Output:               &out,
				DisableInput:         true,
				DisableRenderer:      true,
				DisableAltScreen:     true,
				DisableSignalHandler: true,
				InitialTarget:        "app-01",
				ExternalMsgs:         extMsgs,
				TerminalHooks: tui.TerminalHooks{
					OnEnter:   func() error { rec("enter"); return nil },
					OnRelease: func() error { rec("release"); return nil },
					OnRestore: func() error { rec("restore"); return nil },
				},
				OnTakeover: func(tCtx context.Context, _ tui.TakeoverRequest) error {
					rec("takeover")
					takeoverStarted <- struct{}{}
					<-tCtx.Done()
					return tCtx.Err()
				},
			})
			return nil
		}); err != nil {
			return err
		}

		<-eng.listCalledCh
		// 向 SystemBus 实时投递诊断事件，验证总线订阅者活跃工作无阻塞。
		diag, dErr := events.NewDiagnosticEvent(events.DiagnosticSpec{
			Meta: mustTestMeta(t, false), Scope: events.DiagnosticScopeRuntime, Severity: events.SeverityInfo, Code: "ok", Message: "live",
		})
		if dErr == nil {
			_ = eng.bus.Publish(diag)
		}
		extMsgs <- tea.KeyPressMsg{Code: tea.KeyEnter}
		<-takeoverStarted
		cancel()
		return nil
	})
	if err != nil {
		t.Fatalf("conc.RunWait: %v", err)
	}
	if runErr := <-runErrCh; !errors.Is(runErr, context.Canceled) {
		t.Fatalf("takeover 期间取消 ctx 期望返回 context.Canceled，实际=%v", runErr)
	}
	mu.Lock()
	got := slices.Clone(hooks)
	mu.Unlock()
	want := []string{"enter", "release", "takeover", "restore"}
	if !slices.Equal(got, want) {
		t.Fatalf("takeover 取消终端钩子顺序异常: got=%v want=%v", got, want)
	}
}
