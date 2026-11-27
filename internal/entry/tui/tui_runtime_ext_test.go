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
	mu               sync.Mutex
	hosts            []inventory.Host
	idents           []inventory.Identity
	nodes            []inventory.Node
	rev              engine.Revision
	bus              *events.SystemBus
	halted           bool
	nilOpStream      bool
	listCalledCh     chan struct{}
	metricsStart     chan string
	logsStart        chan string
	streamBlock      bool
	lastMaxSamples   int
	metricsCalls     int
	lastLogHasOutput bool
	lastLogHasStream bool
	onMetrics        func(ctx context.Context, req engine.MetricsStreamRequest) (engine.MetricsStreamResult, error)
	onLogs           func(ctx context.Context, req engine.LogStreamRequest) (engine.LogStreamResult, error)
}

func zeroVal[T any]() (z T) { return z }

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
	f.mu.Lock()
	retNil := f.nilOpStream
	f.mu.Unlock()
	if retNil {
		return nil, nil
	}
	tid, _ := security.ParseTraceID("0123456789abcdef0123456789abcdef")
	oid, _ := security.ParseOperationID("fedcba9876543210fedcba9876543210")
	return events.NewOperationStream(events.OperationStreamConfig{TraceID: tid, OperationID: oid, OperationBuffer: max(buffer, 16)})
}

// StreamMetrics 强制执行真实 observability.Service.StreamMetrics 的核心不变量：
//   - MaxSamples==0 退化为 1、超过 10000 拒绝、返回前关闭 OperationStream；
//   - 第 1 帧无前序样本 CPUPercent=0.0%，第 2 帧起返回非零增量 CPU%。
func (f *fakeEngineClient) StreamMetrics(ctx context.Context, req engine.MetricsStreamRequest) (engine.MetricsStreamResult, error) {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	maxSamples := req.MaxSamples
	if maxSamples == 0 {
		maxSamples = 1
	}
	if maxSamples < 1 || maxSamples > 10000 {
		return zeroVal[engine.MetricsStreamResult](), engine.ErrInvalidRequest
	}
	f.mu.Lock()
	f.lastMaxSamples = req.MaxSamples
	f.metricsCalls++
	f.mu.Unlock()
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
		req.OnFrame(engine.HostMetricsFrame{NodeID: req.TargetSpec, Hostname: req.TargetSpec, CPUPercent: 0.0, MemPercent: 40.0})
		if maxSamples >= 2 {
			req.OnFrame(engine.HostMetricsFrame{NodeID: req.TargetSpec, Hostname: req.TargetSpec, CPUPercent: 27.5, MemPercent: 41.0})
		}
	}
	if f.streamBlock {
		<-ctx.Done()
		return zeroVal[engine.MetricsStreamResult](), ctx.Err()
	}
	return zeroVal[engine.MetricsStreamResult](), nil
}

// StreamLogs 强制执行真实 observability.Service.StreamLogs 的核心不变量：
// 只要传入 OperationStream 即同步镜像 OutputChunkEvent，返回前关闭 OperationStream。
func (f *fakeEngineClient) StreamLogs(ctx context.Context, req engine.LogStreamRequest) (engine.LogStreamResult, error) {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	f.mu.Lock()
	f.lastLogHasOutput = req.Output != nil
	f.lastLogHasStream = req.OperationStream != nil
	f.mu.Unlock()
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
	if req.OperationStream != nil {
		emitFakeOutputChunk(req.OperationStream, "streamed remote log line\n")
	}
	if f.streamBlock {
		<-ctx.Done()
		return zeroVal[engine.LogStreamResult](), ctx.Err()
	}
	return zeroVal[engine.LogStreamResult](), nil
}

func emitFakeOutputChunk(stream *events.OperationStream, data string) {
	meta, err := events.NewEventMeta(events.EventMetaSpec{
		TraceID:     stream.TraceID(),
		OperationID: algebraic.Some(stream.OperationID()),
		OccurredAt:  time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		return
	}
	ev, err := events.NewOutputChunkEvent(events.OutputChunkSpec{
		Meta: meta, Stream: events.OutputStreamStdout, ChunkIndex: 1, Data: []byte(data),
	})
	if err == nil {
		_ = stream.Emit(context.Background(), ev)
	}
}

func (f *fakeEngineClient) SystemBus() *events.SystemBus { return f.bus }
func (f *fakeEngineClient) IsHalted() bool               { return f.halted }
func (f *fakeEngineClient) HaltInfo() (engine.HaltInfo, bool) {
	return zeroVal[engine.HaltInfo](), false
}

type fakeProjectionSource struct {
	mu       sync.Mutex
	closed   bool
	attached []*events.OperationStream
	waits    chan struct{}
	unblock  chan struct{}
}

func (p *fakeProjectionSource) AttachOperationStream(s *events.OperationStream) error {
	p.mu.Lock()
	p.attached = append(p.attached, s)
	p.mu.Unlock()
	return nil
}

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
	eng := newSampleFakeEngine(t)
	defer eng.bus.Close()
	negDur := algebraic.FromStdDuration(-time.Second)
	if err := tui.Run(context.Background(), tui.Config{
		Engine:          eng,
		MetricsInterval: algebraic.Some(negDur),
	}); !errors.Is(err, tui.ErrInvalidConfig) {
		t.Fatalf("负 MetricsInterval 期望 ErrInvalidConfig，实际=%v", err)
	}
	if err := tui.Run(context.Background(), tui.Config{
		Engine:            eng,
		MetricsMaxSamples: 10001,
	}); !errors.Is(err, tui.ErrInvalidConfig) {
		t.Fatalf("越界 MetricsMaxSamples 期望 ErrInvalidConfig，实际=%v", err)
	}
}

func TestRun_ProjectionAttachesOperationStreamsAndCtxCancel_ZeroLeaks(t *testing.T) {
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

		<-proj.waits
		<-eng.listCalledCh
		opStream.Close()
		cancel()
		return nil
	})
	if err != nil {
		t.Fatalf("conc.RunWait: %v", err)
	}
	if runErr := <-runErrCh; !errors.Is(runErr, context.Canceled) {
		t.Fatalf("ctx 取消期望返回 context.Canceled，实际=%v", runErr)
	}
	proj.mu.Lock()
	attachedN := len(proj.attached)
	proj.mu.Unlock()
	if attachedN != 1 {
		t.Fatalf("存在 Projection 时初始 OperationStream 应直接挂载至 Projection，attached=%d", attachedN)
	}
	mu.Lock()
	gotHooks := slices.Clone(eventsLog)
	mu.Unlock()
	if !slices.Equal(gotHooks, []string{"enter", "restore"}) {
		t.Fatalf("终端生命周期钩子顺序错误: got=%v", gotHooks)
	}
}

func TestRun_MetricsMaxSamplesLogsSinglePathAndTakeoverRestore_ZeroLeaks(t *testing.T) {
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

		<-eng.listCalledCh
		extMsgs <- tea.KeyPressMsg{Code: 'm', Text: "m"}
		if gotTarget := <-eng.metricsStart; gotTarget != "app-01" {
			t.Errorf("metrics 目标期望 app-01，实际=%q", gotTarget)
		}
		extMsgs <- tea.KeyPressMsg{Code: 'l', Text: "l"}
		if gotTarget := <-eng.logsStart; gotTarget != "app-01" {
			t.Errorf("logs 目标期望 app-01，实际=%q", gotTarget)
		}
		// 不先按 x 直接切入接管，验证 pass 1 排空后流状态复位（重入后按 s 切换排序绝不错误触发新 metrics 流）。
		extMsgs <- tea.KeyPressMsg{Code: '1', Text: "1"}
		extMsgs <- tea.KeyPressMsg{Code: tea.KeyEnter}
		req := <-takeoverEntered
		if req.TargetSpec != "app-01" {
			t.Errorf("接管目标期望 app-01，实际=%q", req.TargetSpec)
		}
		<-eng.listCalledCh
		extMsgs <- tea.KeyPressMsg{Code: 's', Text: "s"}
		extMsgs <- tea.KeyPressMsg{Code: 'r', Text: "r"}
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
	eng.mu.Lock()
	maxSamples, metricsCalls, hasOut, hasStream := eng.lastMaxSamples, eng.metricsCalls, eng.lastLogHasOutput, eng.lastLogHasStream
	eng.mu.Unlock()
	if maxSamples != 10000 || metricsCalls != 1 {
		t.Fatalf("runMetricsStream 期望 MaxSamples=10000 且接管后按 s 不重复启动流，实际 maxSamples=%d calls=%d", maxSamples, metricsCalls)
	}
	if hasOut || !hasStream {
		t.Fatalf("runLogsStream 在存在 OperationStream 时不得同时传 Output（防双重入队）: hasOutput=%v hasStream=%v", hasOut, hasStream)
	}
	mu.Lock()
	got := slices.Clone(hookSeq)
	mu.Unlock()
	want := []string{"enter", "release", "takeover:app-01", "enter", "restore"}
	if !slices.Equal(got, want) {
		t.Fatalf("终端接管与恢复钩子顺序失配: got=%v want=%v", got, want)
	}
}

func TestRun_TakeoverReenterFailureAbortsFailClosed_ZeroLeaks(t *testing.T) {
	defer goleak.VerifyNone(t)

	eng := newSampleFakeEngine(t)
	defer eng.bus.Close()

	reenterErr := errors.New("terminal raw mode failed")
	enterCalls := 0
	var mu sync.Mutex
	var hooks []string
	rec := func(s string) {
		mu.Lock()
		hooks = append(hooks, s)
		mu.Unlock()
	}

	extMsgs := make(chan tea.Msg, 4)
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
					OnEnter: func() error {
						enterCalls++
						rec("enter")
						if enterCalls == 2 {
							return reenterErr
						}
						return nil
					},
					OnRelease: func() error { rec("release"); return nil },
					OnRestore: func() error { rec("restore"); return nil },
				},
				OnTakeover: func(_ context.Context, _ tui.TakeoverRequest) error {
					rec("takeover")
					return nil
				},
			})
			return nil
		}); err != nil {
			return err
		}

		<-eng.listCalledCh
		extMsgs <- tea.KeyPressMsg{Code: tea.KeyEnter}
		return nil
	})
	if err != nil {
		t.Fatalf("conc.RunWait: %v", err)
	}
	if runErr := <-runErrCh; !errors.Is(runErr, reenterErr) {
		t.Fatalf("接管后重入终端失败必须中止并返回 reenterErr，实际=%v", runErr)
	}
	mu.Lock()
	got := slices.Clone(hooks)
	mu.Unlock()
	want := []string{"enter", "release", "takeover", "enter", "restore"}
	if !slices.Equal(got, want) {
		t.Fatalf("重入失败终端钩子序列错误: got=%v want=%v", got, want)
	}
}

func TestRun_LogsFallbackLineBufferNoMidLineSplit_ZeroLeaks(t *testing.T) {
	defer goleak.VerifyNone(t)

	eng := newSampleFakeEngine(t)
	eng.nilOpStream = true
	logsDone := make(chan struct{}, 1)
	eng.onLogs = func(_ context.Context, req engine.LogStreamRequest) (engine.LogStreamResult, error) {
		if req.Output == nil {
			return zeroVal[engine.LogStreamResult](), errors.New("expected fallback Output writer")
		}
		_, _ = io.WriteString(req.Output, "part1-")
		_, _ = io.WriteString(req.Output, "part2\ntrailing")
		logsDone <- struct{}{}
		return zeroVal[engine.LogStreamResult](), nil
	}
	defer eng.bus.Close()

	extMsgs := make(chan tea.Msg, 4)
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
			})
			return nil
		}); err != nil {
			return err
		}

		<-eng.listCalledCh
		extMsgs <- tea.KeyPressMsg{Code: 'l', Text: "l"}
		<-logsDone
		extMsgs <- tea.KeyPressMsg{Code: 'q', Text: "q"}
		close(extMsgs)
		return nil
	})
	if err != nil {
		t.Fatalf("conc.RunWait: %v", err)
	}
	if runErr := <-runErrCh; runErr != nil {
		t.Fatalf("Run 失败: %v", runErr)
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
