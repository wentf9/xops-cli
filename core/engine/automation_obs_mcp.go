package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime"
	mcptools "github.com/wentf9/xops-cli/core/internal/mcpruntime/tools"
	ucauto "github.com/wentf9/xops-cli/core/internal/usecase/automation"
	ucobs "github.com/wentf9/xops-cli/core/internal/usecase/observability"
)

// toAutoTargetNodes 将公开 ResolvedTarget 切片直接转换为 automation.TargetNode：
// 托管目标直接消费解析期快照的不可变 Tags 与 DefaultProfile，严禁隐式二次 ListNodes 门控与幽灵审计。
func toAutoTargetNodes(targets []ResolvedTarget) ([]ucauto.TargetNode, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	out := make([]ucauto.TargetNode, 0, len(targets))
	for i, t := range targets {
		if !t.IsValid() {
			return nil, fmt.Errorf("%w: targets[%d] 无效", ErrInvalidRequest, i)
		}
		nid, err := mcptools.SynthesizeTargetNodeID(t.NodeID(), t.OriginKind(), t.Plan())
		if err != nil {
			return nil, fmt.Errorf("%w: targets[%d] 节点标识 %q 非法: %w", ErrInvalidRequest, i, t.NodeID(), err)
		}
		spec := ucauto.TargetNodeSpec{NodeID: nid, Plan: t.Plan()}
		if t.OriginKind() == option.OriginManaged {
			spec.Tags, spec.DefaultProfile = t.Tags(), t.DefaultProfile()
		}
		tn, err := ucauto.NewTargetNode(spec)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
		}
		out = append(out, tn)
	}
	return out, nil
}

// BatchExec / RunPlaybook 执行受 Nursery 监督的跨节点批量命令与 Playbook 编排，并在全路径确保事件流确定性 EOF。
func (e *Engine) BatchExec(ctx context.Context, req BatchExecRequest) (BatchExecReport, error) {
	defer closeOpStreams(req.OperationStream, req.NodeStreams)
	return runOp(e, ctx, func(c context.Context) (BatchExecReport, error) {
		nodes, err := toAutoTargetNodes(req.Targets)
		if err != nil {
			return zeroVal[BatchExecReport](), err
		}
		return e.automation.BatchExec(c, ucauto.BatchExecRequest{
			Targets: nodes, Selector: req.Selector, CLIOptions: req.CLIOptions, ExcludeNodes: req.ExcludeNodes, ExcludeTags: req.ExcludeTags,
			Command: req.Command, Concurrency: req.Concurrency, MaxOutputBytes: req.MaxOutputBytes, OutputDir: req.OutputDir, FailFast: req.FailFast,
			Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream, NodeStreams: req.NodeStreams, NodeStreamFactory: req.NodeStreamFactory,
		})
	})
}
func (e *Engine) RunPlaybook(ctx context.Context, req PlaybookRequest) (PlaybookRunResult, error) {
	defer closeOpStreams(req.OperationStream, req.NodeStreams)
	return runOp(e, ctx, func(c context.Context) (PlaybookRunResult, error) {
		nodes, err := toAutoTargetNodes(req.Targets)
		if err != nil {
			return zeroVal[PlaybookRunResult](), err
		}
		return e.automation.RunPlaybook(c, ucauto.PlaybookRequest{
			Playbook: req.Playbook, Targets: nodes, CLIOptions: req.CLIOptions, DefaultProfile: req.DefaultProfile,
			ScopedSourceRoot: req.ScopedSourceRoot, Concurrency: req.Concurrency, Timeout: req.Timeout, ExtraVars: req.ExtraVars,
			Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream, NodeStreams: req.NodeStreams, NodeStreamFactory: req.NodeStreamFactory,
		})
	})
}

// StreamMetrics / StreamLogs / ExecuteGUI / OpenGUISession / InspectGUISession / CloseGUISession 暴露可观测性与 GUI 能力。
func (e *Engine) StreamMetrics(ctx context.Context, req MetricsStreamRequest) (MetricsStreamResult, error) {
	return runTargetOp(e, ctx, req.RemoteCall, func(c context.Context, r ResolvedTarget) (MetricsStreamResult, error) {
		return e.observability.StreamMetrics(c, ucobs.MetricsStreamRequest{Plan: r.Plan(), NodeID: r.NodeID(), Profile: req.Profile, Interval: req.Interval, MaxSamples: req.MaxSamples, TopProcesses: req.TopProcesses, SortBy: req.SortBy, Timeout: req.Timeout, OnFrame: req.OnFrame, Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream})
	})
}
func (e *Engine) StreamLogs(ctx context.Context, req LogStreamRequest) (LogStreamResult, error) {
	return runTargetOp(e, ctx, req.RemoteCall, func(c context.Context, r ResolvedTarget) (LogStreamResult, error) {
		return e.observability.StreamLogs(c, ucobs.LogStreamRequest{Plan: r.Plan(), NodeID: r.NodeID(), Profile: req.Profile, Target: req.Target, TailLines: req.TailLines, Follow: req.Follow, MaxBytes: req.MaxBytes, Timeout: req.Timeout, Output: req.Output, Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream})
	})
}
func (e *Engine) ExecuteGUI(ctx context.Context, req GUIExecRequest) (GUIExecResult, error) {
	return runTargetOp(e, ctx, req.RemoteCall, func(c context.Context, r ResolvedTarget) (GUIExecResult, error) {
		return e.observability.ExecuteGUI(c, ucobs.GUIExecRequest{Plan: r.Plan(), NodeID: r.NodeID(), Profile: req.Profile, Spec: req.Spec, Artifact: req.Artifact, Timeout: req.Timeout, Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream})
	})
}
func (e *Engine) OpenGUISession(ctx context.Context, req OpenGUISessionRequest) (GUISessionInfo, error) {
	return runTargetOp(e, ctx, req.RemoteCall, func(c context.Context, r ResolvedTarget) (GUISessionInfo, error) {
		return e.observability.OpenGUISession(c, ucobs.OpenGUISessionRequest{Plan: r.Plan(), NodeID: r.NodeID(), Spec: req.Spec, Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream})
	})
}
func (e *Engine) InspectGUISession(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel]) (GUISessionStatus, error) {
	return runOp(e, ctx, func(c context.Context) (GUISessionStatus, error) { return e.observability.InspectGUISession(c, handle) })
}
func (e *Engine) CloseGUISession(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel]) error {
	return runOpErr(e, ctx, func(c context.Context) error { return e.observability.CloseGUISession(c, handle) })
}
func registerChild[T comparable](e *Engine, m map[T]struct{}, item T, rollback func()) error {
	e.opMu.Lock()
	if e.closing {
		e.opMu.Unlock()
		rollback()
		return ErrEngineClosed
	}
	m[item] = struct{}{}
	e.opMu.Unlock()
	return nil
}
func unregisterChild[T comparable](e *Engine, m map[T]struct{}, item T) {
	if e != nil {
		e.opMu.Lock()
		delete(m, item)
		e.opMu.Unlock()
	}
}
func (e *Engine) checkReadyForChild() error {
	if e == nil || !e.initialized {
		return ErrEngineNotInitialized
	}
	if e.IsClosed() {
		return ErrEngineClosed
	}
	return nil
}

// Projection 封装面向 Phase 5 entry/tui 的实时事件投影聚合器，自动纳入 Engine.Close 逆序关闭管理；零值恒失败关闭。
//
//xops:opaque
//xops:failclosed
type Projection struct {
	eng   *Engine
	inner *ucobs.Projection
	valid bool
}

// NewProjection 构造绑定至 Engine.SystemBus 的实时事件投影聚合器，并登记至 Engine 逆序关闭列表（早于 SystemBus.Close 排空）。
func (e *Engine) NewProjection(ctx context.Context, cfg ProjectionConfig) (*Projection, error) {
	if err := e.checkReadyForChild(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, ErrNilContext
	}
	if cfg.SystemBus == nil {
		cfg.SystemBus = e.bus
	}
	p, err := ucobs.NewProjection(ctx, cfg)
	if err != nil {
		return nil, mapEngineError(err)
	}
	proj := &Projection{eng: e, inner: p, valid: true}
	if err = registerChild(e, e.projections, proj, func() { _ = p.Close() }); err != nil {
		return nil, err
	}
	return proj, nil
}

// AttachOperationStream / Snapshot / WaitUpdate / Close 提供事件投影只读快照、阻塞等待与幂等关闭。
func (p *Projection) AttachOperationStream(s *events.OperationStream) error {
	return runChildErr(p != nil && p.valid, ErrProjectionNotInitialized, func() error { return p.inner.AttachOperationStream(s) })
}
func (p *Projection) Snapshot() ProjectionSnapshot {
	if p == nil || !p.valid {
		return zeroVal[ProjectionSnapshot]()
	}
	return p.inner.Snapshot()
}
func (p *Projection) WaitUpdate(ctx context.Context, sinceVersion uint64) (ProjectionSnapshot, error) {
	return runChildVal(p != nil && p.valid, ErrProjectionNotInitialized, func() (ProjectionSnapshot, error) { return p.inner.WaitUpdate(ctx, sinceVersion) })
}
func (p *Projection) Close() error {
	return runChildErr(p != nil && p.valid, ErrProjectionNotInitialized, func() error {
		unregisterChild(p.eng, p.eng.projections, p)
		return p.inner.Close()
	})
}

// MCPServer 是由 Engine 派生的公开 MCP 运行时门面（供 entry/mcpcmd 与外部 xops-mcp 消费）；
// 物理仅接收沙箱隔离的 ScopedRootFS 与 0 OperatorReadFS 服务，且自动纳入 Engine.Close 逆序停机管理。
//
//xops:opaque
//xops:failclosed
type MCPServer struct {
	eng   *Engine
	inner *mcpruntime.Server
	valid bool
}

// NewMCPServer 从 Engine 装配并登记受沙箱隔离（0 OperatorReadFS）的 MCPServer 实例。
func (e *Engine) NewMCPServer(cfg MCPConfig) (*MCPServer, error) {
	if err := e.checkReadyForChild(); err != nil {
		return nil, err
	}
	inner, err := mcpruntime.NewServer(mcpruntime.ServerConfig{
		Gate: e.gate, ReconcileAudits: e.gate.ReconcileCrashedAudits, AllowOptionalReconciler: cfg.AllowOptionalReconciler,
		Inventory: e.inventory, Session: e.session, Transfer: e.mcpTransfer, Automation: e.mcpAutomation,
		Observability: e.observability, ScopedFS: e.scopedFS, TransferRoot: cfg.TransferRoot, ArtifactRoot: cfg.ArtifactRoot,
		Clock: e.clock, Entropy: e.entropy, SystemBus: e.bus, ServerName: cfg.ServerName, ServerVersion: cfg.ServerVersion,
		Instructions: cfg.Instructions, MaxMessageBytes: cfg.MaxMessageBytes, MaxTrackedHandles: cfg.MaxTrackedHandles,
		HTTPChunkSize: cfg.HTTPChunkSize, MaxHTTPSessions: cfg.MaxHTTPSessions, AllowNonLoopbackHTTP: cfg.AllowNonLoopbackHTTP,
		HTTPAllowedOrigins: cfg.HTTPAllowedOrigins, HTTPAllowedHosts: cfg.HTTPAllowedHosts,
		HTTPReadHeaderTimeout: cfg.HTTPReadHeaderTimeout, HTTPShutdownTimeout: cfg.HTTPShutdownTimeout,
		PruneSupersededJournals: cfg.PruneSupersededJournals, FailOnCorruptJournal: cfg.FailOnCorruptJournal,
	})
	if err != nil {
		return nil, mapEngineError(err)
	}
	srv := &MCPServer{eng: e, inner: inner, valid: true}
	if err = registerChild(e, e.mcpServers, srv, func() { _ = inner.Close(context.Background()) }); err != nil {
		return nil, err
	}
	return srv, nil
}

// Prepare / ServeStdio / ServeHTTPListener / ListenAndServeHTTP / Handler / HandleMessage / StartupReport / IsClosed / Close。
func (s *MCPServer) Prepare(ctx context.Context) (MCPStartupReport, error) {
	return runChildVal(s != nil && s.valid, ErrMCPServerNotInitialized, func() (MCPStartupReport, error) { return s.inner.Prepare(ctx) })
}
func (s *MCPServer) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	return runChildErr(s != nil && s.valid, ErrMCPServerNotInitialized, func() error { return s.inner.ServeStdio(ctx, in, out) })
}
func (s *MCPServer) ServeHTTPListener(ctx context.Context, ln net.Listener) error {
	return runChildErr(s != nil && s.valid, ErrMCPServerNotInitialized, func() error { return s.inner.ServeHTTPListener(ctx, ln) })
}
func (s *MCPServer) ListenAndServeHTTP(ctx context.Context, addr string) error {
	return runChildErr(s != nil && s.valid, ErrMCPServerNotInitialized, func() error { return s.inner.ListenAndServeHTTP(ctx, addr) })
}
func (s *MCPServer) Handler() http.Handler {
	if s == nil || !s.valid {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	}
	return s.inner.Handler()
}
func (s *MCPServer) HandleMessage(ctx context.Context, raw []byte) ([]byte, bool, error) {
	if s == nil || !s.valid {
		return nil, false, ErrMCPServerNotInitialized
	}
	resp, ok, err := s.inner.HandleMessage(ctx, raw)
	return resp, ok, mapEngineError(err)
}
func (s *MCPServer) StartupReport() MCPStartupReport {
	if s == nil || !s.valid {
		return zeroVal[MCPStartupReport]()
	}
	return s.inner.StartupReport()
}
func (s *MCPServer) IsClosed() bool { return s == nil || !s.valid || s.inner.IsClosed() }
func (s *MCPServer) Close(ctx context.Context) error {
	return runChildErr(s != nil && s.valid, ErrMCPServerNotInitialized, func() error {
		unregisterChild(s.eng, s.eng.mcpServers, s)
		return s.inner.Close(ctx)
	})
}

//xops:syncclosure
func runChildVal[T any](ready bool, notInitErr error, fn func() (T, error)) (T, error) {
	if !ready {
		return zeroVal[T](), notInitErr
	}
	return mapRes(fn())
}

//xops:syncclosure
func runChildErr(ready bool, notInitErr error, fn func() error) error {
	_, err := runChildVal(ready, notInitErr, func() (struct{}, error) { return struct{}{}, fn() })
	return err
}
