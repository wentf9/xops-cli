package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime"
	mcptools "github.com/wentf9/xops-cli/core/internal/mcpruntime/tools"
	ucauto "github.com/wentf9/xops-cli/core/internal/usecase/automation"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	ucobs "github.com/wentf9/xops-cli/core/internal/usecase/observability"
)

// toAutoTargetNodes 将公开 ResolvedTarget 切片转换为 automation.TargetNode：
// 托管目标自动从资产快照补齐 Tags 与 DefaultProfile；IPv6 与多端口 AdHoc 目标按末跳端点生成确定性合法合成 NodeID。
func (e *Engine) toAutoTargetNodes(ctx context.Context, targets []ResolvedTarget) ([]ucauto.TargetNode, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	hasManaged := false
	for i, t := range targets {
		if !t.IsValid() {
			return nil, fmt.Errorf("%w: targets[%d] 无效", ErrInvalidRequest, i)
		}
		if t.OriginKind() == option.OriginManaged {
			hasManaged = true
		}
	}
	managedByID, err := e.loadManagedNodeMap(ctx, hasManaged)
	if err != nil {
		return nil, err
	}
	out := make([]ucauto.TargetNode, 0, len(targets))
	for i, t := range targets {
		nid, nErr := mcptools.SynthesizeTargetNodeID(t.NodeID(), t.OriginKind(), t.Plan())
		if nErr != nil {
			return nil, fmt.Errorf("%w: targets[%d] 节点标识 %q 非法: %w", ErrInvalidRequest, i, t.NodeID(), nErr)
		}
		spec := ucauto.TargetNodeSpec{NodeID: nid, Plan: t.Plan()}
		if managed, ok := managedByID[nid]; ok && t.OriginKind() == option.OriginManaged {
			spec.Tags = managed.Tags()
			spec.DefaultProfile = managed.Execution()
		}
		tn, tErr := ucauto.NewTargetNode(spec)
		if tErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, tErr)
		}
		out = append(out, tn)
	}
	return out, nil
}

func (e *Engine) loadManagedNodeMap(ctx context.Context, needed bool) (map[inventory.NodeID]inventory.Node, error) {
	if !needed || e.inventory == nil {
		return nil, nil
	}
	nodes, _, err := e.inventory.ListNodes(ctx, ucinv.QueryRequest{})
	if err != nil {
		return nil, err
	}
	out := make(map[inventory.NodeID]inventory.Node, len(nodes))
	for _, n := range nodes {
		out[n.ID()] = n
	}
	return out, nil
}

// BatchExec 执行受 Nursery 监督的跨节点并发批量命令，返回确定性排序折叠报告。
func (e *Engine) BatchExec(ctx context.Context, req BatchExecRequest) (BatchExecReport, error) {
	return runOp(e, ctx, func(c context.Context) (BatchExecReport, error) {
		nodes, err := e.toAutoTargetNodes(c, req.Targets)
		if err != nil {
			return zeroVal[BatchExecReport](), err
		}
		return e.automation.BatchExec(c, ucauto.BatchExecRequest{
			Targets: nodes, Selector: req.Selector, CLIOptions: req.CLIOptions,
			ExcludeNodes: req.ExcludeNodes, ExcludeTags: req.ExcludeTags, Command: req.Command,
			Concurrency: req.Concurrency, MaxOutputBytes: req.MaxOutputBytes, OutputDir: req.OutputDir,
			FailFast: req.FailFast, Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		})
	})
}

// RunPlaybook 执行声明式 Playbook vNext 判别式 AST 与 EnsureFSM 幂等收敛。
func (e *Engine) RunPlaybook(ctx context.Context, req PlaybookRequest) (PlaybookRunResult, error) {
	return runOp(e, ctx, func(c context.Context) (PlaybookRunResult, error) {
		nodes, err := e.toAutoTargetNodes(c, req.Targets)
		if err != nil {
			return zeroVal[PlaybookRunResult](), err
		}
		return e.automation.RunPlaybook(c, ucauto.PlaybookRequest{
			Playbook: req.Playbook, Targets: nodes, CLIOptions: req.CLIOptions,
			ScopedSourceRoot: req.ScopedSourceRoot, Concurrency: req.Concurrency, Timeout: req.Timeout,
			ExtraVars: req.ExtraVars, Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		})
	})
}

// StreamMetrics / StreamLogs / ExecuteGUI / OpenGUISession / InspectGUISession / CloseGUISession 暴露可观测性与 GUI 能力。
func (e *Engine) StreamMetrics(ctx context.Context, req MetricsStreamRequest) (MetricsStreamResult, error) {
	return runTargetOp(e, ctx, req.TargetInput, func(c context.Context, r ResolvedTarget) (MetricsStreamResult, error) {
		return e.observability.StreamMetrics(c, ucobs.MetricsStreamRequest{
			Plan: r.Plan(), NodeID: r.NodeID(), Interval: req.Interval, MaxSamples: req.MaxSamples,
			TopProcesses: req.TopProcesses, SortBy: req.SortBy, Timeout: req.Timeout, OnFrame: req.OnFrame,
			Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		})
	})
}
func (e *Engine) StreamLogs(ctx context.Context, req LogStreamRequest) (LogStreamResult, error) {
	return runTargetOp(e, ctx, req.TargetInput, func(c context.Context, r ResolvedTarget) (LogStreamResult, error) {
		return e.observability.StreamLogs(c, ucobs.LogStreamRequest{
			Plan: r.Plan(), NodeID: r.NodeID(), Target: req.Target, TailLines: req.TailLines,
			Follow: req.Follow, MaxBytes: req.MaxBytes, Timeout: req.Timeout, Output: req.Output,
			Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		})
	})
}
func (e *Engine) ExecuteGUI(ctx context.Context, req GUIExecRequest) (GUIExecResult, error) {
	return runTargetOp(e, ctx, req.TargetInput, func(c context.Context, r ResolvedTarget) (GUIExecResult, error) {
		return e.observability.ExecuteGUI(c, ucobs.GUIExecRequest{
			Plan: r.Plan(), NodeID: r.NodeID(), Spec: req.Spec, Artifact: req.Artifact, Timeout: req.Timeout,
			Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		})
	})
}
func (e *Engine) OpenGUISession(ctx context.Context, req OpenGUISessionRequest) (GUISessionInfo, error) {
	return runTargetOp(e, ctx, req.TargetInput, func(c context.Context, r ResolvedTarget) (GUISessionInfo, error) {
		return e.observability.OpenGUISession(c, ucobs.OpenGUISessionRequest{
			Plan: r.Plan(), NodeID: r.NodeID(), Spec: req.Spec,
			Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		})
	})
}
func (e *Engine) InspectGUISession(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel]) (GUISessionStatus, error) {
	return runOp(e, ctx, func(c context.Context) (GUISessionStatus, error) { return e.observability.InspectGUISession(c, handle) })
}
func (e *Engine) CloseGUISession(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel]) error {
	return runOpErr(e, ctx, func(c context.Context) error { return e.observability.CloseGUISession(c, handle) })
}

// ParseGUIActionKind / ParseGUISessionKind / ParseScrollDirection / ParseProcessSortBy / NewFileLogTarget / NewDockerLogTarget。
func ParseGUIActionKind(raw string) (ucobs.GUIActionKind, error) {
	return ucobs.ParseGUIActionKind(raw)
}
func ParseGUISessionKind(raw string) (ucobs.GUISessionKind, error) {
	return ucobs.ParseGUISessionKind(raw)
}
func ParseScrollDirection(raw string) (ucobs.ScrollDirection, error) {
	return ucobs.ParseScrollDirection(raw)
}
func ParseProcessSortBy(raw string) (ProcessSortBy, error)     { return ucobs.ParseProcessSortBy(raw) }
func NewFileLogTarget(p pathalg.RemotePath) (LogTarget, error) { return ucobs.NewFileLogTarget(p) }
func NewDockerLogTarget(container string) (LogTarget, error) {
	return ucobs.NewDockerLogTarget(container)
}

// Projection 封装面向 Phase 5 entry/tui 的实时事件投影聚合器；零值恒未初始化并失败关闭。
//
//xops:opaque
//xops:failclosed
type Projection struct {
	inner *ucobs.Projection
	valid bool
}

// NewProjection 构造绑定至 Engine.SystemBus 的实时事件投影聚合器（需由调用方 Close 排空）。
func (e *Engine) NewProjection(ctx context.Context, cfg ProjectionConfig) (*Projection, error) {
	if e == nil || !e.initialized {
		return nil, ErrEngineNotInitialized
	}
	if cfg.SystemBus == nil {
		cfg.SystemBus = e.bus
	}
	p, err := ucobs.NewProjection(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Projection{inner: p, valid: true}, nil
}

func (p *Projection) AttachOperationStream(stream *events.OperationStream) error {
	if p == nil || !p.valid {
		return ErrProjectionNotInitialized
	}
	return p.inner.AttachOperationStream(stream)
}
func (p *Projection) Snapshot() ProjectionSnapshot {
	if p == nil || !p.valid {
		return zeroVal[ProjectionSnapshot]()
	}
	return p.inner.Snapshot()
}
func (p *Projection) WaitUpdate(ctx context.Context, sinceVersion uint64) (ProjectionSnapshot, error) {
	if p == nil || !p.valid {
		return zeroVal[ProjectionSnapshot](), ErrProjectionNotInitialized
	}
	return p.inner.WaitUpdate(ctx, sinceVersion)
}
func (p *Projection) Close() error {
	if p == nil || !p.valid {
		return ErrProjectionNotInitialized
	}
	return p.inner.Close()
}

// MCPServer 是由 Engine 派生的公开 MCP 运行时门面（供 entry/mcpcmd 与外部 xops-mcp 消费）；
// 物理上仅接收沙箱隔离的 ScopedRootFS 与 0 OperatorReadFS 的 Transfer/Automation 用例服务，
// 且自动纳入 Engine.Close 逆序停机管理（Entry/MCP -> UseCases -> Pool -> SystemBus）。
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
	if e == nil || !e.initialized {
		return nil, ErrEngineNotInitialized
	}
	if e.IsClosed() {
		return nil, ErrEngineClosed
	}
	inner, err := mcpruntime.NewServer(mcpruntime.ServerConfig{
		Gate: e.gate, ReconcileAudits: e.gate.ReconcileCrashedAudits, AllowOptionalReconciler: cfg.AllowOptionalReconciler,
		Inventory: e.inventory, Session: e.session, Transfer: e.mcpTransfer, Automation: e.mcpAutomation,
		Observability: e.observability, ScopedFS: e.scopedFS, TransferRoot: cfg.TransferRoot, ArtifactRoot: cfg.ArtifactRoot,
		Clock: e.clock, Entropy: e.entropy, SystemBus: e.bus,
		ServerName: cfg.ServerName, ServerVersion: cfg.ServerVersion, Instructions: cfg.Instructions,
		MaxMessageBytes: cfg.MaxMessageBytes, MaxTrackedHandles: cfg.MaxTrackedHandles,
		HTTPChunkSize: cfg.HTTPChunkSize, MaxHTTPSessions: cfg.MaxHTTPSessions,
		AllowNonLoopbackHTTP: cfg.AllowNonLoopbackHTTP, HTTPAllowedOrigins: cfg.HTTPAllowedOrigins,
		HTTPAllowedHosts: cfg.HTTPAllowedHosts, HTTPReadHeaderTimeout: cfg.HTTPReadHeaderTimeout,
		HTTPShutdownTimeout: cfg.HTTPShutdownTimeout, PruneSupersededJournals: cfg.PruneSupersededJournals,
		FailOnCorruptJournal: cfg.FailOnCorruptJournal,
	})
	if err != nil {
		return nil, err
	}
	srv := &MCPServer{eng: e, inner: inner, valid: true}
	e.opMu.Lock()
	if e.closing {
		e.opMu.Unlock()
		_ = inner.Close(context.Background())
		return nil, ErrEngineClosed
	}
	e.mcpServers[srv] = struct{}{}
	e.opMu.Unlock()
	return srv, nil
}

// Prepare / ServeStdio / ServeHTTPListener / ListenAndServeHTTP / Handler / HandleMessage / StartupReport / IsClosed / Close。
func (s *MCPServer) Prepare(ctx context.Context) (MCPStartupReport, error) {
	if err := s.checkValid(); err != nil {
		return zeroVal[MCPStartupReport](), err
	}
	rep, err := s.inner.Prepare(ctx)
	return rep, mapGateError(err)
}
func (s *MCPServer) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	return s.runErr(func() error { return s.inner.ServeStdio(ctx, in, out) })
}
func (s *MCPServer) ServeHTTPListener(ctx context.Context, ln net.Listener) error {
	return s.runErr(func() error { return s.inner.ServeHTTPListener(ctx, ln) })
}
func (s *MCPServer) ListenAndServeHTTP(ctx context.Context, addr string) error {
	return s.runErr(func() error { return s.inner.ListenAndServeHTTP(ctx, addr) })
}
func (s *MCPServer) Handler() http.Handler {
	if err := s.checkValid(); err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	}
	return s.inner.Handler()
}
func (s *MCPServer) HandleMessage(ctx context.Context, raw []byte) ([]byte, bool, error) {
	if err := s.checkValid(); err != nil {
		return nil, false, err
	}
	return s.inner.HandleMessage(ctx, raw)
}
func (s *MCPServer) StartupReport() MCPStartupReport {
	if s == nil || !s.valid {
		return zeroVal[MCPStartupReport]()
	}
	return s.inner.StartupReport()
}
func (s *MCPServer) IsClosed() bool { return s == nil || !s.valid || s.inner.IsClosed() }
func (s *MCPServer) Close(ctx context.Context) error {
	if err := s.checkValid(); err != nil {
		return err
	}
	if s.eng != nil {
		s.eng.opMu.Lock()
		delete(s.eng.mcpServers, s)
		s.eng.opMu.Unlock()
	}
	return s.inner.Close(ctx)
}

func (s *MCPServer) checkValid() error {
	if s == nil || !s.valid {
		return ErrMCPServerNotInitialized
	}
	return nil
}

//xops:syncclosure
func (s *MCPServer) runErr(fn func() error) error {
	if err := s.checkValid(); err != nil {
		return err
	}
	return mapGateError(fn())
}
