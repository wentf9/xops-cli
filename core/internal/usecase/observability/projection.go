package observability

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/events"
)

// ringBuf 是固定容量的泛型环形队列，O(1) 覆盖最旧记录以防止长时运行内存无界增长。
type ringBuf[T any] struct {
	items           []T
	cap, head, size int
}

func newRingBuf[T any](capacity int) ringBuf[T] {
	return ringBuf[T]{items: make([]T, capacity), cap: capacity}
}
func (r *ringBuf[T]) push(v T) {
	if r.cap <= 0 {
		return
	}
	if r.size < r.cap {
		r.items[(r.head+r.size)%r.cap] = v
		r.size++
		return
	}
	r.items[r.head] = v
	r.head = (r.head + 1) % r.cap
}
func (r *ringBuf[T]) snapshot() []T {
	if r.size == 0 {
		return nil
	}
	out := make([]T, r.size)
	for i := range r.size {
		out[i] = r.items[(r.head+i)%r.cap]
	}
	return out
}

// Projection 是面向 Phase 5 entry/tui 与诊断面板的实时状态投影聚合器（ADR-010 / Plan P3-T4）：
//   - 受 core/conc.Nursery 全程监督消费 SystemBus 与多条 OperationStream（0 裸 go、0 goroutine 泄漏）；
//   - 穷尽消费全部 12 类封闭 events.Event 变体，单调锁存 GateHalted / OutcomeUnknown 告警位；
//   - 提供无锁竞态不可变 Snapshot() 与纯事件驱动 WaitUpdate()（0 轮询、0 time.Sleep）。
//
//xops:opaque
//xops:failclosed
type Projection struct {
	nursery                       *conc.Nursery
	sub                           *events.SystemSubscription
	maxOps, maxMetrics            int
	mu                            sync.Mutex
	initialized, closed           bool
	gateHalted, hasUnknownOutcome bool
	version, totalEvents, dropped uint64
	activeStreams                 int
	notifyCh                      chan struct{}
	opOrder, metricKeys           []string
	ops                           map[string]*OperationView
	metrics                       map[string]MetricPoint
	logs                          ringBuf[LogEntry]
	diags                         ringBuf[DiagnosticRecord]
	poolEvents                    ringBuf[PoolRecord]
	closeOnce                     sync.Once
}

// NewProjection 校验缓冲配置并在 core/conc.Nursery 监督下启动 SystemBus 消费投影。
func NewProjection(ctx context.Context, cfg ProjectionConfig) (*Projection, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if cfg.SystemBus != nil && cfg.SystemBus.IsClosed() {
		return nil, fmt.Errorf("%w: SystemBus 未初始化或已关闭", ErrInvalidConfig)
	}
	busBuf, maxLogs, maxDiags, maxPool, maxOps, maxMet, err := normalizeProjectionCaps(cfg)
	if err != nil {
		return nil, err
	}
	nursery, err := conc.NewNursery(ctx)
	if err != nil {
		return nil, err
	}
	var sub *events.SystemSubscription
	if cfg.SystemBus != nil {
		if sub, err = cfg.SystemBus.SubscribeWithBuffer(busBuf); err != nil {
			_ = nursery.Close()
			return nil, err
		}
	}
	p := &Projection{
		nursery: nursery, sub: sub, maxOps: maxOps, maxMetrics: maxMet,
		initialized: true, notifyCh: make(chan struct{}),
		ops: make(map[string]*OperationView, min(maxOps, 64)), metrics: make(map[string]MetricPoint, min(maxMet, 64)),
		logs: newRingBuf[LogEntry](maxLogs), diags: newRingBuf[DiagnosticRecord](maxDiags), poolEvents: newRingBuf[PoolRecord](maxPool),
	}
	if sub != nil {
		if err := nursery.Go(func(wCtx context.Context) error { p.consumeSystemBus(wCtx, sub); return nil }); err != nil {
			sub.Close()
			_ = nursery.Close()
			return nil, err
		}
	}
	return p, nil
}

func normalizeProjectionCaps(cfg ProjectionConfig) (busBuf, maxLogs, maxDiags, maxPool, maxOps, maxMet int, err error) {
	busBuf = pickIf(cfg.BusBuffer == 0, defaultProjectionBusBuf, cfg.BusBuffer)
	maxLogs = pickIf(cfg.MaxLogEntries == 0, defaultProjectionLogs, cfg.MaxLogEntries)
	maxDiags = pickIf(cfg.MaxDiagnostics == 0, defaultProjectionDiags, cfg.MaxDiagnostics)
	maxPool = pickIf(cfg.MaxPoolEvents == 0, defaultProjectionPoolEvs, cfg.MaxPoolEvents)
	maxOps = pickIf(cfg.MaxOperations == 0, defaultProjectionOps, cfg.MaxOperations)
	maxMet = pickIf(cfg.MaxMetrics == 0, defaultProjectionMetrics, cfg.MaxMetrics)
	for _, n := range [...]int{busBuf, maxLogs, maxDiags, maxPool, maxOps, maxMet} {
		if n < 1 || n > maxProjectionBufferCap {
			return 0, 0, 0, 0, 0, 0, fmt.Errorf("%w: Projection 缓冲容量 %d 须落在 [1, %d]", ErrInvalidConfig, n, maxProjectionBufferCap)
		}
	}
	return busBuf, maxLogs, maxDiags, maxPool, maxOps, maxMet, nil
}

// AttachOperationStream 将单次用例调用的隔离 OperationStream 挂载至本 Projection 异步排空消费。
func (p *Projection) AttachOperationStream(stream *events.OperationStream) error {
	if p == nil || !p.initialized {
		return ErrProjectionClosed
	}
	if stream == nil {
		return fmt.Errorf("%w: OperationStream 不能为 nil", ErrInvalidRequest)
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return ErrProjectionClosed
	}
	p.activeStreams++
	p.bumpLocked()
	p.mu.Unlock()
	if err := p.nursery.Go(func(wCtx context.Context) error {
		defer p.onStreamDetached()
		for {
			ev, ok, err := stream.Next(wCtx)
			if err != nil || !ok {
				return nil
			}
			_ = p.ApplyEvent(ev)
		}
	}); err != nil {
		p.onStreamDetached()
		return err
	}
	return nil
}

func (p *Projection) onStreamDetached() {
	p.mu.Lock()
	if p.activeStreams > 0 {
		p.activeStreams--
	}
	p.bumpLocked()
	p.mu.Unlock()
}

func (p *Projection) consumeSystemBus(ctx context.Context, sub *events.SystemSubscription) {
	for {
		ev, ok, err := sub.Next(ctx)
		if delta := sub.DrainDroppedDelta(); delta > 0 {
			p.mu.Lock()
			p.dropped += delta
			p.bumpLocked()
			p.mu.Unlock()
		}
		if err != nil || !ok {
			return
		}
		_ = p.ApplyEvent(ev)
	}
}

// ApplyEvent 将单条有效封闭 events.Event 同步投影至内部有界视图，穷尽覆盖全部 12 类事件并 fail-closed 拒绝未知变体。
func (p *Projection) ApplyEvent(ev events.Event) error {
	if p == nil || !p.initialized {
		return ErrProjectionClosed
	}
	if ev == nil || !ev.IsValid() {
		return fmt.Errorf("%w: 无效事件", ErrInvalidRequest)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrProjectionClosed
	}
	if err := p.applyEventLocked(ev); err != nil {
		return err
	}
	p.totalEvents++
	p.bumpLocked()
	return nil
}

func (p *Projection) applyEventLocked(ev events.Event) error {
	switch v := ev.(type) {
	case *events.OperationStartedEvent:
		op := p.ensureOpLocked(v.Meta())
		op.Tool, op.Action, op.Summary = v.Tool(), v.Action(), v.Summary()
		return nil
	case *events.OperationCompletedEvent:
		p.applyOpCompletedLocked(v)
		return nil
	case *events.OutputChunkEvent:
		p.applyOutputChunkLocked(v)
		return nil
	case *events.StepEvent:
		p.applyStepLocked(v)
		return nil
	case *events.FSMTransitionEvent:
		op := p.ensureOpLocked(v.Meta())
		op.LastCode, op.LastMessage = v.EventName(), fmt.Sprintf("%s:%s->%s", v.Machine(), v.FromState(), v.ToState())
		return nil
	case *events.ApprovalChallengeEvent:
		op := p.ensureOpLocked(v.Meta())
		op.LastCode, op.LastMessage = "approval_challenge", v.Reason()
		return nil
	case *events.TransferProgressEvent:
		op := p.ensureOpLocked(v.Meta())
		op.LastCode, op.LastMessage = "transfer_progress", fmt.Sprintf("%s %d/%d", v.Stage(), v.BytesTransferred(), v.TotalBytes())
		return nil
	case *events.MetricSampleEvent:
		p.applyMetricSampleLocked(v)
		return nil
	case *events.AuditRecordEvent:
		if v.Stage() == events.AuditStageHalted {
			p.gateHalted = true
		}
		if out, ok := v.Outcome().Get(); ok && out != nil && out.Kind() == execution.OutcomeKindUnknown {
			p.hasUnknownOutcome = true
		}
		return nil
	case *events.PoolStateEvent:
		p.applyPoolStateLocked(v)
		return nil
	case *events.DiagnosticEvent:
		if v.Code() == "gate_halted" {
			p.gateHalted = true
		}
		p.diags.push(DiagnosticRecord{Scope: v.Scope(), Severity: v.Severity(), Code: v.Code(), Message: v.Message(), Attrs: v.Attrs(), OccurredAt: v.Meta().OccurredAt()})
		return nil
	case *events.BusDroppedEvent:
		p.dropped += v.DroppedDelta()
		return nil
	default:
		return fmt.Errorf("%w: 不支持的事件类型 %T", ErrInvalidRequest, ev)
	}
}

func (p *Projection) ensureOpLocked(meta events.EventMeta) *OperationView {
	opID := meta.TraceID().String()
	if id, ok := meta.OperationID().Get(); ok {
		opID = id.String()
	}
	if existing, ok := p.ops[opID]; ok {
		existing.UpdatedAt = meta.OccurredAt()
		if n, has := meta.NodeID().Get(); has && existing.NodeID == "" {
			existing.NodeID = n.String()
		}
		return existing
	}
	if len(p.opOrder) >= p.maxOps {
		delete(p.ops, p.opOrder[0])
		p.opOrder = p.opOrder[1:]
	}
	view := &OperationView{OperationID: opID, TraceID: meta.TraceID().String(), UpdatedAt: meta.OccurredAt()}
	if n, has := meta.NodeID().Get(); has {
		view.NodeID = n.String()
	}
	p.ops[opID] = view
	p.opOrder = append(p.opOrder, opID)
	return view
}

func (p *Projection) applyOpCompletedLocked(v *events.OperationCompletedEvent) {
	op := p.ensureOpLocked(v.Meta())
	op.Completed, op.Succeeded, op.Duration, op.LastCode, op.LastMessage = true, v.Succeeded(), v.Duration(), v.Code(), v.Message()
	if out, ok := v.Outcome().Get(); ok && out != nil && out.Kind() == execution.OutcomeKindUnknown {
		op.Unknown, p.hasUnknownOutcome = true, true
	}
}
func (p *Projection) applyOutputChunkLocked(v *events.OutputChunkEvent) {
	meta := v.Meta()
	opID, nodeID := optStringer(meta.OperationID()), optStringer(meta.NodeID())
	p.logs.push(LogEntry{
		TraceID: meta.TraceID().String(), OperationID: opID, NodeID: nodeID,
		Stream: v.Stream(), ChunkIndex: v.ChunkIndex(), Data: string(v.Data()), Truncated: v.Truncated(), OccurredAt: meta.OccurredAt(),
	})
}
func (p *Projection) applyStepLocked(v *events.StepEvent) {
	op := p.ensureOpLocked(v.Meta())
	op.LastStepID, op.LastStepStat, op.LastMessage = v.StepID().String(), v.Status().String(), v.Message()
	if out, ok := v.Outcome().Get(); ok && out != nil && out.Kind() == execution.OutcomeKindUnknown {
		op.Unknown, p.hasUnknownOutcome = true, true
	}
}
func (p *Projection) applyMetricSampleLocked(v *events.MetricSampleEvent) {
	key := v.CoalesceKey()
	if _, exists := p.metrics[key]; !exists {
		if len(p.metricKeys) >= p.maxMetrics {
			delete(p.metrics, p.metricKeys[0])
			p.metricKeys = p.metricKeys[1:]
		}
		p.metricKeys = append(p.metricKeys, key)
	}
	p.metrics[key] = MetricPoint{
		Key: key, NodeID: optStringer(v.Meta().NodeID()), Name: v.MetricName(), Unit: v.Unit(),
		Value: v.Value(), Interval: v.Interval(), Labels: v.Labels(), OccurredAt: v.Meta().OccurredAt(),
	}
}
func (p *Projection) applyPoolStateLocked(v *events.PoolStateEvent) {
	if v.Action() == events.PoolActionGateHalted {
		p.gateHalted = true
	}
	p.poolEvents.push(PoolRecord{
		Action: v.Action(), Endpoint: optStringer(v.Endpoint()), ActiveLeases: v.ActiveLeases(),
		Latency: v.Latency(), Detail: v.Detail(), OccurredAt: v.Meta().OccurredAt(),
	})
}
func optStringer[T interface{ String() string }](o algebraic.Option[T]) string {
	if v, ok := o.Get(); ok {
		return v.String()
	}
	return ""
}

func (p *Projection) bumpLocked() {
	p.version++
	close(p.notifyCh)
	p.notifyCh = make(chan struct{})
}

// Snapshot 返回当前聚合投影的无锁竞态、确定性排序不可变快照；未初始化零值失败关闭。
func (p *Projection) Snapshot() ProjectionSnapshot {
	if p == nil || !p.initialized {
		return ProjectionSnapshot{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.snapshotLocked()
}

func (p *Projection) snapshotLocked() ProjectionSnapshot {
	ops := make([]OperationView, 0, len(p.opOrder))
	for _, id := range p.opOrder {
		if v, ok := p.ops[id]; ok {
			ops = append(ops, *v)
		}
	}
	mets := make([]MetricPoint, 0, len(p.metrics))
	for _, m := range p.metrics {
		m.Labels = maps.Clone(m.Labels)
		mets = append(mets, m)
	}
	slices.SortFunc(mets, func(a, b MetricPoint) int { return cmp.Compare(a.Key, b.Key) })
	return ProjectionSnapshot{
		version: p.version, totalEvents: p.totalEvents, droppedEvents: p.dropped,
		gateHalted: p.gateHalted, hasUnknownOutcome: p.hasUnknownOutcome, activeStreams: p.activeStreams,
		operations: ops, metrics: mets, logs: p.logs.snapshot(),
		diagnostics: p.diags.snapshot(), poolEvents: p.poolEvents.snapshot(), valid: true,
	}
}

// WaitUpdate 以纯事件驱动阻塞等待投影版本号严格大于 sinceVersion，或 ctx 取消 / Projection 关闭（0 轮询）。
func (p *Projection) WaitUpdate(ctx context.Context, sinceVersion uint64) (ProjectionSnapshot, error) {
	if p == nil || !p.initialized {
		return ProjectionSnapshot{}, ErrProjectionClosed
	}
	if ctx == nil {
		return ProjectionSnapshot{}, ErrNilContext
	}
	for {
		p.mu.Lock()
		if p.version > sinceVersion {
			snap := p.snapshotLocked()
			p.mu.Unlock()
			return snap, nil
		}
		if p.closed {
			snap := p.snapshotLocked()
			p.mu.Unlock()
			return snap, ErrProjectionClosed
		}
		waitCh := p.notifyCh
		p.mu.Unlock()
		select {
		case <-waitCh:
		case <-ctx.Done():
			return ProjectionSnapshot{}, ctx.Err()
		}
	}
}

// Close 幂等关闭订阅与 Nursery，确定性排空全部后台消费协程并唤醒所有 WaitUpdate 等待者（0 goroutine 泄漏）。
func (p *Projection) Close() error {
	if p == nil || !p.initialized {
		return nil
	}
	var closeErr error
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.bumpLocked()
		p.mu.Unlock()
		if p.sub != nil {
			p.sub.Close()
		}
		p.nursery.Cancel(ErrProjectionClosed)
		closeErr = p.nursery.Close()
	})
	return closeErr
}
