package pool

import (
	"context"
	"math"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
)

type poolEventInput struct {
	traceID      security.TraceID
	opID         algebraic.Option[security.OperationID]
	action       events.PoolEventAction
	planDigest   algebraic.Option[plan.PlanDigest]
	hopDigest    algebraic.Option[plan.HopDigest]
	endpoint     algebraic.Option[netaddr.Endpoint]
	handleKind   algebraic.Option[plan.HandleKindCode]
	handleID     algebraic.Option[plan.HandleID]
	generation   uint64
	activeLeases int
	latency      time.Duration
	detail       string
}

func traceFromContextOrDefault(ctx context.Context, fallback security.TraceID) (security.TraceID, algebraic.Option[security.OperationID]) {
	if tid, oid, ok := trace.TraceFromContext(ctx); ok {
		if !tid.IsValid() {
			tid = fallback
		}
		if oid.IsValid() {
			return tid, algebraic.Some(oid)
		}
		return tid, algebraic.None[security.OperationID]()
	}
	return fallback, algebraic.None[security.OperationID]()
}

// emitPoolEvent 以非阻塞 DropAndCount 语义向可选 SystemBus 发布一条脱敏连接池状态事件。
// 当未挂载 SystemBus 时直接零分配返回，保障数据面与高频控制操作零额外开销。
func (p *Pool) emitPoolEvent(in poolEventInput) {
	if p == nil || p.bus == nil {
		return
	}
	tid := in.traceID
	if !tid.IsValid() {
		tid = p.poolTraceID
	}
	meta, err := events.NewEventMeta(events.EventMetaSpec{
		TraceID:     tid,
		OperationID: in.opID,
		OccurredAt:  p.clock.Now().UTC(),
		Seq:         p.eventSeq.Add(1),
		NodeID:      algebraic.None[inventory.NodeID](),
	})
	if err != nil {
		return
	}
	lat := in.latency
	if lat < 0 {
		lat = 0
	}
	ev, err := events.NewPoolStateEvent(events.PoolStateSpec{
		Meta:         meta,
		Action:       in.action,
		PlanDigest:   in.planDigest,
		HopDigest:    in.hopDigest,
		Endpoint:     in.endpoint,
		HandleKind:   in.handleKind,
		HandleID:     in.handleID,
		Generation:   in.generation,
		ActiveLeases: clampUint32(in.activeLeases),
		Latency:      algebraic.FromStdDuration(lat),
		Detail:       in.detail,
	})
	if err != nil {
		return
	}
	// SystemBus 属于 DropAndCount 非阻塞观测面，池运行期忽略关闭/丢弃状态而不阻断控制路径。
	_ = p.bus.Publish(ev)
}

func (p *Pool) emitDiagnostic(sev events.Severity, code, msg string) {
	if p == nil || p.bus == nil {
		return
	}
	meta, err := events.NewEventMeta(events.EventMetaSpec{
		TraceID:    p.poolTraceID,
		OccurredAt: p.clock.Now().UTC(),
		Seq:        p.eventSeq.Add(1),
	})
	if err != nil {
		return
	}
	ev, err := events.NewDiagnosticEvent(events.DiagnosticSpec{
		Meta:     meta,
		Scope:    events.DiagnosticScopePool,
		Severity: sev,
		Code:     code,
		Message:  msg,
	})
	if err != nil {
		return
	}
	_ = p.bus.Publish(ev)
}

func clampUint32(n int) uint32 {
	if n <= 0 {
		return 0
	}
	if uint64(n) > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n)
}
