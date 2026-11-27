package events

import (
	"context"
	"iter"
	"sync"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// OperationStreamConfig 定义单次操作隔离事件流 OperationStream 的初始化参数（零裸 time.Duration）。
type OperationStreamConfig struct {
	TraceID         security.TraceID     // 绑定所属链路追踪标识（必填）
	OperationID     security.OperationID // 绑定独占操作唯一标识（必填）
	OperationBuffer int                  // EventClassOperation 有界环形队列容量（必须 > 0）
	MaxCoalesceKeys int                  // EventClassProgress 未消费键上限；0 使用默认 256，负值失败关闭
}

// OperationStreamStats 提供 OperationStream 当前的不可变运行统计快照。
type OperationStreamStats struct {
	Published, Delivered, Coalesced          uint64
	BufferedOperations, PendingCoalescedKeys int
	Closed                                   bool
}

// OperationStream 是绑定单次用例调用的隔离事件流（ADR-010），0 裸 go 语句且零外部 I/O 依赖：
//   - 单操作隔离：仅接受匹配绑定 TraceID/OperationID 的 operation/progress 事件；
//   - 差异化背压：EventClassOperation 走有界环形队列 BlockWithContext，EventClassProgress 按 CoalesceKey
//     覆盖未消费最新快照（CoalesceLatest），慢渲染器绝不阻塞生产者；
//   - 终态锁存与确定性 EOF：入队 *OperationCompletedEvent 后锁存终态并拒绝后续 Emit，消费侧确保先排空
//     全部残留进度快照再交付 *OperationCompletedEvent，Close() 后排空稳定返回 (nil, false, nil)。
//
//xops:opaque
//xops:failclosed
type OperationStream struct {
	traceID         security.TraceID
	opID            security.OperationID
	opCap           int
	maxCoalesceKeys int

	mu                                              sync.Mutex
	initialized, closed, completed, preferCoalesced bool
	opQueue                                         []Event
	opHead, opCount                                 int
	coalOrder                                       []string
	coalLatest                                      map[string]Event
	dataReady, spaceReady                           chan struct{}
	publishedTotal, deliveredTotal, coalN           uint64
}

// NewOperationStream 校验绑定标识与缓冲配置，创建并初始化一个 OperationStream。
func NewOperationStream(cfg OperationStreamConfig) (*OperationStream, error) {
	if !cfg.TraceID.IsValid() || !cfg.OperationID.IsValid() || cfg.OperationBuffer <= 0 || cfg.MaxCoalesceKeys < 0 {
		return nil, fieldErr(ErrInvalidStreamConfig, "operation_stream_config")
	}
	return &OperationStream{
		traceID: cfg.TraceID, opID: cfg.OperationID, opCap: cfg.OperationBuffer,
		maxCoalesceKeys: pickIf(cfg.MaxCoalesceKeys == 0, defaultMaxCoalesceKeys, cfg.MaxCoalesceKeys),
		initialized:     true, opQueue: make([]Event, cfg.OperationBuffer), coalLatest: make(map[string]Event),
		dataReady: make(chan struct{}), spaceReady: make(chan struct{}),
	}, nil
}

func (s *OperationStream) TraceID() security.TraceID {
	if s == nil || !s.initialized {
		return zeroVal[security.TraceID]()
	}
	return s.traceID
}
func (s *OperationStream) OperationID() security.OperationID {
	if s == nil || !s.initialized {
		return zeroVal[security.OperationID]()
	}
	return s.opID
}

// Emit 按事件类别背压策略向操作流投递事件；严守锁纪律，绝不持锁调用外部 ctx.Err()。
func (s *OperationStream) Emit(ctx context.Context, ev Event) error {
	if err := s.validateEmitInput(ctx, ev); err != nil {
		return err
	}
	switch ev.Backpressure() {
	case BackpressureCoalesceLatest:
		return s.emitCoalesced(ctx, ev)
	case BackpressureBlockWithContext:
		return s.emitBlocking(ctx, ev)
	default:
		return domi18n.EF(ErrUnsupportedEventClass, domi18n.KeyCommonNotSupported, domi18n.Str("feature", ev.Backpressure().String()))
	}
}

func (s *OperationStream) validateEmitInput(ctx context.Context, ev Event) error {
	if s == nil || !s.initialized {
		return ErrStreamNotInitialized
	}
	if ctx == nil {
		return ErrNilContext
	}
	if ev == nil || !ev.IsValid() {
		return ErrInvalidEvent
	}
	if cls := ev.Class(); cls != EventClassOperation && cls != EventClassProgress {
		return domi18n.EF(ErrUnsupportedEventClass, domi18n.KeyEventsClassMismatch, domi18n.Str("expected", "operation/progress"), domi18n.Str("actual", cls.String()))
	}
	meta := ev.Meta()
	if opID, ok := meta.OperationID().Get(); !meta.TraceID().Equal(s.traceID) || !ok || !opID.Equal(s.opID) {
		return fieldErr(ErrOperationMismatch, "trace_id/operation_id")
	}
	return nil
}

func (s *OperationStream) emitCoalesced(ctx context.Context, ev Event) error {
	if s.IsClosed() {
		return ErrStreamClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	key := ev.CoalesceKey()
	if key == "" {
		key = ev.Kind().String()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStreamClosed
	}
	if s.completed {
		return domi18n.EF(ErrInvalidEvent, domi18n.KeyCommonStateForbidden, domi18n.Str("action", "emit"), domi18n.Str("state", "completed"))
	}
	s.upsertCoalescedLocked(key, ev)
	s.publishedTotal++
	s.notifyDataLocked()
	return nil
}

func (s *OperationStream) upsertCoalescedLocked(key string, ev Event) {
	if _, exists := s.coalLatest[key]; exists {
		s.coalLatest[key] = ev
		s.coalN++
		return
	}
	if len(s.coalLatest) >= s.maxCoalesceKeys && len(s.coalOrder) > 0 {
		s.popCoalKeyLocked()
		s.coalN++
	}
	s.coalOrder = append(s.coalOrder, key)
	s.coalLatest[key] = ev
}

func (s *OperationStream) emitBlocking(ctx context.Context, ev Event) error {
	for {
		if s.IsClosed() {
			return ErrStreamClosed
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		waitCh, done, err := s.tryEnqueueOp(ev)
		if done || err != nil {
			return err
		}
		select {
		case <-waitCh:
		case <-ctx.Done():
			if s.IsClosed() {
				return ErrStreamClosed
			}
			return ctx.Err()
		}
	}
}

func (s *OperationStream) tryEnqueueOp(ev Event) (<-chan struct{}, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, true, ErrStreamClosed
	}
	if s.completed {
		return nil, true, domi18n.EF(ErrInvalidEvent, domi18n.KeyCommonStateForbidden, domi18n.Str("action", "emit"), domi18n.Str("state", "completed"))
	}
	if s.opCount < s.opCap {
		s.opQueue[(s.opHead+s.opCount)%s.opCap] = ev
		s.opCount++
		s.publishedTotal++
		if ev.Kind() == EventKindOperationCompleted {
			s.completed = true
			s.notifySpaceLocked()
		}
		s.notifyDataLocked()
		return nil, true, nil
	}
	return s.spaceReady, false, nil
}

// Next 读取下一条事件；流关闭且全部已入队事件与最新进度快照排空后，稳定返回 (nil, false, nil) 确定性 EOF。
func (s *OperationStream) Next(ctx context.Context) (Event, bool, error) {
	if s == nil || !s.initialized {
		return nil, false, ErrStreamNotInitialized
	}
	if ctx == nil {
		return nil, false, ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	for {
		ev, ok, eof, waitCh := s.tryPopNext()
		if ok || eof {
			return ev, ok, nil
		}
		select {
		case <-waitCh:
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
}

func (s *OperationStream) tryPopNext() (Event, bool, bool, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hasOp, hasCoal := s.opCount > 0, len(s.coalOrder) > 0
	if hasOp || hasCoal {
		s.deliveredTotal++
		// 队首为终态 OperationCompletedEvent 时优先排空全部残留进度快照，确保完成事件确定性落于 EOF 前最后一位。
		if hasCoal && (!hasOp || s.preferCoalesced || s.opQueue[s.opHead].Kind() == EventKindOperationCompleted) {
			s.preferCoalesced = false
			return s.popCoalKeyLocked(), true, false, nil
		}
		s.preferCoalesced = true
		return s.popOpLocked(), true, false, nil
	}
	if s.closed {
		return nil, false, true, nil
	}
	return nil, false, false, s.dataReady
}

func (s *OperationStream) popOpLocked() Event {
	ev := s.opQueue[s.opHead]
	// 立即清零出队槽位指针，避免已消费事件被底层环形切片长期滞留。
	s.opQueue[s.opHead] = nil
	s.opHead = (s.opHead + 1) % s.opCap
	s.opCount--
	s.notifySpaceLocked()
	return ev
}

func (s *OperationStream) popCoalKeyLocked() Event {
	key := s.coalOrder[0]
	copy(s.coalOrder, s.coalOrder[1:])
	s.coalOrder[len(s.coalOrder)-1] = ""
	s.coalOrder = s.coalOrder[:len(s.coalOrder)-1]
	ev := s.coalLatest[key]
	delete(s.coalLatest, key)
	return ev
}

// All 返回适配 Go 1.27 range-over-func 的延迟顺序迭代视图，持续产出事件直至确定性 EOF 或 ctx 取消。
func (s *OperationStream) All(ctx context.Context) iter.Seq2[Event, error] {
	return iterNextStream(ctx, s.Next)
}

// Close、IsClosed 与 Stats 提供操作流幂等关闭、状态查询及线程安全运行统计（零值恒返回 Closed=true）。
func (s *OperationStream) Close() {
	if s == nil || !s.initialized {
		return
	}
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.dataReady)
		close(s.spaceReady)
	}
	s.mu.Unlock()
}
func (s *OperationStream) IsClosed() bool {
	if s == nil || !s.initialized {
		return true
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	return closed
}
func (s *OperationStream) Stats() OperationStreamStats {
	if s == nil || !s.initialized {
		return OperationStreamStats{Closed: true}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return OperationStreamStats{s.publishedTotal, s.deliveredTotal, s.coalN, s.opCount, len(s.coalLatest), s.closed}
}

func (s *OperationStream) notifyDataLocked() {
	if !s.closed {
		close(s.dataReady)
		s.dataReady = make(chan struct{})
	}
}
func (s *OperationStream) notifySpaceLocked() {
	if !s.closed {
		close(s.spaceReady)
		s.spaceReady = make(chan struct{})
	}
}
