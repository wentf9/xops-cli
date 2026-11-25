package events

import (
	"context"
	"fmt"
	"iter"
	"sync"
	"sync/atomic"
)

// SystemBusConfig 定义系统诊断与连接池事件总线 SystemBus 的初始化参数（无 time.Duration）。
type SystemBusConfig struct {
	DefaultSubscriberBuffer int // Subscribe() 默认分配的有界订阅通道容量，必须大于 0
	MaxSubscribers          int // 可选活跃订阅者上限；0 表示不额外设限，负值失败关闭
}

// SystemBusStats 提供 SystemBus 当前的不可变运行统计快照。
type SystemBusStats struct {
	Published, Delivered, Dropped uint64
	ActiveSubscribers             int
	Closed                        bool
}

// SystemBus 是承载连接池、多路复用与协议脱敏诊断事件的有界非阻塞发布订阅总线（ADR-010）：
//   - 仅接受 EventClassSystem 事件；
//   - DropAndCount 背压：Publish 持读锁向全部活跃订阅者非阻塞扇出，单个慢订阅者满缓冲时立即丢弃并累加两级丢弃计数，
//     绝不阻塞发布者或连累其他快订阅者；
//   - 并发安全关闭：Subscribe / Unsubscribe / Close 持写锁维护订阅表并关闭子通道，彻底消除向已关闭通道发送 panic。
//
//xops:opaque
//xops:failclosed
type SystemBus struct {
	defaultBuf, maxSubs         int
	mu                          sync.RWMutex
	initialized, closed         bool
	nextSubID                   uint64
	subs                        map[uint64]*SystemSubscription
	published, delivered, drops atomic.Uint64
}

// SystemSubscription 表示 SystemBus 上的单个隔离有界订阅句柄；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type SystemSubscription struct {
	id                             uint64
	bus                            *SystemBus
	ch                             chan Event
	initialized, closed            bool
	delivered, dropped, lastReport atomic.Uint64
}

// NewSystemBus 校验缓冲容量与订阅上限并构造 SystemBus。
func NewSystemBus(cfg SystemBusConfig) (*SystemBus, error) {
	if cfg.DefaultSubscriberBuffer <= 0 || cfg.MaxSubscribers < 0 {
		return nil, fmt.Errorf("%w: default_subscriber_buffer 须大于 0 且 max_subscribers 不能为负", ErrInvalidBusConfig)
	}
	return &SystemBus{
		defaultBuf: cfg.DefaultSubscriberBuffer, maxSubs: cfg.MaxSubscribers,
		initialized: true, subs: make(map[uint64]*SystemSubscription),
	}, nil
}

// Publish 以非阻塞 DropAndCount 语义广播一条系统诊断事件；慢订阅者满缓冲立即丢弃计数，绝不阻塞发布者。
func (b *SystemBus) Publish(ev Event) error {
	if b == nil || !b.initialized {
		return ErrBusNotInitialized
	}
	if ev == nil || !ev.IsValid() {
		return ErrInvalidEvent
	}
	if ev.Class() != EventClassSystem {
		return fmt.Errorf("%w: SystemBus 仅接受 system 类事件，实际=%s", ErrUnsupportedEventClass, ev.Class())
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return ErrBusClosed
	}
	b.published.Add(1)
	for _, sub := range b.subs {
		select {
		case sub.ch <- ev:
			sub.delivered.Add(1)
			b.delivered.Add(1)
		default:
			sub.dropped.Add(1)
			b.drops.Add(1)
		}
	}
	return nil
}

// Subscribe 使用总线默认缓冲容量创建独立订阅句柄。
func (b *SystemBus) Subscribe() (*SystemSubscription, error) {
	if b == nil || !b.initialized {
		return nil, ErrBusNotInitialized
	}
	return b.SubscribeWithBuffer(b.defaultBuf)
}

// SubscribeWithBuffer 使用指定正整数缓冲容量创建独立订阅句柄。
func (b *SystemBus) SubscribeWithBuffer(buffer int) (*SystemSubscription, error) {
	if b == nil || !b.initialized {
		return nil, ErrBusNotInitialized
	}
	if buffer <= 0 {
		return nil, fmt.Errorf("%w: 订阅缓冲区容量必须大于 0", ErrInvalidBusConfig)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, ErrBusClosed
	}
	if b.maxSubs > 0 && len(b.subs) >= b.maxSubs {
		return nil, fmt.Errorf("%w: 上限=%d", ErrBusSubscriberLimit, b.maxSubs)
	}
	b.nextSubID++
	sub := &SystemSubscription{id: b.nextSubID, bus: b, ch: make(chan Event, buffer), initialized: true}
	b.subs[sub.id] = sub
	return sub, nil
}

// Close 幂等关闭 SystemBus，拒绝后续 Publish/Subscribe 并确定性关闭全部活跃订阅通道发送 EOF。
func (b *SystemBus) Close() {
	if b == nil || !b.initialized {
		return
	}
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		for _, sub := range b.subs {
			if !sub.closed {
				sub.closed = true
				close(sub.ch)
			}
		}
		clear(b.subs)
	}
	b.mu.Unlock()
}

// IsClosed 报告总线是否已关闭（nil 或未初始化零值失败关闭返回 true）。
func (b *SystemBus) IsClosed() bool {
	if b == nil || !b.initialized {
		return true
	}
	b.mu.RLock()
	closed := b.closed
	b.mu.RUnlock()
	return closed
}

// Stats 返回总线的并发安全运行统计快照。
func (b *SystemBus) Stats() SystemBusStats {
	if b == nil || !b.initialized {
		return SystemBusStats{Closed: true}
	}
	b.mu.RLock()
	active, closed := len(b.subs), b.closed
	b.mu.RUnlock()
	return SystemBusStats{b.published.Load(), b.delivered.Load(), b.drops.Load(), active, closed}
}

// Next 读取下一条系统事件；订阅或总线关闭且缓冲排空后稳定返回 (nil, false, nil) 确定性 EOF。
func (s *SystemSubscription) Next(ctx context.Context) (Event, bool, error) {
	if s == nil || !s.initialized {
		return nil, false, ErrSubscriptionNotInitialized
	}
	if ctx == nil {
		return nil, false, ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	select {
	case ev, ok := <-s.ch:
		return pickIf(ok, ev, nil), ok, nil
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
}

// All 返回适配 Go 1.27 range-over-func 的延迟顺序迭代视图。
func (s *SystemSubscription) All(ctx context.Context) iter.Seq2[Event, error] {
	return iterNextStream(ctx, s.Next)
}

// Delivered、Dropped 与 DrainDroppedDelta 返回本订阅者的投递、累计丢弃及增量丢弃计数。
func (s *SystemSubscription) Delivered() uint64 {
	if s == nil || !s.initialized {
		return 0
	}
	return s.delivered.Load()
}
func (s *SystemSubscription) Dropped() uint64 {
	if s == nil || !s.initialized {
		return 0
	}
	return s.dropped.Load()
}
func (s *SystemSubscription) DrainDroppedDelta() uint64 {
	if s == nil || !s.initialized {
		return 0
	}
	for {
		total, prev := s.dropped.Load(), s.lastReport.Load()
		if total <= prev {
			return 0
		}
		if s.lastReport.CompareAndSwap(prev, total) {
			return total - prev
		}
	}
}

// Close 幂等退订并关闭本订阅通道，确保与 Publish/bus.Close 并发执行零竞态零 panic。
func (s *SystemSubscription) Close() {
	if s == nil || !s.initialized || s.bus == nil {
		return
	}
	b := s.bus
	b.mu.Lock()
	if !s.closed {
		s.closed = true
		delete(b.subs, s.id)
		close(s.ch)
	}
	b.mu.Unlock()
}

// IsClosed 报告订阅是否已关闭（nil 或未初始化零值失败关闭返回 true）。
func (s *SystemSubscription) IsClosed() bool {
	if s == nil || !s.initialized || s.bus == nil {
		return true
	}
	s.bus.mu.RLock()
	closed := s.closed
	s.bus.mu.RUnlock()
	return closed
}
