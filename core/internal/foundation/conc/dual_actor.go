package conc

import (
	"context"
	"sync"
	"sync/atomic"
)

// DualActorConfig 定义 DualActor 的初始化参数。
// 注意：本结构体故意不包含 time.Duration 字段，保持 Actor 核心循环 100% 纯内存非阻塞。
type DualActorConfig[Req any, Ctrl any] struct {
	// AcquireBuffer 为有界请求通道 acquireCh 的缓冲区容量，必须大于 0。
	AcquireBuffer int
	// OnRequest 在 Actor 循环中串行处理每条高背压普通请求（不可为 nil）。
	OnRequest func(req Req)
	// OnControl 在 Actor 循环中以最高优先级串行处理每条控制消息（不可为 nil）。
	OnControl func(ctrl Ctrl)
	// OnDrainRequest 为可选的停机排空请求回调；若为 nil 则回退复用 OnRequest。
	OnDrainRequest func(req Req)
}

// DualActor 是一个双通道纯内存并发 Actor：
//   - 控制面（Ctrl）：通过极薄互斥锁保护的无界环形队列 ctrlQueue 与容量为 1 的非阻塞唤醒通道 controlReady 传递，
//     确保高并发归还租约、熔断通知等控制消息永不阻塞发送方。
//   - 请求面（Req）：通过有界通道 acquireCh 提供确定性背压。
//   - 调度循环采用两段式 select：阶段 1 排空全部控制消息后，阶段 2 才同时监听控制唤醒与请求通道，
//     并在处理每条请求前再次排空控制队列以消除 select 随机选择带来的优先级竞态窗口。
//
//xops:opaque
//xops:failclosed
type DualActor[Req any, Ctrl any] struct {
	acquireCh    chan Req
	controlReady chan struct{}
	stopCh       chan struct{}
	actorDone    chan struct{}

	ctrlMu     sync.Mutex
	ctrlQueue  ringQueue[Ctrl]
	ctrlClosed bool

	onRequest      func(Req)
	onControl      func(Ctrl)
	onDrainRequest func(Req)

	initialized bool
	started     atomic.Bool
	stopOnce    sync.Once
}

// NewDualActor 根据 cfg 创建并初始化一个 DualActor 实例。
// 若缓冲区容量非正或缺失必需回调，则返回 ErrInvalidActorConfig。
func NewDualActor[Req any, Ctrl any](cfg DualActorConfig[Req, Ctrl]) (*DualActor[Req, Ctrl], error) {
	if cfg.AcquireBuffer <= 0 || cfg.OnRequest == nil || cfg.OnControl == nil {
		return nil, ErrInvalidActorConfig
	}
	onDrain := cfg.OnDrainRequest
	if onDrain == nil {
		onDrain = cfg.OnRequest
	}
	return &DualActor[Req, Ctrl]{
		acquireCh:      make(chan Req, cfg.AcquireBuffer),
		controlReady:   make(chan struct{}, 1),
		stopCh:         make(chan struct{}),
		actorDone:      make(chan struct{}),
		onRequest:      cfg.OnRequest,
		onControl:      cfg.OnControl,
		onDrainRequest: onDrain,
		initialized:    true,
	}, nil
}

// SendControl 以永不阻塞的方式向控制队列投递一条高优先级控制消息。
// 若 Actor 未初始化、已停机或已关闭控制队列，则立即返回 false，绝不挂起调用方。
func (a *DualActor[Req, Ctrl]) SendControl(ctrl Ctrl) bool {
	if a == nil || !a.initialized {
		return false
	}
	// 快速路径：若 actorDone 已关闭，直接拒绝入队。
	select {
	case <-a.actorDone:
		return false
	default:
	}

	a.ctrlMu.Lock()
	if a.ctrlClosed {
		a.ctrlMu.Unlock()
		return false
	}
	a.ctrlQueue.push(ctrl)
	a.ctrlMu.Unlock()

	// 容量为 1 的合并唤醒信号：若已有未消费唤醒则无需重复发送。
	// 因为 Run 仅在 drainControls 之前消费 controlReady，故不会丢失任何唤醒。
	select {
	case a.controlReady <- struct{}{}:
	default:
	}
	return true
}

// SendAcquire 向有界请求通道 acquireCh 提交一条请求，受背压与 ctx 取消控制，
// 并持续监听 stopCh 与 actorDone 以确保 Actor 停机时永不阻塞。
func (a *DualActor[Req, Ctrl]) SendAcquire(ctx context.Context, req Req) error {
	if a == nil || !a.initialized {
		return ErrActorNotInitialized
	}
	if ctx == nil {
		return ErrNilContext
	}
	if a.isStopping() {
		return ErrActorStopped
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case a.acquireCh <- req:
		return nil
	case <-a.actorDone:
		return ErrActorStopped
	case <-a.stopCh:
		return ErrActorStopped
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *DualActor[Req, Ctrl]) isStopping() bool {
	select {
	case <-a.actorDone:
		return true
	case <-a.stopCh:
		return true
	default:
		return false
	}
}

// Stop 请求 DualActor 停止调度循环并进入停机排空阶段（幂等且非阻塞）。
func (a *DualActor[Req, Ctrl]) Stop() {
	if a == nil || !a.initialized {
		return
	}
	a.stopOnce.Do(func() {
		close(a.stopCh)
	})
}

// Done 返回一个在 Actor 主循环完全排空并退出后关闭的只读信号通道。
// 若接收者为 nil 或未初始化，则返回一个已预先关闭的通道，避免调用方监听阻塞。
func (a *DualActor[Req, Ctrl]) Done() <-chan struct{} {
	if a == nil || !a.initialized || a.actorDone == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return a.actorDone
}

// Run 启动 DualActor 的单线程串行事件循环，直至 Stop 被调用或 ctx 被取消。
// 每个 DualActor 实例仅允许运行一次 Run；退出前会自动完成停机排空并关闭 Done() 通道。
func (a *DualActor[Req, Ctrl]) Run(ctx context.Context) error {
	if a == nil || !a.initialized {
		return ErrActorNotInitialized
	}
	if ctx == nil {
		return ErrNilContext
	}
	if !a.started.CompareAndSwap(false, true) {
		return ErrActorAlreadyStarted
	}
	defer close(a.actorDone)

	for {
		stopped, err := a.step(ctx)
		if stopped {
			return err
		}
	}
}

// step 执行一次完整的两段式调度：
// 阶段 1 先无条件排空控制队列并优先响应停机/取消，阶段 2 再阻塞监听控制唤醒与请求通道。
func (a *DualActor[Req, Ctrl]) step(ctx context.Context) (bool, error) {
	a.drainControls()

	if stopped, err := a.checkShutdown(ctx); stopped {
		return true, err
	}

	select {
	case <-a.controlReady:
		a.drainControls()
		return false, nil
	case req := <-a.acquireCh:
		// 在真正处理请求前再排空一次控制队列，避免 controlReady 与 acquireCh 同时就绪时的优先级反转。
		a.drainControls()
		a.onRequest(req)
		return false, nil
	case <-a.stopCh:
		a.drainAndStop()
		return true, nil
	case <-ctx.Done():
		a.drainAndStop()
		return true, ctx.Err()
	}
}

func (a *DualActor[Req, Ctrl]) checkShutdown(ctx context.Context) (bool, error) {
	select {
	case <-a.stopCh:
		a.drainAndStop()
		return true, nil
	case <-ctx.Done():
		a.drainAndStop()
		return true, ctx.Err()
	default:
		return false, nil
	}
}

func (a *DualActor[Req, Ctrl]) drainControls() {
	var batch []Ctrl
	for {
		batch = a.popControlBatch(batch)
		if len(batch) == 0 {
			return
		}
		for _, ctrl := range batch {
			a.onControl(ctrl)
		}
	}
}

func (a *DualActor[Req, Ctrl]) popControlBatch(dst []Ctrl) []Ctrl {
	a.ctrlMu.Lock()
	batch := a.ctrlQueue.popAll(dst)
	a.ctrlMu.Unlock()
	return batch
}

// drainAndStop 按序排空：先处理现有控制消息，再排空 acquireCh 中已缓冲的请求，
// 最后在 ctrlMu 下原子置位 ctrlClosed=true 并排空剩余控制消息，确保不漏处理任何已返回 true 的 SendControl。
func (a *DualActor[Req, Ctrl]) drainAndStop() {
	a.drainControls()
	a.drainAcquireCh()
	a.closeAndDrainControls()
}

func (a *DualActor[Req, Ctrl]) drainAcquireCh() {
	for {
		select {
		case req := <-a.acquireCh:
			a.drainControls()
			a.onDrainRequest(req)
		default:
			return
		}
	}
}

func (a *DualActor[Req, Ctrl]) closeAndDrainControls() {
	a.ctrlMu.Lock()
	a.ctrlClosed = true
	batch := a.ctrlQueue.popAll(nil)
	a.ctrlMu.Unlock()

	for _, ctrl := range batch {
		a.onControl(ctrl)
	}
}
