package actor

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

// DualActor 是一个双通道纯内存并发 Actor（零裸 go，由调用方在 core/conc.Nursery 中运行）：
//   - 控制面（Ctrl）：通过极薄互斥锁保护的无界环形队列 ctrlQueue 与容量为 1 的非阻塞唤醒通道 controlReady 传递，
//     确保高并发归还租约、熔断通知等控制消息永不阻塞发送方。
//   - 请求面（Req）：通过有界通道 acquireCh 提供确定性背压，并由 acqMu + acqClosed + acqSenders 组成入站发送者屏障，
//     保证停机排空阶段零丢弃任何已返回 nil 的 SendAcquire 请求。
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

	acqMu      sync.Mutex
	acqClosed  bool
	acqSenders sync.WaitGroup

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

// SendAcquire 向有界请求通道 acquireCh 提交一条请求，受背压与 ctx 取消控制。
// 执行顺序严格遵循：未初始化/nil 校验 -> 无锁停机快检（优先于 ctx.Err()）-> 锁外 ctx.Err() 校验
// -> acqMu 发送者屏障登记 -> 阻塞投递，确保绝不持锁调用外部 ctx.Err() 且停机零丢请求。
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

	// 在 acqMu 临界区内原子核验 acqClosed 并登记在途发送者，保证与 drainAndStop 中 acqSenders.Wait 的严格先后关系。
	a.acqMu.Lock()
	if a.acqClosed {
		a.acqMu.Unlock()
		return ErrActorStopped
	}
	a.acqSenders.Add(1)
	a.acqMu.Unlock()
	defer a.acqSenders.Done()

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

// beginStop 原子关闭入站请求门闩并幂等关闭 stopCh，唤醒全部阻塞发送方并阻止新的在途发送者登记。
func (a *DualActor[Req, Ctrl]) beginStop() {
	a.acqMu.Lock()
	a.acqClosed = true
	a.acqMu.Unlock()
	a.stopOnce.Do(func() {
		close(a.stopCh)
	})
}

// Stop 请求 DualActor 停止调度循环并进入停机排空阶段（幂等且非阻塞）。
func (a *DualActor[Req, Ctrl]) Stop() {
	if a == nil || !a.initialized {
		return
	}
	a.beginStop()
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
// 每个 DualActor 实例仅允许运行一次 Run；正常退出会完整排空请求与控制队列，
// 回调发生 panic 时会通过 LIFO defer 封锁新入站并清空控制队列滞留指针，最后关闭 Done() 通道。
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
	// LIFO 异常防护：若回调发生 panic 跳过 drainAndStop，仍在关闭 actorDone 之前封锁新入站、
	// 关闭控制队列并调用零分配 reset() 清空未消费槽位指针（不调用 acqSenders.Wait 以防异常路径挂起）。
	defer func() {
		a.beginStop()
		a.ctrlMu.Lock()
		a.ctrlClosed = true
		a.ctrlQueue.reset()
		a.ctrlMu.Unlock()
	}()

	for {
		stopped, err := a.step(ctx)
		if stopped {
			return err
		}
	}
}

// step 执行一次完整的两段式调度：
// 阶段 1 先无条件排空控制队列并按确定性优先级响应停机/取消（stopCh 优先于 ctx.Done()）；
// 阶段 2 再阻塞监听控制唤醒、请求通道与停机信号；在 acquireCh 支路排空控制队列后立即复核停机状态，
// 防止 OnControl 期间触发 Stop()（例如 GateHalted 熔断）后仍误执行普通 onRequest。
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
		// 在真正处理请求前再排空一次控制队列，避免 controlReady 与 acquireCh 同时就绪时的优先级反转；
		// 排空后立即复核停机信号，若控制消息已触发停机则严格按 FIFO 经 onDrainRequest 排空 req 及剩余请求。
		a.drainControls()
		if stopped, err := a.isShutdown(ctx); stopped {
			a.drainAndStopWithPending(req)
			return true, err
		}
		a.onRequest(req)
		return false, nil
	case <-a.stopCh:
		a.drainAndStop()
		return true, nil
	case <-ctx.Done():
		// 在 beginStop 关闭 stopCh 之前先检测 stopCh 是否已由 Stop() 主动关闭，
		// 保证 Stop() 与 ctx 取消并发就绪时全路径确定性优先返回 nil，消除 select 随机抖动。
		var exitErr error
		select {
		case <-a.stopCh:
		default:
			exitErr = ctx.Err()
		}
		a.drainAndStop()
		return true, exitErr
	}
}

// isShutdown 以确定性优先级检查停机信号：始终优先判定 stopCh（返回 nil）；
// 若观测到 ctx.Done() 就绪，必须在其后再次复核 stopCh，依托 Go 内存模型保证
// Stop() happens-before cancel() 时绝无 TOCTOU 窗口误返 context.Canceled。
func (a *DualActor[Req, Ctrl]) isShutdown(ctx context.Context) (bool, error) {
	select {
	case <-a.stopCh:
		return true, nil
	default:
	}
	select {
	case <-ctx.Done():
		select {
		case <-a.stopCh:
			return true, nil
		default:
			return true, ctx.Err()
		}
	default:
		return false, nil
	}
}

func (a *DualActor[Req, Ctrl]) checkShutdown(ctx context.Context) (bool, error) {
	stopped, err := a.isShutdown(ctx)
	if !stopped {
		return false, nil
	}
	a.drainAndStop()
	return true, err
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

// drainAndStop 严格按 5 步顺序执行停机排空：
// 1) beginStop 关闭入站门闩与 stopCh；
// 2) acqSenders.Wait 等待全部在途 SendAcquire 退出（此后零协程能再写入 acquireCh）；
// 3) drainControls 优先排空当前已入队的控制消息；
// 4) drainAcquireCh 排空 acquireCh 中全部残留请求；
// 5) closeAndDrainControls 在 ctrlMu 下置位 ctrlClosed=true 并排空剩余控制消息。
func (a *DualActor[Req, Ctrl]) drainAndStop() {
	a.beginStop()
	a.acqSenders.Wait()
	a.drainControls()
	a.drainAcquireCh()
	a.closeAndDrainControls()
}

// drainAndStopWithPending 用于 acquireCh 已出队一条 pending 请求、但在前置 drainControls 期间触发停机的场景：
// 严格遵循相同 5 步屏障，并在排空 acquireCh 之前先交由 onDrainRequest 处理 pending，保证零丢弃且严格 FIFO。
func (a *DualActor[Req, Ctrl]) drainAndStopWithPending(pending Req) {
	a.beginStop()
	a.acqSenders.Wait()
	a.drainControls()
	a.onDrainRequest(pending)
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
