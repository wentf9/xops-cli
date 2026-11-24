package actor

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
)

func TestDualActorInvalidAndZeroFailClosed(t *testing.T) {
	invalidConfigs := []DualActorConfig[int, int]{
		{AcquireBuffer: 0, OnRequest: func(int) {}, OnControl: func(int) {}},
		{AcquireBuffer: 1, OnRequest: nil, OnControl: func(int) {}},
		{AcquireBuffer: 1, OnRequest: func(int) {}, OnControl: nil},
	}
	for i, cfg := range invalidConfigs {
		if _, err := NewDualActor(cfg); !errors.Is(err, ErrInvalidActorConfig) {
			t.Fatalf("case %d: err = %v, want ErrInvalidActorConfig", i, err)
		}
	}

	var zero DualActor[int, int]
	var nilPtr *DualActor[int, int]
	checkUninitializedActor(t, &zero)
	checkUninitializedActor(t, nilPtr)
}

func checkUninitializedActor(t *testing.T, a *DualActor[int, int]) {
	t.Helper()
	if a.SendControl(1) {
		t.Fatal("uninitialized SendControl must return false")
	}
	if err := a.SendAcquire(context.Background(), 1); !errors.Is(err, ErrActorNotInitialized) {
		t.Fatalf("SendAcquire error = %v, want ErrActorNotInitialized", err)
	}
	if err := a.Run(context.Background()); !errors.Is(err, ErrActorNotInitialized) {
		t.Fatalf("Run error = %v, want ErrActorNotInitialized", err)
	}
	a.Stop()
	select {
	case <-a.Done():
	default:
		t.Fatal("uninitialized Done() must be pre-closed")
	}
}

func TestDualActorStage1DrainsControlsBeforeRequests(t *testing.T) {
	var mu sync.Mutex
	order := make([]string, 0, 16)
	reqRelease := make(chan struct{})
	firstReqStarted := make(chan struct{})
	allDone := make(chan struct{})

	a, err := NewDualActor(DualActorConfig[string, string]{
		AcquireBuffer: 8,
		OnRequest: func(req string) {
			if req == "req-block" {
				close(firstReqStarted)
				<-reqRelease
			}
			mu.Lock()
			order = append(order, "req:"+req)
			done := len(order) == 7
			mu.Unlock()
			if done {
				close(allDone)
			}
		},
		OnControl: func(ctrl string) {
			mu.Lock()
			order = append(order, "ctrl:"+ctrl)
			done := len(order) == 7
			mu.Unlock()
			if done {
				close(allDone)
			}
		},
	})
	if err != nil {
		t.Fatalf("NewDualActor failed: %v", err)
	}

	err = conc.RunWait(context.Background(), func(ctx context.Context, n *conc.Nursery) error {
		if goErr := n.Go(func(runCtx context.Context) error {
			return a.Run(runCtx)
		}); goErr != nil {
			return goErr
		}
		if sendErr := a.SendAcquire(ctx, "req-block"); sendErr != nil {
			return sendErr
		}
		<-firstReqStarted

		// 当 Actor 阻塞在第一条请求回调中时，先后填入多条请求与控制消息；
		// 放行后，所有控制消息必须先于后续请求执行。
		enqueuePriorityBurst(t, a)
		close(reqRelease)

		select {
		case <-allDone:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for actor order")
		}

		a.Stop()
		<-a.Done()
		return nil
	})
	if err != nil {
		t.Fatalf("RunWait error = %v", err)
	}

	verifyControlPriorityOrder(t, order)
}

func enqueuePriorityBurst(t *testing.T, a *DualActor[string, string]) {
	t.Helper()
	for _, r := range []string{"req-1", "req-2"} {
		if err := a.SendAcquire(context.Background(), r); err != nil {
			t.Fatalf("SendAcquire %s failed: %v", r, err)
		}
	}
	for _, c := range []string{"ctrl-1", "ctrl-2", "ctrl-3", "ctrl-4"} {
		if !a.SendControl(c) {
			t.Fatalf("SendControl %s returned false", c)
		}
	}
}

func verifyControlPriorityOrder(t *testing.T, order []string) {
	t.Helper()
	wantPrefix := []string{"req:req-block", "ctrl:ctrl-1", "ctrl:ctrl-2", "ctrl:ctrl-3", "ctrl:ctrl-4", "req:req-1", "req:req-2"}
	if len(order) != len(wantPrefix) {
		t.Fatalf("order len = %d (%v), want %d", len(order), order, len(wantPrefix))
	}
	for i := range wantPrefix {
		if order[i] != wantPrefix[i] {
			t.Fatalf("order[%d] = %q, want %q (full=%v)", i, order[i], wantPrefix[i], order)
		}
	}
}

func TestDualActorUnboundedControlBurstNeverBlocks(t *testing.T) {
	const totalControls = 12000
	var ctrlCount atomic.Int64
	gate := make(chan struct{})
	gateEntered := make(chan struct{})

	a, err := NewDualActor(DualActorConfig[int, int]{
		AcquireBuffer: 4,
		OnRequest: func(int) {
			close(gateEntered)
			<-gate
		},
		OnControl: func(v int) {
			got := ctrlCount.Add(1)
			if int64(v+1) != got {
				ctrlCount.Store(-1)
			}
		},
	})
	if err != nil {
		t.Fatalf("NewDualActor failed: %v", err)
	}

	err = conc.RunWait(context.Background(), func(ctx context.Context, n *conc.Nursery) error {
		if goErr := n.Go(a.Run); goErr != nil {
			return goErr
		}
		if sendErr := a.SendAcquire(ctx, 1); sendErr != nil {
			return sendErr
		}
		<-gateEntered

		// 在 Actor 循环阻塞期间一次性发送超过 10,000 条控制消息，验证绝不阻塞发送方。
		for i := range totalControls {
			if !a.SendControl(i) {
				t.Fatalf("SendControl(%d) returned false", i)
			}
		}
		close(gate)

		a.Stop()
		<-a.Done()
		return nil
	})
	if err != nil {
		t.Fatalf("RunWait error = %v", err)
	}
	if got := ctrlCount.Load(); got != totalControls {
		t.Fatalf("ctrlCount = %d, want %d", got, totalControls)
	}
}

func TestDualActorShutdownDrainsAndStopsHangingSenders(t *testing.T) {
	var drainedReqs atomic.Int32
	var drainedCtrls atomic.Int32
	blockReq := make(chan struct{})
	entered := make(chan struct{})

	a, err := NewDualActor(DualActorConfig[int, int]{
		AcquireBuffer: 2,
		OnRequest: func(int) {
			close(entered)
			<-blockReq
		},
		OnDrainRequest: func(int) {
			drainedReqs.Add(1)
		},
		OnControl: func(int) {
			drainedCtrls.Add(1)
		},
	})
	if err != nil {
		t.Fatalf("NewDualActor failed: %v", err)
	}

	checkActorNilContextFailClosed(t, a)

	blockedSendErr := make(chan error, 1)
	err = conc.RunWait(context.Background(), func(ctx context.Context, n *conc.Nursery) error {
		return driveShutdownDrainScenario(t, ctx, n, a, entered, blockReq, blockedSendErr)
	})
	if err != nil {
		t.Fatalf("RunWait error = %v", err)
	}

	verifyPostShutdownState(t, a, <-blockedSendErr, drainedReqs.Load(), drainedCtrls.Load())
}

func checkActorNilContextFailClosed(t *testing.T, a *DualActor[int, int]) {
	t.Helper()
	var nilCtx context.Context
	if err := a.Run(nilCtx); !errors.Is(err, ErrNilContext) {
		t.Fatalf("Run(nil) error = %v, want ErrNilContext", err)
	}
	if err := a.SendAcquire(nilCtx, 1); !errors.Is(err, ErrNilContext) {
		t.Fatalf("SendAcquire(nil) error = %v, want ErrNilContext", err)
	}
}

func driveShutdownDrainScenario(
	t *testing.T,
	ctx context.Context,
	n *conc.Nursery,
	a *DualActor[int, int],
	entered <-chan struct{},
	blockReq chan struct{},
	blockedSendErr chan<- error,
) error {
	t.Helper()
	if goErr := n.Go(a.Run); goErr != nil {
		return goErr
	}
	if sendErr := a.SendAcquire(ctx, 1); sendErr != nil {
		return sendErr
	}
	<-entered
	// 确认后台 Run 已处于运行态后，重复调用 Run 必须立即失败关闭。
	if dupErr := a.Run(ctx); !errors.Is(dupErr, ErrActorAlreadyStarted) {
		t.Fatalf("second Run error = %v, want ErrActorAlreadyStarted", dupErr)
	}
	for _, req := range []int{2, 3} {
		if sendErr := a.SendAcquire(ctx, req); sendErr != nil {
			return sendErr
		}
	}
	// acquireCh 已满（cap=2），此时发起阻塞 SendAcquire 应在 Stop 后立即返回 ErrActorStopped。
	if goErr := n.Go(func(sendCtx context.Context) error {
		blockedSendErr <- a.SendAcquire(sendCtx, 4)
		return nil
	}); goErr != nil {
		return goErr
	}
	time.Sleep(2 * time.Millisecond)

	if !a.SendControl(10) || !a.SendControl(20) {
		t.Fatal("SendControl before Stop failed")
	}
	a.Stop()
	close(blockReq)
	<-a.Done()
	return nil
}

func verifyPostShutdownState(t *testing.T, a *DualActor[int, int], blockedErr error, drainedReqs, drainedCtrls int32) {
	t.Helper()
	if !errors.Is(blockedErr, ErrActorStopped) {
		t.Fatalf("blocked SendAcquire error = %v, want ErrActorStopped", blockedErr)
	}
	if a.SendControl(30) {
		t.Fatal("SendControl after shutdown must return false")
	}
	if err := a.SendAcquire(context.Background(), 5); !errors.Is(err, ErrActorStopped) {
		t.Fatalf("SendAcquire after shutdown error = %v, want ErrActorStopped", err)
	}
	if drainedReqs != 2 || drainedCtrls != 2 {
		t.Fatalf("drainedReqs=%d drainedCtrls=%d, want 2 and 2", drainedReqs, drainedCtrls)
	}
}

func TestDualActorContextCancellationAndSendAcquireCancel(t *testing.T) {
	a, err := NewDualActor(DualActorConfig[int, int]{
		AcquireBuffer: 1,
		OnRequest:     func(int) {},
		OnControl:     func(int) {},
	})
	if err != nil {
		t.Fatalf("NewDualActor failed: %v", err)
	}

	// 填满缓冲区测试运行前 SendAcquire 上下文取消。
	if err := a.SendAcquire(context.Background(), 1); err != nil {
		t.Fatalf("SendAcquire failed: %v", err)
	}
	cancelledCtx, cancelSend := context.WithCancel(context.Background())
	cancelSend()
	if err := a.SendAcquire(cancelledCtx, 2); !errors.Is(err, context.Canceled) {
		t.Fatalf("SendAcquire cancelled error = %v, want context.Canceled", err)
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	err = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if goErr := n.Go(func(context.Context) error {
			runErr <- a.Run(runCtx)
			return nil
		}); goErr != nil {
			return goErr
		}
		cancelRun()
		<-a.Done()
		return nil
	})
	if err != nil {
		t.Fatalf("RunWait failed: %v", err)
	}
	if err := <-runErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}

	// 停机后即便传入已取消 ctx，isStopping() 优先于 ctx.Err()，必须确定性返回 ErrActorStopped。
	if err := a.SendAcquire(cancelledCtx, 3); !errors.Is(err, ErrActorStopped) {
		t.Fatalf("SendAcquire(stopped, cancelledCtx) error = %v, want ErrActorStopped", err)
	}
}

func TestDualActorSendAcquireStopBarrierZeroDrop(t *testing.T) {
	runSendAcquireBarrierStress(t, false)
}

func TestDualActorSendAcquireContextCancelBarrierZeroDrop(t *testing.T) {
	runSendAcquireBarrierStress(t, true)
}

type barrierStressState struct {
	handledNormal   atomic.Int64
	handledDrain    atomic.Int64
	accepted        atomic.Int64
	rejectedStopped atomic.Int64
	firstHandled    chan struct{}
	firstOnce       sync.Once
}

func runSendAcquireBarrierStress(t *testing.T, stopByContextCancel bool) {
	t.Helper()

	const producers = 12
	state := &barrierStressState{firstHandled: make(chan struct{})}

	a, err := NewDualActor(DualActorConfig[int, int]{
		AcquireBuffer: 4,
		OnRequest: func(int) {
			state.handledNormal.Add(1)
			state.firstOnce.Do(func() { close(state.firstHandled) })
		},
		OnDrainRequest: func(int) {
			state.handledDrain.Add(1)
		},
		OnControl: func(int) {},
	})
	if err != nil {
		t.Fatalf("NewDualActor failed: %v", err)
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	runErrCh := make(chan error, 1)
	stopFn := a.Stop
	if stopByContextCancel {
		stopFn = cancelRun
	}

	err = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		return launchBarrierProducersAndStop(n, a, runCtx, runErrCh, producers, state, stopFn)
	})
	if err != nil {
		t.Fatalf("RunWait failed: %v", err)
	}

	verifyBarrierResult(t, <-runErrCh, stopByContextCancel, producers, state)
}

func launchBarrierProducersAndStop(
	n *conc.Nursery,
	a *DualActor[int, int],
	runCtx context.Context,
	runErrCh chan<- error,
	producers int,
	state *barrierStressState,
	stopFn func(),
) error {
	if goErr := n.Go(func(context.Context) error {
		runErrCh <- a.Run(runCtx)
		return nil
	}); goErr != nil {
		return goErr
	}
	for p := range producers {
		producerID := p
		if goErr := n.Go(func(sendCtx context.Context) error {
			return hammerSendAcquireUntilStop(sendCtx, a, producerID, &state.accepted, &state.rejectedStopped)
		}); goErr != nil {
			return goErr
		}
	}

	// 等待至少一条请求进入主循环后再触发并发停机，确保真实命中发送者屏障竞争窗口。
	<-state.firstHandled
	time.Sleep(time.Millisecond)
	stopFn()
	<-a.Done()
	return nil
}

func verifyBarrierResult(t *testing.T, runErr error, stopByContextCancel bool, producers int64, state *barrierStressState) {
	t.Helper()
	if stopByContextCancel {
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("Run error = %v, want context.Canceled", runErr)
		}
	} else if runErr != nil {
		t.Fatalf("Run error = %v, want nil", runErr)
	}

	totalHandled := state.handledNormal.Load() + state.handledDrain.Load()
	if state.accepted.Load() == 0 || totalHandled != state.accepted.Load() {
		t.Fatalf(
			"barrier mismatch: accepted=%d handled=%d (normal=%d drain=%d) rejected=%d",
			state.accepted.Load(),
			totalHandled,
			state.handledNormal.Load(),
			state.handledDrain.Load(),
			state.rejectedStopped.Load(),
		)
	}
	if state.rejectedStopped.Load() != producers {
		t.Fatalf("rejectedStopped = %d, want %d", state.rejectedStopped.Load(), producers)
	}
}

func hammerSendAcquireUntilStop(
	ctx context.Context,
	a *DualActor[int, int],
	producerID int,
	accepted *atomic.Int64,
	rejectedStopped *atomic.Int64,
) error {
	for i := 0; ; i++ {
		err := a.SendAcquire(ctx, producerID*100000+i)
		if err == nil {
			accepted.Add(1)
			continue
		}
		if errors.Is(err, ErrActorStopped) {
			rejectedStopped.Add(1)
			return nil
		}
		return err
	}
}

type panicCtrlPayload struct {
	tag string
}

func TestDualActorOnRequestPanicCleansUpAndStopsSenders(t *testing.T) {
	entered := make(chan struct{})
	releasePanic := make(chan struct{})

	a, err := NewDualActor(DualActorConfig[int, *panicCtrlPayload]{
		AcquireBuffer: 1,
		OnRequest: func(int) {
			close(entered)
			<-releasePanic
			panic("actor callback exploded")
		},
		OnControl: func(*panicCtrlPayload) {},
	})
	if err != nil {
		t.Fatalf("NewDualActor failed: %v", err)
	}

	actorNursery := mustStartNursery(t, a.Run)
	preparePanicActorBacklog(t, a, entered)

	blockedErrCh := make(chan error, 1)
	senderNursery := mustStartNursery(t, func(sendCtx context.Context) error {
		blockedErrCh <- a.SendAcquire(sendCtx, 3)
		return nil
	})
	time.Sleep(2 * time.Millisecond)

	// 放行触发 OnRequest panic，验证 LIFO defer 封锁新入站、唤醒阻塞发送者并清空控制队列滞留指针。
	close(releasePanic)
	<-a.Done()

	if waitErr := actorNursery.Wait(); !errors.Is(waitErr, conc.ErrTaskPanicked) {
		t.Fatalf("actorNursery.Wait() = %v, want conc.ErrTaskPanicked", waitErr)
	}
	if waitErr := senderNursery.Wait(); waitErr != nil {
		t.Fatalf("senderNursery.Wait() = %v, want nil", waitErr)
	}
	verifyPostPanicActorState(t, a, <-blockedErrCh)
}

func mustStartNursery(t *testing.T, fn func(context.Context) error) *conc.Nursery {
	t.Helper()
	n, err := conc.NewNursery(context.Background())
	if err != nil {
		t.Fatalf("NewNursery failed: %v", err)
	}
	if err := n.Go(fn); err != nil {
		t.Fatalf("Nursery.Go failed: %v", err)
	}
	return n
}

func preparePanicActorBacklog(t *testing.T, a *DualActor[int, *panicCtrlPayload], entered <-chan struct{}) {
	t.Helper()
	if err := a.SendAcquire(context.Background(), 1); err != nil {
		t.Fatalf("SendAcquire(1) failed: %v", err)
	}
	<-entered
	// 填满有界缓冲并在控制队列中滞留若干指针消息，用于验证 panic defer 清理指针与唤醒阻塞发送者。
	if err := a.SendAcquire(context.Background(), 2); err != nil {
		t.Fatalf("SendAcquire(2) failed: %v", err)
	}
	for range 16 {
		if !a.SendControl(&panicCtrlPayload{tag: "pending"}) {
			t.Fatal("SendControl before panic returned false")
		}
	}
}

func verifyPostPanicActorState(t *testing.T, a *DualActor[int, *panicCtrlPayload], blockedErr error) {
	t.Helper()
	if !errors.Is(blockedErr, ErrActorStopped) {
		t.Fatalf("blocked SendAcquire after panic = %v, want ErrActorStopped", blockedErr)
	}
	if sendErr := a.SendAcquire(context.Background(), 4); !errors.Is(sendErr, ErrActorStopped) {
		t.Fatalf("SendAcquire after panic = %v, want ErrActorStopped", sendErr)
	}
	if a.SendControl(&panicCtrlPayload{tag: "after"}) {
		t.Fatal("SendControl after panic must return false")
	}

	// 白盒校验控制队列已关闭且底层缓冲区无任何滞留指针。
	a.ctrlMu.Lock()
	ctrlClosed := a.ctrlClosed
	queueLen := a.ctrlQueue.len()
	retainedPtr := hasNonNilCtrlSlot(a.ctrlQueue.buf)
	a.ctrlMu.Unlock()

	if !ctrlClosed || queueLen != 0 || retainedPtr {
		t.Fatalf("post-panic ctrl state: closed=%v len=%d retainedPtr=%v", ctrlClosed, queueLen, retainedPtr)
	}
}

func hasNonNilCtrlSlot(buf []*panicCtrlPayload) bool {
	for _, slot := range buf {
		if slot != nil {
			return true
		}
	}
	return false
}

func TestDualActorWithNurseryRunScopedNormalReturnIsNil(t *testing.T) {
	var processed atomic.Int32
	allProcessed := make(chan struct{})
	const reqCount = 4

	a, err := NewDualActor(DualActorConfig[int, int]{
		AcquireBuffer: 4,
		OnRequest: func(int) {
			if processed.Add(1) == reqCount {
				close(allProcessed)
			}
		},
		OnControl: func(int) {},
	})
	if err != nil {
		t.Fatalf("NewDualActor failed: %v", err)
	}

	err = conc.RunScoped(context.Background(), func(ctx context.Context, n *conc.Nursery) error {
		if goErr := n.Go(a.Run); goErr != nil {
			return goErr
		}
		for i := range reqCount {
			if sendErr := a.SendAcquire(ctx, i); sendErr != nil {
				return sendErr
			}
		}
		<-allProcessed
		// 不显式调用 a.Stop()，直接由 RunScoped 正常退出触发取消与排空。
		return nil
	})

	if err != nil {
		t.Fatalf("RunScoped with DualActor normal return error = %v, want nil", err)
	}
	select {
	case <-a.Done():
	default:
		t.Fatal("DualActor Done() must be closed after RunScoped returns")
	}
	if got := processed.Load(); got != reqCount {
		t.Fatalf("processed = %d, want %d", got, reqCount)
	}
}

func TestRingQueueWrapGrowAndShrink(t *testing.T) {
	var q ringQueue[int]
	if _, ok := q.pop(); ok {
		t.Fatal("empty pop must return false")
	}

	for i := range 100 {
		q.push(i)
	}
	for i := range 60 {
		v, ok := q.pop()
		if !ok || v != i {
			t.Fatalf("pop = (%d, %v), want (%d, true)", v, ok, i)
		}
	}
	// 制造环形绕回：head 在后半段，再持续入队触发 resize 线性化拷贝。
	for i := 100; i < 200; i++ {
		q.push(i)
	}
	if q.len() != 140 {
		t.Fatalf("q.len() = %d, want 140", q.len())
	}
	for i := 60; i < 200; i++ {
		v, ok := q.pop()
		if !ok || v != i {
			t.Fatalf("wrapped pop = (%d, %v), want (%d, true)", v, ok, i)
		}
	}
	if q.len() != 0 {
		t.Fatalf("q.len() after drain = %d, want 0", q.len())
	}
}

func TestRingQueueResetZeroAllocsAndClearsPointers(t *testing.T) {
	var q ringQueue[*panicCtrlPayload]
	for range 128 {
		q.push(&panicCtrlPayload{tag: "live"})
	}
	backing := q.buf
	allocs := testing.AllocsPerRun(20, func() {
		q.reset()
	})
	if allocs != 0 {
		t.Fatalf("ringQueue.reset() allocs = %v, want 0", allocs)
	}
	if q.buf != nil || q.head != 0 || q.count != 0 {
		t.Fatalf("reset state invalid: buf=%v head=%d count=%d", q.buf, q.head, q.count)
	}
	if hasNonNilCtrlSlot(backing) {
		t.Fatal("reset did not zero retained pointers in backing array")
	}
}

func TestDualActorControlStopDuringAcquireDrainsPendingFIFO(t *testing.T) {
	var mu sync.Mutex
	var normalReqs, drainedReqs []string
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})

	a := mustNewControlStopActor(t, &mu, &normalReqs, &drainedReqs, firstStarted, releaseFirst)

	err := conc.RunWait(context.Background(), func(ctx context.Context, n *conc.Nursery) error {
		return driveControlStopDuringAcquire(t, ctx, n, a, firstStarted, releaseFirst)
	})
	if err != nil {
		t.Fatalf("RunWait failed: %v", err)
	}

	assertStringSliceEqual(t, "normalReqs", normalReqs, []string{"req-0"})
	assertStringSliceEqual(t, "drainedReqs", drainedReqs, []string{"req-1", "req-2"})
}

func mustNewControlStopActor(
	t *testing.T,
	mu *sync.Mutex,
	normalReqs *[]string,
	drainedReqs *[]string,
	firstStarted chan struct{},
	releaseFirst <-chan struct{},
) *DualActor[string, string] {
	t.Helper()
	var a *DualActor[string, string]
	var err error
	a, err = NewDualActor(DualActorConfig[string, string]{
		AcquireBuffer: 8,
		OnRequest: func(req string) {
			if req == "req-0" {
				close(firstStarted)
				<-releaseFirst
			}
			mu.Lock()
			*normalReqs = append(*normalReqs, req)
			mu.Unlock()
		},
		OnDrainRequest: func(req string) {
			mu.Lock()
			*drainedReqs = append(*drainedReqs, req)
			mu.Unlock()
		},
		OnControl: func(ctrl string) {
			if ctrl == "halt-stop" {
				a.Stop()
			}
		},
	})
	if err != nil {
		t.Fatalf("NewDualActor failed: %v", err)
	}
	return a
}

func driveControlStopDuringAcquire(
	t *testing.T,
	ctx context.Context,
	n *conc.Nursery,
	a *DualActor[string, string],
	firstStarted <-chan struct{},
	releaseFirst chan struct{},
) error {
	t.Helper()
	if goErr := n.Go(a.Run); goErr != nil {
		return goErr
	}
	if sendErr := a.SendAcquire(ctx, "req-0"); sendErr != nil {
		return sendErr
	}
	<-firstStarted

	// 先入队 req-1/req-2，再在控制队列放入 halt-stop；放行后无论 step 先选中 acquireCh 还是 controlReady，
	// req-1 与 req-2 均绝不可进入普通 OnRequest，且必须在 OnDrainRequest 中保持严格 FIFO 顺序。
	for _, r := range []string{"req-1", "req-2"} {
		if sendErr := a.SendAcquire(ctx, r); sendErr != nil {
			return sendErr
		}
	}
	if !a.SendControl("halt-stop") {
		t.Fatal("SendControl(halt-stop) returned false")
	}
	close(releaseFirst)
	<-a.Done()
	return nil
}

func TestDualActorStopPriorityOverConcurrentContextCancel(t *testing.T) {
	for range 32 {
		a, err := NewDualActor(DualActorConfig[int, int]{
			AcquireBuffer: 2,
			OnRequest:     func(int) {},
			OnControl:     func(int) {},
		})
		if err != nil {
			t.Fatalf("NewDualActor failed: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		a.Stop()
		cancel()
		if runErr := a.Run(ctx); runErr != nil {
			t.Fatalf("Run with both Stop and canceled ctx = %v, want nil (stopCh priority)", runErr)
		}
	}
}

func assertStringSliceEqual(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s[%d] = %q, want %q (full=%v)", label, i, got[i], want[i], got)
		}
	}
}
