package conc

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

	actor, err := NewDualActor(DualActorConfig[string, string]{
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

	runErr := make(chan error, 1)
	go func() {
		runErr <- actor.Run(context.Background())
	}()

	if err := actor.SendAcquire(context.Background(), "req-block"); err != nil {
		t.Fatalf("SendAcquire block failed: %v", err)
	}
	<-firstReqStarted

	// 当 Actor 阻塞在第一条请求回调中时，先后填入多条请求与控制消息；
	// 放行后，所有控制消息必须先于后续请求执行。
	enqueuePriorityBurst(t, actor)
	close(reqRelease)

	select {
	case <-allDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for actor order")
	}

	actor.Stop()
	<-actor.Done()
	if err := <-runErr; err != nil {
		t.Fatalf("Run error = %v", err)
	}

	verifyControlPriorityOrder(t, order)
}

func enqueuePriorityBurst(t *testing.T, actor *DualActor[string, string]) {
	t.Helper()
	for _, r := range []string{"req-1", "req-2"} {
		if err := actor.SendAcquire(context.Background(), r); err != nil {
			t.Fatalf("SendAcquire %s failed: %v", r, err)
		}
	}
	for _, c := range []string{"ctrl-1", "ctrl-2", "ctrl-3", "ctrl-4"} {
		if !actor.SendControl(c) {
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

	actor, err := NewDualActor(DualActorConfig[int, int]{
		AcquireBuffer: 4,
		OnRequest: func(int) {
			close(gateEntered)
			<-gate
		},
		OnControl: func(v int) {
			got := ctrlCount.Add(1)
			if int64(v+1) != got {
				// 仅在出错时记录，避免竞争。
				ctrlCount.Store(-1)
			}
		},
	})
	if err != nil {
		t.Fatalf("NewDualActor failed: %v", err)
	}

	runErr := make(chan error, 1)
	go func() {
		runErr <- actor.Run(context.Background())
	}()

	if err := actor.SendAcquire(context.Background(), 1); err != nil {
		t.Fatalf("SendAcquire failed: %v", err)
	}
	<-gateEntered

	// 在 Actor 循环阻塞期间一次性发送超过 10,000 条控制消息，验证绝不阻塞发送方。
	for i := range totalControls {
		if !actor.SendControl(i) {
			t.Fatalf("SendControl(%d) returned false", i)
		}
	}
	close(gate)

	actor.Stop()
	<-actor.Done()
	if err := <-runErr; err != nil {
		t.Fatalf("Run error = %v", err)
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

	actor, err := NewDualActor(DualActorConfig[int, int]{
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

	var nilCtx context.Context
	if err := actor.Run(nilCtx); !errors.Is(err, ErrNilContext) {
		t.Fatalf("Run(nil) error = %v, want ErrNilContext", err)
	}
	if err := actor.SendAcquire(nilCtx, 1); !errors.Is(err, ErrNilContext) {
		t.Fatalf("SendAcquire(nil) error = %v, want ErrNilContext", err)
	}

	runErr := make(chan error, 1)
	go func() {
		runErr <- actor.Run(context.Background())
	}()

	if err := actor.SendAcquire(context.Background(), 1); err != nil {
		t.Fatalf("SendAcquire 1 failed: %v", err)
	}
	<-entered
	// 确认后台 Run 已处于运行态后，重复调用 Run 必须立即失败关闭。
	if err := actor.Run(context.Background()); !errors.Is(err, ErrActorAlreadyStarted) {
		t.Fatalf("second Run error = %v, want ErrActorAlreadyStarted", err)
	}
	if err := actor.SendAcquire(context.Background(), 2); err != nil {
		t.Fatalf("SendAcquire 2 failed: %v", err)
	}
	if err := actor.SendAcquire(context.Background(), 3); err != nil {
		t.Fatalf("SendAcquire 3 failed: %v", err)
	}

	// acquireCh 已满（cap=2），此时发起阻塞 SendAcquire 应在 Stop 后立即返回 ErrActorStopped。
	blockedSendErr := make(chan error, 1)
	go func() {
		blockedSendErr <- actor.SendAcquire(context.Background(), 4)
	}()
	time.Sleep(2 * time.Millisecond)

	if !actor.SendControl(10) || !actor.SendControl(20) {
		t.Fatal("SendControl before Stop failed")
	}
	actor.Stop()
	close(blockReq)

	<-actor.Done()
	if err := <-runErr; err != nil {
		t.Fatalf("Run error = %v", err)
	}
	if err := <-blockedSendErr; !errors.Is(err, ErrActorStopped) {
		t.Fatalf("blocked SendAcquire error = %v, want ErrActorStopped", err)
	}
	if actor.SendControl(30) {
		t.Fatal("SendControl after shutdown must return false")
	}
	if err := actor.SendAcquire(context.Background(), 5); !errors.Is(err, ErrActorStopped) {
		t.Fatalf("SendAcquire after shutdown error = %v, want ErrActorStopped", err)
	}
	if drainedReqs.Load() != 2 || drainedCtrls.Load() != 2 {
		t.Fatalf("drainedReqs=%d drainedCtrls=%d, want 2 and 2", drainedReqs.Load(), drainedCtrls.Load())
	}
}

func TestDualActorContextCancellationAndSendAcquireCancel(t *testing.T) {
	actor, err := NewDualActor(DualActorConfig[int, int]{
		AcquireBuffer: 1,
		OnRequest:     func(int) {},
		OnControl:     func(int) {},
	})
	if err != nil {
		t.Fatalf("NewDualActor failed: %v", err)
	}

	// 填满缓冲区测试 SendAcquire 上下文取消。
	if err := actor.SendAcquire(context.Background(), 1); err != nil {
		t.Fatalf("SendAcquire failed: %v", err)
	}
	cancelledCtx, cancelSend := context.WithCancel(context.Background())
	cancelSend()
	if err := actor.SendAcquire(cancelledCtx, 2); !errors.Is(err, context.Canceled) {
		t.Fatalf("SendAcquire cancelled error = %v, want context.Canceled", err)
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() {
		runErr <- actor.Run(runCtx)
	}()
	cancelRun()

	<-actor.Done()
	if err := <-runErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
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
