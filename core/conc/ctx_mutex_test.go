package conc

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestCtxMutexNilAndUninitializedFailClosed(t *testing.T) {
	var zero CtxMutex
	var nilPtr *CtxMutex
	checkUninitializedMutex(t, &zero)
	checkUninitializedMutex(t, nilPtr)

	mu := NewCtxMutex()
	var nilCtx context.Context
	if err := mu.Lock(nilCtx); !errors.Is(err, ErrNilContext) {
		t.Fatalf("Lock(nil) error = %v, want ErrNilContext", err)
	}
	if err := mu.WithLock(nilCtx, func() error { return nil }); !errors.Is(err, ErrNilContext) {
		t.Fatalf("WithLock(nil) error = %v, want ErrNilContext", err)
	}
	if err := mu.WithLock(context.Background(), nil); !errors.Is(err, ErrNilTask) {
		t.Fatalf("WithLock(ctx, nil) error = %v, want ErrNilTask", err)
	}
}

func checkUninitializedMutex(t *testing.T, mu *CtxMutex) {
	t.Helper()
	if err := mu.Lock(context.Background()); !errors.Is(err, ErrMutexNotInitialized) {
		t.Fatalf("Lock error = %v, want ErrMutexNotInitialized", err)
	}
	if mu.TryLock() {
		t.Fatal("uninitialized TryLock must return false")
	}
	if err := mu.WithLock(context.Background(), func() error { return nil }); !errors.Is(err, ErrMutexNotInitialized) {
		t.Fatalf("WithLock error = %v, want ErrMutexNotInitialized", err)
	}
	assertPanics(t, func() {
		mu.Unlock()
	})
}

func TestCtxMutexMutualExclusionAndTryLock(t *testing.T) {
	mu := NewCtxMutex()
	if !mu.TryLock() {
		t.Fatal("first TryLock must succeed")
	}
	if mu.TryLock() {
		t.Fatal("second TryLock while held must fail")
	}
	mu.Unlock()

	var inCritical atomic.Int32
	var maxObserved atomic.Int32

	err := RunWait(context.Background(), func(_ context.Context, n *Nursery) error {
		for range 8 {
			if goErr := n.Go(func(childCtx context.Context) error {
				return hammerCtxMutex(childCtx, mu, &inCritical, &maxObserved)
			}); goErr != nil {
				return goErr
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("RunWait failed: %v", err)
	}
	if maxObserved.Load() != 1 {
		t.Fatalf("maxObserved in critical section = %d, want 1", maxObserved.Load())
	}
}

func hammerCtxMutex(ctx context.Context, mu *CtxMutex, inCritical, maxObserved *atomic.Int32) error {
	for range 20 {
		err := mu.WithLock(ctx, func() error {
			cur := inCritical.Add(1)
			if cur > maxObserved.Load() {
				maxObserved.Store(cur)
			}
			inCritical.Add(-1)
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func TestCtxMutexLockCancellation(t *testing.T) {
	mu := NewCtxMutex()
	if err := mu.Lock(context.Background()); err != nil {
		t.Fatalf("initial Lock failed: %v", err)
	}
	defer mu.Unlock()

	preCancelled, cancelPre := context.WithCancel(context.Background())
	cancelPre()
	if err := mu.Lock(preCancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled Lock error = %v, want context.Canceled", err)
	}

	waitCtx, cancelWait := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancelWait()
	if err := mu.Lock(waitCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timed-out Lock error = %v, want context.DeadlineExceeded", err)
	}
}

func TestCtxMutexDoubleUnlockAndWithLockPanicUnlocks(t *testing.T) {
	mu := NewCtxMutex()
	assertPanics(t, func() {
		mu.Unlock()
	})

	if err := mu.Lock(context.Background()); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}
	mu.Unlock()
	assertPanics(t, func() {
		mu.Unlock()
	})

	assertPanics(t, func() {
		_ = mu.WithLock(context.Background(), func() error {
			panic("inside lock")
		})
	})

	// 即使 WithLock 内部发生 panic，锁也必须已被释放。
	if !mu.TryLock() {
		t.Fatal("WithLock did not unlock after panic")
	}
	mu.Unlock()
}

func assertPanics(t *testing.T, fn func()) {
	t.Helper()
	var panicked bool
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		fn()
	}()
	if !panicked {
		t.Fatal("expected panic, got none")
	}
}
