package conc

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNurseryNilAndUninitializedFailClosed(t *testing.T) {
	var nilCtx context.Context
	if _, err := NewNursery(nilCtx); !errors.Is(err, ErrNilContext) {
		t.Fatalf("NewNursery(nil) error = %v, want ErrNilContext", err)
	}
	if err := Run(nilCtx, func(context.Context, *Nursery) error { return nil }); !errors.Is(err, ErrNilContext) {
		t.Fatalf("Run(nil) error = %v, want ErrNilContext", err)
	}
	if err := Run(context.Background(), nil); !errors.Is(err, ErrNilTask) {
		t.Fatalf("Run(ctx, nil) error = %v, want ErrNilTask", err)
	}

	var zero Nursery
	var nilPtr *Nursery
	checkUninitializedNursery(t, &zero)
	checkUninitializedNursery(t, nilPtr)
}

func checkUninitializedNursery(t *testing.T, n *Nursery) {
	t.Helper()
	if err := n.Go(func(context.Context) error { return nil }); !errors.Is(err, ErrNurseryNotInitialized) {
		t.Fatalf("Go error = %v, want ErrNurseryNotInitialized", err)
	}
	if err := n.Wait(); !errors.Is(err, ErrNurseryNotInitialized) {
		t.Fatalf("Wait error = %v, want ErrNurseryNotInitialized", err)
	}
	if err := n.Close(); !errors.Is(err, ErrNurseryNotInitialized) {
		t.Fatalf("Close error = %v, want ErrNurseryNotInitialized", err)
	}
	n.Cancel(errors.New("ignored"))
	ctx := n.Context()
	if ctx.Err() == nil {
		t.Fatal("uninitialized Context() must be pre-cancelled")
	}
	if !errors.Is(context.Cause(ctx), ErrNurseryNotInitialized) {
		t.Fatalf("context.Cause = %v, want ErrNurseryNotInitialized", context.Cause(ctx))
	}
}

func TestNurseryRunNormalAndWaitAllChildren(t *testing.T) {
	const taskCount = 16
	var completed atomic.Int32
	var scopeCtx context.Context

	err := Run(context.Background(), func(ctx context.Context, n *Nursery) error {
		scopeCtx = ctx
		for range taskCount {
			if goErr := n.Go(func(childCtx context.Context) error {
				select {
				case <-childCtx.Done():
					return childCtx.Err()
				case <-time.After(2 * time.Millisecond):
					completed.Add(1)
					return nil
				}
			}); goErr != nil {
				return goErr
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if got := completed.Load(); got != taskCount {
		t.Fatalf("completed = %d, want %d", got, taskCount)
	}
	if scopeCtx.Err() == nil {
		t.Fatal("scopeCtx must be cancelled after Run returns")
	}
}

func TestNurseryFirstErrorCancelsSiblingsAndWaits(t *testing.T) {
	sentinel := errors.New("boom")
	started := make(chan struct{})
	var siblingExited atomic.Bool

	err := Run(context.Background(), func(_ context.Context, n *Nursery) error {
		if goErr := n.Go(func(childCtx context.Context) error {
			close(started)
			<-childCtx.Done()
			siblingExited.Store(true)
			return nil
		}); goErr != nil {
			return goErr
		}
		if goErr := n.Go(func(context.Context) error {
			<-started
			return sentinel
		}); goErr != nil {
			return goErr
		}
		return nil
	})

	if !errors.Is(err, sentinel) {
		t.Fatalf("Run error = %v, want sentinel", err)
	}
	if !siblingExited.Load() {
		t.Fatal("Run returned before sibling exited")
	}
}

func TestNurseryChildPanicRecoveredAndCancels(t *testing.T) {
	started := make(chan struct{})
	var siblingCancelled atomic.Bool

	err := Run(context.Background(), func(_ context.Context, n *Nursery) error {
		if goErr := n.Go(func(childCtx context.Context) error {
			close(started)
			<-childCtx.Done()
			siblingCancelled.Store(true)
			return nil
		}); goErr != nil {
			return goErr
		}
		if goErr := n.Go(func(context.Context) error {
			<-started
			panic("child kaboom")
		}); goErr != nil {
			return goErr
		}
		return nil
	})

	if !errors.Is(err, ErrTaskPanicked) {
		t.Fatalf("err = %v, want ErrTaskPanicked", err)
	}
	var pErr *PanicError
	if !errors.As(err, &pErr) {
		t.Fatalf("err = %v, want *PanicError", err)
	}
	if pErr.Value() != "child kaboom" {
		t.Fatalf("PanicError.Value() = %v, want child kaboom", pErr.Value())
	}
	if len(pErr.Stack()) == 0 || !strings.Contains(pErr.Error(), "child kaboom") {
		t.Fatalf("unexpected PanicError formatting: %q", pErr.Error())
	}
	if !siblingCancelled.Load() {
		t.Fatal("sibling must be cancelled and waited on after child panic")
	}
}

func TestNurseryScopePanicRecoveredAndWaitsChildren(t *testing.T) {
	started := make(chan struct{})
	var childDone atomic.Bool

	err := Run(context.Background(), func(_ context.Context, n *Nursery) error {
		if goErr := n.Go(func(childCtx context.Context) error {
			close(started)
			<-childCtx.Done()
			childDone.Store(true)
			return nil
		}); goErr != nil {
			return goErr
		}
		<-started
		panic("scope kaboom")
	})

	if !errors.Is(err, ErrTaskPanicked) {
		t.Fatalf("err = %v, want ErrTaskPanicked", err)
	}
	if !childDone.Load() {
		t.Fatal("child goroutine did not finish before Run returned from scope panic")
	}
}

func TestNurseryGoRejectedAfterWaitOrClose(t *testing.T) {
	n1, err := NewNursery(context.Background())
	if err != nil {
		t.Fatalf("NewNursery failed: %v", err)
	}
	if err := n1.Go(func(context.Context) error { return ErrNilTask }); err != nil {
		t.Fatalf("Go failed: %v", err)
	}
	if waitErr := n1.Wait(); !errors.Is(waitErr, ErrNilTask) {
		t.Fatalf("Wait error = %v, want ErrNilTask", waitErr)
	}
	if goErr := n1.Go(func(context.Context) error { return nil }); !errors.Is(goErr, ErrNurseryClosed) {
		t.Fatalf("Go after Wait error = %v, want ErrNurseryClosed", goErr)
	}

	n2, err := NewNursery(context.Background())
	if err != nil {
		t.Fatalf("NewNursery failed: %v", err)
	}
	if closeErr := n2.Close(); closeErr != nil {
		t.Fatalf("Close error = %v", closeErr)
	}
	if goErr := n2.Go(func(context.Context) error { return nil }); !errors.Is(goErr, ErrNurseryClosed) {
		t.Fatalf("Go after Close error = %v, want ErrNurseryClosed", goErr)
	}
	if goErr := n2.Go(nil); !errors.Is(goErr, ErrNilTask) {
		t.Fatalf("Go(nil) error = %v, want ErrNilTask", goErr)
	}
}

func TestNurseryConcurrentGoAndWaitStress(t *testing.T) {
	n, err := NewNursery(context.Background())
	if err != nil {
		t.Fatalf("NewNursery failed: %v", err)
	}

	var ran atomic.Int32
	var rejected atomic.Int32
	const spawners = 8
	const perSpawner = 25

	start := make(chan struct{})
	done := make(chan struct{}, spawners)
	for range spawners {
		go spawnIntoNursery(n, start, done, perSpawner, &ran, &rejected)
	}
	close(start)

	time.Sleep(time.Millisecond)
	if waitErr := n.Wait(); waitErr != nil {
		t.Fatalf("Wait failed: %v", waitErr)
	}
	for range spawners {
		<-done
	}
	if ran.Load()+rejected.Load() != spawners*perSpawner {
		t.Fatalf("ran=%d rejected=%d total=%d", ran.Load(), rejected.Load(), spawners*perSpawner)
	}
}

func spawnIntoNursery(
	n *Nursery,
	start <-chan struct{},
	done chan<- struct{},
	count int,
	ran *atomic.Int32,
	rejected *atomic.Int32,
) {
	<-start
	for range count {
		if err := n.Go(func(context.Context) error {
			ran.Add(1)
			return nil
		}); err != nil {
			rejected.Add(1)
		}
	}
	done <- struct{}{}
}

func TestPanicErrorNilSafe(t *testing.T) {
	var nilPErr *PanicError
	if nilPErr.Error() != ErrTaskPanicked.Error() {
		t.Fatalf("nil PanicError.Error = %q", nilPErr.Error())
	}
	if nilPErr.Value() != nil || nilPErr.Stack() != nil {
		t.Fatal("nil PanicError Value/Stack must be nil")
	}
	noStack := newPanicError(42, nil)
	if !errors.Is(noStack, ErrTaskPanicked) || !strings.Contains(noStack.Error(), "42") {
		t.Fatalf("noStack = %v", noStack)
	}
}
