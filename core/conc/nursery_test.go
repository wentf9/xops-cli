package conc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// wrappedCleanupError 模拟携带操作语义的单值包装错误（类似 *os.PathError / *AuditPostWriteError），
// 用于验证 RunScoped 绝不会递归解包并吞噬具名清理或 I/O 故障。
type wrappedCleanupError struct {
	op  string
	err error
}

func (e *wrappedCleanupError) Error() string {
	return fmt.Sprintf("%s: %v", e.op, e.err)
}

func (e *wrappedCleanupError) Unwrap() error {
	return e.err
}

// emptyMultiError 模拟返回空切片的多值错误包装，用于验证 checkMultiScopeCancel 的 fail-closed 边界。
type emptyMultiError struct{}

func (emptyMultiError) Error() string   { return "empty multi error" }
func (emptyMultiError) Unwrap() []error { return nil }

func TestNurseryNilAndUninitializedFailClosed(t *testing.T) {
	var nilCtx context.Context
	if _, err := NewNursery(nilCtx); !errors.Is(err, ErrNilContext) {
		t.Fatalf("NewNursery(nil) error = %v, want ErrNilContext", err)
	}
	if err := RunWait(nilCtx, func(context.Context, *Nursery) error { return nil }); !errors.Is(err, ErrNilContext) {
		t.Fatalf("RunWait(nil) error = %v, want ErrNilContext", err)
	}
	if err := RunWait(context.Background(), nil); !errors.Is(err, ErrNilTask) {
		t.Fatalf("RunWait(ctx, nil) error = %v, want ErrNilTask", err)
	}
	if err := RunScoped(nilCtx, func(context.Context, *Nursery) error { return nil }); !errors.Is(err, ErrNilContext) {
		t.Fatalf("RunScoped(nil) error = %v, want ErrNilContext", err)
	}
	if err := RunScoped(context.Background(), nil); !errors.Is(err, ErrNilTask) {
		t.Fatalf("RunScoped(ctx, nil) error = %v, want ErrNilTask", err)
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

func TestNurseryRunWaitNormalAndWaitAllChildren(t *testing.T) {
	const taskCount = 16
	var completed atomic.Int32
	var scopeCtx context.Context

	err := RunWait(context.Background(), func(ctx context.Context, n *Nursery) error {
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
		t.Fatalf("RunWait failed: %v", err)
	}
	if got := completed.Load(); got != taskCount {
		t.Fatalf("completed = %d, want %d", got, taskCount)
	}
	if scopeCtx.Err() == nil {
		t.Fatal("scopeCtx must be cancelled after RunWait returns")
	}
}

func TestNurseryFirstErrorCancelsSiblingsAndWaits(t *testing.T) {
	sentinel := errors.New("boom")
	started := make(chan struct{})
	var siblingExited atomic.Bool

	err := RunWait(context.Background(), func(_ context.Context, n *Nursery) error {
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
		t.Fatalf("RunWait error = %v, want sentinel", err)
	}
	if !siblingExited.Load() {
		t.Fatal("RunWait returned before sibling exited")
	}
}

func TestNurseryChildPanicRecoveredAndCancels(t *testing.T) {
	started := make(chan struct{})
	var siblingCancelled atomic.Bool

	err := RunWait(context.Background(), func(_ context.Context, n *Nursery) error {
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
	pErr, ok := errors.AsType[*PanicError](err)
	if !ok {
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
	for _, tc := range []struct {
		name string
		run  func(context.Context, func(context.Context, *Nursery) error) error
	}{
		{name: "RunWait", run: RunWait},
		{name: "RunScoped", run: RunScoped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := make(chan struct{})
			var childDone atomic.Bool

			err := tc.run(context.Background(), func(_ context.Context, n *Nursery) error {
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
				t.Fatalf("child goroutine did not finish before %s returned from scope panic", tc.name)
			}
		})
	}
}

func TestNurseryRunScopedCancelsBackgroundDaemonOnNormalReturn(t *testing.T) {
	daemonStarted := make(chan struct{})
	var daemonExited atomic.Bool
	var scopeCtx context.Context

	err := RunScoped(context.Background(), func(ctx context.Context, n *Nursery) error {
		scopeCtx = ctx
		if goErr := n.Go(func(childCtx context.Context) error {
			close(daemonStarted)
			<-childCtx.Done()
			daemonExited.Store(true)
			return childCtx.Err()
		}); goErr != nil {
			return goErr
		}
		<-daemonStarted
		return nil
	})

	if err != nil {
		t.Fatalf("RunScoped normal return error = %v, want nil", err)
	}
	if !daemonExited.Load() {
		t.Fatal("background daemon did not exit before RunScoped returned")
	}
	if scopeCtx.Err() == nil {
		t.Fatal("scopeCtx must be cancelled after RunScoped returns")
	}
}

func TestNurseryRunScopedIgnoresContextCauseSentinel(t *testing.T) {
	started := make(chan struct{}, 2)

	err := RunScoped(context.Background(), func(_ context.Context, n *Nursery) error {
		if goErr := n.Go(func(childCtx context.Context) error {
			started <- struct{}{}
			<-childCtx.Done()
			return context.Cause(childCtx)
		}); goErr != nil {
			return goErr
		}
		if goErr := n.Go(func(childCtx context.Context) error {
			started <- struct{}{}
			<-childCtx.Done()
			return errors.Join(childCtx.Err(), context.Cause(childCtx))
		}); goErr != nil {
			return goErr
		}
		<-started
		<-started
		return nil
	})

	if err != nil {
		t.Fatalf("RunScoped error = %v, want nil (must filter errScopeCompleted sentinel)", err)
	}
}

func TestNurseryRunScopedPreservesSingleWrappedCleanupError(t *testing.T) {
	cases := []struct {
		name      string
		makeError func(childCtx context.Context) error
		wantSub   string
	}{
		{
			name: "fmt_errorf_wraps_canceled",
			makeError: func(childCtx context.Context) error {
				return fmt.Errorf("flush wal: %w", childCtx.Err())
			},
			wantSub: "flush wal",
		},
		{
			name: "fmt_errorf_wraps_cause",
			makeError: func(childCtx context.Context) error {
				return fmt.Errorf("flush cause: %w", context.Cause(childCtx))
			},
			wantSub: "flush cause",
		},
		{
			name: "custom_single_unwrapper_error",
			makeError: func(childCtx context.Context) error {
				return &wrappedCleanupError{op: "close-audit", err: childCtx.Err()}
			},
			wantSub: "close-audit",
		},
		{
			name: "single_wrapper_around_joined_cancels",
			makeError: func(childCtx context.Context) error {
				return fmt.Errorf("teardown: %w", errors.Join(childCtx.Err(), context.Cause(childCtx)))
			},
			wantSub: "teardown",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			started := make(chan struct{})
			err := RunScoped(context.Background(), func(_ context.Context, n *Nursery) error {
				if goErr := n.Go(func(childCtx context.Context) error {
					close(started)
					<-childCtx.Done()
					return tc.makeError(childCtx)
				}); goErr != nil {
					return goErr
				}
				<-started
				return nil
			})
			if err == nil {
				t.Fatalf("RunScoped swallowed single-wrapped cleanup error (%s)", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("RunScoped error = %q, want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestNurseryRunScopedPreservesJoinedCleanupError(t *testing.T) {
	cleanupSentinel := errors.New("audit flush failed")

	t.Run("join_with_real_error", func(t *testing.T) {
		err := runScopedWithDaemonError(t, func(childCtx context.Context) error {
			return errors.Join(childCtx.Err(), cleanupSentinel)
		})
		if !errors.Is(err, cleanupSentinel) {
			t.Fatalf("RunScoped error = %v, want cleanupSentinel", err)
		}
	})

	t.Run("join_with_single_wrapped_cancel", func(t *testing.T) {
		err := runScopedWithDaemonError(t, func(childCtx context.Context) error {
			return errors.Join(childCtx.Err(), fmt.Errorf("drain socket: %w", childCtx.Err()))
		})
		if err == nil || !strings.Contains(err.Error(), "drain socket") {
			t.Fatalf("RunScoped error = %v, want preserved wrapped error inside Join", err)
		}
	})

	t.Run("empty_multi_unwrapper_not_swallowed", func(t *testing.T) {
		err := runScopedWithDaemonError(t, func(context.Context) error {
			return emptyMultiError{}
		})
		if err == nil || !strings.Contains(err.Error(), "empty multi error") {
			t.Fatalf("RunScoped error = %v, want emptyMultiError preserved", err)
		}
	})
}

func runScopedWithDaemonError(t *testing.T, makeErr func(childCtx context.Context) error) error {
	t.Helper()
	started := make(chan struct{})
	return RunScoped(context.Background(), func(_ context.Context, n *Nursery) error {
		if goErr := n.Go(func(childCtx context.Context) error {
			close(started)
			<-childCtx.Done()
			return makeErr(childCtx)
		}); goErr != nil {
			return goErr
		}
		<-started
		return nil
	})
}

func TestNurseryRunScopedPreservesParentCancel(t *testing.T) {
	parentCtx, cancelParent := context.WithCancel(context.Background())
	daemonStarted := make(chan struct{})
	parentCancelled := make(chan struct{})

	err := RunScoped(parentCtx, func(_ context.Context, n *Nursery) error {
		if goErr := n.Go(func(childCtx context.Context) error {
			close(daemonStarted)
			<-childCtx.Done()
			return childCtx.Err()
		}); goErr != nil {
			return goErr
		}
		<-daemonStarted
		cancelParent()
		close(parentCancelled)
		return nil
	})
	<-parentCancelled

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunScoped error = %v, want context.Canceled when parent cancelled", err)
	}
}

func TestNurseryRunScopedReturnsFnErrorAndCancelsDaemon(t *testing.T) {
	fnSentinel := errors.New("main scope failed")
	daemonStarted := make(chan struct{})
	var daemonExited atomic.Bool

	err := RunScoped(context.Background(), func(_ context.Context, n *Nursery) error {
		if goErr := n.Go(func(childCtx context.Context) error {
			close(daemonStarted)
			<-childCtx.Done()
			daemonExited.Store(true)
			return nil
		}); goErr != nil {
			return goErr
		}
		<-daemonStarted
		return fnSentinel
	})

	if !errors.Is(err, fnSentinel) {
		t.Fatalf("RunScoped error = %v, want fnSentinel", err)
	}
	if !daemonExited.Load() {
		t.Fatal("daemon did not exit before RunScoped returned error")
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
