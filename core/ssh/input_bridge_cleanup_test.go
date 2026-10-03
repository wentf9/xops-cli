package ssh

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

type delayedInputBridge struct {
	waiting                   chan context.Context
	stopping, release, reaped chan struct{}
	cleanupErr                error
	payload                   string
}
type observedInputCopy struct {
	InputCopy
	waiting chan context.Context
}

func (c observedInputCopy) Wait(ctx context.Context) error {
	c.waiting <- ctx
	return c.InputCopy.Wait(ctx)
}
func (b *delayedInputBridge) Start(ctx context.Context, _ InteractiveIO, dst io.Writer) (InputCopy, error) {
	if b.payload != "" {
		if _, err := io.WriteString(dst, b.payload); err != nil {
			return nil, err
		}
	}
	done := make(chan error, 1)
	stop := sync.OnceFunc(func() { close(b.stopping) })
	go func() {
		select {
		case <-b.stopping:
		case <-ctx.Done():
		}
		<-b.release
		close(b.reaped)
		done <- nil
	}()
	copy, err := NewInputCopy(ctx, func() error { stop(); return b.cleanupErr }, done)
	return observedInputCopy{InputCopy: copy, waiting: b.waiting}, err
}
func TestBridgedInputJoinsAfterOperationCancellation(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "cleanup-error"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			b := &delayedInputBridge{waiting: make(chan context.Context, 1), stopping: make(chan struct{}), release: make(chan struct{}), reaped: make(chan struct{})}
			if fail {
				b.cleanupErr = errors.New("input cleanup failed")
			}
			release := sync.OnceFunc(func() { close(b.release) })
			defer release()
			stop, done, err := startInputCopy(ctx, b, InteractiveIO{}, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			waitCtx := <-b.waiting
			cancel()
			if err := stop(); !errors.Is(err, b.cleanupErr) {
				t.Errorf("close error: %v", err)
			}
			if err := waitCtx.Err(); err != nil {
				t.Errorf("input joined with cancelled operation context: %v", err)
			}
			select {
			case err := <-done:
				t.Fatalf("join finished before pump cleanup: %v", err)
			default:
			}
			release()
			select {
			case err := <-done:
				if errors.Is(err, context.Canceled) || !errors.Is(err, b.cleanupErr) {
					t.Errorf("joined error: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("input cleanup did not finish")
			}
			select {
			case <-b.reaped:
			default:
				t.Fatal("input worker still running")
			}
		})
	}
}

func TestSuccessfulPrivilegeSessionWaitsForOpenInputCleanup(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeSudo, SudoModeSu} {
		t.Run(string(mode), func(t *testing.T) {
			setTestHome(t)
			address, _ := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: mode, password: "valid", inputBytes: 1})
			client := exchangeTestClient(t, address, mode, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
			b := &delayedInputBridge{waiting: make(chan context.Context, 1), stopping: make(chan struct{}), release: make(chan struct{}), reaped: make(chan struct{}), payload: "x"}
			client.environment.InputBridge = b
			release := sync.OnceFunc(func() { close(b.release) })
			input, err := os.CreateTemp(t.TempDir(), "stdin")
			if err != nil {
				t.Fatal(err)
			}
			defer closePrivilegeTestResource(t, input)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			done := make(chan error, 1)
			go func() { done <- client.runPrivilegeOperation(ctx, mode, "command", input, io.Discard, io.Discard) }()
			joined := false
			defer func() {
				release()
				cancel()
				if !joined {
					<-done
				}
			}()
			var waitCtx context.Context
			select {
			case waitCtx = <-b.waiting:
			case <-ctx.Done():
				t.Fatal("input wait did not start")
			}
			select {
			case <-b.stopping:
			case <-ctx.Done():
				t.Fatal("successful session did not close input")
			}
			if waitCtx.Err() != nil {
				t.Error("successful command cancelled its cleanup wait")
			}
			release()
			err = <-done
			joined = true
			if err != nil {
				t.Fatalf("successful command acquired cleanup error: %v", err)
			}
			select {
			case <-b.reaped:
			default:
				t.Fatal("command returned before input cleanup")
			}
		})
	}
}
