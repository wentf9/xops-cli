package ssh

import (
	"context"
	"errors"
	"os"
	"testing"
)

type retainedRelayBinding struct {
	scope   *consoleRelayScope
	ctx     context.Context
	failure error
	calls   int
}

func (b *retainedRelayBinding) close() error {
	b.calls++
	if b.ctx.Err() != context.Canceled {
		return errors.New("scope did not cancel output before joining it")
	}
	if b.failure != nil {
		return b.failure
	}
	b.scope.remove(b)
	return nil
}

func TestConsoleOutputRelayScopeOwnsFailedCleanup(t *testing.T) {
	ctx, cleanup := WithConsoleOutputRelay(t.Context(), ConsoleOutputRelay{})
	scope := ctx.Value(consoleOutputRelayKey{}).(*consoleRelayScope)
	failure := errors.New("relay termination pending")
	binding := &retainedRelayBinding{scope: scope, ctx: ctx, failure: failure}
	if err := scope.add(binding); err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); !errors.Is(err, failure) {
		t.Fatalf("cleanup failure lost: %v", err)
	}
	if len(scope.owned) != 1 || binding.calls != 1 {
		t.Fatal("scope discarded an unjoined binding")
	}
	if err := scope.add(&retainedRelayBinding{}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed scope accepted new output: %v", err)
	}
	binding.failure = nil
	if err := cleanup(); err != nil {
		t.Fatalf("retry owner cleanup: %v", err)
	}
	if len(scope.owned) != 0 || binding.calls != 2 {
		t.Fatal("owner cleanup did not reclaim failed binding")
	}
	if err := cleanup(); err != nil || binding.calls != 2 {
		t.Fatalf("cleanup not idempotent: %v", err)
	}
}
