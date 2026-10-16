package ssh

import (
	"context"
	"testing"
)

func TestConsoleOutputRelayContextSnapshot(t *testing.T) {
	parent := t.Context()
	relay := ConsoleOutputRelay{Executable: "host", Args: []string{"private"}, Env: []string{"KEY=value"}}
	ctx, cleanup := WithConsoleOutputRelay(parent, relay)
	defer func() { _ = cleanup() }()
	relay.Args[0], relay.Env[0] = "changed", "changed"
	got := ctx.Value(consoleOutputRelayKey{}).(*consoleRelayScope).config
	if got.Executable != "host" || got.Args[0] != "private" || got.Env[0] != "KEY=value" {
		t.Fatalf("relay snapshot mutated: %+v", got)
	}
	if parent.Value(consoleOutputRelayKey{}) != nil {
		t.Fatal("relay capability escaped into parent context")
	}
	work, cancel := context.WithCancel(ctx)
	cancel()
	if work.Err() != context.Canceled || work.Value(consoleOutputRelayKey{}) == nil {
		t.Fatal("relay context lost cancellation or capability propagation")
	}
}
