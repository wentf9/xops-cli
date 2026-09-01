package cmd

import (
	"context"
	"errors"
	"testing"
)

func TestNCListenMode_CancellationUnblocksAccept(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := ncListenMode(ctx, 0, "tcp")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ncListenMode() error = %v, want context.Canceled", err)
	}
}
