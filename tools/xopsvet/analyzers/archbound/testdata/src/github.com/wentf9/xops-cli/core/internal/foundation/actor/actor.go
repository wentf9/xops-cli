package actor

import (
	"context"
	"runtime/debug"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
)

type DualActor struct {
	mu sync.Mutex
	D  algebraic.Duration
}

func New(ctx context.Context) *DualActor {
	_ = trace.WithTrace(ctx)
	_ = debug.Stack
	_ = time.Millisecond
	return &DualActor{}
}
