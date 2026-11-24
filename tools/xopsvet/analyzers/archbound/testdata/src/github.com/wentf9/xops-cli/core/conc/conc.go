package conc

import (
	"context"
	"runtime/debug"
	"sync"
	"time"
)

type Nursery struct {
	mu sync.Mutex
}

func NewNursery(ctx context.Context) *Nursery {
	_ = ctx
	_ = debug.Stack
	_ = time.Second
	return &Nursery{}
}
