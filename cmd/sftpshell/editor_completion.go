package sftpshell

import (
	"context"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"
)

type completionResult struct {
	head       string
	candidates []string
	tail       string
	err        error
}
type completionFunc func(context.Context, string, int) completionResult
type completionRequest struct {
	id     uint64
	line   string
	pos    int
	ctx    context.Context
	cancel context.CancelFunc
}
type completionMsg struct {
	id     uint64
	line   string
	pos    int
	result completionResult
}

// One worker per prompt bounds network concurrency. Every request is canceled
// on input changes, and Close joins the worker before terminal handoff.
type completionWorker struct {
	ctx      context.Context
	cancel   context.CancelFunc
	complete completionFunc
	requests chan completionRequest
	done     chan struct{}
	once     sync.Once
}

func newCompletionWorker(ctx context.Context, complete completionFunc) *completionWorker {
	ctx, cancel := context.WithCancel(ctx)
	return &completionWorker{ctx: ctx, cancel: cancel, complete: complete, requests: make(chan completionRequest, 1), done: make(chan struct{})}
}
func (w *completionWorker) Start(send func(tea.Msg)) {
	go func() {
		defer close(w.done)
		for {
			select {
			case <-w.ctx.Done():
				return
			case req := <-w.requests:
				if req.ctx.Err() != nil {
					req.cancel()
					continue
				}
				result := w.complete(req.ctx, req.line, req.pos)
				if req.ctx.Err() == nil || req.ctx.Err() == context.DeadlineExceeded {
					if req.ctx.Err() != nil {
						result.err = req.ctx.Err()
					}
					send(completionMsg{req.id, req.line, req.pos, result})
				}
				req.cancel()
			}
		}
	}()
}
func (w *completionWorker) Schedule(id uint64, line string, pos int) context.CancelFunc {
	ctx, cancel := context.WithTimeout(w.ctx, 2*time.Second)
	req := completionRequest{id, line, pos, ctx, cancel}
	select {
	case old := <-w.requests:
		old.cancel()
	default:
	}
	select {
	case w.requests <- req:
	case <-w.ctx.Done():
		cancel()
	}
	return cancel
}
func (w *completionWorker) Close() {
	w.once.Do(func() {
		w.cancel()
		<-w.done
		select {
		case req := <-w.requests:
			req.cancel()
		default:
		}
	})
}
