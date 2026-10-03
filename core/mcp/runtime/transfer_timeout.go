package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// forwardFileStream bounds inactivity across both sides of the relay, including
// an SFTP read/write/close that makes no progress while SSH stays healthy. The
// worker exits on parent cancellation, idle expiry, or operation completion and
// is joined before returning. This child context never cancels the lease or its
// independent commit context.
func (r *Runtime) forwardFileStream(parent context.Context, controller *http.ResponseController, progress func(int64) error, forward func(context.Context, func(int64) error) (streamResult, error)) (result streamResult, retErr error) {
	ctx, cancel := context.WithCancelCause(parent)
	idle := r.http.StreamIdle
	var mu sync.Mutex
	lastProgress := time.Now()
	idleErr := fmt.Errorf("file stream made no progress within %s: %w", idle, context.DeadlineExceeded)
	done := make(chan struct{})
	timer := time.NewTimer(idle)
	go func() {
		defer close(done)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				mu.Lock()
				remaining := idle - time.Since(lastProgress)
				if remaining <= 0 {
					cancel(idleErr)
				}
				mu.Unlock()
				if remaining <= 0 {
					return
				}
				timer.Reset(remaining)
			}
		}
	}()
	stopIO := r.interruptHTTPIO(ctx, controller)
	defer func() {
		// Join HTTP cancellation before deliberate child cancellation so successful
		// streams do not poison the subsequent commit or final response deadlines.
		stopIO()
		retErr = errors.Join(retErr, context.Cause(ctx))
		cancel(context.Canceled)
		<-done
	}()
	report := func(n int64) error {
		mu.Lock()
		if time.Since(lastProgress) >= idle {
			cancel(idleErr)
		}
		err := context.Cause(ctx)
		if err == nil && n > 0 {
			lastProgress = time.Now()
		}
		mu.Unlock()
		if err != nil {
			return err
		}
		return progress(n)
	}
	return forward(ctx, report)
}
