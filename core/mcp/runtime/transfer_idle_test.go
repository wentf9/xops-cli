package runtime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"
)

// Keep deadline handling in-process so synctest controls all timer advancement.
// Socket interruption and cleanup are exercised by transfer_timeout_test.go.
type idleTestResponseWriter struct{ *httptest.ResponseRecorder }

func (*idleTestResponseWriter) SetReadDeadline(time.Time) error  { return nil }
func (*idleTestResponseWriter) SetWriteDeadline(time.Time) error { return nil }

func TestForwardFileStreamIdleDeadline(t *testing.T) {
	for _, mode := range []string{"stalled", "zero progress", "renewed by progress"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := &Runtime{http: &HTTPOptions{StreamIdle: time.Second}}
				controller := http.NewResponseController(&idleTestResponseWriter{httptest.NewRecorder()})
				var reported int64
				start := time.Now()
				result, err := r.forwardFileStream(t.Context(), controller, func(n int64) error {
					reported += n
					return nil
				}, func(ctx context.Context, report func(int64) error) (streamResult, error) {
					if mode == "renewed by progress" {
						for range 4 {
							time.Sleep(750 * time.Millisecond)
							if err := report(1); err != nil {
								return streamResult{}, err
							}
						}
						return streamResult{Bytes: 4}, nil
					}
					if mode == "zero progress" {
						time.Sleep(750 * time.Millisecond)
						if err := report(0); err != nil {
							return streamResult{}, err
						}
					}
					select {
					case <-ctx.Done():
						return streamResult{}, ctx.Err()
					case <-time.After(10 * time.Second):
						return streamResult{}, errors.New("idle stream was not cancelled")
					}
				})
				if mode == "renewed by progress" {
					if err != nil || result.Bytes != 4 || reported != 4 || time.Since(start) != 3*time.Second {
						t.Fatalf("progressing stream: result=%+v reported=%d duration=%v error=%v", result, reported, time.Since(start), err)
					}
				} else if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != time.Second || reported != 0 {
					t.Fatalf("idle stream: reported=%d duration=%v error=%v", reported, time.Since(start), err)
				}
				if t.Context().Err() != nil {
					t.Fatal("stream cancellation propagated to its parent")
				}
			})
		})
	}
}
