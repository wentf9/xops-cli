//go:build linux && amd64

package kdfhelper

import (
	"context"
	"errors"
	"testing"
	"time"
)

type capturedInput struct {
	writes int
	closed bool
}

func (c *capturedInput) Write(b []byte) (int, error) { c.writes++; return len(b), nil }
func (c *capturedInput) Close() error                { c.closed = true; return nil }

func TestFailedAdmissionNeverSendsKDFRequest(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(ErrResource)
	out := &capturedInput{}
	if err := sendRequest(ctx, out, []byte("public-placeholder")); !errors.Is(err, ErrResource) {
		t.Fatal(err)
	}
	if out.writes != 0 || !out.closed {
		t.Fatal("request was sent after limit/admission failure")
	}
}

func TestRunnerInheritsCallerBudget(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	d, err := processTimeout(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if d < time.Minute || d > 2*time.Minute {
		t.Fatal("caller budget silently capped at default")
	}
}

func TestCgroupRemainingBounds(t *testing.T) {
	for _, tc := range []struct {
		name, limit, used string
		want              uint64
		known             bool
	}{
		{"bounded", "100", "60", 40, true}, {"overfull", "100", "110", 0, true}, {"unlimited", "max", "60", 0, false}, {"invalid", "bad", "1", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, known := cgroupRemaining(tc.limit, tc.used)
			if n != tc.want || known != tc.known {
				t.Fatalf("remaining=%d known=%t", n, known)
			}
		})
	}
}
