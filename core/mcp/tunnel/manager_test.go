package tunnel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func testSpec(id string) Spec {
	return Spec{RequestID: id, NodeID: "node", Mode: "local", ListenHost: "127.0.0.1", TargetHost: "localhost", TargetPort: 8080, TTLSeconds: 3600}
}

func idleRunner(ctx context.Context, _ Spec, ready func(string) bool, _ func(error)) error {
	if !ready("127.0.0.1:12345") {
		return nil
	}
	<-ctx.Done()
	return nil
}

func testManager(t *testing.T, run Runner, observe Observer) *Manager {
	t.Helper()
	t.Cleanup(func() { goleak.VerifyNone(t) })
	m := New(t.Context(), run, observe)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := m.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	return m
}

func TestNormalize(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Spec)
	}{
		{"dynamic", func(s *Spec) { s.Mode = "dynamic" }},
		{"empty node", func(s *Spec) { s.NodeID = "" }},
		{"empty request", func(s *Spec) { s.RequestID = "" }},
		{"control request", func(s *Spec) { s.RequestID = "abc\x1bdef" }},
		{"DNS listen", func(s *Spec) { s.ListenHost = "example.org" }},
		{"negative port", func(s *Spec) { s.ListenPort = -1 }},
		{"large port", func(s *Spec) { s.ListenPort = 65536 }},
		{"zero target", func(s *Spec) { s.TargetPort = 0 }},
		{"bad host", func(s *Spec) { s.TargetHost = "host:12" }},
		{"control host", func(s *Spec) { s.TargetHost = "host\a" }},
		{"empty host", func(s *Spec) { s.TargetHost = "" }},
		{"bracketed IPv6", func(s *Spec) { s.TargetHost = "[::1]" }},
		{"long TTL", func(s *Spec) { s.TTLSeconds = 86401 }},
		{"negative TTL", func(s *Spec) { s.TTLSeconds = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testSpec("test")
			tc.change(&s)
			if _, err := Normalize(s); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	s := testSpec("defaults")
	s.ListenHost = ""
	s.TTLSeconds = 0
	n, err := Normalize(s)
	if err != nil || n.ListenAddress() != "127.0.0.1:0" || n.TTLSeconds != 3600 {
		t.Fatalf("defaults: %+v, %v", n, err)
	}
	s.ListenHost, s.TargetHost = "::1", "2001:db8::1"
	n, err = Normalize(s)
	if err != nil || n.ListenAddress() != "[::1]:0" || n.TargetAddress() != "[2001:db8::1]:8080" {
		t.Fatalf("IPv6: %+v, %v", n, err)
	}
}

func TestCreateDetachedIdempotentAndStop(t *testing.T) {
	var starts atomic.Int32
	m := testManager(t, func(ctx context.Context, s Spec, ready func(string) bool, report func(error)) error {
		starts.Add(1)
		report(errors.New("one connection failed"))
		return idleRunner(ctx, s, ready, report)
	}, nil)
	callCtx, cancelCall := context.WithCancel(t.Context())
	first, err := m.Create(callCtx, testSpec("first"), "op")
	if err != nil || first.State != "running" {
		t.Fatalf("create: %+v, %v", first, err)
	}
	cancelCall()
	second, err := m.Create(t.Context(), testSpec("second"), "op2")
	if err != nil {
		t.Fatal(err)
	}
	var calls sync.WaitGroup
	for range 16 {
		calls.Go(func() {
			s, err := m.Create(t.Context(), testSpec("first"), "other-op")
			if err != nil || s.TunnelID != first.TunnelID || s.State != "running" {
				t.Errorf("retry: %+v, %v", s, err)
			}
		})
	}
	calls.Wait()
	if starts.Load() != 2 {
		t.Fatalf("starts = %d", starts.Load())
	}
	changed := testSpec("first")
	changed.TargetPort++
	if _, _, err := m.Retry(changed); err == nil {
		t.Fatal("changed retry accepted")
	}
	assertRepeatedStop(t, m, first.TunnelID)
	retry, err := m.Create(t.Context(), testSpec("first"), "retry")
	if err != nil || retry.State != "stopped" || starts.Load() != 2 {
		t.Fatalf("terminal retry recreated: %+v, %v", retry, err)
	}
	if alive, err := m.Status(second.TunnelID); err != nil || alive.State != "running" || alive.LastConnectionError == "" {
		t.Fatalf("sibling: %+v, %v", alive, err)
	}
	if len(m.List("node", "running")) != 1 || len(m.List("other", "")) != 0 {
		t.Fatal("list filters failed")
	}
}

func assertRepeatedStop(t *testing.T, m *Manager, id string) {
	t.Helper()
	for range 2 {
		s, err := m.Stop(t.Context(), id)
		if err != nil || s.State != "stopped" {
			t.Fatalf("stop: %+v, %v", s, err)
		}
	}
}

func TestConcurrentFirstCreate(t *testing.T) {
	var starts atomic.Int32
	m := testManager(t, func(ctx context.Context, s Spec, ready func(string) bool, report func(error)) error {
		starts.Add(1)
		return idleRunner(ctx, s, ready, report)
	}, nil)
	ids := make(chan string, 32)
	var callers sync.WaitGroup
	for range cap(ids) {
		callers.Go(func() {
			s, err := m.Create(t.Context(), testSpec("same"), "op")
			if err != nil {
				t.Error(err)
				return
			}
			ids <- s.TunnelID
		})
	}
	callers.Wait()
	close(ids)
	first := ""
	for id := range ids {
		if first == "" {
			first = id
		}
		if id != first {
			t.Fatal("duplicate tunnels")
		}
	}
	if starts.Load() != 1 {
		t.Fatalf("started %d times", starts.Load())
	}
}

func TestStartupCancellationAndTimeout(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(fmt.Sprint(timeout), func(t *testing.T) {
			entered := make(chan struct{})
			cancelled := make(chan struct{})
			m := testManager(t, func(ctx context.Context, _ Spec, ready func(string) bool, _ func(error)) error {
				close(entered)
				<-ctx.Done()
				close(cancelled)
				wantCause := errStartupCancelled
				if timeout {
					wantCause = context.DeadlineExceeded
				}
				if cause := context.Cause(ctx); !errors.Is(cause, wantCause) {
					t.Errorf("startup cancellation cause = %v, want %v", cause, wantCause)
				}
				if ready("127.0.0.1:1234") {
					t.Error("published after cancellation")
				}
				return nil
			}, nil)
			if timeout {
				m.startupTimeout = 10 * time.Millisecond
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := m.Create(ctx, testSpec("cancel"), "op"); done <- err }()
			<-entered
			if !timeout {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("creation hung")
			}
			// Create may return before its asynchronous cancellation callback
			// runs. Let the runner observe startup cancellation before Shutdown
			// can supply a different cancellation cause to the task.
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("startup cancellation did not reach the runner")
			}
			if err := m.Shutdown(t.Context()); err != nil {
				t.Fatal(err)
			}
			states := m.List("", "")
			if len(states) != 1 || states[0].State != "failed" || states[0].Error == "" {
				t.Fatalf("state: %+v", states)
			}
		})
	}
}

func TestExpiryAndShutdown(t *testing.T) {
	m := testManager(t, idleRunner, nil)
	spec := testSpec("expiry")
	spec.TTLSeconds = 1
	spec.Mode = "remote"
	s, err := m.Create(t.Context(), spec, "op")
	if err != nil {
		t.Fatal(err)
	}
	m.mu.RLock()
	done := m.tasks[s.TunnelID].done
	m.mu.RUnlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("TTL did not stop task")
	}
	s, err = m.Status(s.TunnelID)
	if err != nil || s.State != "expired" || s.RemoteRelease != "unconfirmed" {
		t.Fatalf("expiry: %+v, %v", s, err)
	}
	other, err := m.Create(t.Context(), testSpec("shutdown"), "op")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if s, err = m.Status(other.TunnelID); err != nil || s.State != "stopped" {
		t.Fatalf("shutdown: %+v, %v", s, err)
	}
	if _, err := m.Create(t.Context(), testSpec("after close"), "op"); err == nil {
		t.Fatal("created after shutdown")
	}
}

func TestCapacityAndRetention(t *testing.T) {
	t.Run("active capacity", func(t *testing.T) {
		m := testManager(t, idleRunner, nil)
		var first Status
		for i := range MaxActive {
			s, err := m.Create(t.Context(), testSpec(fmt.Sprint(i)), "op")
			if err != nil {
				t.Fatal(err)
			}
			first = s
		}
		if _, err := m.Create(t.Context(), testSpec("excess"), "op"); err == nil {
			t.Fatal("capacity exceeded")
		}
		if _, err := m.Stop(t.Context(), first.TunnelID); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Create(t.Context(), testSpec("excess"), "op"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("records and retention", func(t *testing.T) {
		m := testManager(t, idleRunner, nil)
		for i := range MaxRecords {
			id := fmt.Sprint(i)
			done := make(chan struct{})
			close(done)
			m.tasks[id] = &task{ctx: t.Context(), done: done, status: Status{Spec: testSpec(id), TunnelID: id, State: "stopped", FinishedAt: time.Now()}}
			m.requests[id] = id
		}
		if _, err := m.Create(t.Context(), testSpec("excess"), "op"); err == nil {
			t.Fatal("record capacity exceeded")
		}
		m.tasks["0"].status.FinishedAt = time.Now().Add(-Retention - time.Second)
		if _, err := m.Create(t.Context(), testSpec("excess"), "op"); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Status("0"); err == nil {
			t.Fatal("expired record retained")
		}
	})
}

func TestFailureAudit(t *testing.T) {
	for _, event := range []string{"starting", "running"} {
		t.Run("audit "+event, func(t *testing.T) {
			var starts atomic.Int32
			m := testManager(t, func(ctx context.Context, s Spec, ready func(string) bool, report func(error)) error {
				starts.Add(1)
				return idleRunner(ctx, s, ready, report)
			},
				func(_ Status, phase string, _ error) error {
					if phase == event {
						return errors.New("audit unavailable")
					}
					return nil
				})
			s, err := m.Create(t.Context(), testSpec("audit"), "op")
			if err != nil {
				t.Fatal(err)
			}
			if event == "starting" {
				if s.State != "failed" || starts.Load() != 0 || !strings.Contains(s.Error, "audit unavailable") {
					t.Fatalf("pre audit: %+v", s)
				}
			} else if s.State != "running" || s.AuditError == "" {
				t.Fatalf("post audit: %+v", s)
			}
		})
	}
	t.Run("failed runner stays queryable", func(t *testing.T) {
		m := testManager(t, func(context.Context, Spec, func(string) bool, func(error)) error { return errors.New("port occupied") }, nil)
		s, err := m.Create(t.Context(), testSpec("fail"), "op")
		if err != nil || s.State != "failed" || s.Error != "port occupied" {
			t.Fatalf("failed: %+v, %v", s, err)
		}
		if err := m.Shutdown(t.Context()); err != nil {
			t.Fatal("historical failure broke shutdown:", err)
		}
	})
}
