//go:build linux

package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// fullOutputPipe returns a pipe whose writer would block until the reader
// drains it. Both ends are closed at test cleanup.
func fullOutputPipe(t *testing.T) (reader, writer *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := writer.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(bytes.Repeat([]byte("x"), 1<<20)); err == nil {
		t.Fatal("pipe did not fill")
	}
	if err := writer.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	return reader, writer
}

func TestBindOutputPipeCancelsStalledWriteWithoutChangingCaller(t *testing.T) {
	_, writer := fullOutputPipe(t)
	before := outputDescriptorFlags(t, writer)
	ctx, cancel := context.WithCancel(t.Context())
	bound, closeFn, cancelable, err := BindOutput(ctx, writer)
	if err != nil || !cancelable {
		t.Fatalf("pipe not bound: %v %v", cancelable, err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := bound.Write([]byte("blocked"))
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("write on a full pipe returned early: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled write error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled write did not return")
	}
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Stat(); err != nil {
		t.Fatalf("borrowed output closed: %v", err)
	}
	if after := outputDescriptorFlags(t, writer); after != before {
		t.Fatal("borrowed output flags changed")
	}
}

func TestBindOutputPipeHasNoIdleWriteLimit(t *testing.T) {
	reader, writer := fullOutputPipe(t)
	bound, closeFn, cancelable, err := BindOutput(t.Context(), writer)
	if err != nil || !cancelable {
		t.Fatalf("pipe not bound: %v %v", cancelable, err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := bound.Write([]byte("slow consumer"))
		result <- err
	}()
	// A pager-style consumer may stall; the write resumes when it drains.
	time.Sleep(150 * time.Millisecond)
	drained := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		_, err := reader.Read(buf)
		drained <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("slow consumer write failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("write did not resume after the consumer drained")
	}
	if err := <-drained; err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyEntryPointsCancelBlockedOutputWithoutLeaks(t *testing.T) {
	for name, run := range map[string]func(context.Context, *Client, *os.File) error{
		"Run stream": func(ctx context.Context, c *Client, out *os.File) error {
			_, err := c.Run(ctx, "command", WithStream(out, ""))
			return err
		},
		"RunScript stream": func(ctx context.Context, c *Client, out *os.File) error {
			_, err := c.RunScript(ctx, "command", WithStream(out, "[h] "))
			return err
		},
		"RunCommandWithIO": func(ctx context.Context, c *Client, out *os.File) error {
			return c.RunCommandWithIO(ctx, "command", false, nil, out, io.Discard)
		},
	} {
		t.Run(name, func(t *testing.T) {
			baseline := goleak.IgnoreCurrent()
			t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
			_, writer := fullOutputPipe(t)
			before := outputDescriptorFlags(t, writer)
			scenario := &commandFixture{output: "blocked output"}
			client := commandTestClient(t, scenario)
			ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
			defer cancel()
			start := time.Now()
			err := run(ctx, client, writer)
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
				t.Fatalf("blocked output did not cancel promptly: %v", err)
			}
			if _, err := writer.Stat(); err != nil {
				t.Fatalf("borrowed output closed: %v", err)
			}
			if after := outputDescriptorFlags(t, writer); after != before {
				t.Fatal("borrowed output flags changed")
			}
			if scenario.attempts.Load() != 1 {
				t.Fatal("blocked output caused replay")
			}
		})
	}
}
