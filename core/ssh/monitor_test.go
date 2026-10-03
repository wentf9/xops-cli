package ssh

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"testing"
	"time"
)

func TestFormatUptime(t *testing.T) {
	if formatUptime(3660) != "01:01" {
		t.Errorf("expected 01:01, got %s", formatUptime(3660))
	}
	if formatUptime(90060) != "1 days, 01:01" {
		t.Errorf("expected 1 days, 01:01, got %s", formatUptime(90060))
	}
}

func TestMetricsCollectorCancellationClosesAndJoinsBlockedDecode(t *testing.T) {
	reader, writer := io.Pipe()
	collector := &MetricsCollector{
		decoder:   json.NewDecoder(reader),
		stream:    reader,
		lastProcs: make(map[int]procTick),
	}
	defer func() {
		if err := writer.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("close metrics test writer: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := collector.NextFrame(ctx)
		result <- err
	}()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("NextFrame() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("NextFrame() did not return after cancellation")
	}
}

func TestCPUTicks(t *testing.T) {
	t1 := &CPUTicks{User: 100, Sys: 50, Idle: 800, Iowait: 50}
	if t1.Total() != 1000 {
		t.Errorf("expected total 1000, got %d", t1.Total())
	}
	if t1.IdleTicks() != 850 {
		t.Errorf("expected idle 850, got %d", t1.IdleTicks())
	}

	t2 := &CPUTicks{User: 120, Sys: 80, Idle: 1200, Iowait: 100}

	totalDelta := float64(t2.Total() - t1.Total())
	idleDelta := float64(t2.IdleTicks() - t1.IdleTicks())
	usage := 100.0 * (totalDelta - idleDelta) / totalDelta

	// Total delta = 1500 - 1000 = 500
	// Idle delta = 1300 - 850 = 450
	// Usage = (500 - 450) / 500 = 10%
	if math.Abs(usage-10.0) > 0.1 {
		t.Errorf("expected CPU usage 10.0%%, got %f%%", usage)
	}
}
