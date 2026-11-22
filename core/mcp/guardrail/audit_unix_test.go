//go:build unix

package guardrail

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/fsx"
	"golang.org/x/sys/unix"
)

func TestAuditLogger_RefusesFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "audit.fifo")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo failed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- NewAuditLogger(fifoPath).Log(AuditEntry{OperationID: "op-fifo", Tool: "exec", Outcome: "intent"})
	}()
	select {
	case err := <-done:
		if !errors.Is(err, fsx.ErrNonRegular) {
			t.Fatalf("AuditLogger.Log(fifo) = %v, want fsx.ErrNonRegular", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AuditLogger.Log blocked on FIFO")
	}
}
