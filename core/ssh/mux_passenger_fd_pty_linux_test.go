//go:build linux

package ssh

import (
	"bytes"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// saturatePTYMasterInput fills the PTY master's 4095-byte n_tty receive ring
// buffer and waits until Linux's async flush_to_ldisc kworker has populated
// master TIOCINQ >= 4095 (triggering TTY_THROTTLED). Once saturated, further
// writes to slave accumulate purely in tty_buffer and POLLOUT==0 remains sticky
// instead of racing flush_to_ldisc draining 4095 bytes behind poll(2)'s back.
func saturatePTYMasterInput(t *testing.T, master, slave *os.File) {
	t.Helper()
	// 2048 newlines expand under OPOST|ONLCR to 4096 bytes, exceeding the
	// 4095-byte N_TTY_BUF_SIZE-1 ring while staying well under tty_buffer capacity.
	seed := bytes.Repeat([]byte{'\n'}, 2048)
	if _, err := slave.Write(seed); err != nil {
		t.Fatalf("seed PTY slave: %v", err)
	}
	masterConn, err := master.SyscallConn()
	if err != nil {
		t.Fatalf("master SyscallConn: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	var lastInq int
	var lastErr error
	for time.Now().Before(deadline) {
		if err := t.Context().Err(); err != nil {
			t.Fatalf("context canceled while saturating PTY master input (last TIOCINQ=%d): %v", lastInq, err)
		}
		if ctrlErr := masterConn.Control(func(fd uintptr) {
			lastInq, lastErr = unix.IoctlGetInt(int(fd), unix.TIOCINQ)
		}); ctrlErr != nil {
			t.Fatalf("master Control: %v", ctrlErr)
		}
		if lastErr == nil && lastInq >= 4095 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("PTY master n_tty buffer never saturated (TIOCINQ=%d, err=%v)", lastInq, lastErr)
}
