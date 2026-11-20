//go:build linux || darwin || freebsd

package ssh

import (
	"bytes"
	"context"
	"os"
	"sync"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func TestRound5_P3_4_DiscardAbortedChannelRequests(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	reqs := make(chan *cryptoSSH.Request)

	done := make(chan struct{})
	go func() {
		defer close(done)
		discardAbortedChannelRequests(ctx, reqs)
	}()

	// Unbuffered send proves discardAbortedChannelRequests actively drains requests
	// before context cancellation.
	select {
	case reqs <- &cryptoSSH.Request{Type: "exit-status", WantReply: false}:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("discardAbortedChannelRequests did not drain incoming channel request")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("discardAbortedChannelRequests did not exit promptly after context cancel")
	}
}

func TestRound5_P3_5_PreparePollableWriteTargetAllowReopenFalse(t *testing.T) {
	t.Parallel()

	// Use raw unix.Pipe (blocking pipe without O_NONBLOCK) because os.Pipe marks descriptors non-blocking.
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		t.Fatalf("unix.Pipe: %v", err)
	}
	r := os.NewFile(uintptr(fds[0]), "r5-pipe-r")
	w := os.NewFile(uintptr(fds[1]), "r5-pipe-w")
	defer func() {
		_ = r.Close()
		_ = w.Close()
	}()

	// With allowReopen=false, a blocking pipe must NOT reopen /proc/self/fd and
	// must signal needSharedLock=true so callers serialize via sharedMu.
	_, owned, useMsgDontWait, needSharedLock, maxChunk, err := preparePollableWriteTarget(w, false)
	if err != nil {
		t.Fatalf("preparePollableWriteTarget(allowReopen=false) failed: %v", err)
	}
	if owned != nil {
		_ = owned.Close()
		t.Fatal("expected owned == nil when allowReopen == false")
	}
	if useMsgDontWait {
		t.Fatal("expected useMsgDontWait == false on pipe")
	}
	if !needSharedLock {
		t.Fatal("expected needSharedLock == true on blocking pipe when allowReopen == false")
	}
	if maxChunk <= 0 {
		t.Fatalf("expected positive maxChunk, got %d", maxChunk)
	}

	var sharedMu sync.Mutex
	if err := copyToPollableFDWithReopen(w, bytes.NewReader([]byte("r5-shared-ok")), nil, &sharedMu, false); err != nil {
		t.Fatalf("copyToPollableFDWithReopen(allowReopen=false) failed: %v", err)
	}
	_ = w.Close()
	buf := make([]byte, 32)
	n, err := r.Read(buf)
	if err != nil || string(buf[:n]) != "r5-shared-ok" {
		t.Fatalf("pipe read = (%q, %v), want r5-shared-ok", string(buf[:n]), err)
	}
}
