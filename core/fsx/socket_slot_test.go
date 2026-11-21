package fsx

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// shortSocketTempDir returns a short temporary directory so Unix domain socket
// paths stay well under the 103/107-byte sun_path limit on Darwin and Linux.
func shortSocketTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fsx-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

type orderCheckListener struct {
	net.Listener
	onClose func()
}

func (l *orderCheckListener) Close() error {
	if l.onClose != nil {
		l.onClose()
	}
	return l.Listener.Close()
}

func TestSocketSlot_BindReleaseOrderAndIdempotency(t *testing.T) {
	dir := shortSocketTempDir(t)
	sockPath := filepath.Join(dir, "order.sock")

	var (
		closeCalled            atomic.Bool
		unlinkedBeforeListener atomic.Bool
	)
	listenFn := func(addr string) (net.Listener, error) {
		raw, err := net.Listen("unix", addr)
		if err != nil {
			return nil, err
		}
		disableAutoUnlink(raw)
		return &orderCheckListener{
			Listener: raw,
			onClose: func() {
				closeCalled.Store(true)
				if _, statErr := os.Lstat(sockPath); errors.Is(statErr, os.ErrNotExist) {
					unlinkedBeforeListener.Store(true)
				}
			},
		}, nil
	}

	slot, err := BindSocketSlot(sockPath, listenFn)
	if err != nil {
		t.Fatalf("BindSocketSlot failed: %v", err)
	}
	if slot.Path() != sockPath || slot.Listener() == nil || slot.FileInfo() == nil {
		t.Fatalf("unexpected slot metadata: path=%q ln=%v fi=%v", slot.Path(), slot.Listener(), slot.FileInfo())
	}

	// Second BindSocketSlot on the same path must fail with ErrSlotOccupied.
	if dup, err := BindSocketSlot(sockPath, nil); !errors.Is(err, ErrSlotOccupied) {
		if dup != nil {
			_ = dup.Release()
		}
		t.Fatalf("duplicate BindSocketSlot = %v, want ErrSlotOccupied", err)
	}

	// Concurrent Release calls must be idempotent and strictly unlink before closing listener.
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- slot.Release()
		}()
	}
	wg.Wait()
	close(errs)
	for rErr := range errs {
		if rErr != nil {
			t.Fatalf("Release returned error: %v", rErr)
		}
	}

	if !closeCalled.Load() {
		t.Fatal("listener.Close was not called by Release")
	}
	if !unlinkedBeforeListener.Load() {
		t.Fatal("Release closed listener BEFORE unlinking socket path (violates unlink-before-close ordering)")
	}
	if slot.Listener() != nil {
		t.Fatal("Listener() must be nil after Release")
	}
}

func TestSocketSlot_ReplaceStaleAndPrune(t *testing.T) {
	dir := shortSocketTempDir(t)
	sockPath := filepath.Join(dir, "stale.sock")

	// Nil probe fails closed.
	if _, err := ReplaceStaleSocketSlot(sockPath, nil, nil); !errors.Is(err, ErrInvalidProbe) {
		t.Fatalf("ReplaceStaleSocketSlot(nil probe) = %v, want ErrInvalidProbe", err)
	}
	if _, err := PruneStaleSocket(sockPath, nil, nil); !errors.Is(err, ErrInvalidProbe) {
		t.Fatalf("PruneStaleSocket(nil probe) = %v, want ErrInvalidProbe", err)
	}

	// Non-socket regular file must NEVER be unlinked even when probe returns true.
	regPath := filepath.Join(dir, "regular.file")
	if err := os.WriteFile(regPath, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if slot, err := ReplaceStaleSocketSlot(regPath, nil, func() bool { return true }); !errors.Is(err, ErrSlotOccupied) {
		if slot != nil {
			_ = slot.Release()
		}
		t.Fatalf("ReplaceStaleSocketSlot on regular file = %v, want ErrSlotOccupied", err)
	}
	if _, err := os.Lstat(regPath); err != nil {
		t.Fatalf("ReplaceStaleSocketSlot unlinked a regular file: %v", err)
	}

	// Create a genuinely stale socket (listen then close with unlink disabled).
	deadLn, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	disableAutoUnlink(deadLn)
	if err := deadLn.Close(); err != nil {
		t.Fatal(err)
	}
	staleFi, err := os.Lstat(sockPath)
	if err != nil {
		t.Fatal(err)
	}

	// Fail-closed: if probe returns false, stale socket is NOT replaced.
	if slot, err := ReplaceStaleSocketSlot(sockPath, nil, func() bool { return false }); !errors.Is(err, ErrSlotOccupied) {
		if slot != nil {
			_ = slot.Release()
		}
		t.Fatalf("ReplaceStaleSocketSlot(probe=false) = %v, want ErrSlotOccupied", err)
	}

	// Real probe detects ECONNREFUSED -> ReplaceStaleSocketSlot replaces it.
	slot, err := ReplaceStaleSocketSlot(sockPath, nil, func() bool {
		return ProbeStaleUnixSocket(sockPath, 100*time.Millisecond)
	})
	if err != nil {
		t.Fatalf("ReplaceStaleSocketSlot(stale) failed: %v", err)
	}
	defer func() { _ = slot.Release() }()

	// Live socket must NOT be replaced or pruned.
	if slot2, err := ReplaceStaleSocketSlot(sockPath, nil, func() bool {
		return ProbeStaleUnixSocket(sockPath, 100*time.Millisecond)
	}); !errors.Is(err, ErrSlotOccupied) {
		if slot2 != nil {
			_ = slot2.Release()
		}
		t.Fatalf("ReplaceStaleSocketSlot(live) = %v, want ErrSlotOccupied", err)
	}

	// PruneStaleSocket with old staleFi detects identity change -> StaleSocketReplaced.
	outcome, err := PruneStaleSocket(sockPath, staleFi, func() bool { return true })
	if err != nil || outcome != StaleSocketReplaced {
		t.Fatalf("PruneStaleSocket(old fi) = (%v, %v), want (StaleSocketReplaced, nil)", outcome, err)
	}
	// Live socket still exists and matches slot.FileInfo().
	currFi, err := os.Lstat(sockPath)
	if err != nil || !os.SameFile(slot.FileInfo(), currFi) {
		t.Fatalf("live socket was clobbered: fi=%v err=%v", currFi, err)
	}
}

func TestSocketSlot_ReleaseDoesNotUnlinkReplacedSocket(t *testing.T) {
	dir := shortSocketTempDir(t)
	sockPath := filepath.Join(dir, "swap.sock")

	slotA, err := BindSocketSlot(sockPath, nil)
	if err != nil {
		t.Fatalf("BindSocketSlot A failed: %v", err)
	}

	// Simulate an external crash-recovery unlink + new live owner B taking sockPath
	// before A calls Release().
	if err := os.Remove(sockPath); err != nil {
		_ = slotA.Release()
		t.Fatal(err)
	}
	slotB, err := BindSocketSlot(sockPath, nil)
	if err != nil {
		_ = slotA.Release()
		t.Fatalf("BindSocketSlot B failed: %v", err)
	}
	defer func() { _ = slotB.Release() }()

	// A's Release MUST see SameFile mismatch and leave B's live socket untouched.
	if err := slotA.Release(); err != nil {
		t.Fatalf("slotA.Release failed: %v", err)
	}
	currFi, err := os.Lstat(sockPath)
	if err != nil {
		t.Fatalf("slotA.Release unlinked slotB's live socket: %v", err)
	}
	if !os.SameFile(slotB.FileInfo(), currFi) {
		t.Fatal("sockPath identity does not match live slotB after slotA.Release")
	}
}

// TestSocketSlot_TwoInstanceReplaceReleaseInterleaving verifies the core H9
// invariant under concurrent interleavings: when Instance A releases a live
// socket while Instance B concurrently runs ReplaceStaleSocketSlot and/or
// PruneStaleSocket, whichever live socket wins MUST never be unlinked by the
// other instance.
func TestSocketSlot_TwoInstanceReplaceReleaseInterleaving(t *testing.T) {
	dir := shortSocketTempDir(t)
	sockPath := filepath.Join(dir, "race.sock")

	const iterations = 40
	for iter := range iterations {
		slotA, err := BindSocketSlot(sockPath, nil)
		if err != nil {
			t.Fatalf("iter %d: BindSocketSlot A failed: %v", iter, err)
		}

		// Background acceptor for slotA so probes while A is live observe an active server.
		acceptDoneA := make(chan struct{})
		go func(ln net.Listener) {
			defer close(acceptDoneA)
			for {
				c, aErr := ln.Accept()
				if aErr != nil {
					return
				}
				_ = c.Close()
			}
		}(slotA.Listener())

		start := make(chan struct{})
		var (
			slotB     *SocketSlot
			errB      error
			releaseA  error
			pruneErrC error
			wg        sync.WaitGroup
		)

		wg.Add(3)
		go func() {
			defer wg.Done()
			<-start
			releaseA = slotA.Release()
		}()
		go func() {
			defer wg.Done()
			<-start
			slotB, errB = ReplaceStaleSocketSlot(sockPath, nil, func() bool {
				return ProbeStaleUnixSocket(sockPath, 100*time.Millisecond)
			})
		}()
		go func() {
			defer wg.Done()
			<-start
			_, pruneErrC = PruneStaleSocket(sockPath, nil, func() bool {
				return ProbeStaleUnixSocket(sockPath, 100*time.Millisecond)
			})
		}()

		close(start)
		wg.Wait()
		<-acceptDoneA

		if releaseA != nil {
			t.Fatalf("iter %d: slotA.Release failed: %v", iter, releaseA)
		}
		if pruneErrC != nil && !errors.Is(pruneErrC, ErrSlotOccupied) {
			t.Fatalf("iter %d: PruneStaleSocket unexpected error: %v", iter, pruneErrC)
		}

		if errB == nil {
			if slotB == nil {
				t.Fatalf("iter %d: slotB nil with nil error", iter)
			}
			// CRITICAL INVARIANT: slotB won the slot -> its socket MUST still
			// exist on disk with matching inode AND accept live connections now
			// that A's Release and C's PruneStaleSocket have both completed.
			currFi, statErr := os.Lstat(sockPath)
			if statErr != nil {
				_ = slotB.Release()
				t.Fatalf("iter %d: live slotB socket was unlinked during interleaving: %v", iter, statErr)
			}
			if !os.SameFile(slotB.FileInfo(), currFi) {
				_ = slotB.Release()
				t.Fatalf("iter %d: live slotB socket identity changed", iter)
			}

			acceptDoneB := make(chan struct{})
			go func(ln net.Listener) {
				defer close(acceptDoneB)
				if c, aErr := ln.Accept(); aErr == nil {
					_ = c.Close()
				}
			}(slotB.Listener())

			conn, dialErr := net.DialTimeout("unix", sockPath, time.Second)
			if dialErr != nil {
				_ = slotB.Release()
				<-acceptDoneB
				t.Fatalf("iter %d: dialing live slotB failed: %v", iter, dialErr)
			}
			_ = conn.Close()
			if err := slotB.Release(); err != nil {
				<-acceptDoneB
				t.Fatalf("iter %d: slotB.Release failed: %v", iter, err)
			}
			<-acceptDoneB
		} else if !errors.Is(errB, ErrSlotOccupied) {
			t.Fatalf("iter %d: unexpected ReplaceStaleSocketSlot error: %v", iter, errB)
		}

		// After releasing all winners, sockPath must be clean for the next iteration.
		if _, statErr := os.Lstat(sockPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("iter %d: sockPath left behind after all releases: %v", iter, statErr)
		}
	}
}
