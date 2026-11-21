//go:build unix

package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/fsx"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func p7NewEd25519PublicKey(t *testing.T) cryptoSSH.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	sshPub, err := cryptoSSH.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey failed: %v", err)
	}
	return sshPub
}

// TestP7Repro_H8_ReadBoundedRegularFile_SwappedFIFOBlocks verifies H8 is fixed:
// fsx.ReadAllBounded opens handle-first with O_NONBLOCK (no Stat->Open race),
// so swapping a FIFO in atomically via hard-link rename never blocks waiting
// for a FIFO writer.
func TestP7Repro_H8_ReadBoundedRegularFile_SwappedFIFOBlocks(t *testing.T) {
	dir := t.TempDir()
	regSrc := filepath.Join(dir, "reg.src")
	fifoSrc := filepath.Join(dir, "fifo.src")
	targetPath := filepath.Join(dir, "target")

	if err := os.WriteFile(regSrc, []byte("regular-content"), 0o600); err != nil {
		t.Fatalf("write regSrc: %v", err)
	}
	if err := syscall.Mkfifo(fifoSrc, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	if err := os.Link(regSrc, targetPath); err != nil {
		t.Fatalf("initial link regSrc -> target: %v", err)
	}

	stopFlip := make(chan struct{})
	var flipWG sync.WaitGroup
	flipWG.Add(1)
	go func() {
		defer flipWG.Done()
		tmpReg := filepath.Join(dir, "tmp.reg")
		tmpFifo := filepath.Join(dir, "tmp.fifo")
		for {
			select {
			case <-stopFlip:
				return
			default:
			}
			_ = os.Remove(tmpFifo)
			if os.Link(fifoSrc, tmpFifo) == nil {
				_ = os.Rename(tmpFifo, targetPath)
			}
			_ = os.Remove(tmpReg)
			if os.Link(regSrc, tmpReg) == nil {
				_ = os.Rename(tmpReg, targetPath)
			}
		}
	}()
	defer func() {
		select {
		case <-stopFlip:
		default:
			close(stopFlip)
		}
		flipWG.Wait()
	}()

	const (
		maxAttempts  = 5000
		callDeadline = 250 * time.Millisecond
		totalBudget  = 5 * time.Second
	)
	overallDeadline := time.Now().Add(totalBudget)

	for attempt := 1; attempt <= maxAttempts && time.Now().Before(overallDeadline); attempt++ {
		doneCh := make(chan error, 1)
		go func() {
			_, err := fsx.ReadAllBounded(targetPath, fsx.Limits{MaxBytes: 1024}, fsx.FollowSymlinks())
			doneCh <- err
		}()

		select {
		case <-doneCh:
			// Completed without blocking; continue attempting to hit the swap window.
		case <-time.After(callDeadline):
			// Stop flipping and unblock the stuck O_RDONLY FIFO open by briefly opening the write end.
			close(stopFlip)
			flipWG.Wait()

			unblocker, unblockErr := os.OpenFile(fifoSrc, os.O_WRONLY|syscall.O_NONBLOCK, 0)
			if unblockErr == nil {
				_ = unblocker.Close()
			}
			select {
			case err := <-doneCh:
				t.Fatalf("H8 reproduced on attempt %d: fsx.ReadAllBounded blocked >%s on swapped FIFO (unblocked only after opening FIFO writer; final err=%v)", attempt, callDeadline, err)
			case <-time.After(2 * time.Second):
				t.Fatalf("H8 reproduced on attempt %d: fsx.ReadAllBounded remained blocked >%s on swapped FIFO (unblockErr=%v)", attempt, callDeadline, unblockErr)
			}
		}
	}
}

type p7CloseObserverListener struct {
	net.Listener
	onAfterClose func()
}

func (l *p7CloseObserverListener) Close() error {
	err := l.Listener.Close()
	if l.onAfterClose != nil {
		l.onAfterClose()
	}
	return err
}

// TestP7Repro_H9_MuxServer_ShutdownUnlinksWithoutDirLockAndAfterListenerClose verifies H9 is fixed:
//  1. MuxServer releases its control socket through fsx.SocketSlot.Release, which acquires the
//     control socket directory lock before unlinking.
//  2. MuxServer.Shutdown unlinks the socket under the directory lock BEFORE closing the listener,
//     preventing an ECONNREFUSED stale window where a replacement master could be unlinked.
func TestP7Repro_H9_MuxServer_ShutdownUnlinksWithoutDirLockAndAfterListenerClose(t *testing.T) {
	t.Run("shutdown_ignores_directory_flock", func(t *testing.T) {
		sockDir := shortSocketDir(t)
		sockPath := filepath.Join(sockDir, "h9-dirlock.sock")

		srv, err := NewMuxServer(MuxServerOptions{
			ControlPath: sockPath,
			SSHClient:   newDummySSHClient(),
		})
		if err != nil {
			t.Fatalf("NewMuxServer failed: %v", err)
		}
		go func() { _ = srv.Serve() }()
		t.Cleanup(func() { _ = srv.Shutdown() })

		// Acquire the same directory flock(LOCK_EX) that fsx.SocketSlot /
		// fsx.PruneStaleSocket use to serialize control-socket ownership transitions.
		dirFile, err := os.Open(sockDir)
		if err != nil {
			t.Fatalf("open socket dir: %v", err)
		}
		defer func() { _ = dirFile.Close() }()
		if err := syscall.Flock(int(dirFile.Fd()), syscall.LOCK_EX); err != nil {
			t.Fatalf("flock(LOCK_EX) on socket dir failed: %v", err)
		}
		unlocked := false
		unlockDir := func() {
			if !unlocked {
				unlocked = true
				_ = syscall.Flock(int(dirFile.Fd()), syscall.LOCK_UN)
			}
		}
		defer unlockDir()

		shutdownDone := make(chan struct{})
		go func() {
			_ = srv.Shutdown()
			close(shutdownDone)
		}()

		// While the directory lock is held, Shutdown MUST NOT unlink the socket or complete release.
		select {
		case <-shutdownDone:
			_, statErr := os.Lstat(sockPath)
			unlockDir()
			t.Fatalf("H9 reproduced: MuxServer.Shutdown completed and unlinked socket (lstat err=%v) while directory flock(LOCK_EX) was held", statErr)
		case <-time.After(150 * time.Millisecond):
		}

		if _, statErr := os.Lstat(sockPath); statErr != nil {
			unlockDir()
			t.Fatalf("H9 reproduced: socket disappeared while directory flock(LOCK_EX) was still held (lstat err=%v)", statErr)
		}

		unlockDir()
		select {
		case <-shutdownDone:
		case <-time.After(3 * time.Second):
			t.Fatal("MuxServer.Shutdown did not complete after releasing directory lock")
		}
	})

	t.Run("shutdown_closes_listener_before_unlinking_socket", func(t *testing.T) {
		sockPath := filepath.Join(shortSocketDir(t), "h9-order.sock")
		srv, err := NewMuxServer(MuxServerOptions{
			ControlPath: sockPath,
			SSHClient:   newDummySSHClient(),
		})
		if err != nil {
			t.Fatalf("NewMuxServer failed: %v", err)
		}

		var (
			observed      atomic.Bool
			socketExisted bool
			dialRefused   bool
		)
		srv.listener = &p7CloseObserverListener{
			Listener: srv.listener,
			onAfterClose: func() {
				if !observed.CompareAndSwap(false, true) {
					return
				}
				if _, statErr := os.Lstat(sockPath); statErr == nil {
					socketExisted = true
					conn, dialErr := net.DialTimeout("unix", sockPath, 100*time.Millisecond)
					if conn != nil {
						_ = conn.Close()
					}
					dialRefused = isConnectionRefused(dialErr)
				}
			},
		}

		go func() { _ = srv.Serve() }()
		if err := srv.Shutdown(); err != nil {
			t.Fatalf("Shutdown failed: %v", err)
		}
		if !observed.Load() {
			t.Fatal("listener Close hook never fired")
		}
		if socketExisted {
			t.Fatalf("H9 reproduced: MuxServer.Shutdown closed listener BEFORE unlinking %q (exposed stale ECONNREFUSED=%v window)", sockPath, dialRefused)
		}
	})
}

// TestP7Repro_MED9_KnownHostsFlock_WriteLostAfterAtomicReplace reproduces MED-9:
// appendKnownHost and parseFileStrict acquire flock(2) on an already-opened fd without verifying
// os.SameFile(f.Stat(), os.Lstat(path)) after acquiring the lock. If another actor atomically
// replaces known_hosts while holding LOCK_EX, the writer appends to the unlinked old inode (lost write)
// and the reader parses stale content from the unlinked inode.
func TestP7Repro_MED9_KnownHostsFlock_WriteLostAfterAtomicReplace(t *testing.T) {
	t.Run("appendKnownHost_loses_write_after_atomic_replace", reproMED9AppendLostWrite)
	t.Run("parseFileStrict_reads_unlinked_inode_after_atomic_replace", reproMED9ParseStaleInode)
}

func lockExternalKnownHostsFile(t *testing.T, khPath string) (*os.File, func()) {
	t.Helper()
	oldFile, err := os.OpenFile(khPath, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open oldFile: %v", err)
	}
	t.Cleanup(func() { _ = oldFile.Close() })
	if err := syscall.Flock(int(oldFile.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatalf("flock(LOCK_EX) on oldFile: %v", err)
	}
	var unlockOnce sync.Once
	unlock := func() {
		unlockOnce.Do(func() {
			_ = syscall.Flock(int(oldFile.Fd()), syscall.LOCK_UN)
		})
	}
	t.Cleanup(unlock)
	return oldFile, unlock
}

func atomicReplaceKnownHosts(t *testing.T, dir, khPath, content string) {
	t.Helper()
	tmpPath := filepath.Join(dir, "known_hosts.tmp")
	if err := os.WriteFile(tmpPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write replacement known_hosts: %v", err)
	}
	if err := os.Rename(tmpPath, khPath); err != nil {
		t.Fatalf("atomic rename replacement known_hosts: %v", err)
	}
}

func reproMED9AppendLostWrite(t *testing.T) {
	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")

	keyA := p7NewEd25519PublicKey(t)
	keyB := p7NewEd25519PublicKey(t)
	keyC := p7NewEd25519PublicKey(t)

	seedLine := formatKnownHostEntry("host-a.example:22", keyA, false) + "\n"
	if err := os.WriteFile(khPath, []byte(seedLine), 0o600); err != nil {
		t.Fatalf("write initial known_hosts: %v", err)
	}

	oldFile, unlockOld := lockExternalKnownHostsFile(t, khPath)

	appendDone := make(chan error, 1)
	go func() {
		appendDone <- appendKnownHost(khPath, "host-b.example:22", keyB, false)
	}()

	// Wait until appendKnownHost has entered its critical section and blocked on flock(LOCK_EX) of inode I1.
	waitForCondition(t, 2*time.Second, func() bool {
		if knownHostsFileMutex.TryLock() {
			knownHostsFileMutex.Unlock()
			return false
		}
		return true
	}, "appendKnownHost did not acquire knownHostsFileMutex")
	time.Sleep(50 * time.Millisecond)

	select {
	case err := <-appendDone:
		t.Fatalf("appendKnownHost unexpectedly completed while external LOCK_EX was held: err=%v", err)
	default:
	}

	atomicReplaceKnownHosts(t, dir, khPath, formatKnownHostEntry("host-c.example:22", keyC, false)+"\n")
	unlockOld()

	select {
	case err := <-appendDone:
		if err != nil {
			t.Fatalf("appendKnownHost returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("appendKnownHost did not finish after releasing LOCK_EX")
	}

	onDisk, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("read known_hosts on disk: %v", err)
	}
	if !strings.Contains(string(onDisk), "host-b.example") {
		if _, seekErr := oldFile.Seek(0, 0); seekErr == nil {
			buf := make([]byte, 4096)
			n, _ := oldFile.Read(buf)
			t.Fatalf("MED-9 reproduced: host-b.example lost from known_hosts on disk after atomic replace (on-disk=%q; written to unlinked inode=%q)", string(onDisk), string(buf[:n]))
		}
		t.Fatalf("MED-9 reproduced: host-b.example lost from known_hosts on disk after atomic replace (on-disk=%q)", string(onDisk))
	}
}

func reproMED9ParseStaleInode(t *testing.T) {
	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")

	keyOld := p7NewEd25519PublicKey(t)
	keyNew := p7NewEd25519PublicKey(t)

	oldLine := formatKnownHostEntry("old-host.example:22", keyOld, false) + "\n"
	if err := os.WriteFile(khPath, []byte(oldLine), 0o600); err != nil {
		t.Fatalf("write initial known_hosts: %v", err)
	}

	_, unlockOld := lockExternalKnownHostsFile(t, khPath)

	db := newKnownHostsDB()
	parseDone := make(chan error, 1)
	go func() {
		parseDone <- db.parseFileStrict(khPath)
	}()

	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-parseDone:
		t.Fatalf("parseFileStrict unexpectedly completed while LOCK_EX was held: err=%v", err)
	default:
	}

	atomicReplaceKnownHosts(t, dir, khPath, formatKnownHostEntry("new-host.example:22", keyNew, false)+"\n")
	unlockOld()

	select {
	case err := <-parseDone:
		if err != nil {
			t.Fatalf("parseFileStrict returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("parseFileStrict did not finish after releasing LOCK_EX")
	}

	_, newPinned := db.matchingHostKeyTypes(khAddr{host: "new-host.example", port: "22"})
	_, oldPinned := db.matchingHostKeyTypes(khAddr{host: "old-host.example", port: "22"})
	if len(newPinned) == 0 || len(oldPinned) > 0 {
		t.Fatalf("MED-9 reproduced: parseFileStrict read unlinked old inode after atomic replace (oldPinned=%v, newPinned=%v)", oldPinned, newPinned)
	}
}
