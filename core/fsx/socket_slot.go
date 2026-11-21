package fsx

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ListenFunc creates a listening socket bound to addr (for example
// net.Listen("unix", addr)). When nil is passed to BindSocketSlot or
// ReplaceStaleSocketSlot, defaultUnixListen is used.
type ListenFunc func(addr string) (net.Listener, error)

func defaultUnixListen(addr string) (net.Listener, error) {
	return net.Listen("unix", addr)
}

func resolveListenFunc(listenFn ListenFunc) ListenFunc {
	if listenFn != nil {
		return listenFn
	}
	return defaultUnixListen
}

func disableAutoUnlink(ln net.Listener) {
	if u, ok := ln.(interface{ SetUnlinkOnClose(bool) }); ok {
		u.SetUnlinkOnClose(false)
	}
}

// StaleSocketOutcome classifies the result of PruneStaleSocket.
// Zero value (StaleSocketLive) fails closed by indicating the socket must not
// be treated as removed.
type StaleSocketOutcome uint8

const (
	// StaleSocketLive indicates the socket is live or could not be proven stale.
	StaleSocketLive StaleSocketOutcome = iota
	// StaleSocketRemoved indicates the verified stale socket was unlinked under
	// the directory lock.
	StaleSocketRemoved
	// StaleSocketReplaced indicates the socket identity changed before pruning,
	// meaning another owner already replaced it; nothing was unlinked.
	StaleSocketReplaced
	// StaleSocketAlreadyGone indicates no socket entry existed at path.
	StaleSocketAlreadyGone
)

// SocketSlot is the sole owner of a bound control socket path and its
// associated net.Listener.
//
// Invariants:
//   - Every bind, stale-socket replacement, and release is serialized under a
//     real directory lock on both Unix (flock on parent directory) and Windows
//     (LockFileEx on a fixed lock file inside the verified owner-only directory).
//   - Release strictly executes: dir lock -> os.SameFile(origFi, Lstat(path))
//     -> unlink -> release dir lock -> close listener.
//   - UnixListener auto-unlink on Close is always disabled so closing the
//     listener can never unlink a replacement owner's live socket.
//
// Ownership: callers own *SocketSlot and MUST call Release() (not
// Listener().Close() directly) to tear down the socket. Release is idempotent
// and safe for concurrent calls.
type SocketSlot struct {
	mu       sync.Mutex
	path     string
	listener net.Listener
	origFi   os.FileInfo
	released bool
}

// BindSocketSlot atomically binds and publishes a control socket at path.
//
// On Unix, it binds a temporary path in the same directory, applies mode 0600,
// records origFi, links to path under the directory lock, and unlinks the
// temporary name (falling back to a direct bind under the directory lock when
// the sun_path length budget cannot fit an 8-byte temporary suffix).
//
// On Windows, it ensures/verifies the parent directory is owner-only, acquires
// the real directory lock, binds path, hardens and verifies the socket DACL via
// handle-based Win32 APIs, and records origFi.
//
// If path is already occupied, BindSocketSlot cleans up all temporary state and
// returns ErrSlotOccupied.
func BindSocketSlot(path string, listenFn ListenFunc) (*SocketSlot, error) {
	targetPath, err := cleanSocketSlotPath(path)
	if err != nil {
		return nil, err
	}
	return bindSocketSlotOS(targetPath, resolveListenFunc(listenFn), false, nil)
}

// ReplaceStaleSocketSlot atomically binds and publishes a control socket at
// path, replacing an existing stale socket under the directory lock when
// isStale returns true.
//
// Fail-closed semantics: isStale MUST return true ONLY when the caller has
// verified the existing socket at path is dead/stale (for example,
// ECONNREFUSED). Returning false (the zero value) preserves the existing socket
// and fails with ErrSlotOccupied. A nil isStale callback fails with
// ErrInvalidProbe. Non-socket entries (regular files, symlinks, directories) are
// never unlinked.
func ReplaceStaleSocketSlot(path string, listenFn ListenFunc, isStale func() bool) (*SocketSlot, error) {
	if isStale == nil {
		return nil, ErrInvalidProbe
	}
	targetPath, err := cleanSocketSlotPath(path)
	if err != nil {
		return nil, err
	}
	return bindSocketSlotOS(targetPath, resolveListenFunc(listenFn), true, isStale)
}

// PruneStaleSocket checks path under the same directory lock used by
// BindSocketSlot and Release, unlinking path ONLY if:
//  1. path currently exists and is a socket (os.ModeSocket),
//  2. expected (when non-nil) matches os.SameFile(expected, current),
//  3. isStale() returns true while holding the directory lock, and
//  4. a final os.Lstat(path) still matches os.SameFile.
//
// Non-socket files and live or replaced sockets are never unlinked.
func PruneStaleSocket(path string, expected os.FileInfo, isStale func() bool) (StaleSocketOutcome, error) {
	if isStale == nil {
		return StaleSocketLive, ErrInvalidProbe
	}
	targetPath, err := cleanSocketSlotPath(path)
	if err != nil {
		return StaleSocketLive, err
	}
	return pruneStaleSocketOS(targetPath, expected, isStale)
}

// Release unlinks the owned socket entry (only if os.SameFile(origFi, Lstat)
// still matches under the directory lock) and then closes the underlying
// listener. Release is idempotent and concurrency-safe.
func (s *SocketSlot) Release() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		return nil
	}
	s.released = true
	path := s.path
	origFi := s.origFi
	ln := s.listener
	s.listener = nil
	s.mu.Unlock()

	return releaseSocketSlotOS(path, origFi, ln)
}

// Listener returns the owned net.Listener, or nil after Release has been called.
// Callers must NOT call Close() directly on the returned listener; always call
// slot.Release() so unlink occurs under the directory lock before listener close.
func (s *SocketSlot) Listener() net.Listener {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listener
}

// Path returns the cleaned control socket path owned by this slot.
func (s *SocketSlot) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// FileInfo returns the os.FileInfo recorded for the bound socket entry at bind time.
func (s *SocketSlot) FileInfo() os.FileInfo {
	if s == nil {
		return nil
	}
	return s.origFi
}

// ProbeStaleUnixSocket performs a bounded dial probe against a Unix domain
// socket path and returns true ONLY when the kernel reports connection refused
// (indicating a dead/stale socket file with no active listener). Any successful
// connection, timeout, or other error returns false (fail-closed).
func ProbeStaleUnixSocket(path string, timeout time.Duration) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	if timeout <= 0 {
		timeout = 100 * time.Millisecond
	}
	conn, err := net.DialTimeout("unix", path, timeout)
	if err == nil {
		_ = conn.Close()
		return false
	}
	return isConnRefusedOS(err)
}

func cleanSocketSlotPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", ErrEmptyPath
	}
	cleaned := filepath.Clean(trimmed)
	if cleaned == "" || cleaned == "." || cleaned == string(filepath.Separator) {
		return "", fmt.Errorf("%w: invalid socket path %q", ErrEmptyPath, path)
	}
	return cleaned, nil
}

func isSocketEntry(fi os.FileInfo) bool {
	return fi != nil && fi.Mode()&os.ModeSocket != 0
}

// pruneLockedSocketEntry runs inside an active directory lock to check and
// remove a verified stale socket at targetPath.
func pruneLockedSocketEntry(targetPath string, expected os.FileInfo, isStale func() bool) (StaleSocketOutcome, error) {
	currFi, err := os.Lstat(targetPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return StaleSocketAlreadyGone, nil
		}
		return StaleSocketLive, err
	}
	if !isSocketEntry(currFi) {
		return StaleSocketLive, fmt.Errorf("%w: %q is not a socket", ErrSlotOccupied, targetPath)
	}
	if expected != nil && !os.SameFile(expected, currFi) {
		return StaleSocketReplaced, nil
	}
	if !isStale() {
		return StaleSocketLive, nil
	}
	finalFi, finalErr := os.Lstat(targetPath)
	if finalErr != nil {
		if errors.Is(finalErr, os.ErrNotExist) {
			return StaleSocketAlreadyGone, nil
		}
		return StaleSocketLive, finalErr
	}
	if !isSocketEntry(finalFi) || !os.SameFile(currFi, finalFi) {
		return StaleSocketReplaced, nil
	}
	if rmErr := os.Remove(targetPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		return StaleSocketLive, rmErr
	}
	return StaleSocketRemoved, nil
}
