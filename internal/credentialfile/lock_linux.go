//go:build linux && amd64

package credentialfile

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"
)

const gateCapacity = math.MaxInt32

type sharedGate struct {
	sem  *semaphore.Weighted
	refs int
}

var processGates = struct {
	sync.Mutex
	entries map[fileID]*sharedGate
}{entries: make(map[fileID]*sharedGate)}

func retainGate(id fileID) *sharedGate {
	processGates.Lock()
	defer processGates.Unlock()
	g := processGates.entries[id]
	if g == nil {
		g = &sharedGate{sem: semaphore.NewWeighted(gateCapacity)}
		processGates.entries[id] = g
	}
	g.refs++
	return g
}

func releaseGate(id fileID) {
	processGates.Lock()
	defer processGates.Unlock()
	if g := processGates.entries[id]; g != nil {
		g.refs--
		if g.refs == 0 {
			delete(processGates.entries, id)
		}
	}
}

type fileLock struct {
	file   *os.File
	gate   *sharedGate
	weight int64
	ops    fileOps
}

func (l *fileLock) close() error {
	err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	err = errors.Join(err, l.file.Close())
	l.gate.sem.Release(l.weight)
	if l.ops.before != nil {
		err = errors.Join(err, l.ops.before("lock:close"))
	}
	if err != nil {
		return fmt.Errorf("release vault lock: %w", err)
	}
	return nil
}

func (s *Store) lock(ctx context.Context, write bool) (_ *fileLock, err error) {
	weight := int64(1)
	flags := unix.LOCK_SH | unix.LOCK_NB
	if write {
		weight = gateCapacity
		flags = unix.LOCK_EX | unix.LOCK_NB
	}
	if err := s.gate.sem.Acquire(ctx, weight); err != nil {
		return nil, fmt.Errorf("wait for vault gate: %w", context.Cause(ctx))
	}
	defer func() {
		if err != nil {
			s.gate.sem.Release(weight)
		}
	}()
	f, err := s.root.open("vault.lock", unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, f.Close())
		}
	}()
	st, err := inspect(f)
	if err != nil {
		return nil, err
	}
	if (fileID{st.Dev, st.Ino}) != s.lockID {
		return nil, ErrRevisionChanged
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		err = s.ops.step(ctx, "lock:attempt", func() error { return unix.Flock(int(f.Fd()), flags) })
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("lock vault: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-ticker.C:
		}
	}
	// A waiter must not silently acquire an unlinked/replaced lock inode.
	var current unix.Stat_t
	if err := unix.Fstatat(int(s.root.file.Fd()), "vault.lock", &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if (fileID{current.Dev, current.Ino}) != s.lockID {
		return nil, ErrRevisionChanged
	}
	if err := validatePrivate(current, false); err != nil {
		return nil, err
	}
	return &fileLock{file: f, gate: s.gate, weight: weight, ops: s.ops}, nil
}
