package fsx

import (
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestOpenRegularAndReadAllBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.txt")
	content := []byte("hello handle-based fsx kernel")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("valid_exact_boundary", func(t *testing.T) {
		got, err := ReadAllBounded(path, Limits{MaxBytes: int64(len(content))})
		if err != nil {
			t.Fatalf("ReadAllBounded exact limit failed: %v", err)
		}
		if !bytes.Equal(got, content) {
			t.Fatalf("got %q, want %q", got, content)
		}
	})

	t.Run("oversize_rejected_at_open", func(t *testing.T) {
		_, err := OpenRegular(path, Limits{MaxBytes: int64(len(content) - 1)})
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("OpenRegular oversize = %v, want ErrTooLarge", err)
		}
		_, err = ReadAllBounded(path, Limits{MaxBytes: int64(len(content) - 1)})
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("ReadAllBounded oversize = %v, want ErrTooLarge", err)
		}
	})

	t.Run("zero_and_negative_limits_fail_closed", func(t *testing.T) {
		for _, lim := range []int64{0, -1, -1024} {
			if _, err := OpenRegular(path, Limits{MaxBytes: lim}); !errors.Is(err, ErrInvalidLimit) {
				t.Fatalf("OpenRegular(MaxBytes=%d) = %v, want ErrInvalidLimit", lim, err)
			}
		}
	})

	t.Run("max_int64_limit_no_overflow", func(t *testing.T) {
		got, err := ReadAllBounded(path, Limits{MaxBytes: math.MaxInt64})
		if err != nil {
			t.Fatalf("ReadAllBounded(MaxInt64) failed: %v", err)
		}
		if !bytes.Equal(got, content) {
			t.Fatalf("got %q, want %q", got, content)
		}
	})

	t.Run("empty_path_missing_and_dir", func(t *testing.T) {
		if _, err := OpenRegular("", Limits{MaxBytes: 10}); !errors.Is(err, ErrEmptyPath) {
			t.Fatalf("OpenRegular('') = %v, want ErrEmptyPath", err)
		}
		if _, err := OpenRegular(filepath.Join(dir, "nope"), Limits{MaxBytes: 10}); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("OpenRegular(missing) = %v, want os.ErrNotExist", err)
		}
		if _, err := OpenRegular(dir, Limits{MaxBytes: 1024}); !errors.Is(err, ErrNonRegular) {
			t.Fatalf("OpenRegular(dir) = %v, want ErrNonRegular", err)
		}
	})
}

func TestOpenRegular_DevNull(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !IsDevNullPath(os.DevNull) || IsDevNullPath("") || IsDevNullPath(path) {
		t.Fatalf("unexpected IsDevNullPath results for %q", os.DevNull)
	}
	if _, err := OpenRegular(os.DevNull, Limits{MaxBytes: 1024}); !errors.Is(err, ErrNonRegular) {
		t.Fatalf("OpenRegular(os.DevNull) without option = %v, want ErrNonRegular", err)
	}
	rf, err := OpenRegular(os.DevNull, Limits{MaxBytes: 1024}, AllowDevNull())
	if err != nil {
		t.Fatalf("OpenRegular(os.DevNull, AllowDevNull()) failed: %v", err)
	}
	defer func() { _ = rf.Close() }()
	if !rf.IsDevNull() || rf.Size() != 0 {
		t.Fatalf("unexpected DevNull metadata: isDevNull=%v size=%d", rf.IsDevNull(), rf.Size())
	}
	st, statErr := rf.Stat()
	if statErr != nil || st == nil {
		t.Fatalf("Stat() on DevNull RegularFile = (%v, %v)", st, statErr)
	}
	var buf [8]byte
	if n, rErr := rf.Read(buf[:]); n != 0 || !errors.Is(rErr, io.EOF) {
		t.Fatalf("Read on DevNull = (%d, %v), want (0, io.EOF)", n, rErr)
	}
	data, err := ReadAllBounded(os.DevNull, Limits{MaxBytes: 1024}, AllowDevNull())
	if err != nil || len(data) != 0 {
		t.Fatalf("ReadAllBounded(os.DevNull, AllowDevNull()) = (%q, %v), want empty nil", data, err)
	}
}

func TestOpenRegular_ConcurrentGrowth(t *testing.T) {
	dir := t.TempDir()
	growPath := filepath.Join(dir, "growing.txt")
	if err := os.WriteFile(growPath, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	rf, err := OpenRegular(growPath, Limits{MaxBytes: 10})
	if err != nil {
		t.Fatalf("OpenRegular failed: %v", err)
	}
	defer func() { _ = rf.Close() }()

	wf, err := os.OpenFile(growPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, wErr := wf.WriteString("678901")
	cErr := wf.Close()
	if wErr != nil || cErr != nil {
		t.Fatalf("append failed: write=%v close=%v", wErr, cErr)
	}

	if _, err := rf.ReadAll(); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ReadAll after concurrent growth = %v, want ErrTooLarge", err)
	}
}

func TestOpenRegular_CloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	rf, err := OpenRegular(path, Limits{MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if err := rf.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	if err := rf.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
	var b [4]byte
	if _, err := rf.Read(b[:]); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read after Close = %v, want os.ErrClosed", err)
	}
	if _, err := rf.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Stat after Close = %v, want os.ErrClosed", err)
	}
}

func TestOpenRegularSymlinkRejectionAndOptInFollow(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable without elevation on Windows: %v", err)
		}
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "dangling.txt")
	if err := os.Symlink(filepath.Join(dir, "missing.txt"), dangling); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenRegular(link, Limits{MaxBytes: 1024}); !errors.Is(err, ErrSymlink) {
		t.Fatalf("OpenRegular(symlink) = %v, want ErrSymlink", err)
	}
	if _, err := OpenRegular(dangling, Limits{MaxBytes: 1024}); !errors.Is(err, ErrSymlink) {
		t.Fatalf("OpenRegular(dangling symlink) = %v, want ErrSymlink", err)
	}

	got, err := ReadAllBounded(link, Limits{MaxBytes: 1024}, FollowSymlinks())
	if err != nil {
		t.Fatalf("ReadAllBounded(symlink, FollowSymlinks()) failed: %v", err)
	}
	if string(got) != "secret" {
		t.Fatalf("got %q, want %q", got, "secret")
	}
}

func TestCreateExclusive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "newfile.txt")

	f, err := CreateExclusive(path, OwnerOnlyPerm)
	if err != nil {
		t.Fatalf("CreateExclusive failed: %v", err)
	}
	if _, err := f.WriteString("created-exclusively"); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// Second call must fail with os.ErrExist.
	if f2, err := CreateExclusive(path, OwnerOnlyPerm); !errors.Is(err, os.ErrExist) {
		if f2 != nil {
			_ = f2.Close()
		}
		t.Fatalf("CreateExclusive(existing) = %v, want os.ErrExist", err)
	}

	// Dangling symlink must also be rejected with os.ErrExist.
	dangling := filepath.Join(dir, "dangling-excl")
	if err := os.Symlink(filepath.Join(dir, "target-never-created"), dangling); err == nil {
		if f3, err := CreateExclusive(dangling, OwnerOnlyPerm); !errors.Is(err, os.ErrExist) {
			if f3 != nil {
				_ = f3.Close()
			}
			t.Fatalf("CreateExclusive(dangling symlink) = %v, want os.ErrExist", err)
		}
		if _, statErr := os.Lstat(filepath.Join(dir, "target-never-created")); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("CreateExclusive followed dangling symlink and created target")
		}
	}

	if _, err := CreateExclusive("", OwnerOnlyPerm); !errors.Is(err, ErrEmptyPath) {
		t.Fatalf("CreateExclusive('') = %v, want ErrEmptyPath", err)
	}
}

func TestOpenLocked_BasicAndMutualExclusion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")

	if _, err := OpenLocked(path, LockMode(0), false, OwnerOnlyPerm); !errors.Is(err, ErrInvalidLockMode) {
		t.Fatalf("OpenLocked(LockMode(0)) = %v, want ErrInvalidLockMode", err)
	}
	if _, err := OpenLocked(path, LockShared, false, OwnerOnlyPerm); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OpenLocked(missing, create=false) = %v, want os.ErrNotExist", err)
	}

	lf, err := OpenLocked(path, LockExclusive, true, OwnerOnlyPerm)
	if err != nil {
		t.Fatalf("OpenLocked(create=true) failed: %v", err)
	}
	if !lf.Created() {
		t.Fatal("expected Created() == true on new file")
	}
	if _, err := lf.Write([]byte("line1\n")); err != nil {
		_ = lf.Close()
		t.Fatal(err)
	}

	// While lf holds LockExclusive, a second LockShared must block until Close.
	sharedAcquired := make(chan *LockedFile, 1)
	sharedErr := make(chan error, 1)
	go func() {
		sf, sErr := OpenLocked(path, LockShared, false, 0)
		if sErr != nil {
			sharedErr <- sErr
			return
		}
		sharedAcquired <- sf
	}()

	select {
	case sf := <-sharedAcquired:
		_ = sf.Close()
		_ = lf.Close()
		t.Fatal("LockShared acquired while LockExclusive was still held")
	case sErr := <-sharedErr:
		_ = lf.Close()
		t.Fatalf("LockShared failed unexpectedly: %v", sErr)
	case <-time.After(80 * time.Millisecond):
	}

	if err := lf.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	// Idempotent second Close.
	if err := lf.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}

	select {
	case sf := <-sharedAcquired:
		defer func() { _ = sf.Close() }()
		if sf.Created() {
			t.Fatal("expected Created() == false for existing file")
		}
		data, err := io.ReadAll(sf)
		if err != nil {
			t.Fatalf("ReadAll on LockShared failed: %v", err)
		}
		if string(data) != "line1\n" {
			t.Fatalf("got %q, want %q", data, "line1\n")
		}
		if _, err := sf.Write([]byte("denied")); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("Write on LockShared = %v, want os.ErrPermission", err)
		}
	case sErr := <-sharedErr:
		t.Fatalf("LockShared failed after unlock: %v", sErr)
	case <-time.After(3 * time.Second):
		t.Fatal("LockShared did not unblock after LockExclusive Close")
	}
}

func TestOpenLocked_ReplaceUnderLockSameFileRetry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "locked.dat")
	if err := os.WriteFile(path, []byte("v1-stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	holder, err := OpenLocked(path, LockExclusive, false, OwnerOnlyPerm)
	if err != nil {
		t.Fatalf("holder OpenLocked failed: %v", err)
	}
	defer func() { _ = holder.Close() }()

	// Waiter opens inode v1 and blocks in flock/LockFileEx waiting for holder.
	type result struct {
		lf  *LockedFile
		err error
	}
	waiterCh := make(chan result, 1)
	go func() {
		lf, lErr := OpenLocked(path, LockShared, false, 0)
		waiterCh <- result{lf: lf, err: lErr}
	}()

	// Give waiter time to open v1 and block on the lock.
	time.Sleep(60 * time.Millisecond)

	// Atomically replace path with a brand new inode while holder still holds v1's lock.
	tmp := filepath.Join(dir, "locked.dat.new")
	if err := os.WriteFile(tmp, []byte("v2-fresh"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}

	// Release holder's lock on stale v1; waiter must detect SameFile mismatch,
	// close v1, retry, lock v2, and read "v2-fresh".
	if err := holder.Close(); err != nil {
		t.Fatalf("holder Close failed: %v", err)
	}

	select {
	case res := <-waiterCh:
		if res.err != nil {
			t.Fatalf("waiter OpenLocked failed: %v", res.err)
		}
		defer func() { _ = res.lf.Close() }()
		got, err := io.ReadAll(res.lf)
		if err != nil {
			t.Fatalf("waiter ReadAll failed: %v", err)
		}
		if string(got) != "v2-fresh" {
			t.Fatalf("waiter read %q, want %q (SameFile retry failed)", got, "v2-fresh")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter OpenLocked timed out after replacement")
	}
}

func TestOpenLocked_RetryExhaustedAndSymlinkSwap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "churn.dat")
	if err := os.WriteFile(path, []byte("init"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Hook replaces path on every attempt before SameFile verification -> ErrRetryExhausted.
	var mu sync.Mutex
	attempts := 0
	prevHook := lockedPostAcquireHook
	lockedPostAcquireHook = func(p string, attempt int) {
		mu.Lock()
		attempts++
		mu.Unlock()
		tmp := filepath.Join(dir, "swap.tmp")
		_ = os.WriteFile(tmp, []byte("replaced"), 0o600)
		_ = os.Rename(tmp, p)
	}
	t.Cleanup(func() { lockedPostAcquireHook = prevHook })

	if lf, err := OpenLocked(path, LockExclusive, false, OwnerOnlyPerm); !errors.Is(err, ErrRetryExhausted) {
		if lf != nil {
			_ = lf.Close()
		}
		t.Fatalf("OpenLocked under continuous churn = %v, want ErrRetryExhausted", err)
	}
	if attempts != DefaultLockRetries {
		t.Fatalf("observed %d attempts, want DefaultLockRetries (%d)", attempts, DefaultLockRetries)
	}

	// Hook swaps path with a symlink -> must fail closed with ErrSymlink immediately.
	target := filepath.Join(dir, "outside.txt")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	lockedPostAcquireHook = func(p string, _ int) {
		_ = os.Remove(p)
		_ = os.Symlink(target, p)
	}
	if lf, err := OpenLocked(path, LockExclusive, false, OwnerOnlyPerm); !errors.Is(err, ErrSymlink) {
		if lf != nil {
			_ = lf.Close()
		}
		t.Fatalf("OpenLocked after symlink swap = %v, want ErrSymlink", err)
	}
}
