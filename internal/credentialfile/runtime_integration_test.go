//go:build integration && (linux || darwin || windows) && (amd64 || arm64)

package credentialfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/internal/kdfhelper"
	"github.com/wentf9/xops-cli/pkg/credential"
)

type promptFunc func(context.Context, string) ([]byte, error)

func (f promptFunc) Password(ctx context.Context, id string) ([]byte, error) { return f(ctx, id) }

type deriveFunc func(context.Context, kdfhelper.Request) ([]byte, error)

func (f deriveFunc) Derive(ctx context.Context, r kdfhelper.Request) ([]byte, error) {
	return f(ctx, r)
}

func passwordFixture(t *testing.T) fixture {
	f := makeFixture(t)
	m, err := format.ParseMeta(f.data["meta_password"])
	if err != nil {
		t.Fatal(err)
	}
	c := format.Current{VaultID: m.VaultID, Generation: 1, Revision: 1, MetaHash: sha256.Sum256(f.data["meta_password"])}
	b, err := c.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(f.root, "CURRENT"), b)
	writeFixtureFile(t, filepath.Join(f.root, "revisions/1/vault.meta"), f.data["meta_password"])
	return f
}

func testRuntime(t *testing.T, p PromptProvider, d kdfhelper.Deriver) *Runtime {
	t.Helper()
	r := NewRuntime(t.Context(), p, d)
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}
func runtimeStore(t *testing.T, r *Runtime, f fixture, o SessionOptions) *Store {
	t.Helper()
	s, err := r.OpenStore(t.Context(), f.root, "offline", Options{Timeout: 2 * time.Second}, o)
	if errors.Is(err, ErrUnsupported) {
		t.Skip("required filesystem operations unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRuntimeSharedUnlockAndCache(t *testing.T) {
	f := passwordFixture(t)
	var prompts, derivations atomic.Int32
	r := testRuntime(t, promptFunc(func(context.Context, string) ([]byte, error) {
		prompts.Add(1)
		return bytes.Clone(f.data["password"]), nil
	}), deriveFunc(func(context.Context, kdfhelper.Request) ([]byte, error) {
		derivations.Add(1)
		return bytes.Clone(f.data["password_key"]), nil
	}))
	o := SessionOptions{Mode: "prompt", CacheTTL: time.Minute}
	a, b := runtimeStore(t, r, f, o), runtimeStore(t, r, f, o)
	secret := credential.NewSecret([]byte("public-runtime-secret"))
	defer secret.Zero()
	if err := a.Put(t.Context(), f.ref, secret); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 12)
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Go(func() {
			s := a
			if i%2 == 0 {
				s = b
			}
			got, err := s.Get(t.Context(), f.ref)
			if err == nil && !bytes.Equal(got.Value, secret.Value) {
				err = errors.New("secret differs")
			}
			got.Zero()
			results <- err
		})
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if prompts.Load() != 1 || derivations.Load() != 1 {
		t.Fatal("duplicate unlock")
	}
	if err := a.Lock(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(credential.WithoutInteraction(t.Context()), f.ref); !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("locked cache bypass: %v", err)
	}
	b.session.mu.Lock()
	keyLen, cacheLen := len(b.session.key), len(b.session.digests)
	b.session.mu.Unlock()
	if keyLen != 0 || cacheLen != 0 {
		t.Fatal("lock retained material")
	}
}

func TestRuntimeWaitersCancelIndependently(t *testing.T) {
	f := passwordFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var prompts atomic.Int32
	r := testRuntime(t, promptFunc(func(ctx context.Context, _ string) ([]byte, error) {
		prompts.Add(1)
		close(entered)
		select {
		case <-release:
			return bytes.Clone(f.data["password"]), nil
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	}), deriveFunc(func(context.Context, kdfhelper.Request) ([]byte, error) {
		return bytes.Clone(f.data["password_key"]), nil
	}))
	s := runtimeStore(t, r, f, SessionOptions{Mode: "prompt"})
	first, cancel := context.WithCancel(t.Context())
	defer cancel()
	one := make(chan error, 1)
	two := make(chan error, 1)
	go func() {
		l, err := s.session.acquire(first, f.data["meta_password"])
		if l != nil {
			l.release()
		}
		one <- err
	}()
	<-entered
	go func() {
		l, err := s.session.acquire(t.Context(), f.data["meta_password"])
		if l != nil {
			l.release()
		}
		two <- err
	}()
	deadline := time.Now().Add(time.Second)
	for {
		s.session.mu.Lock()
		n := s.session.task.waiters
		s.session.mu.Unlock()
		if n == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("second waiter missing")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := s.session.acquire(credential.WithoutInteraction(t.Context()), f.data["meta_password"]); !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatal("noninteractive request joined prompt")
	}
	cancel()
	if err := <-one; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	if err := <-two; err != nil {
		t.Fatal(err)
	}
	if prompts.Load() != 1 {
		t.Fatal("first cancel restarted prompt")
	}
}

func TestRuntimeIdleExpiryAndKeyFileRecheck(t *testing.T) {
	f := makeFixture(t)
	keyPath := filepath.Join(platformTempDir(t), "key")
	writeFixtureFile(t, keyPath, f.data["file_key"])
	r := testRuntime(t, nil, nil)
	s := runtimeStore(t, r, f, SessionOptions{Mode: "key-file", KeyFile: keyPath, IdleTTL: time.Minute, CacheTTL: time.Minute})
	secret := credential.NewSecret([]byte("public-idle-secret"))
	defer secret.Zero()
	if err := s.Put(t.Context(), f.ref, secret); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(t.Context(), f.ref)
	got.Zero()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	// Start the timer assertion only after disk I/O completes; race instrumentation
	// and fsync latency must not expire the setup operation itself.
	s.session.mu.Lock()
	s.session.deadline = time.Now().Add(40 * time.Millisecond)
	s.session.mu.Unlock()
	s.session.notify()
	deadline := time.Now().Add(time.Second)
	for {
		s.session.mu.Lock()
		locked := len(s.session.key) == 0
		s.session.mu.Unlock()
		if locked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("idle lock did not clear key")
		}
		time.Sleep(time.Millisecond)
	}
	if err := s.Lock(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(t.Context(), f.ref); !errors.Is(err, credential.ErrCredentialStoreUnavailable) {
		t.Fatalf("missing key-file ignored: %v", err)
	}
}

func TestRuntimeAllWaitersCancelThenRetry(t *testing.T) {
	f := passwordFixture(t)
	entered := make(chan struct{}, 1)
	var calls atomic.Int32
	r := testRuntime(t, promptFunc(func(ctx context.Context, _ string) ([]byte, error) {
		if calls.Add(1) == 1 {
			entered <- struct{}{}
			<-ctx.Done()
			return nil, context.Cause(ctx)
		}
		return bytes.Clone(f.data["password"]), nil
	}), deriveFunc(func(context.Context, kdfhelper.Request) ([]byte, error) {
		return bytes.Clone(f.data["password_key"]), nil
	}))
	s := runtimeStore(t, r, f, SessionOptions{Mode: "prompt"})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		l, err := s.session.acquire(ctx, f.data["meta_password"])
		if l != nil {
			l.release()
		}
		done <- err
	}()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	l, err := s.session.acquire(t.Context(), f.data["meta_password"])
	if err != nil {
		t.Fatal(err)
	}
	l.release()
	if calls.Load() != 2 {
		t.Fatalf("retry did not create exactly one fresh task: %d", calls.Load())
	}
}

func TestRuntimeQueueBoundAndCancellation(t *testing.T) {
	var active, peak atomic.Int32
	r := testRuntime(t, nil, deriveFunc(func(ctx context.Context, _ kdfhelper.Request) ([]byte, error) {
		n := active.Add(1)
		peak.Store(n)
		defer active.Add(-1)
		<-ctx.Done()
		return nil, context.Cause(ctx)
	}))
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	results := make(chan error, 9)
	var wg sync.WaitGroup
	for range 9 {
		wg.Go(func() { key, err := r.deriveKey(ctx, kdfhelper.Request{}); clear(key); results <- err })
	}
	deadline := time.Now().Add(time.Second)
	for {
		r.queueMu.Lock()
		n := r.admitted
		r.queueMu.Unlock()
		if n == 9 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("queue not populated")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := r.deriveKey(t.Context(), kdfhelper.Request{}); !errors.Is(err, ErrResourceBusy) {
		t.Fatalf("queue overflow: %v", err)
	}
	cancel()
	wg.Wait()
	close(results)
	for err := range results {
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	if peak.Load() > 1 {
		t.Fatal("parallel KDF work exceeded one")
	}
	r.queueMu.Lock()
	remaining := r.admitted
	r.queueMu.Unlock()
	if remaining != 0 {
		t.Fatal("queue slots leaked")
	}
}

func TestRuntimeUnlockFailureAllowsRetry(t *testing.T) {
	f := passwordFixture(t)
	var calls atomic.Int32
	r := testRuntime(t, promptFunc(func(context.Context, string) ([]byte, error) { return bytes.Clone(f.data["password"]), nil }), deriveFunc(func(context.Context, kdfhelper.Request) ([]byte, error) {
		if calls.Add(1) == 1 {
			return make([]byte, 32), nil
		}
		return bytes.Clone(f.data["password_key"]), nil
	}))
	s := runtimeStore(t, r, f, SessionOptions{Mode: "prompt"})
	if _, err := s.session.acquire(t.Context(), f.data["meta_password"]); !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("wrong material: %v", err)
	}
	l, err := s.session.acquire(t.Context(), f.data["meta_password"])
	if err != nil {
		t.Fatal(err)
	}
	l.release()
}

func TestRuntimeRevisionInvalidatesWarmKey(t *testing.T) {
	f := makeFixture(t)
	path := filepath.Join(platformTempDir(t), "key")
	writeFixtureFile(t, path, f.data["file_key"])
	r := testRuntime(t, nil, nil)
	s := runtimeStore(t, r, f, SessionOptions{Mode: "key-file", KeyFile: path})
	l, err := s.session.acquire(t.Context(), f.data["meta_file"])
	if err != nil {
		t.Fatal(err)
	}
	oldEpoch := l.epoch
	l.release()
	m, err := format.ParseMeta(f.data["meta_file"])
	if err != nil {
		t.Fatal(err)
	}
	m.Revision++
	m.Salt = bytes.Repeat([]byte{0x53}, 32)
	key, err := format.KeyFileWrappingKey(m, f.data["file_key"])
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	meta, err := format.SealMeta(m, key, f.data["dek"])
	if err != nil {
		t.Fatal(err)
	}
	l, err = s.session.acquire(t.Context(), meta)
	if err != nil {
		t.Fatal(err)
	}
	defer l.release()
	if l.epoch == oldEpoch {
		t.Fatal("revision retained old lease epoch")
	}
}

func TestRuntimePolicyConflictAndClose(t *testing.T) {
	f := makeFixture(t)
	path := filepath.Join(platformTempDir(t), "key")
	writeFixtureFile(t, path, f.data["file_key"])
	r := testRuntime(t, nil, nil)
	o := SessionOptions{Mode: "key-file", KeyFile: path}
	s := runtimeStore(t, r, f, o)
	conflict := o
	conflict.IdleTTL = time.Minute
	if _, err := r.OpenStore(t.Context(), f.root, "offline", Options{}, conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting session policy accepted: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(t.Context(), f.ref); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestCompletedUnlockCannotCrossLockEpoch(t *testing.T) {
	f := passwordFixture(t)
	r := testRuntime(t, nil, nil)
	s := runtimeStore(t, r, f, SessionOptions{Mode: "prompt"})
	ctx, cancel := context.WithCancelCause(r.ctx)
	defer cancel(context.Canceled)
	task := &unlockTask{ctx: ctx, cancel: cancel, done: make(chan struct{}), waiters: 1, epoch: 0}
	close(task.done)
	s.session.mu.Lock()
	s.session.task = task
	s.session.epoch = 1
	s.session.mu.Unlock()
	if err := s.session.waitTask(t.Context(), task); !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("completed pre-lock task was accepted: %v", err)
	}
}

func TestRuntimeDerivationDeadlineClearsLateKey(t *testing.T) {
	f := passwordFixture(t)
	var lateKey []byte
	r := testRuntime(t, promptFunc(func(context.Context, string) ([]byte, error) { return bytes.Clone(f.data["password"]), nil }), deriveFunc(func(ctx context.Context, _ kdfhelper.Request) ([]byte, error) {
		<-ctx.Done()
		lateKey = bytes.Clone(f.data["password_key"])
		return lateKey, nil
	}))
	s := runtimeStore(t, r, f, SessionOptions{Mode: "prompt", UnlockTimeout: 10 * time.Millisecond})
	if _, err := s.session.acquire(t.Context(), f.data["meta_password"]); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late result accepted: %v", err)
	}
	if !bytes.Equal(lateKey, make([]byte, 32)) {
		t.Fatal("late key not cleared")
	}
}

func TestRuntimeExplicitUnlockIsProcessLocal(t *testing.T) {
	f := makeFixture(t)
	path := filepath.Join(platformTempDir(t), "key")
	writeFixtureFile(t, path, f.data["file_key"])
	r := testRuntime(t, nil, nil)
	s := runtimeStore(t, r, f, SessionOptions{Mode: "key-file", KeyFile: path})
	if err := s.Unlock(t.Context()); err != nil {
		t.Fatal(err)
	}
	s.session.mu.Lock()
	unlocked := len(s.session.key) == 32
	s.session.mu.Unlock()
	if !unlocked {
		t.Fatal("explicit unlock did not retain DEK")
	}
	if err := s.Lock(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeRootNoninteractiveCannotBeOverridden(t *testing.T) {
	f := passwordFixture(t)
	var prompts atomic.Int32
	r := NewRuntime(credential.WithoutInteraction(t.Context()), promptFunc(func(context.Context, string) ([]byte, error) {
		prompts.Add(1)
		return bytes.Clone(f.data["password"]), nil
	}), nil)
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	s := runtimeStore(t, r, f, SessionOptions{Mode: "prompt"})
	if err := s.Unlock(t.Context()); !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("root policy overridden: %v", err)
	}
	if prompts.Load() != 0 {
		t.Fatal("root noninteractive policy prompted")
	}
}

func TestRuntimeLockCancelsLeaseBeforeDelivery(t *testing.T) {
	f := makeFixture(t)
	keyPath := filepath.Join(platformTempDir(t), "key")
	writeFixtureFile(t, keyPath, f.data["file_key"])
	r := testRuntime(t, nil, nil)
	s := runtimeStore(t, r, f, SessionOptions{Mode: "key-file", KeyFile: keyPath})
	l, err := s.session.acquire(t.Context(), f.data["meta_file"])
	if err != nil {
		t.Fatal(err)
	}
	done := s.session.requestLock()
	if err := l.deliver(t.Context()); !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("stale lease delivered: %v", err)
	}
	select {
	case <-done:
		t.Fatal("lock completed before lease cleanup")
	default:
	}
	l.release()
	if err := waitSession(t.Context(), done); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeCacheChecksActualCiphertext(t *testing.T) {
	f := makeFixture(t)
	keyPath := filepath.Join(platformTempDir(t), "key")
	writeFixtureFile(t, keyPath, f.data["file_key"])
	r := testRuntime(t, nil, nil)
	s := runtimeStore(t, r, f, SessionOptions{Mode: "key-file", KeyFile: keyPath, CacheTTL: time.Minute})
	secret := credential.NewSecret([]byte("public-cache-secret"))
	defer secret.Zero()
	if err := s.Put(t.Context(), f.ref, secret); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(t.Context(), f.ref)
	got.Zero()
	if err != nil {
		t.Fatal(err)
	}
	path := f.itemPath(t, f.ref)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	writeFixtureFile(t, path, data)
	if _, err := s.Get(t.Context(), f.ref); !errors.Is(err, format.ErrCorrupt) {
		t.Fatalf("cache ignored mutation: %v", err)
	}
}

func TestRuntimeReadWaitsForMaintenanceRevocation(t *testing.T) {
	f := makeFixture(t)
	material := adminMaterial(t, f)
	r := testRuntime(t, nil, nil)
	s := runtimeStore(t, r, f, SessionOptions{Mode: "key-file", KeyFile: material.KeyFile})
	value := credential.NewSecret([]byte("public-revocation-value"))
	defer value.Zero()
	if err := s.Put(t.Context(), f.ref, value); err != nil {
		t.Fatal(err)
	}
	pub, err := s.publication(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := s.session.acquire(t.Context(), pub.data)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			lease.release()
		}
	}()
	if _, err := s.Reencrypt(t.Context(), material); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() { got, err := s.Get(t.Context(), f.ref); got.Zero(); readDone <- err }()
	select {
	case err := <-readDone:
		t.Fatalf("read did not wait for revocation: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	lease.release()
	released = true
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("read did not resume after maintenance revocation")
	}
}
