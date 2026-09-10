//go:build integration && linux && amd64

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

func keyFileOptions(t *testing.T, f fixture) SessionOptions {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	writeFixtureFile(t, path, f.data["file_key"])
	return SessionOptions{Mode: "key-file", KeyFile: path}
}

func newerKeyFileMeta(t *testing.T, f fixture) []byte {
	t.Helper()
	m, err := format.ParseMeta(f.data["meta_file"])
	if err != nil {
		t.Fatal(err)
	}
	m.Revision = 2
	m.Salt = bytes.Repeat([]byte{0x53}, 32)
	m.Nonce[0] ^= 0x53
	wrap, err := format.KeyFileWrappingKey(m, f.data["file_key"])
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wrap)
	data, err := format.SealMeta(m, wrap, f.data["dek"])
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func publishReviewRevision(t *testing.T, f fixture, data []byte) {
	t.Helper()
	dir := filepath.Join(f.root, "revisions/2")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "items"), 0700); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(dir, "vault.meta"), data)
	item, err := os.ReadFile(f.itemPath(t, f.ref))
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(dir, "items", filepath.Base(f.itemPath(t, f.ref))), item)
	m, err := format.ParseMeta(data)
	if err != nil {
		t.Fatal(err)
	}
	c := format.Current{VaultID: m.VaultID, Revision: m.Revision, Generation: m.Generation, MetaHash: sha256.Sum256(data)}
	b, err := c.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(f.root, "CURRENT"), b)
}

func TestOldSnapshotCannotCancelCurrentGet(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	f := makeFixture(t)
	plain := f.open(t, fileOps{})
	secret := credential.NewSecret([]byte("public-regression-secret"))
	defer secret.Zero()
	if err := plain.Put(ctx, f.ref, secret); err != nil {
		t.Fatal(err)
	}
	r := testRuntime(t, nil, nil)
	o := keyFileOptions(t, f)
	oldStore, newStore := runtimeStore(t, r, f, o), runtimeStore(t, r, f, o)
	if err := newStore.Unlock(ctx); err != nil {
		t.Fatal(err)
	}
	oldReady, oldContinue := make(chan struct{}), make(chan struct{})
	var oldCloses atomic.Int32
	oldStore.ops.before = func(step string) error {
		if step == "lock:close" && oldCloses.Add(1) == 1 {
			close(oldReady)
			return waitSession(ctx, oldContinue)
		}
		return nil
	}
	oldResult := make(chan error, 1)
	go func() { got, err := oldStore.Get(ctx, f.ref); got.Zero(); oldResult <- err }()
	if err := waitSession(ctx, oldReady); err != nil {
		t.Fatal(err)
	}
	publishReviewRevision(t, f, newerKeyFileMeta(t, f))
	newReady, newContinue := make(chan *keyLease, 1), make(chan struct{})
	var locks atomic.Int32
	newStore.ops.after = func(step string) {
		if step == "lock:attempt" && locks.Add(1) == 2 {
			newStore.session.mu.Lock()
			for lease := range newStore.session.leases {
				newReady <- lease
				break
			}
			newStore.session.mu.Unlock()
			select {
			case <-newContinue:
			case <-ctx.Done():
			}
		}
	}
	newResult := make(chan error, 1)
	go func() {
		got, err := newStore.Get(ctx, f.ref)
		if err == nil && !bytes.Equal(got.Value, secret.Value) {
			err = errors.New("wrong current secret")
		}
		got.Zero()
		newResult <- err
	}()
	var lease *keyLease
	select {
	case lease = <-newReady:
	case <-ctx.Done():
		t.Fatal("new request did not acquire its lease")
	}
	close(oldContinue)
	select {
	case err := <-oldResult:
		if !errors.Is(err, ErrRevisionChanged) {
			t.Fatalf("stale Get: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("old request blocked waiting for a valid newer lease")
	}
	if err := context.Cause(lease.ctx); err != nil {
		t.Fatalf("old snapshot revoked current lease: %v", err)
	}
	close(newContinue)
	if err := <-newResult; err != nil {
		t.Fatalf("current Get failed: %v", err)
	}
}

func TestAuthenticatedRevisionSurvivesLock(t *testing.T) {
	f := makeFixture(t)
	r := testRuntime(t, nil, nil)
	s := runtimeStore(t, r, f, keyFileOptions(t, f))
	newMeta := newerKeyFileMeta(t, f)
	lease, err := s.session.acquire(t.Context(), newMeta)
	if err != nil {
		t.Fatal(err)
	}
	lease.release()
	if err := s.Lock(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.session.acquire(t.Context(), f.data["meta_file"]); !errors.Is(err, ErrRevisionChanged) {
		t.Fatalf("old revision accepted after lock: %v", err)
	}
	lease, err = s.session.acquire(t.Context(), newMeta)
	if err != nil {
		t.Fatal(err)
	}
	lease.release()
}

func TestUnauthenticatedRevisionDoesNotAdvanceWatermark(t *testing.T) {
	f := makeFixture(t)
	r := testRuntime(t, nil, nil)
	s := runtimeStore(t, r, f, keyFileOptions(t, f))
	lease, err := s.session.acquire(t.Context(), f.data["meta_file"])
	if err != nil {
		t.Fatal(err)
	}
	lease.release()
	bad := newerKeyFileMeta(t, f)
	bad[len(bad)-1] ^= 1
	if _, err := s.session.acquire(t.Context(), bad); !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("bad wrapping accepted: %v", err)
	}
	lease, err = s.session.acquire(t.Context(), f.data["meta_file"])
	if err != nil {
		t.Fatalf("unauthenticated revision poisoned session: %v", err)
	}
	lease.release()
}

func TestOldSnapshotCannotCancelNewUnlock(t *testing.T) {
	f := passwordFixture(t)
	m, err := format.ParseMeta(f.data["meta_password"])
	if err != nil {
		t.Fatal(err)
	}
	m.Revision = 2
	m.Salt = bytes.Repeat([]byte{0x67}, 16)
	m.Nonce[0] ^= 0x67
	newKey := sha256.Sum256(m.Salt)
	newMeta, err := format.SealMeta(m, newKey[:], f.data["dek"])
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	r := testRuntime(t, promptFunc(func(context.Context, string) ([]byte, error) { return bytes.Clone(f.data["password"]), nil }), deriveFunc(func(ctx context.Context, req kdfhelper.Request) ([]byte, error) {
		if bytes.Equal(req.Salt[:], m.Salt) {
			close(entered)
			select {
			case <-release:
				return bytes.Clone(newKey[:]), nil
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			}
		}
		return bytes.Clone(f.data["password_key"]), nil
	}))
	s := runtimeStore(t, r, f, SessionOptions{Mode: "prompt"})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		lease, err := s.session.acquire(ctx, newMeta)
		if lease != nil {
			lease.release()
		}
		done <- err
	}()
	if err := waitSession(ctx, entered); err != nil {
		t.Fatal(err)
	}
	if _, err := s.session.acquire(ctx, f.data["meta_password"]); !errors.Is(err, ErrRevisionChanged) {
		t.Fatalf("old request accepted during newer unlock: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("newer unlock was canceled: %v", err)
	}
}

func pauseRuntimeOpen(t *testing.T, r *Runtime) (<-chan *Store, func()) {
	t.Helper()
	opened := make(chan *Store, 1)
	release := make(chan struct{})
	var once sync.Once
	resume := func() { once.Do(func() { close(release) }) }
	t.Cleanup(resume)
	r.openFile = func(ctx, lifetime context.Context, path, id string, o Options) (*Store, error) {
		s, err := openRuntimeFile(ctx, lifetime, path, id, o)
		if err != nil {
			return nil, err
		}
		opened <- s
		<-release // deterministic pause of an already-owned handle, outside the map lock
		return s, nil
	}
	return opened, resume
}

func TestRuntimeCloseWaitsForOpeningCleanup(t *testing.T) {
	f := makeFixture(t)
	f.open(t, fileOps{}) // establish native platform availability
	r := testRuntime(t, nil, nil)
	o := keyFileOptions(t, f)
	opened, resume := pauseRuntimeOpen(t, r)
	openResult := make(chan error, 1)
	go func() { _, err := r.OpenStore(t.Context(), f.root, "offline", Options{}, o); openResult <- err }()
	s := <-opened
	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	<-r.ctx.Done() // Close has committed to shutdown and reached the opening wait
	select {
	case err := <-closed:
		t.Fatalf("Close returned before opening cleanup: %v", err)
	default:
	}
	resume()
	if err := <-openResult; !errors.Is(err, ErrClosed) {
		t.Fatalf("open during close: %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if _, err := s.root.file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("opening descriptor retained: %v", err)
	}
}

func TestRuntimeCanceledOpenDoesNotRegisterStore(t *testing.T) {
	f := makeFixture(t)
	f.open(t, fileOps{})
	r := testRuntime(t, nil, nil)
	o := keyFileOptions(t, f)
	opened, resume := pauseRuntimeOpen(t, r)
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(context.Canceled)
	cause := errors.New("caller canceled opening")
	result := make(chan error, 1)
	go func() {
		s, err := r.OpenStore(ctx, f.root, "offline", Options{}, o)
		if s != nil {
			err = errors.Join(errors.New("canceled open returned a store"), s.Close())
		}
		result <- err
	}()
	s := <-opened
	cancel(cause)
	resume()
	if err := <-result; !errors.Is(err, cause) {
		t.Fatalf("opening cause lost: %v", err)
	}
	r.mu.Lock()
	stores, sessions := len(r.stores), len(r.sessions)
	r.mu.Unlock()
	if stores != 0 || sessions != 0 {
		t.Fatal("canceled open registered runtime state")
	}
	if _, err := s.root.file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("canceled opening retained its descriptor")
	}
}

func TestOpenedStoreOutlivesOpeningRequest(t *testing.T) {
	f := makeFixture(t)
	r := testRuntime(t, nil, nil)
	o := keyFileOptions(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s, err := r.OpenStore(ctx, f.root, "offline", Options{}, o)
	if errors.Is(err, ErrUnsupported) {
		t.Skip("ext4 required")
	}
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := s.Unlock(t.Context()); err != nil {
		t.Fatalf("opening context became store lifetime: %v", err)
	}
}

func TestRuntimePassesCancellationIntoOpener(t *testing.T) {
	r := testRuntime(t, nil, nil)
	entered := make(chan struct{})
	r.openFile = func(ctx, lifetime context.Context, _ string, _ string, _ Options) (*Store, error) {
		close(entered)
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-time.After(time.Second):
			return nil, errors.New("opener did not receive caller cancellation")
		}
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(context.Canceled)
	cause := errors.New("cancel during opening")
	done := make(chan error, 1)
	go func() {
		_, err := r.OpenStore(ctx, "/unused", "offline", Options{}, SessionOptions{Mode: "prompt"})
		done <- err
	}()
	<-entered
	cancel(cause)
	if err := <-done; !errors.Is(err, cause) {
		t.Fatalf("opener cancellation: %v", err)
	}
	if err := context.Cause(r.ctx); err != nil {
		t.Fatalf("opening cancellation affected runtime: %v", err)
	}
}
