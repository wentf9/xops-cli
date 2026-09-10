//go:build linux && amd64

package credentialfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/pkg/credential"
	"golang.org/x/sys/unix"
)

// Store owns a verified root handle. Close cancels and waits for active operations.
// It has no secret cache or background unlock worker and is not registered yet.
type Store struct {
	root     *directory
	lockID   fileID
	gate     *sharedGate
	storeID  string
	options  Options
	ops      fileOps
	ctx      context.Context
	cancel   context.CancelCauseFunc
	mu       sync.Mutex
	closed   bool
	done     chan struct{}
	closeErr error
	active   sync.WaitGroup
	session  *session
}

var _ credential.Store = (*Store)(nil)

// Open opens an existing private vault on Linux amd64. The caller selects
// storage with reliable locking, atomic publication and sync semantics. It never creates
// directories, keys, locks or configuration. ctx governs the store's lifetime.
func Open(ctx context.Context, path, storeID string, options Options) (*Store, error) {
	return openStore(ctx, path, storeID, options, fileOps{})
}

func openStore(ctx context.Context, path, storeID string, options Options, ops fileOps) (_ *Store, err error) {
	return openStoreWithLifetime(ctx, ctx, path, storeID, options, ops)
}

// Opening cancellation is distinct from the lifetime of a successfully returned handle.
func openStoreWithLifetime(ctx, lifetime context.Context, path, storeID string, options Options, ops fileOps) (_ *Store, err error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	if len(storeID) == 0 || len(storeID) > format.MaxIDBytes {
		return nil, credential.ErrInvalidRef
	}
	if err := (credential.Ref{StoreID: storeID, ItemID: "item"}).Validate(); err != nil {
		return nil, err
	}
	if options.Timeout < 0 || options.UnlockTimeout < 0 {
		return nil, fmt.Errorf("vault timeouts cannot be negative")
	}
	if options.Timeout == 0 {
		options.Timeout = 10 * time.Second
	}
	if options.UnlockTimeout == 0 {
		options.UnlockTimeout = 30 * time.Second
	}
	root, err := openRoot(ctx, path)
	if err != nil {
		return nil, mapAccess(err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, root.file.Close())
		}
	}()
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	f, err := root.open("vault.lock", unix.O_RDONLY)
	if err != nil {
		return nil, mapAccess(err)
	}
	st, statErr := inspect(f)
	if err := errors.Join(statErr, f.Close()); err != nil {
		return nil, err
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	life, cancel := context.WithCancelCause(lifetime)
	return &Store{root: root, lockID: fileID{st.Dev, st.Ino}, gate: retainGate(root.id), storeID: storeID, options: options, ops: ops, ctx: life, cancel: cancel, done: make(chan struct{})}, nil
}

func mapAccess(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return errors.Join(credential.ErrCredentialStoreUnavailable, err)
	}
	if errors.Is(err, os.ErrPermission) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return errors.Join(credential.ErrCredentialAccessDenied, err)
	}
	return err
}

// Close is waitable and idempotent; it does not return before active I/O is reaped.
func (s *Store) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		<-s.done
		return s.closeErr
	}
	s.closed = true
	s.cancel(ErrClosed)
	s.mu.Unlock()
	s.active.Wait()
	s.closeErr = s.root.file.Close()
	releaseGate(s.root.id)
	close(s.done)
	return s.closeErr
}

func (s *Store) begin(ctx context.Context) (context.Context, func(), error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, nil, ErrClosed
	}
	s.active.Add(1)
	s.mu.Unlock()
	work, cancel := context.WithCancelCause(ctx)
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(s.ctx, func() { defer close(callbackDone); cancel(context.Cause(s.ctx)) })
	finish := func() {
		if !stop() {
			<-callbackDone
		}
		cancel(context.Canceled)
		s.active.Done()
	}
	if err := context.Cause(s.ctx); err != nil {
		finish()
		return nil, nil, err
	}
	if err := context.Cause(work); err != nil {
		finish()
		return nil, nil, err
	}
	return work, finish, nil
}

type publication struct {
	current format.Current
	meta    format.Meta
	data    []byte
}

func (s *Store) publication(ctx context.Context) (_ publication, err error) {
	data, err := s.root.read(ctx, "CURRENT", 80)
	if err != nil {
		return publication{}, mapAccess(err)
	}
	c, err := format.ParseCurrent(data)
	if err != nil {
		return publication{}, err
	}
	revisions, err := s.root.child("revisions")
	if err != nil {
		return publication{}, mapAccess(err)
	}
	defer func() { err = errors.Join(err, revisions.file.Close()) }()
	dir, err := revisions.child(strconv.FormatUint(c.Revision, 10))
	if err != nil {
		return publication{}, mapAccess(err)
	}
	defer func() { err = errors.Join(err, dir.file.Close()) }()
	meta, err := dir.read(ctx, "vault.meta", format.MaxMetaBytes)
	if err != nil {
		return publication{}, mapAccess(err)
	}
	m, err := format.ParseMeta(meta)
	if err != nil {
		return publication{}, err
	}
	if !c.Matches(meta, m) || m.StoreID != s.storeID {
		return publication{}, format.ErrIdentity
	}
	return publication{current: c, meta: m, data: meta}, nil
}

func (s *Store) snapshot(ctx context.Context) (_ publication, err error) {
	ctx, cancel := context.WithTimeout(ctx, s.options.Timeout)
	defer cancel()
	l, err := s.lock(ctx, false)
	if err != nil {
		return publication{}, mapAccess(err)
	}
	defer func() { err = errors.Join(err, l.close()) }()
	return s.publication(ctx)
}

func (s *Store) validateRef(ref credential.Ref) error {
	if ref.StoreID != s.storeID {
		return credential.ErrInvalidRef
	}
	if _, err := format.ItemFilename(ref.ItemID); err != nil {
		return errors.Join(credential.ErrInvalidRef, err)
	}
	return nil
}

type operation struct {
	store         *Store
	pub           publication
	key           []byte
	items         *directory
	budget        *directory
	outcome       mutationOutcome
	budgetOutcome mutationOutcome
	scope         string
	lease         *keyLease
}

func (o *operation) result(err error, write bool) error {
	if err == nil || o == nil || !write {
		return err
	}
	if o.outcome.applied {
		return &DurabilityError{Op: o.scope, Applied: true, Durable: o.outcome.durable, Cause: err}
	}
	if o.budgetOutcome.applied {
		return &DurabilityError{Op: "budget", Applied: true, Durable: o.budgetOutcome.durable, Cause: err}
	}
	return err
}

func (s *Store) operate(ctx context.Context, ref credential.Ref, write bool, fn func(context.Context, *operation) error) (err error) {
	var op *operation
	// Run after all lock/directory cleanup, preserving committed state on errors.
	defer func() { err = op.result(err, write) }()
	if err := s.validateRef(ref); err != nil {
		return err
	}
	if write && s.options.ReadOnly {
		return credential.ErrCredentialStoreReadOnly
	}
	ctx, finish, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer finish()
	p, err := s.snapshot(ctx)
	if err != nil {
		return err
	}
	key, lease, err := s.unlockKey(ctx, p)
	defer clear(key)
	if err != nil {
		return err
	}
	if lease != nil {
		defer lease.release()
		ctx = lease.ctx
	}
	if len(key) != 32 {
		return credential.ErrCredentialStoreLocked
	}
	ctx, cancel := context.WithTimeout(ctx, s.options.Timeout)
	defer cancel()
	l, err := s.lock(ctx, write)
	if err != nil {
		return mapAccess(err)
	}
	defer func() { err = errors.Join(err, l.close()) }()
	latest, err := s.publication(ctx)
	if err != nil {
		return err
	}
	if latest.current != p.current || !bytes.Equal(latest.data, p.data) {
		return ErrRevisionChanged
	}
	op = &operation{store: s, pub: p, key: key, lease: lease}
	defer func() { err = errors.Join(err, op.close()) }()
	if err := op.openDirectories(ctx, write); err != nil {
		return err
	}
	if write && lease != nil {
		lease.forget(ref)
		defer lease.forget(ref)
	}
	if err := fn(ctx, op); err != nil {
		return err
	}
	if lease != nil {
		return lease.deliver(ctx)
	}
	return context.Cause(ctx)
}

func (s *Store) unlockKey(ctx context.Context, p publication) ([]byte, *keyLease, error) {
	if s.session != nil {
		l, err := s.session.acquire(ctx, p.data)
		if err != nil {
			return nil, nil, err
		}
		return l.key, l, nil
	}
	if s.options.Keys == nil {
		return nil, nil, credential.ErrCredentialStoreLocked
	}
	work, cancel := context.WithTimeout(ctx, s.options.UnlockTimeout)
	defer cancel()
	key, err := s.options.Keys.Unlock(work, bytes.Clone(p.data))
	if cause := context.Cause(work); cause != nil {
		err = errors.Join(err, cause)
	}
	return key, nil, err
}

func (o *operation) openDirectories(ctx context.Context, write bool) (err error) {
	revisions, err := o.store.root.child("revisions")
	if err != nil {
		return mapAccess(err)
	}
	defer func() { err = errors.Join(err, revisions.file.Close()) }()
	revision, err := revisions.child(strconv.FormatUint(o.pub.current.Revision, 10))
	if err != nil {
		return mapAccess(err)
	}
	defer func() { err = errors.Join(err, revision.file.Close()) }()
	o.items, err = revision.child("items")
	if err != nil {
		return mapAccess(err)
	}
	if !write {
		return nil
	}
	tx, err := o.store.root.child("transactions")
	if err != nil {
		return mapAccess(err)
	}
	err = errors.Join(tx.pending(ctx, true), tx.file.Close())
	if err != nil {
		return err
	}
	keyState, err := o.store.root.child("key-state")
	if err != nil {
		return mapAccess(err)
	}
	defer func() { err = errors.Join(err, keyState.file.Close()) }()
	o.budget, err = keyState.child(strconv.FormatUint(o.pub.current.Generation, 10))
	if err != nil {
		return mapAccess(err)
	}
	if err := o.budget.pending(ctx, false); err != nil {
		return err
	}
	return o.items.pending(ctx, false)
}

func (o *operation) close() error {
	var err error
	if o.items != nil {
		err = errors.Join(err, o.items.file.Close())
		o.items = nil
	}
	if o.budget != nil {
		err = errors.Join(err, o.budget.file.Close())
		o.budget = nil
	}
	if o.store.ops.before != nil {
		err = errors.Join(err, o.store.ops.before("operation:close"))
	}
	return err
}

func (o *operation) identity(ref credential.Ref) format.ItemIdentity {
	return format.ItemIdentity{VaultID: o.pub.current.VaultID, Generation: o.pub.current.Generation, Ref: ref}
}

func (o *operation) readBudget(ctx context.Context) (format.Budget, error) {
	b, err := o.budget.read(ctx, "budget", 60+format.MaxIDBytes+32)
	if err != nil {
		return format.Budget{}, mapAccess(err)
	}
	return format.OpenBudget(b, o.key, o.pub.current.VaultID, o.pub.current.Generation, o.store.storeID)
}

// Get reads only the requested authenticated item; no metadata load decrypts all items.
func (s *Store) Get(ctx context.Context, ref credential.Ref) (secret credential.Secret, err error) {
	err = s.operate(ctx, ref, false, func(ctx context.Context, o *operation) error {
		name, err := format.ItemFilename(ref.ItemID)
		if err != nil {
			return err
		}
		data, err := o.items.read(ctx, name, format.MaxItemBytes)
		if err != nil && o.lease != nil {
			o.lease.forget(ref)
		}
		if errors.Is(err, os.ErrNotExist) {
			return credential.ErrCredentialNotFound
		}
		if err != nil {
			return mapAccess(err)
		}
		digest := sha256.Sum256(data)
		found := false
		if o.lease != nil {
			secret, found, err = o.lease.cached(ref, digest)
			if err != nil {
				return err
			}
		}
		if !found {
			secret, err = format.OpenItem(data, o.key, o.identity(ref))
		}
		if err != nil {
			return err
		}
		if secret.ExpiresAt != nil && !time.Now().Before(*secret.ExpiresAt) {
			return credential.ErrCredentialNotFound
		}
		if o.lease != nil && !found {
			return o.lease.remember(ref, digest, secret)
		}
		return nil
	})
	if err != nil {
		secret.Zero()
	}
	return secret, err
}

func validSecret(secret credential.Secret) error {
	if len(secret.Value) == 0 || len(secret.Value) > format.MaxSecretBytes {
		return format.ErrCorrupt
	}
	if t := secret.ExpiresAt; t != nil {
		if !time.Unix(0, t.UnixNano()).Equal(*t) || !time.Now().Before(*t) {
			return fmt.Errorf("credential expiry is invalid or elapsed")
		}
	}
	return nil
}

// Put is immutable and durable: equal value AND expiry succeeds, different data conflicts.
func (s *Store) Put(ctx context.Context, ref credential.Ref, secret credential.Secret) error {
	if err := validSecret(secret); err != nil {
		return err
	}
	return s.operate(ctx, ref, true, func(ctx context.Context, o *operation) error { return o.put(ctx, ref, secret) })
}

func (o *operation) put(ctx context.Context, ref credential.Ref, secret credential.Secret) error {
	o.scope = "put"
	if err := validSecret(secret); err != nil {
		return err
	}
	budget, err := o.readBudget(ctx)
	if err != nil {
		return err
	}
	name, err := format.ItemFilename(ref.ItemID)
	if err != nil {
		return err
	}
	data, err := o.items.read(ctx, name, format.MaxItemBytes)
	if err == nil {
		return o.equalRetry(ctx, name, data, ref, secret)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return mapAccess(err)
	}
	if budget.Consumed >= format.MaxEncryptions || budget.Sequence == math.MaxUint64 {
		return ErrKeyUsageExhausted
	}
	budget.Consumed++
	budget.Sequence++
	encoded, err := format.SealBudget(budget, o.key)
	if err != nil {
		return err
	}
	o.budgetOutcome, err = o.budget.write(ctx, "budget", encoded, true, "budget", o.store.ops)
	if err != nil {
		return fmt.Errorf("reserve encryption budget: %w", err)
	}
	var nonce [12]byte
	if err := o.store.ops.step(ctx, "item:nonce", func() error { return o.store.ops.randomBytes(nonce[:]) }); err != nil {
		return err
	}
	encoded, err = format.SealItem(o.identity(ref), nonce, o.key, secret)
	if err != nil {
		return err
	}
	o.outcome, err = o.items.write(ctx, name, encoded, false, "put", o.store.ops)
	if errors.Is(err, unix.EEXIST) {
		return errors.Join(ErrConflict, err)
	}
	return err
}

func (o *operation) equalRetry(ctx context.Context, name string, data []byte, ref credential.Ref, secret credential.Secret) error {
	existing, err := format.OpenItem(data, o.key, o.identity(ref))
	if err != nil {
		return err
	}
	defer existing.Zero()
	equal := subtle.ConstantTimeCompare(existing.Value, secret.Value) == 1
	if existing.ExpiresAt == nil || secret.ExpiresAt == nil {
		equal = equal && existing.ExpiresAt == nil && secret.ExpiresAt == nil
	} else {
		equal = equal && existing.ExpiresAt.Equal(*secret.ExpiresAt)
	}
	if !equal {
		return ErrConflict
	}
	o.outcome.applied = true
	if durable, err := o.budget.syncExisting(ctx, "budget", "budget-retry", o.store.ops); err != nil {
		return &DurabilityError{Op: "budget", Applied: true, Durable: durable, Cause: err}
	}
	o.outcome.durable, err = o.items.syncExisting(ctx, name, "put-retry", o.store.ops)
	if err != nil {
		return &DurabilityError{Op: "put", Applied: true, Durable: o.outcome.durable, Cause: err}
	}
	o.outcome.durable = true
	return nil
}

// Delete assumes the credential service has durably removed all configuration
// references. It authenticates the target, is idempotent, and never refunds budget.
func (s *Store) Delete(ctx context.Context, ref credential.Ref) error {
	return s.operate(ctx, ref, true, func(ctx context.Context, o *operation) error {
		o.scope = "delete"
		if _, err := o.readBudget(ctx); err != nil {
			return err
		}
		name, err := format.ItemFilename(ref.ItemID)
		if err != nil {
			return err
		}
		data, err := o.items.read(ctx, name, format.MaxItemBytes)
		if err == nil {
			secret, openErr := format.OpenItem(data, o.key, o.identity(ref))
			secret.Zero()
			if openErr != nil {
				return openErr
			}
			if err := s.ops.step(ctx, "delete:unlink", func() error { return unix.Unlinkat(int(o.items.file.Fd()), name, 0) }); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return mapAccess(err)
		}
		o.outcome.applied = true
		if err := s.ops.step(ctx, "delete:dir-sync", o.items.file.Sync); err != nil {
			return &DurabilityError{Op: "delete", Applied: true, Cause: err}
		}
		o.outcome.durable = true
		return nil
	})
}
