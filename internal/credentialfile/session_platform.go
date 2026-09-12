//go:build (linux || darwin || windows) && (amd64 || arm64)

package credentialfile

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/internal/kdfhelper"
	"github.com/wentf9/xops-cli/pkg/credential"
)

type unlockTask struct {
	ctx     context.Context
	cancel  context.CancelCauseFunc
	done    chan struct{}
	waiters int
	err     error
	epoch   uint64
	meta    format.Meta
}
type lockWork struct {
	refresh bool
	done    chan struct{}
	task    *unlockTask
	leases  []*keyLease
}
type session struct {
	runtime  *Runtime
	storeID  string
	options  SessionOptions
	mu       sync.Mutex
	key      []byte
	hash     [32]byte
	accepted publicationIdentity
	epoch    uint64
	deadline time.Time
	task     *unlockTask
	locking  *lockWork
	closed   bool
	leases   map[*keyLease]struct{}
	cache    *credential.Cache
	digests  map[credential.Ref][32]byte
	wake     chan struct{}
	done     chan struct{}
}

// Keep authenticated ordering across idle/explicit locks. This is process-local
// freshness evidence, not an anti-rollback promise across process restarts.
type publicationIdentity struct {
	vault      [16]byte
	revision   uint64
	generation uint64
	hash       [32]byte
}

func newSession(r *Runtime, id string, o SessionOptions) *session {
	s := &session{runtime: r, storeID: id, options: o, leases: make(map[*keyLease]struct{}), digests: make(map[credential.Ref][32]byte), cache: credential.NewCache(credential.CacheOptions{Capacity: 64, DefaultTTL: o.CacheTTL}), wake: make(chan struct{}, 1), done: make(chan struct{})}
	go s.run()
	return s
}

func (s *session) notify() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *session) requestLock() <-chan struct{} { return s.beginLock(true) }

func (s *session) beginLock(force bool) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.beginLockLocked(force)
}

func (s *session) beginLockLocked(force bool) <-chan struct{} {
	if s.closed {
		return s.done
	}
	if !force && (s.deadline.IsZero() || time.Now().Before(s.deadline)) {
		return nil
	}
	if s.locking != nil {
		return s.locking.done
	}
	select {
	case <-s.done:
		return s.done
	default:
	}
	s.epoch++
	clear(s.key)
	s.key = nil
	s.deadline = time.Time{}
	s.cache.Clear()
	clear(s.digests)
	w := &lockWork{done: make(chan struct{}), task: s.task, refresh: !force}
	if s.task != nil {
		s.task.cancel(credential.ErrCredentialStoreLocked)
	}
	for lease := range s.leases {
		lease.cancel(credential.ErrCredentialStoreLocked)
		w.leases = append(w.leases, lease)
	}
	s.locking = w
	s.notify()
	return w.done
}

// Internal publication/expiry revocation is waitable by subsequent readers.
// Explicit user locks retain fail-closed behavior while their leases drain.
func (s *session) beginRefreshLocked() <-chan struct{} {
	if s.locking != nil {
		return s.locking.done
	}
	done := s.beginLockLocked(true)
	if s.locking != nil {
		s.locking.refresh = true
	}
	return done
}

func (s *session) run() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		s.mu.Lock()
		work := s.locking
		deadline := s.deadline
		s.mu.Unlock()
		if work != nil {
			if work.task != nil {
				<-work.task.done
			}
			for _, lease := range work.leases {
				<-lease.done
			}
			s.mu.Lock()
			s.locking = nil
			close(work.done)
			closing := context.Cause(s.runtime.ctx) != nil
			if closing {
				s.closed = true
				close(s.done)
			}
			s.mu.Unlock()
			if closing {
				return
			}
			continue
		}
		if context.Cause(s.runtime.ctx) != nil {
			s.requestLock()
			continue
		}
		delay := time.Hour
		if !deadline.IsZero() {
			delay = time.Until(deadline)
			if delay <= 0 {
				s.beginLock(false)
				continue
			}
		}
		timer.Reset(delay)
		select {
		case <-s.wake:
		case <-timer.C:
		case <-s.runtime.ctx.Done():
		}
	}
}

type keyLease struct {
	maintenance bool
	s           *session
	ctx         context.Context
	cancel      context.CancelCauseFunc
	key         []byte
	epoch       uint64
	done        chan struct{}
}

func (s *session) leaseLocked(ctx context.Context) *keyLease {
	life, cancel := context.WithCancelCause(ctx)
	l := &keyLease{s: s, ctx: life, cancel: cancel, key: append([]byte(nil), s.key...), epoch: s.epoch, done: make(chan struct{})}
	s.leases[l] = struct{}{}
	return l
}

func (l *keyLease) release() {
	l.s.mu.Lock()
	clear(l.key)
	l.key = nil
	delete(l.s.leases, l)
	l.cancel(context.Canceled)
	close(l.done)
	l.s.mu.Unlock()
}
func (l *keyLease) validLocked() error {
	if err := context.Cause(l.s.runtime.ctx); err != nil {
		return err
	}
	if l.s.epoch != l.epoch || l.s.locking != nil || (!l.maintenance && len(l.s.key) != 32) {
		return credential.ErrCredentialStoreLocked
	}
	if !l.s.deadline.IsZero() && !time.Now().Before(l.s.deadline) {
		return credential.ErrCredentialStoreLocked
	}
	return context.Cause(l.ctx)
}
func (l *keyLease) deliver(ctx context.Context) error {
	l.s.mu.Lock()
	defer l.s.mu.Unlock()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if err := l.validLocked(); err != nil {
		return err
	}
	l.s.deadline = time.Now().Add(l.s.options.IdleTTL)
	l.s.notify()
	return nil
}
func (l *keyLease) forget(ref credential.Ref) {
	l.s.mu.Lock()
	l.s.cache.Invalidate(ref)
	delete(l.s.digests, ref)
	l.s.mu.Unlock()
}
func (l *keyLease) cached(ref credential.Ref, digest [32]byte) (credential.Secret, bool, error) {
	l.s.mu.Lock()
	defer l.s.mu.Unlock()
	if err := l.validLocked(); err != nil {
		return credential.Secret{}, false, err
	}
	if expected, ok := l.s.digests[ref]; !ok || expected != digest {
		l.s.cache.Invalidate(ref)
		delete(l.s.digests, ref)
		return credential.Secret{}, false, nil
	}
	secret, ok := l.s.cache.Get(ref)
	return secret, ok, nil
}
func (l *keyLease) remember(ref credential.Ref, digest [32]byte, secret credential.Secret) error {
	l.s.mu.Lock()
	defer l.s.mu.Unlock()
	if err := l.validLocked(); err != nil {
		return err
	}
	if l.s.options.CacheTTL == 0 {
		return nil
	}
	if len(l.s.digests) >= 64 {
		l.s.cache.Clear()
		clear(l.s.digests)
	}
	l.s.digests[ref] = digest
	l.s.cache.Put(ref, secret)
	return nil
}

func waitSession(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (s *session) acquire(ctx context.Context, metadata []byte) (*keyLease, error) {
	m, err := format.ParseMeta(metadata)
	if err != nil {
		return nil, err
	}
	if m.StoreID != s.storeID {
		return nil, format.ErrIdentity
	}
	hash := sha256.Sum256(metadata)
	for {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		if err := context.Cause(s.runtime.ctx); err != nil {
			return nil, err
		}
		lease, task, draining, err := s.startAcquire(ctx, hash, metadata, m)
		if err != nil {
			return nil, err
		}
		if lease != nil {
			return lease, nil
		}
		if draining != nil {
			if err := waitSession(ctx, draining); err != nil {
				return nil, err
			}
			continue
		}
		if err := s.waitTask(ctx, task); err != nil {
			return nil, err
		}
	}
}

func (s *session) startAcquire(ctx context.Context, hash [32]byte, metadata []byte, m format.Meta) (*keyLease, *unlockTask, <-chan struct{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, nil, nil, ErrClosed
	}
	if s.locking != nil {
		if s.locking.refresh {
			return nil, nil, s.locking.done, nil
		}
		return nil, nil, nil, credential.ErrCredentialStoreLocked
	}
	if s.staleLocked(m, hash) {
		return nil, nil, nil, ErrRevisionChanged
	}
	if (len(s.key) > 0 || s.task != nil) && s.hash != hash {
		return nil, nil, s.beginRefreshLocked(), nil
	}
	if len(s.key) == 32 && time.Now().Before(s.deadline) {
		return s.leaseLocked(ctx), nil, nil, nil
	}
	if len(s.key) > 0 {
		return nil, nil, s.beginRefreshLocked(), nil
	}
	if s.options.Mode == "prompt" && s.promptForbidden(ctx) {
		return nil, nil, nil, credential.ErrCredentialStoreLocked
	}
	task := s.task
	if task != nil && context.Cause(task.ctx) != nil {
		select {
		case <-task.done:
			s.task = nil
			task = nil
		default:
			return nil, nil, task.done, nil
		}
	}
	if task == nil {
		life, cancel := context.WithCancelCause(s.runtime.ctx)
		task = &unlockTask{ctx: life, cancel: cancel, done: make(chan struct{}), epoch: s.epoch, meta: m}
		s.task = task
		s.hash = hash
		go s.unlock(task, metadata, m)
	}
	task.waiters++
	return nil, task, nil, nil
}

func (s *session) staleLocked(m format.Meta, hash [32]byte) bool {
	a := s.accepted
	if a.revision != 0 && (m.VaultID != a.vault || m.Revision < a.revision || m.Generation < a.generation || (m.Revision == a.revision && hash != a.hash)) {
		return true
	}
	if task := s.task; task != nil && context.Cause(task.ctx) == nil {
		candidate := task.meta
		return m.VaultID != candidate.VaultID || m.Revision < candidate.Revision || m.Generation < candidate.Generation || (m.Revision == candidate.Revision && hash != s.hash)
	}
	return false
}

func (s *session) promptForbidden(ctx context.Context) bool {
	return s.options.NonInteractive || credential.InteractionDisabled(ctx) || credential.InteractionDisabled(s.runtime.ctx) || s.runtime.prompt == nil
}

func (s *session) waitTask(ctx context.Context, task *unlockTask) error {
	var err error
	select {
	case <-task.done:
		err = task.err
	case <-ctx.Done():
		err = context.Cause(ctx)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		err = context.Cause(ctx)
	}
	if err == nil && task.epoch != s.epoch {
		err = credential.ErrCredentialStoreLocked
	}
	task.waiters--
	if task.waiters == 0 {
		task.cancel(context.Canceled)
		if err != nil && s.task == task && len(s.leases) == 0 {
			clear(s.key)
			s.key = nil
			s.deadline = time.Time{}
			s.epoch++
			s.cache.Clear()
			clear(s.digests)
			s.notify()
		}
		select {
		case <-task.done:
			if s.task == task {
				s.task = nil
			}
		default:
		}
	}
	return err
}

func (s *session) unlock(task *unlockTask, metadata []byte, m format.Meta) {
	defer func() {
		task.cancel(context.Canceled)
		s.mu.Lock()
		if task.waiters == 0 && s.task == task {
			s.task = nil
		}
		close(task.done)
		s.mu.Unlock()
		s.notify()
	}()
	key, err := s.unlockMaterial(task.ctx, metadata, m)
	defer clear(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if cause := context.Cause(task.ctx); cause != nil {
		err = errors.Join(err, cause)
	}
	if task.epoch != s.epoch || s.locking != nil {
		err = errors.Join(err, credential.ErrCredentialStoreLocked)
	}
	if err != nil {
		task.err = err
		return
	}
	s.key = append([]byte(nil), key...)
	s.accepted = publicationIdentity{vault: m.VaultID, revision: m.Revision, generation: m.Generation, hash: sha256.Sum256(metadata)}
	s.deadline = time.Now().Add(s.options.IdleTTL)
}

func (s *session) unlockMaterial(ctx context.Context, metadata []byte, m format.Meta) ([]byte, error) {
	var password []byte
	var err error
	if s.options.Mode == "prompt" {
		if m.Suite != format.WrapPassword {
			return nil, credential.ErrCredentialStoreLocked
		}
		password, err = s.password(ctx)
		if err != nil {
			return nil, err
		}
		defer clear(password)
	} else if m.Suite != format.WrapKeyFile {
		return nil, credential.ErrCredentialStoreLocked
	}
	work, cancel := context.WithTimeout(ctx, s.options.UnlockTimeout)
	defer cancel()
	var wrapping []byte
	if s.options.Mode == "prompt" {
		var salt [16]byte
		copy(salt[:], m.Salt)
		wrapping, err = s.runtime.deriveKey(work, kdfhelper.Request{Salt: salt, Password: password})
	} else {
		key, readErr := readKeyFile(work, s.options.KeyFile)
		if readErr != nil {
			return nil, readErr
		}
		defer clear(key)
		wrapping, err = format.KeyFileWrappingKey(m, key)
	}
	defer clear(wrapping)
	if err != nil {
		return nil, err
	}
	_, key, err := format.OpenMeta(metadata, wrapping, s.storeID)
	if cause := context.Cause(work); cause != nil {
		err = errors.Join(err, cause)
	}
	if err != nil {
		clear(key)
		return nil, err
	}
	return key, nil
}

func (s *session) password(ctx context.Context) ([]byte, error) {
	if s.promptForbidden(ctx) {
		return nil, credential.ErrCredentialStoreLocked
	}
	ctx, cancel := context.WithTimeout(ctx, s.options.PromptTimeout)
	defer cancel()
	select {
	case s.runtime.promptGate <- struct{}{}:
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
	defer func() { <-s.runtime.promptGate }()
	password, err := s.runtime.prompt.Password(ctx, s.storeID)
	if cause := context.Cause(ctx); cause != nil {
		err = errors.Join(err, cause)
	}
	if err != nil {
		clear(password)
		return nil, err
	}
	return password, nil
}
