//go:build (linux || darwin || windows) && (amd64 || arm64)

package credentialfile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/internal/kdfhelper"
	"github.com/wentf9/xops-cli/pkg/credential"
)

type wrappingSeed struct {
	meta format.Meta
	key  []byte
	used bool
}

func (w *wrappingSeed) close() { clear(w.key); w.key = nil }

func prepareNewWrapping(ctx context.Context, r *Runtime, material Wrapping, vault [16]byte, id string, ops fileOps, roots ...*directory) (*wrappingSeed, error) {
	if material.Mode == "key-file" {
		if len(material.Password) != 0 || material.KeyFile == "" {
			return nil, fmt.Errorf("key-file wrapping requires only key_file")
		}
		if err := validateKeyParent(ctx, material.KeyFile, roots); err != nil {
			return nil, err
		}
		if err := ensureWrappingKeyFile(ctx, material.KeyFile, ops); err != nil {
			return nil, fmt.Errorf("prepare wrapping key file: %w", err)
		}
	}
	return prepareWrapping(ctx, r, material, vault, id, ops)
}

func prepareWrapping(ctx context.Context, r *Runtime, material Wrapping, vault [16]byte, id string, ops fileOps) (*wrappingSeed, error) {
	if len(id) == 0 || len(id) > format.MaxIDBytes {
		return nil, credential.ErrInvalidRef
	}
	seed := &wrappingSeed{meta: format.Meta{VaultID: vault, StoreID: id, Generation: 1, Revision: 1}}
	var raw []byte
	switch material.Mode {
	case "prompt":
		if credential.InteractionDisabled(ctx) || (r != nil && credential.InteractionDisabled(r.ctx)) {
			return nil, credential.ErrCredentialStoreLocked
		}
		if material.KeyFile != "" || utf8.RuneCount(material.Password) < 12 {
			return nil, fmt.Errorf("new master password requires at least twelve Unicode characters")
		}
		wire, err := (kdfhelper.Request{Password: material.Password}).MarshalBinary()
		clear(wire)
		if err != nil {
			return nil, err
		}
		if r == nil {
			return nil, ErrUnsupported
		}
		raw = append([]byte(nil), material.Password...)
		defer clear(raw)
		seed.meta.Suite = format.WrapPassword
		seed.meta.Salt = make([]byte, 16)
	case "key-file":
		if len(material.Password) != 0 || material.KeyFile == "" {
			return nil, fmt.Errorf("key-file wrapping requires only key_file")
		}
		key, err := readKeyFile(ctx, material.KeyFile)
		if err != nil {
			return nil, err
		}
		raw = key
		defer clear(raw)
		seed.meta.Suite = format.WrapKeyFile
		seed.meta.Salt = make([]byte, 32)
	default:
		return nil, fmt.Errorf("invalid wrapping mode")
	}
	if err := ops.randomBytes(seed.meta.Salt); err != nil {
		return nil, err
	}
	if err := ops.randomBytes(seed.meta.Nonce[:]); err != nil {
		return nil, err
	}
	var err error
	if seed.meta.Suite == format.WrapPassword {
		work, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		var salt [16]byte
		copy(salt[:], seed.meta.Salt)
		seed.key, err = r.deriveKey(work, kdfhelper.Request{Salt: salt, Password: raw})
	} else {
		seed.key, err = format.KeyFileWrappingKey(seed.meta, raw)
	}
	if err != nil {
		seed.close()
		return nil, err
	}
	return seed, nil
}

func (w *wrappingSeed) seal(revision, generation uint64, dek []byte) ([]byte, error) {
	if w.used {
		return nil, ErrConflict
	}
	w.used = true
	w.meta.Revision, w.meta.Generation = revision, generation
	return format.SealMeta(w.meta, w.key, dek)
}

func unlockWrapping(ctx context.Context, r *Runtime, material Wrapping, data []byte) (key []byte, err error) {
	m, err := format.ParseMeta(data)
	if err != nil {
		return nil, err
	}
	var wrapping []byte
	if material.Mode == "key-file" && m.Suite == format.WrapKeyFile && len(material.Password) == 0 {
		raw, e := readKeyFile(ctx, material.KeyFile)
		if e != nil {
			return nil, e
		}
		defer clear(raw)
		wrapping, err = format.KeyFileWrappingKey(m, raw)
	} else if material.Mode == "prompt" && m.Suite == format.WrapPassword && material.KeyFile == "" && r != nil {
		if credential.InteractionDisabled(ctx) || credential.InteractionDisabled(r.ctx) {
			return nil, credential.ErrCredentialStoreLocked
		}
		work, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		var salt [16]byte
		copy(salt[:], m.Salt)
		wrapping, err = r.deriveKey(work, kdfhelper.Request{Salt: salt, Password: material.Password})
	} else {
		return nil, credential.ErrCredentialStoreLocked
	}
	defer clear(wrapping)
	if err != nil {
		return nil, err
	}
	_, key, err = format.OpenMeta(data, wrapping, m.StoreID)
	return key, err
}

type administration struct {
	store  *Store
	ctx    context.Context
	finish func()
	pub    publication
	key    []byte
	lease  *keyLease
	lock   *fileLock
	guards []*keyLease
}

func (s *Store) admin(ctx context.Context, write bool) (a *administration, err error) {
	if write && s.options.ReadOnly {
		return nil, credential.ErrCredentialStoreReadOnly
	}
	work, finish, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	work, cancel := context.WithTimeout(work, 30*time.Minute)
	if s.session != nil && s.session.options.NonInteractive {
		work = credential.WithoutInteraction(work)
	}
	a = &administration{store: s, ctx: work, finish: func() { cancel(); finish() }}
	owned := a
	defer func() {
		if err != nil {
			err = errors.Join(err, owned.close())
		}
	}()
	a.pub, err = s.snapshot(work)
	if err != nil {
		return nil, err
	}
	a.key, a.lease, err = s.unlockKey(work, a.pub)
	if err != nil {
		return nil, err
	}
	if len(a.key) != 32 {
		return nil, credential.ErrCredentialStoreLocked
	}
	if a.lease != nil {
		a.ctx = a.lease.ctx
	}
	return a, nil
}

func (a *administration) acquire() error {
	lock, err := a.store.lock(a.ctx, true)
	if err != nil {
		return err
	}
	a.lock = lock
	current, err := a.store.publication(a.ctx)
	if err != nil {
		return err
	}
	if current.current != a.pub.current {
		return ErrRevisionChanged
	}
	return nil
}

func (a *administration) close() error {
	if a == nil {
		return nil
	}
	var err error
	if a.lock != nil {
		err = a.lock.close()
		a.lock = nil
	}
	if a.lease != nil {
		a.lease.release()
		a.lease = nil
	} else {
		clear(a.key)
	}
	a.key = nil
	for _, guard := range a.guards {
		guard.release()
	}
	a.guards = nil
	if a.finish != nil {
		a.finish()
		a.finish = nil
	}
	return err
}

func (a *administration) runtime() *Runtime {
	if a.store.session != nil {
		return a.store.session.runtime
	}
	return nil
}
func (a *administration) check() error {
	if err := context.Cause(a.ctx); err != nil {
		return err
	}
	for _, guard := range a.guards {
		if err := guard.deliver(a.ctx); err != nil {
			return err
		}
	}
	if a.lease != nil {
		return a.lease.deliver(a.ctx)
	}
	return nil
}

func newOperationID(ops fileOps) ([16]byte, error) {
	var id [16]byte
	err := ops.randomBytes(id[:])
	if err == nil && id == ([16]byte{}) {
		err = format.ErrCorrupt
	}
	return id, err
}
func operationName(id [16]byte) string { return hex.EncodeToString(id[:]) }

func revisionDir(root *directory, n uint64) (d *directory, err error) {
	p, err := root.child("revisions")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, p.file.Close()) }()
	return p.child(strconv.FormatUint(n, 10))
}

func keyStateDir(root *directory, n uint64) (d *directory, err error) {
	p, err := root.child("key-state")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, p.file.Close()) }()
	return p.child(strconv.FormatUint(n, 10))
}

func endpoint(pub publication) format.Endpoint {
	return format.Endpoint{VaultID: pub.current.VaultID, StoreID: pub.meta.StoreID, Revision: pub.current.Revision, Generation: pub.current.Generation, MetaHash: sha256.Sum256(pub.data)}
}

func closeFile(err *error, f *os.File) {
	if f != nil {
		*err = errors.Join(*err, f.Close())
	}
}

func formatRef(storeID, itemID string) credential.Ref {
	return credential.Ref{StoreID: storeID, ItemID: itemID}
}
func sameExpiry(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// guard registers raw maintenance material with the session revocation barrier.
// It never installs the material as the normal session key.
func (a *administration) guard(store *Store) error {
	if store.session == nil {
		return nil
	}
	s := store.session
	if s.options.NonInteractive {
		a.ctx = credential.WithoutInteraction(a.ctx)
	}
	if err := s.lockMaintenanceGuard(a.ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	l := s.leaseLocked(a.ctx)
	clear(l.key)
	l.key = nil
	l.maintenance = true
	if s.deadline.IsZero() {
		s.deadline = time.Now().Add(s.options.IdleTTL)
		s.notify()
	}
	a.guards = append(a.guards, l)
	a.ctx = l.ctx
	return nil
}

func (s *Store) checkMaintenanceFresh(ep format.Endpoint) error {
	if s.session == nil {
		return nil
	}
	session := s.session
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.staleLocked(format.Meta{VaultID: ep.VaultID, Revision: ep.Revision, Generation: ep.Generation}, ep.MetaHash) {
		return ErrRevisionChanged
	}
	return nil
}
func (m *maintenance) acceptPublication() {
	if m.store.session == nil {
		return
	}
	s := m.store.session
	s.mu.Lock()
	defer s.mu.Unlock()
	ep := m.tx.Target
	if s.staleLocked(format.Meta{VaultID: ep.VaultID, Revision: ep.Revision, Generation: ep.Generation}, ep.MetaHash) {
		return
	}
	s.accepted = publicationIdentity{vault: ep.VaultID, revision: ep.Revision, generation: ep.Generation, hash: ep.MetaHash}
	s.beginLockLocked(true)
}

// lockMaintenanceGuard waits for prior revocation without holding the mutex.
// Success returns with the mutex held, closing the registration/Lock race.
func (s *session) lockMaintenanceGuard(ctx context.Context) error {
	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return credential.ErrCredentialStoreLocked
		}
		if s.locking == nil {
			return nil
		}
		done := s.locking.done
		s.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
}
