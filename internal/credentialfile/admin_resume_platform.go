//go:build (linux || darwin || windows) && (amd64 || arm64)

package credentialfile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	unix "github.com/wentf9/xops-cli/internal/vaultsys"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/pkg/credential"
)

// Resume authenticates an existing maintenance task with explicitly supplied material.
// Both materials are needed before publication; an already-published task only needs target.
func (s *Store) Resume(ctx context.Context, source, target Wrapping) (MaintenanceResult, error) {
	return s.ResumeFrom(ctx, s, source, target)
}

// ResumeFrom resumes clone/restore with an explicit source handle, never a journal path.
func (s *Store) ResumeFrom(ctx context.Context, source *Store, sourceMaterial, targetMaterial Wrapping) (result MaintenanceResult, err error) {
	if source == nil {
		return result, ErrConflict
	}
	if s.options.ReadOnly {
		return result, credential.ErrCredentialStoreReadOnly
	}
	work, finish, err := s.begin(ctx)
	if err != nil {
		return result, err
	}
	defer finish()
	work, cancel := context.WithTimeout(work, 30*time.Minute)
	defer cancel()
	a := &administration{store: source, ctx: work}
	var m *maintenance
	defer func() { finishMaintenance(m, a, &result, &err) }()
	if err := a.guard(s); err != nil {
		return result, err
	}
	if source != s {
		if err := a.guard(source); err != nil {
			return result, err
		}
		next, done, e := source.begin(a.ctx)
		if e != nil {
			return result, e
		}
		a.ctx = next
		defer done()
	}
	name, dir, err := activeTransaction(a.ctx, s.root)
	if errors.Is(err, os.ErrNotExist) {
		return s.resumeArchived(a.ctx, source, targetMaterial)
	}
	if err != nil {
		return result, err
	}
	m = &maintenance{a: a, store: s, dir: dir, result: MaintenanceResult{OperationID: name}}
	if selected, _ := ctx.Value(operationSelection{}).(string); selected != "" && selected != name {
		return result, ErrConflict
	}
	attempt := resumeAttempt{m: m}
	if err := attempt.authenticate(sourceMaterial, targetMaterial); err != nil {
		return result, err
	}
	defer func() {
		if attempt.seed != nil {
			attempt.seed.close()
		}
	}()
	unlock, err := lockStores(a.ctx, source, s)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	if err := attempt.recheck(); err != nil {
		return result, err
	}
	err = attempt.run()
	return result, err
}

type resumeAttempt struct {
	m          *maintenance
	state      []byte
	current    publication
	currentErr error
	applied    bool
	seed       *wrappingSeed
}

func (r *resumeAttempt) authenticate(source, target Wrapping) (err error) {
	m := r.m
	ctx := m.a.ctx
	r.state, err = m.dir.read(ctx, "state", format.MaxStateBytes)
	if err != nil {
		return errors.Join(ErrMaintenanceRequired, err)
	}
	header, err := activeTargetHeader(r.state)
	if err != nil {
		return err
	}
	if operationName(header.OperationID) != m.result.OperationID || header.Target.StoreID != m.store.storeID {
		return format.ErrIdentity
	}
	data, err := readTargetMeta(ctx, m.store.root, header.Target.Revision)
	if err != nil {
		return err
	}
	if err := verifyEndpointMeta(data, header.Target); err != nil {
		return err
	}
	runtime := m.a.runtime()
	if m.store.session != nil {
		runtime = m.store.session.runtime
	}
	m.targetKey, err = unlockWrapping(ctx, runtime, target, data)
	if err != nil {
		return err
	}
	m.tx, err = format.OpenTransaction(r.state, m.targetKey, format.KeyIdentity{VaultID: header.Target.VaultID, StoreID: header.Target.StoreID, Generation: header.Target.Generation}, true)
	if err != nil {
		return err
	}
	r.current, r.currentErr = m.store.publication(ctx)
	r.applied = r.currentErr == nil && r.current.current.Revision == m.tx.Target.Revision && r.current.current.MetaHash == m.tx.Target.MetaHash
	if !r.applied && m.tx.Operation != format.OpInit {
		if err := r.authenticateSource(source); err != nil {
			return err
		}
	}
	if !r.applied && m.tx.Stage <= format.Verified {
		r.seed, err = prepareWrapping(ctx, runtime, target, m.tx.Target.VaultID, m.store.storeID, m.store.ops)
	}
	return err
}
func (r *resumeAttempt) authenticateSource(material Wrapping) (err error) {
	m := r.m
	a := m.a
	if m.tx.Source.StoreID != a.store.storeID {
		return format.ErrIdentity
	}
	a.pub, err = a.store.snapshot(a.ctx)
	if err != nil {
		return err
	}
	if a.pub.current.Revision != m.tx.Source.Revision || a.pub.current.MetaHash != m.tx.Source.MetaHash {
		return ErrRevisionChanged
	}
	a.key, err = unlockWrapping(a.ctx, a.runtime(), material, a.pub.data)
	if err != nil {
		return err
	}
	_, err = format.OpenTransaction(r.state, a.key, format.KeyIdentity{VaultID: m.tx.Source.VaultID, StoreID: m.tx.Source.StoreID, Generation: m.tx.Source.Generation}, false)
	return err
}
func (r *resumeAttempt) recheck() error {
	m := r.m
	ctx := m.a.ctx
	state, err := m.dir.read(ctx, "state", format.MaxStateBytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(state, r.state) {
		return ErrRevisionChanged
	}
	// The open directory may have been archived while KDF was running.
	name, dir, err := activeTransaction(ctx, m.store.root)
	if err != nil {
		return err
	}
	if err := dir.file.Close(); err != nil {
		return err
	}
	if name != m.result.OperationID {
		return ErrRevisionChanged
	}
	current, e := m.store.publication(ctx)
	if (r.currentErr == nil) != (e == nil) || (r.currentErr == nil && current.current != r.current.current) {
		return ErrRevisionChanged
	}
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if m.a.store == m.store {
		if m.tx.Operation == format.OpClone || m.tx.Operation == format.OpRestore {
			return format.ErrIdentity
		}
	} else if m.tx.Operation != format.OpClone && m.tx.Operation != format.OpRestore {
		return format.ErrIdentity
	}
	if err := m.store.checkMaintenanceFresh(m.tx.Target); err != nil {
		return err
	}
	return m.a.check()
}
func (r *resumeAttempt) run() (err error) {
	m := r.m
	ctx := m.a.ctx
	m.result.Revision, m.result.Generation = m.tx.Target.Revision, m.tx.Target.Generation
	if m.tx.Operation == format.OpPrune {
		if m.a.store != m.store {
			return format.ErrIdentity
		}
		m.a.key = append([]byte(nil), m.targetKey...)
		m.revision, err = revisionDir(m.store.root, m.tx.Target.Revision)
		if err != nil {
			return err
		}
		return m.prune()
	}
	if err := openTargetDirectories(m); err != nil {
		return err
	}
	if m.a.store != m.store {
		m.sourceMarker, err = openSourceMarker(ctx, m.a.store, m.tx.OperationID)
		if err != nil {
			return err
		}
		if err := m.validateSourceMarker(); err != nil {
			return err
		}
	}
	if r.applied {
		m.result.Applied = true
		// An active committed transaction still blocks ordinary mutations, so its
		// complete target snapshot and budget must remain valid before archival.
		if err := m.verifyTarget(); err != nil {
			return err
		}
		return m.commit()
	}
	if m.tx.Stage >= format.Published {
		return ErrMaintenanceRequired
	}
	if err := m.resumeSource(); err != nil {
		return err
	}
	if m.tx.Stage <= format.Verified {
		if err := m.resumeBuild(r.seed); err != nil {
			return err
		}
	}
	return m.publish()
}
func (m *maintenance) resumeSource() (err error) {
	if m.tx.Operation == format.OpInit {
		return nil
	}
	rev, err := revisionDir(m.a.store.root, m.tx.Source.Revision)
	if err != nil {
		return err
	}
	defer closeFile(&err, rev.file)
	m.sourceItems, err = rev.child("items")
	if err != nil {
		return err
	}
	m.sourceRun, err = loadManifest(m.a.ctx, m.dir, "source", m.tx.Source.ManifestRoot, m.tx.Source.ItemCount)
	if err != nil {
		return err
	}
	return m.validateSource()
}
func (m *maintenance) resumeBuild(seed *wrappingSeed) error {
	budget, budgetErr := m.targetBudget()
	if budgetErr == nil {
		// Building does not yet record Target.ItemCount. Check the files already
		// published before permitting any further encryption under this DEK.
		var count uint64
		budgetErr = m.items.each(m.a.ctx, func(name string) error {
			if strings.HasPrefix(name, ".tmp-") {
				return nil
			}
			count++
			if count > budget.Consumed {
				return ErrMaintenanceRequired
			}
			return nil
		})
	}
	if budgetErr != nil {
		if err := m.rebuildTarget(seed); err != nil {
			return err
		}
	}
	if m.tx.Stage == format.Verified {
		return nil
	}
	if err := m.items.each(m.a.ctx, func(name string) error {
		if strings.HasPrefix(name, ".tmp-") {
			return unlinkFile(m.a.ctx, m.items, name, m.store.ops)
		}
		return nil
	}); err != nil {
		return err
	}
	return m.build()
}

func (m *maintenance) rebuildTarget(seed *wrappingSeed) error {
	if seed == nil {
		return ErrMaintenanceRequired
	}
	if m.tx.Operation != format.OpInit {
		cert := m.tx
		b, err := format.SealTransaction(cert, m.a.key, m.targetKey)
		if err != nil {
			return err
		}
		if _, err := m.dir.write(m.a.ctx, fmt.Sprintf("abandoned-%020d.state", m.tx.Target.Revision), b, true, "admin:abandoned", m.store.ops); err != nil {
			return err
		}
	}
	var closeErr error
	for _, ptr := range []**directory{&m.budget, &m.items, &m.revision} {
		d := *ptr
		*ptr = nil
		if d != nil {
			closeErr = errors.Join(closeErr, d.file.Close())
		}
	}
	if closeErr != nil {
		return closeErr
	}
	clear(m.targetKey)
	m.targetKey = make([]byte, 32)
	if err := m.store.ops.randomBytes(m.targetKey); err != nil {
		return err
	}
	if m.tx.Operation == format.OpRewrap {
		m.tx.Operation = format.OpReencrypt
	}
	if err := m.createTarget(seed, true); err != nil {
		return err
	}
	return m.save(format.Prepared, false)
}

func lockStores(ctx context.Context, a, b *Store) (func() error, error) {
	stores := []*Store{a}
	if a != b {
		if a.root.id == b.root.id {
			return nil, ErrConflict
		}
		stores = append(stores, b)
	}
	sort.Slice(stores, func(i, j int) bool {
		if stores[i].root.id.dev != stores[j].root.id.dev {
			return stores[i].root.id.dev < stores[j].root.id.dev
		}
		return stores[i].root.id.ino < stores[j].root.id.ino
	})
	var locks []*fileLock
	closeAll := func() error {
		var err error
		for i := len(locks) - 1; i >= 0; i-- {
			err = errors.Join(err, locks[i].close())
		}
		return err
	}
	for _, s := range stores {
		l, err := s.lock(ctx, true)
		if err != nil {
			return nil, errors.Join(err, closeAll())
		}
		locks = append(locks, l)
	}
	return closeAll, nil
}

func openSourceMarker(ctx context.Context, s *Store, id [16]byte) (d *directory, err error) {
	parent, err := s.root.child("transactions")
	if err != nil {
		return nil, err
	}
	defer closeFile(&err, parent.file)
	return parent.child(operationName(id))
}

func (s *Store) resumeArchived(ctx context.Context, source *Store, target Wrapping) (result MaintenanceResult, err error) {
	p, err := s.snapshot(ctx)
	if err != nil {
		return result, err
	}
	var r *Runtime
	if s.session != nil {
		r = s.session.runtime
	}
	key, err := unlockWrapping(ctx, r, target, p.data)
	if err != nil {
		return result, err
	}
	defer clear(key)
	unlock, err := lockStores(ctx, source, s)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	current, err := s.publication(ctx)
	if err != nil {
		return result, err
	}
	if current.current != p.current {
		return result, ErrRevisionChanged
	}
	if err := s.checkMaintenanceFresh(endpoint(p)); err != nil {
		return result, err
	}
	rev, err := revisionDir(s.root, p.current.Revision)
	if err != nil {
		return result, err
	}
	defer closeFile(&err, rev.file)
	dir, err := rev.child("commit")
	if err != nil {
		return result, err
	}
	defer closeFile(&err, dir.file)
	tx, err := readArchivedTransaction(ctx, dir, p, key)
	if err != nil {
		return result, err
	}
	if selected, _ := ctx.Value(operationSelection{}).(string); selected != "" && selected != operationName(tx.OperationID) {
		return result, ErrConflict
	}
	result = MaintenanceResult{OperationID: operationName(tx.OperationID), Revision: p.current.Revision, Generation: p.current.Generation, Stage: format.Committed, Applied: true}
	if err := s.checkArchivedBudget(ctx, p, key); err != nil {
		return result, err
	}
	if _, err := s.root.syncExisting(ctx, "CURRENT", "admin:confirm", s.ops); err != nil {
		return result, err
	}
	result.Durable = true
	parent, err := s.root.child("transactions")
	if err != nil {
		return result, err
	}
	defer closeFile(&err, parent.file)
	if err := parent.pending(ctx, true); err != nil {
		return result, err
	}
	if err := errors.Join(unix.SyncFile(parent.file), unix.SyncFile(rev.file)); err != nil {
		return result, err
	}
	if err := s.finishArchivedSource(ctx, source, tx, key); err != nil {
		return result, err
	}
	return MaintenanceResult{OperationID: operationName(tx.OperationID), Revision: p.current.Revision, Generation: p.current.Generation, Stage: format.Committed, Applied: true, Durable: true}, nil
}

func (s *Store) finishArchivedSource(ctx context.Context, source *Store, tx format.Transaction, key []byte) error {
	if source != s {
		if tx.Operation != format.OpClone && tx.Operation != format.OpRestore {
			return format.ErrIdentity
		}
		current, err := source.publication(ctx)
		if err != nil {
			return err
		}
		if current.current.VaultID != tx.Source.VaultID || source.storeID != tx.Source.StoreID {
			return format.ErrIdentity
		}
		marker, err := openSourceMarker(ctx, source, tx.OperationID)
		if err == nil {
			m := maintenance{a: &administration{store: source, ctx: ctx}, store: s, tx: tx, sourceMarker: marker, targetKey: key}
			err = m.removeSourceMarker()
			err = errors.Join(err, marker.file.Close())
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if source != s {
		parent, err := source.root.child("transactions")
		if err != nil {
			return err
		}
		return errors.Join(unix.SyncFile(parent.file), parent.file.Close())
	}
	return nil
}

// checkArchivedBudget checks the current mutable item set, not the commit snapshot.
// The caller holds the vault lock and has authenticated the current publication.
func (s *Store) checkArchivedBudget(ctx context.Context, p publication, key []byte) (err error) {
	budgetDir, err := keyStateDir(s.root, p.current.Generation)
	if err != nil {
		return err
	}
	defer closeFile(&err, budgetDir.file)
	if err := budgetDir.pending(ctx, false); err != nil {
		return err
	}
	data, err := budgetDir.read(ctx, "budget", format.MaxStateBytes)
	if err != nil {
		return err
	}
	budget, err := format.OpenBudget(data, key, p.current.VaultID, p.current.Generation, s.storeID)
	if err != nil {
		return err
	}
	rev, err := revisionDir(s.root, p.current.Revision)
	if err != nil {
		return err
	}
	defer closeFile(&err, rev.file)
	items, err := rev.child("items")
	if err != nil {
		return err
	}
	defer closeFile(&err, items.file)
	var count uint64
	return items.each(ctx, func(name string) error {
		if strings.HasPrefix(name, ".tmp-") {
			return ErrMaintenanceRequired
		}
		count++
		if count > budget.Consumed {
			return ErrMaintenanceRequired
		}
		return nil
	})
}

func readArchivedTransaction(ctx context.Context, dir *directory, p publication, key []byte) (format.Transaction, error) {
	data, err := dir.read(ctx, "state", format.MaxStateBytes)
	if err != nil {
		return format.Transaction{}, err
	}
	tx, err := format.OpenTransaction(data, key, format.KeyIdentity{VaultID: p.current.VaultID, StoreID: p.meta.StoreID, Generation: p.current.Generation}, true)
	if err != nil {
		return format.Transaction{}, err
	}
	if tx.Stage != format.Committed || tx.Target.MetaHash != p.current.MetaHash || tx.Target.Revision != p.current.Revision {
		return format.Transaction{}, ErrMaintenanceRequired
	}
	return tx, nil
}
