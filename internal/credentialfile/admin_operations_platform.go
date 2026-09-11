//go:build (linux || darwin || windows) && (amd64 || arm64)

package credentialfile

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/pkg/credential"
)

func finishMaintenance(m *maintenance, a *administration, result *MaintenanceResult, err *error) {
	if m != nil {
		*err = errors.Join(*err, m.close())
		*result = m.result
	}
	if a != nil {
		*err = errors.Join(*err, a.close())
	}
	if m != nil && m.result.Applied && m.store.session != nil {
		m.acceptPublication()
	}
	if m != nil {
		*err = m.outcome(*err)
	} else if *err != nil && result.Applied {
		*err = &DurabilityError{Op: "maintenance", Applied: true, Durable: result.Durable, Cause: *err}
	}
}

// Rewrap copies authenticated ciphertext into a new revision with new wrapping material.
func (s *Store) Rewrap(ctx context.Context, target Wrapping) (MaintenanceResult, error) {
	return s.upgrade(ctx, target, false)
}

// Reencrypt writes a complete new revision and DEK before switching CURRENT.
func (s *Store) Reencrypt(ctx context.Context, target Wrapping) (MaintenanceResult, error) {
	return s.upgrade(ctx, target, true)
}

func (s *Store) upgrade(ctx context.Context, target Wrapping, newKey bool) (result MaintenanceResult, err error) {
	a, err := s.admin(ctx, true)
	if err != nil {
		return result, err
	}
	var m *maintenance
	defer func() { finishMaintenance(m, a, &result, &err) }()
	seed, err := prepareNewWrapping(a.ctx, a.runtime(), target, a.pub.current.VaultID, s.storeID, s.ops, s.root)
	if err != nil {
		return result, err
	}
	defer seed.close()
	if err := a.acquire(); err != nil {
		return result, err
	}
	if !newKey {
		if err := a.checkSharedBudget(); err != nil {
			return result, err
		}
	}
	parent, err := s.root.child("transactions")
	if err != nil {
		return result, err
	}
	defer closeFile(&err, parent.file)
	if err := parent.pending(a.ctx, true); err != nil {
		return result, err
	}
	id, err := newOperationID(s.ops)
	if err != nil {
		return result, err
	}
	m = &maintenance{a: a, store: s, tx: format.Transaction{OperationID: id, Operation: format.OpRewrap}, result: MaintenanceResult{OperationID: operationName(id)}}
	if newKey {
		m.tx.Operation = format.OpReencrypt
	}
	m.dir, err = parent.mkdir(a.ctx, operationName(id), false, s.ops)
	if err != nil {
		return result, err
	}
	rev, err := revisionDir(s.root, a.pub.current.Revision)
	if err != nil {
		return result, err
	}
	defer closeFile(&err, rev.file)
	m.sourceItems, err = rev.child("items")
	if err != nil {
		return result, err
	}
	m.sourceRun, err = scanSource(a.ctx, m.sourceItems, m.dir, a.key, a.pub, s.ops, a.check)
	if err != nil {
		return result, err
	}
	m.tx.Source = endpoint(a.pub)
	m.tx.Source.ManifestRoot = m.sourceRun.root
	m.tx.Source.ItemCount = m.sourceRun.items
	m.targetKey = append([]byte(nil), a.key...)
	if newKey {
		if err := s.ops.randomBytes(m.targetKey); err != nil {
			return result, err
		}
	}
	if err := m.createTarget(seed, newKey); err != nil {
		return result, err
	}
	if _, err := m.targetBudget(); err != nil {
		return result, err
	}
	if err := m.save(format.Prepared, true); err != nil {
		return result, err
	}
	if err := m.build(); err != nil {
		return result, err
	}
	err = m.publish()
	return result, err
}

func layout(ctx context.Context, root *directory, ops fileOps) (err error) {
	for _, name := range []string{"revisions", "key-state", "transactions"} {
		d, err := root.mkdir(ctx, name, false, ops)
		if err != nil {
			return err
		}
		if err := d.file.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Init creates only an absent or empty private root. It never overwrites an existing vault.
func (r *Runtime) Init(ctx context.Context, path, id string, target Wrapping) (MaintenanceResult, error) {
	return r.initialize(ctx, path, id, target, fileOps{})
}

func (r *Runtime) initialize(ctx context.Context, path, id string, target Wrapping, ops fileOps) (result MaintenanceResult, err error) {
	if err := validateWrappingKeyLocation(path, target); err != nil {
		return result, err
	}
	if err := (credential.Ref{StoreID: id, ItemID: "validate"}).Validate(); err != nil {
		return result, err
	}
	work, finish, err := r.beginOpen(ctx)
	if err != nil {
		return result, err
	}
	defer finish()
	work, cancel := context.WithTimeout(work, 30*time.Minute)
	defer cancel()
	var vault [16]byte
	if err := ops.randomBytes(vault[:]); err != nil {
		return result, err
	}
	root, err := createVaultRoot(work, path)
	if err != nil {
		return result, err
	}
	err = errors.Join(ensureVaultLock(work, root, ops), root.file.Close())
	if err != nil {
		return result, err
	}
	s, err := openStoreWithLifetime(work, r.ctx, path, id, Options{}, ops)
	if err != nil {
		return result, err
	}
	defer closeMaintenanceStore(s, &result, &err)
	a := &administration{store: s, ctx: work}
	var m *maintenance
	defer func() { finishMaintenance(m, a, &result, &err) }()
	a.lock, err = s.lock(work, true)
	if err != nil {
		return result, err
	}
	if err := emptyVault(work, s.root); err != nil {
		return result, err
	}
	seed, err := prepareNewWrapping(work, r, target, vault, id, ops, s.root)
	if err != nil {
		return result, err
	}
	defer seed.close()
	if err := layout(work, s.root, ops); err != nil {
		return result, err
	}
	opID, err := newOperationID(ops)
	if err != nil {
		return result, err
	}
	m = &maintenance{a: a, store: s, tx: format.Transaction{OperationID: opID, Operation: format.OpInit}, result: MaintenanceResult{OperationID: operationName(opID)}, targetKey: make([]byte, 32)}
	if err := ops.randomBytes(m.targetKey); err != nil {
		return result, err
	}
	parent, err := s.root.child("transactions")
	if err != nil {
		return result, err
	}
	defer closeFile(&err, parent.file)
	m.dir, err = parent.mkdir(work, operationName(opID), false, ops)
	if err != nil {
		return result, err
	}
	m.sourceRun.root, err = format.ManifestRoot(nil)
	if err != nil {
		return result, err
	}
	if err := m.createTarget(seed, true); err != nil {
		return result, err
	}
	if err := m.save(format.Prepared, true); err != nil {
		return result, err
	}
	if err := m.build(); err != nil {
		return result, err
	}
	err = m.publish()
	return result, err
}

func activeTransaction(ctx context.Context, root *directory) (name string, dir *directory, err error) {
	parent, err := root.child("transactions")
	if err != nil {
		return "", nil, err
	}
	defer closeFile(&err, parent.file)
	err = parent.each(ctx, func(entry string) error {
		if name != "" {
			return ErrMaintenanceRequired
		}
		if _, err := parseOperationID(entry); err != nil {
			return err
		}
		name = entry
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	if name == "" {
		return "", nil, os.ErrNotExist
	}
	dir, err = parent.child(name)
	return name, dir, err
}

func readTargetMeta(ctx context.Context, root *directory, revision uint64) (data []byte, err error) {
	dir, err := revisionDir(root, revision)
	if err != nil {
		return nil, err
	}
	defer closeFile(&err, dir.file)
	return dir.read(ctx, "vault.meta", format.MaxMetaBytes)
}

// activeTargetHeader inspects only bounded public state for locating a target.
// It never authorizes publication; OpenTransaction must authenticate afterwards.
func activeTargetHeader(data []byte) (format.Transaction, error) {
	return format.InspectTransaction(data)
}

func openTargetDirectories(m *maintenance) (err error) {
	m.revision, err = revisionDir(m.store.root, m.tx.Target.Revision)
	if err != nil {
		return err
	}
	m.items, err = m.revision.child("items")
	if err != nil {
		return err
	}
	m.budget, err = keyStateDir(m.store.root, m.tx.Target.Generation)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func closeMaintenanceStore(s *Store, result *MaintenanceResult, err *error) {
	*err = errors.Join(*err, s.Close())
	if *err != nil && result.Applied {
		*err = &DurabilityError{Op: "maintenance", Applied: true, Durable: result.Durable, Cause: *err}
	}
}

func (a *administration) checkSharedBudget() (err error) {
	d, err := keyStateDir(a.store.root, a.pub.current.Generation)
	if err != nil {
		return err
	}
	defer closeFile(&err, d.file)
	if err := d.pending(a.ctx, false); err != nil {
		return err
	}
	b, err := d.read(a.ctx, "budget", format.MaxStateBytes)
	if err != nil {
		return err
	}
	_, err = format.OpenBudget(b, a.key, a.pub.current.VaultID, a.pub.current.Generation, a.store.storeID)
	return err
}
