//go:build linux && amd64

package credentialfile

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/pkg/credential"
	"golang.org/x/sys/unix"
)

// Clone creates an independent vault, preserving ItemIDs under the explicit target StoreID.
func (s *Store) Clone(ctx context.Context, path, id string, target Wrapping) (MaintenanceResult, error) {
	return s.transfer(ctx, path, id, target, nil, format.OpClone)
}

// Restore copies a trusted stopped backup into a fresh root with a new DEK.
// required must contain the backup configuration's references to this StoreID.
// The caller owns the trusted backup/configuration selection; this method does not edit it.
func (s *Store) Restore(ctx context.Context, path string, target Wrapping, required []credential.Ref) (MaintenanceResult, error) {
	return s.transfer(ctx, path, s.storeID, target, required, format.OpRestore)
}

func (s *Store) transfer(ctx context.Context, path, id string, target Wrapping, required []credential.Ref, op format.Operation) (result MaintenanceResult, err error) {
	if err := (credential.Ref{StoreID: id, ItemID: "validate"}).Validate(); err != nil {
		return result, err
	}
	a, err := s.admin(ctx, false)
	if err != nil {
		return result, err
	}
	var m *maintenance
	defer func() { finishMaintenance(m, a, &result, &err) }()
	vault := a.pub.current.VaultID
	if op == format.OpClone {
		if err := s.ops.randomBytes(vault[:]); err != nil {
			return result, err
		}
	}
	seed, err := prepareWrapping(a.ctx, a.runtime(), target, vault, id, s.ops)
	if err != nil {
		return result, err
	}
	defer seed.close()
	dest, err := createTransferTarget(a, path, id)
	if err != nil {
		return result, err
	}
	defer func() {
		err = errors.Join(err, dest.Close())
		if m != nil {
			err = m.outcome(err)
		}
	}()
	unlock, err := lockStores(a.ctx, s, dest)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	if err := emptyVault(a.ctx, dest.root); err != nil {
		return result, err
	}
	current, err := s.publication(a.ctx)
	if err != nil {
		return result, err
	}
	if current.current != a.pub.current {
		return result, ErrRevisionChanged
	}
	sourceTx, err := s.root.child("transactions")
	if err != nil {
		return result, err
	}
	defer closeFile(&err, sourceTx.file)
	if err := sourceTx.pending(a.ctx, true); err != nil {
		return result, err
	}
	if err := layout(a.ctx, dest.root, s.ops); err != nil {
		return result, err
	}
	opID, err := newOperationID(s.ops)
	if err != nil {
		return result, err
	}
	m = &maintenance{a: a, store: dest, tx: format.Transaction{OperationID: opID, Operation: op}, result: MaintenanceResult{OperationID: operationName(opID)}, targetKey: make([]byte, 32)}
	if err := s.ops.randomBytes(m.targetKey); err != nil {
		return result, err
	}
	err = m.transferBuild(sourceTx, seed, required)
	return result, err
}

func (m *maintenance) transferBuild(sourceTx *directory, seed *wrappingSeed, required []credential.Ref) (err error) {
	txParent, err := m.store.root.child("transactions")
	if err != nil {
		return err
	}
	defer closeFile(&err, txParent.file)
	m.dir, err = txParent.mkdir(m.a.ctx, operationName(m.tx.OperationID), false, m.store.ops)
	if err != nil {
		return err
	}
	rev, err := revisionDir(m.a.store.root, m.a.pub.current.Revision)
	if err != nil {
		return err
	}
	defer closeFile(&err, rev.file)
	m.sourceItems, err = rev.child("items")
	if err != nil {
		return err
	}
	if err := validateRequired(m.a, m.sourceItems, required); err != nil {
		return err
	}
	m.sourceRun, err = scanSource(m.a.ctx, m.sourceItems, m.dir, m.a.key, m.a.pub, m.store.ops, m.a.check)
	if err != nil {
		return err
	}
	m.tx.Source = endpoint(m.a.pub)
	m.tx.Source.ManifestRoot = m.sourceRun.root
	m.tx.Source.ItemCount = m.sourceRun.items
	if err := m.createTarget(seed, true); err != nil {
		return err
	}
	m.sourceMarker, err = sourceTx.mkdir(m.a.ctx, operationName(m.tx.OperationID), false, m.store.ops)
	if err != nil {
		return err
	}
	if err := m.save(format.Prepared, true); err != nil {
		return err
	}
	if err := m.build(); err != nil {
		return err
	}
	return m.publish()
}

func validateRequired(a *administration, items *directory, refs []credential.Ref) error {
	for _, ref := range refs {
		if err := ref.Validate(); err != nil {
			return err
		}
		if ref.StoreID != a.store.storeID {
			return format.ErrIdentity
		}
		name, err := format.ItemFilename(ref.ItemID)
		if err != nil {
			return err
		}
		b, err := items.read(a.ctx, name, format.MaxItemBytes)
		if err != nil {
			return err
		}
		secret, err := format.OpenItem(b, a.key, format.ItemIdentity{VaultID: a.pub.current.VaultID, Generation: a.pub.current.Generation, Ref: ref})
		secret.Zero()
		if err != nil {
			return err
		}
	}
	return nil
}

// containsDirectory walks physical ancestors, so aliases cannot defeat overlap checks.
func containsDirectory(ctx context.Context, start *os.File, want fileID) (found bool, err error) {
	fd, err := unix.Openat(int(start.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	current := os.NewFile(uintptr(fd), "vault-ancestor")
	defer func() { err = errors.Join(err, current.Close()) }()
	for {
		if err := context.Cause(ctx); err != nil {
			return false, err
		}
		st, err := inspect(current)
		if err != nil {
			return false, err
		}
		id := fileID{dev: st.Dev, ino: st.Ino}
		if id == want {
			return true, nil
		}
		fd, err := unix.Openat(int(current.Fd()), "..", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return false, err
		}
		parent := os.NewFile(uintptr(fd), "vault-ancestor")
		pst, err := inspect(parent)
		if err != nil {
			return false, errors.Join(err, parent.Close())
		}
		if pst.Dev == st.Dev && pst.Ino == st.Ino {
			return false, parent.Close()
		}
		previous := current
		current = parent
		if err := previous.Close(); err != nil {
			return false, err
		}
	}
}

func createTransferTarget(a *administration, path, id string) (*Store, error) {
	// Reject descendants before creating anything under the source.
	parent, err := walkDirectory(a.ctx, filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	nested, e := containsDirectory(a.ctx, parent, a.store.root.id)
	err = errors.Join(e, parent.Close())
	if err != nil {
		return nil, err
	}
	if nested {
		return nil, ErrConflict
	}
	root, err := createVaultRoot(a.ctx, path)
	if err != nil {
		return nil, err
	}
	nested, e = containsDirectory(a.ctx, a.store.root.file, root.id)
	if e != nil || nested {
		return nil, errors.Join(e, ErrConflict, root.file.Close())
	}
	err = errors.Join(ensureVaultLock(a.ctx, root, a.store.ops), root.file.Close())
	if err != nil {
		return nil, err
	}
	dest, err := openStoreWithLifetime(a.ctx, a.store.ctx, path, id, Options{}, a.store.ops)
	if err != nil {
		return nil, err
	}
	return dest, nil
}
