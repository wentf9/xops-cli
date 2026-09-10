//go:build linux && amd64

package credentialfile

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"golang.org/x/sys/unix"
)

// Prune defaults to a read-only plan. Apply revalidates provenance and records intent.
func (s *Store) Prune(ctx context.Context, apply bool) (result PruneResult, err error) {
	a, err := s.admin(ctx, apply)
	if err != nil {
		return result, err
	}
	var m *maintenance
	defer func() { finishMaintenance(m, a, &result.Maintenance, &err) }()
	if err := a.acquire(); err != nil {
		return result, err
	}
	parent, err := s.root.child("transactions")
	if err != nil {
		return result, err
	}
	defer closeFile(&err, parent.file)
	if err := parent.pending(a.ctx, true); err != nil {
		return result, err
	}
	if err := s.checkArchivedBudget(a.ctx, a.pub, a.key); err != nil {
		return result, err
	}
	ep := endpoint(a.pub)
	candidates, err := readCleanupCertificates(a.ctx, s.root, ep, a.key)
	if err != nil {
		return result, err
	}
	slices.Sort(candidates)
	candidates = slices.Compact(candidates)
	for _, n := range candidates {
		if n == ep.Revision {
			return result, format.ErrIdentity
		}
		d, e := revisionDir(s.root, n)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return result, e
		}
		if err := d.file.Close(); err != nil {
			return result, err
		}
		result.Revisions = append(result.Revisions, n)
		if len(result.Revisions) == 256 {
			break
		}
	}
	if !apply || len(result.Revisions) == 0 {
		return result, nil
	}
	ep.ManifestRoot, err = format.ManifestRoot(nil)
	if err != nil {
		return result, err
	}
	id, err := newOperationID(s.ops)
	if err != nil {
		return result, err
	}
	m = &maintenance{a: a, store: s, targetKey: append([]byte(nil), a.key...), tx: format.Transaction{OperationID: id, Operation: format.OpPrune, Source: ep, Target: ep, CleanupRevisions: result.Revisions}, result: MaintenanceResult{OperationID: operationName(id), Revision: ep.Revision, Generation: ep.Generation}}
	m.dir, err = parent.mkdir(a.ctx, operationName(id), false, s.ops)
	if err != nil {
		return result, err
	}
	m.revision, err = revisionDir(s.root, ep.Revision)
	if err != nil {
		return result, err
	}
	if err := m.save(format.CleanupPending, true); err != nil {
		return result, err
	}
	err = m.prune()
	return result, err
}

func (m *maintenance) prune() error {
	m.pruneOps = m.store.ops
	after := m.pruneOps.after
	m.pruneOps.after = func(step string) {
		if step == "admin:unlink" || step == "admin:rmdir" {
			m.result.Changed = true
			m.result.Durable = false
		}
		if after != nil {
			after(step)
		}
	}
	if m.a.store != m.store || m.tx.Source != m.tx.Target {
		return format.ErrIdentity
	}
	current, err := m.store.publication(m.a.ctx)
	if err != nil {
		return err
	}
	if current.current.Revision != m.tx.Target.Revision || current.current.MetaHash != m.tx.Target.MetaHash {
		return ErrRevisionChanged
	}
	// Recovery must revalidate the current mutable set as well as budget MAC.
	if err := m.store.checkArchivedBudget(m.a.ctx, current, m.targetKey); err != nil {
		return err
	}
	allowed, err := readCleanupCertificates(m.a.ctx, m.store.root, m.tx.Target, m.targetKey)
	if err != nil {
		return err
	}
	for _, n := range m.tx.CleanupRevisions {
		if !slices.Contains(allowed, n) {
			return format.ErrIdentity
		}
	}
	for _, n := range m.tx.CleanupRevisions {
		if err := m.pruneRevision(n); err != nil {
			return err
		}
	}
	if err := m.save(format.Committed, false); err != nil {
		return err
	}
	parent, err := m.store.root.child("transactions")
	if err != nil {
		return err
	}
	e := m.store.ops.step(m.a.ctx, "admin:prune-archive", func() error {
		return unix.Renameat2(int(parent.file.Fd()), operationName(m.tx.OperationID), int(m.revision.file.Fd()), "prune-"+operationName(m.tx.OperationID), unix.RENAME_NOREPLACE)
	})
	err = errors.Join(e, parent.file.Sync(), m.revision.file.Sync(), parent.file.Close())
	if err == nil {
		m.result.Durable = true
	}
	return err
}

func (m *maintenance) pruneRevision(n uint64) (err error) {
	dir, err := revisionDir(m.store.root, n)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer closeFile(&err, dir.file)
	proofs, err := readProvenance(m.a.ctx, m.store.root, m.tx.Target, m.targetKey)
	if err != nil {
		return err
	}
	proof, ok := proofs[n]
	if !ok {
		return format.ErrIdentity
	}
	data, readErr := dir.read(m.a.ctx, "vault.meta", format.MaxMetaBytes)
	var gen uint64
	if readErr == nil {
		if sha256.Sum256(data) != proof.MetaHash {
			return format.ErrIdentity
		}
		meta, e := format.ParseMeta(data)
		if e != nil {
			return e
		}
		if meta.Revision != n || meta.VaultID != m.tx.Target.VaultID || meta.StoreID != m.tx.Target.StoreID {
			return format.ErrIdentity
		}
		gen = meta.Generation
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	// Only the documented layout is deletable. Unexpected objects stop cleanup.
	if err := dir.each(m.a.ctx, func(name string) error {
		switch {
		case name == "vault.meta":
			return nil
		case name == "items":
			return removeFlatDirectory(m.a.ctx, dir, name, itemCleanupName, m.pruneOps)
		case name == "commit" || canonicalOperationDirectory(name, "prune-"):
			return removeFlatDirectory(m.a.ctx, dir, name, transactionCleanupName, m.pruneOps)
		default:
			return ErrMaintenanceRequired
		}
	}); err != nil {
		return err
	}
	if err := m.pruneOldBudget(n, gen); err != nil {
		return err
	}
	if err := unlinkFile(m.a.ctx, dir, "vault.meta", m.pruneOps); err != nil {
		return err
	}
	revisions, err := m.store.root.child("revisions")
	if err != nil {
		return err
	}
	defer closeFile(&err, revisions.file)
	return removeDirectory(m.a.ctx, revisions, strconv.FormatUint(n, 10), m.pruneOps)
}

func generationRetained(ctx context.Context, root *directory, removed, gen uint64) (used bool, err error) {
	revisions, err := root.child("revisions")
	if err != nil {
		return false, err
	}
	defer closeFile(&err, revisions.file)
	err = revisions.each(ctx, func(name string) error {
		n, e := strconv.ParseUint(name, 10, 64)
		if e != nil || strconv.FormatUint(n, 10) != name {
			return ErrMaintenanceRequired
		}
		if n == removed {
			return nil
		}
		data, e := readTargetMeta(ctx, root, n)
		if e != nil {
			return errors.Join(ErrMaintenanceRequired, e)
		}
		meta, e := format.ParseMeta(data)
		if e != nil {
			return e
		}
		if meta.Generation == gen {
			used = true
		}
		return nil
	})
	return used, err
}

func removeFlatDirectory(ctx context.Context, parent *directory, name string, allowed func(string) bool, ops fileOps) (err error) {
	dir, err := parent.child(name)
	if errors.Is(err, os.ErrNotExist) {
		return parent.file.Sync()
	}
	if err != nil {
		return err
	}
	defer closeFile(&err, dir.file)
	if err := dir.each(ctx, func(entry string) error {
		if !allowed(entry) {
			return ErrMaintenanceRequired
		}
		f, err := dir.open(entry, unix.O_RDONLY)
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		return unlinkFile(ctx, dir, entry, ops)
	}); err != nil {
		return err
	}
	return removeDirectory(ctx, parent, name, ops)
}
func removeDirectory(ctx context.Context, parent *directory, name string, ops fileOps) error {
	err := ops.step(ctx, "admin:rmdir", func() error { return unix.Unlinkat(int(parent.file.Fd()), name, unix.AT_REMOVEDIR) })
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return ops.step(ctx, "admin:rmdir-sync", parent.file.Sync)
}
func canonicalOperationDirectory(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	_, err := parseOperationID(strings.TrimPrefix(name, prefix))
	return err == nil
}
func itemCleanupName(name string) bool {
	if strings.HasPrefix(name, ".tmp-") {
		return true
	}
	if len(name) != 68 || !strings.HasSuffix(name, ".enc") {
		return false
	}
	for _, c := range name[:64] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
func transactionCleanupName(name string) bool {
	if name == "state" || strings.HasPrefix(name, ".tmp-") {
		return true
	}
	for _, prefix := range []string{"source", "target"} {
		if canonicalManifestName(name, prefix) {
			return true
		}
	}
	for _, spec := range []struct {
		prefix string
		width  int
	}{{"cleanup-", 8}, {"abandoned-", 20}, {"provenance-", 20}} {
		if strings.HasPrefix(name, spec.prefix) && strings.HasSuffix(name, ".state") {
			raw := strings.TrimSuffix(strings.TrimPrefix(name, spec.prefix), ".state")
			n, err := strconv.ParseUint(raw, 10, 64)
			return err == nil && fmt.Sprintf("%0*d", spec.width, n) == raw
		}
	}
	return false
}
func canonicalManifestName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix+"-") || !strings.HasSuffix(name, ".manifest") {
		return false
	}
	raw := strings.TrimSuffix(strings.TrimPrefix(name, prefix+"-"), ".manifest")
	n, err := strconv.ParseUint(raw, 10, 32)
	return err == nil && blockName(prefix, uint32(n)) == name
}

func (m *maintenance) pruneOldBudget(n, gen uint64) error {
	if gen != 0 && gen != m.tx.Target.Generation {
		used, err := generationRetained(m.a.ctx, m.store.root, n, gen)
		if err != nil {
			return err
		}
		if !used {
			keys, err := m.store.root.child("key-state")
			if err != nil {
				return err
			}
			e := removeFlatDirectory(m.a.ctx, keys, strconv.FormatUint(gen, 10), func(name string) bool { return name == "budget" || strings.HasPrefix(name, ".tmp-") }, m.pruneOps)
			if err := errors.Join(e, keys.file.Close()); err != nil {
				return err
			}
		}
	}
	return nil
}
