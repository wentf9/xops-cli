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
	"sort"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"golang.org/x/sys/unix"
)

type maintenance struct {
	pruneOps                                  fileOps
	a                                         *administration
	store                                     *Store
	tx                                        format.Transaction
	dir, revision, items, budget, sourceItems *directory
	sourceMarker                              *directory
	targetKey                                 []byte
	sourceRun                                 manifestRun
	result                                    MaintenanceResult
}

func (m *maintenance) close() error {
	var err error
	for _, d := range []*directory{m.sourceItems, m.budget, m.items, m.revision, m.dir, m.sourceMarker} {
		if d != nil {
			err = errors.Join(err, d.file.Close())
		}
	}
	clear(m.targetKey)
	m.targetKey = nil
	return err
}
func (m *maintenance) outcome(err error) error {
	if err != nil && m.result.Changed {
		return &DurabilityError{Op: "prune", Applied: true, Durable: m.result.Durable, Cause: err}
	}
	if err != nil && m.result.Applied {
		return &DurabilityError{Op: "maintenance", Applied: true, Durable: m.result.Durable, Cause: err}
	}
	return err
}

func (m *maintenance) save(stage format.Stage, first bool) error {
	m.tx.Stage = stage
	b, err := format.SealTransaction(m.tx, m.a.key, m.targetKey)
	if err != nil {
		return err
	}
	// Mirror before target intent: a published target can always authenticate its marker.
	if m.sourceMarker != nil {
		if _, err := m.sourceMarker.write(m.a.ctx, "state", b, true, "admin:source-state", m.store.ops); err != nil {
			return err
		}
	}
	if _, err := m.dir.write(m.a.ctx, "state", b, !first, "admin:state", m.store.ops); err != nil {
		return err
	}
	m.result.Stage = stage
	return m.store.ops.step(m.a.ctx, fmt.Sprintf("admin:stage-%d", stage), func() error { return nil })
}

func (m *maintenance) createTarget(seed *wrappingSeed, newKey bool) (err error) {
	root := m.store.root
	ctx := m.a.ctx
	ops := m.store.ops
	revisions, err := root.child("revisions")
	if err != nil {
		return err
	}
	defer closeFile(&err, revisions.file)
	minimumRevision := m.tx.Source.Revision
	if m.tx.Operation == format.OpClone {
		minimumRevision = 0
	}
	rev, err := nextNumber(ctx, revisions, minimumRevision)
	if err != nil {
		return err
	}
	keys, err := root.child("key-state")
	if err != nil {
		return err
	}
	defer closeFile(&err, keys.file)
	gen := m.tx.Source.Generation
	if m.tx.Operation == format.OpClone {
		gen = 0
	}
	if newKey {
		gen, err = nextNumber(ctx, keys, gen)
		if err != nil {
			return err
		}
	}
	m.revision, err = revisions.mkdir(ctx, strconv.FormatUint(rev, 10), false, ops)
	if err != nil {
		return err
	}
	m.items, err = m.revision.mkdir(ctx, "items", false, ops)
	if err != nil {
		return err
	}
	meta, err := seed.seal(rev, gen, m.targetKey)
	if err != nil {
		return err
	}
	if _, err := m.revision.write(ctx, "vault.meta", meta, false, "admin:meta", ops); err != nil {
		return err
	}
	m.budget, err = keys.mkdir(ctx, strconv.FormatUint(gen, 10), !newKey, ops)
	if err != nil {
		return err
	}
	if newKey {
		b, err := format.SealBudget(format.Budget{VaultID: seed.meta.VaultID, StoreID: seed.meta.StoreID, Generation: gen, Sequence: 1}, m.targetKey)
		if err != nil {
			return err
		}
		if _, err := m.budget.write(ctx, "budget", b, false, "admin:new-budget", ops); err != nil {
			return err
		}
	}
	m.tx.Target = format.Endpoint{VaultID: seed.meta.VaultID, StoreID: seed.meta.StoreID, Generation: gen, Revision: rev, MetaHash: sha256.Sum256(meta)}
	m.result.Revision, m.result.Generation = rev, gen
	return nil
}

func (m *maintenance) validateSource() error {
	if m.tx.Operation == format.OpInit {
		return nil
	}
	current, err := m.a.store.publication(m.a.ctx)
	if err != nil {
		return err
	}
	if current.current != m.a.pub.current {
		return ErrRevisionChanged
	}
	if err := countItems(m.a.ctx, m.sourceItems, m.tx.Source.ItemCount); err != nil {
		return err
	}
	reader := manifestReader{dir: m.dir, run: m.sourceRun}
	for {
		e, ok, err := reader.next(m.a.ctx)
		if err != nil {
			return err
		}
		if !ok {
			break
		}
		_, secret, err := readSnapshotItem(m.a.ctx, m.sourceItems, m.a.key, e, m.tx.Source)
		secret.Zero()
		if err != nil {
			return err
		}
		if err := m.a.check(); err != nil {
			return err
		}
	}
	return nil
}

func (m *maintenance) targetBudget() (format.Budget, error) {
	if m.budget == nil {
		return format.Budget{}, ErrMaintenanceRequired
	}
	if err := m.budget.pending(m.a.ctx, false); err != nil {
		return format.Budget{}, err
	}
	b, err := m.budget.read(m.a.ctx, "budget", 60+format.MaxIDBytes+32)
	if err != nil {
		return format.Budget{}, err
	}
	budget, err := format.OpenBudget(b, m.targetKey, m.tx.Target.VaultID, m.tx.Target.Generation, m.tx.Target.StoreID)
	if err != nil {
		return budget, err
	}
	minimum := m.tx.Target.ItemCount
	if m.tx.Operation == format.OpRewrap {
		minimum = max(minimum, m.tx.Source.ItemCount)
	}
	if budget.Consumed < minimum {
		return budget, ErrMaintenanceRequired
	}
	return budget, nil
}

func (m *maintenance) build() error {
	if err := m.save(format.Building, false); err != nil {
		return err
	}
	reader := manifestReader{dir: m.dir, run: m.sourceRun}
	writer := manifestWriter{dir: m.dir, ops: m.store.ops, run: manifestRun{prefix: "target"}}
	// Partial target manifests are derived progress, never the source of truth.
	if err := removeManifestFiles(m.a.ctx, m.dir, "target", m.store.ops); err != nil {
		return err
	}
	for {
		e, ok, err := reader.next(m.a.ctx)
		if err != nil {
			return err
		}
		if !ok {
			break
		}
		target, err := m.copyItem(e)
		if err != nil {
			return err
		}
		if err := writer.add(m.a.ctx, target); err != nil {
			return err
		}
		if err := m.a.check(); err != nil {
			return err
		}
	}
	run, err := writer.finish(m.a.ctx)
	if err != nil {
		return err
	}
	if err := countItems(m.a.ctx, m.items, run.items); err != nil {
		return err
	}
	m.tx.Target.ManifestRoot, m.tx.Target.ItemCount = run.root, run.items
	for _, d := range []*directory{m.items, m.revision, m.budget} {
		if err := m.store.ops.step(m.a.ctx, "admin:target-sync", d.file.Sync); err != nil {
			return err
		}
	}
	return m.save(format.Verified, false)
}

func (m *maintenance) copyItem(e format.ManifestEntry) (format.ManifestEntry, error) {
	data, source, err := readSnapshotItem(m.a.ctx, m.sourceItems, m.a.key, e, m.tx.Source)
	if err != nil {
		return format.ManifestEntry{}, err
	}
	defer source.Zero()
	name, err := format.ItemFilename(e.ItemID)
	if err != nil {
		return format.ManifestEntry{}, err
	}
	existing, err := m.items.read(m.a.ctx, name, format.MaxItemBytes)
	if errors.Is(err, os.ErrNotExist) {
		if m.tx.Operation != format.OpRewrap {
			budget, err := m.targetBudget()
			if err != nil {
				return format.ManifestEntry{}, err
			}
			if budget.Consumed >= format.MaxEncryptions || budget.Sequence == math.MaxUint64 {
				return format.ManifestEntry{}, ErrKeyUsageExhausted
			}
			budget.Consumed++
			budget.Sequence++
			b, err := format.SealBudget(budget, m.targetKey)
			if err != nil {
				return format.ManifestEntry{}, err
			}
			if _, err := m.budget.write(m.a.ctx, "budget", b, true, "admin:budget", m.store.ops); err != nil {
				return format.ManifestEntry{}, err
			}
			var nonce [12]byte
			if err := m.store.ops.randomBytes(nonce[:]); err != nil {
				return format.ManifestEntry{}, err
			}
			identity := format.ItemIdentity{VaultID: m.tx.Target.VaultID, Generation: m.tx.Target.Generation, Ref: formatRef(m.tx.Target.StoreID, e.ItemID)}
			data, err = format.SealItem(identity, nonce, m.targetKey, source)
			if err != nil {
				return format.ManifestEntry{}, err
			}
		}
		if _, err := m.items.write(m.a.ctx, name, data, false, "admin:item", m.store.ops); err != nil {
			return format.ManifestEntry{}, err
		}
		existing, err = m.items.read(m.a.ctx, name, format.MaxItemBytes)
	}
	if err != nil {
		return format.ManifestEntry{}, err
	}
	identity := format.ItemIdentity{VaultID: m.tx.Target.VaultID, Generation: m.tx.Target.Generation, Ref: formatRef(m.tx.Target.StoreID, e.ItemID)}
	target, err := format.OpenItem(existing, m.targetKey, identity)
	if err != nil {
		return format.ManifestEntry{}, err
	}
	defer target.Zero()
	if subtle.ConstantTimeCompare(source.Value, target.Value) != 1 || !sameExpiry(source.ExpiresAt, target.ExpiresAt) {
		return format.ManifestEntry{}, ErrConflict
	}
	if m.tx.Operation == format.OpRewrap && !bytes.Equal(existing, data) {
		return format.ManifestEntry{}, ErrConflict
	}
	if _, err := m.items.syncExisting(m.a.ctx, name, "admin:item-retry", m.store.ops); err != nil {
		return format.ManifestEntry{}, err
	}
	return format.ManifestEntry{ItemID: e.ItemID, FileSize: uint32(len(existing)), Hash: sha256.Sum256(existing)}, nil
}

func (m *maintenance) verifyTarget() error {
	data, err := m.revision.read(m.a.ctx, "vault.meta", format.MaxMetaBytes)
	if err != nil {
		return err
	}
	if err := verifyEndpointMeta(data, m.tx.Target); err != nil {
		return err
	}
	run, err := loadManifest(m.a.ctx, m.dir, "target", m.tx.Target.ManifestRoot, m.tx.Target.ItemCount)
	if err != nil {
		return err
	}
	if err := countItems(m.a.ctx, m.items, run.items); err != nil {
		return err
	}
	r := manifestReader{dir: m.dir, run: run}
	for {
		e, ok, err := r.next(m.a.ctx)
		if err != nil {
			return err
		}
		if !ok {
			break
		}
		_, secret, err := readSnapshotItem(m.a.ctx, m.items, m.targetKey, e, m.tx.Target)
		secret.Zero()
		if err != nil {
			return err
		}
	}
	budget, err := m.targetBudget()
	if err != nil {
		return err
	}
	if budget.Consumed < m.tx.Target.ItemCount {
		return ErrMaintenanceRequired
	}
	return nil
}

func (m *maintenance) publish() error {
	if err := m.validateSource(); err != nil {
		return err
	}
	if err := m.verifyTarget(); err != nil {
		return err
	}
	if err := m.writeCleanupCertificates(); err != nil {
		return err
	}
	if err := m.items.file.Sync(); err != nil {
		return err
	}
	if err := m.revision.file.Sync(); err != nil {
		return err
	}
	if err := m.a.check(); err != nil {
		return err
	}
	c := format.Current{VaultID: m.tx.Target.VaultID, Generation: m.tx.Target.Generation, Revision: m.tx.Target.Revision, MetaHash: m.tx.Target.MetaHash}
	b, err := c.MarshalBinary()
	if err != nil {
		return err
	}
	out, err := m.store.root.write(m.a.ctx, "CURRENT", b, m.tx.Operation != format.OpInit && m.tx.Operation != format.OpClone && m.tx.Operation != format.OpRestore, "admin:current", m.store.ops)
	m.result.Applied, m.result.Durable = out.applied, out.durable
	if err != nil {
		return err
	}
	if err := m.save(format.Published, false); err != nil {
		return err
	}
	return m.commit()
}

func (m *maintenance) commit() error {
	p, err := m.store.publication(m.a.ctx)
	if err != nil {
		return err
	}
	if p.current.Revision != m.tx.Target.Revision || p.current.MetaHash != m.tx.Target.MetaHash {
		return ErrRevisionChanged
	}
	if _, err := m.store.root.syncExisting(m.a.ctx, "CURRENT", "admin:confirm", m.store.ops); err != nil {
		return err
	}
	m.result.Applied, m.result.Durable = true, true
	if err := cleanMaintenanceTemps(m.a.ctx, m.store.root, m.store.ops); err != nil {
		return err
	}
	if err := m.save(format.Committed, false); err != nil {
		return err
	}
	return m.archive()
}

func (m *maintenance) archive() (err error) {
	parent, err := m.store.root.child("transactions")
	if err != nil {
		return err
	}
	defer closeFile(&err, parent.file)
	err = m.store.ops.step(m.a.ctx, "admin:archive", func() error {
		return unix.Renameat2(int(parent.file.Fd()), operationName(m.tx.OperationID), int(m.revision.file.Fd()), "commit", unix.RENAME_NOREPLACE)
	})
	if err != nil {
		return err
	}
	if err := errors.Join(parent.file.Sync(), m.revision.file.Sync()); err != nil {
		return err
	}
	if m.sourceMarker != nil {
		return m.removeSourceMarker()
	}
	return nil
}

func (m *maintenance) removeSourceMarker() (err error) {
	if err := m.validateSourceMarker(); err != nil {
		return err
	}
	if err := cleanMaintenanceTemps(m.a.ctx, m.sourceMarker, m.store.ops); err != nil {
		return err
	}
	if err := unlinkFile(m.a.ctx, m.sourceMarker, "state", m.store.ops); err != nil {
		return err
	}
	parent, err := m.a.store.root.child("transactions")
	if err != nil {
		return err
	}
	defer closeFile(&err, parent.file)
	err = unix.Unlinkat(int(parent.file.Fd()), operationName(m.tx.OperationID), unix.AT_REMOVEDIR)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil {
		return err
	}
	return parent.file.Sync()
}

func removeManifestFiles(ctx context.Context, d *directory, prefix string, ops fileOps) error {
	return d.each(ctx, func(name string) error {
		if canonicalManifestName(name, prefix) {
			return unlinkFile(ctx, d, name, ops)
		}
		return nil
	})
}

func (m *maintenance) writeCleanupCertificates() error {
	proofs := make(map[uint64]format.Endpoint)
	if m.tx.Operation == format.OpRewrap || m.tx.Operation == format.OpReencrypt {
		old, err := readProvenance(m.a.ctx, m.a.store.root, m.tx.Source, m.a.key)
		if err != nil {
			return err
		}
		for n, ep := range old {
			proofs[n] = ep
		}
		proofs[m.tx.Source.Revision] = m.tx.Source
	}
	if m.tx.Operation != format.OpInit {
		if err := m.dir.each(m.a.ctx, func(name string) error {
			if !strings.HasPrefix(name, "abandoned-") {
				return nil
			}
			b, err := m.dir.read(m.a.ctx, name, format.MaxStateBytes)
			if err != nil {
				return err
			}
			tx, err := format.OpenTransaction(b, m.a.key, format.KeyIdentity{VaultID: m.tx.Source.VaultID, StoreID: m.tx.Source.StoreID, Generation: m.tx.Source.Generation}, false)
			if err != nil {
				return err
			}
			if tx.OperationID != m.tx.OperationID || tx.Source != m.tx.Source {
				return format.ErrIdentity
			}
			ep := tx.Target
			if ep.ManifestRoot == ([32]byte{}) {
				ep.ManifestRoot, err = format.ManifestRoot(nil)
				if err != nil {
					return err
				}
			}
			proofs[ep.Revision] = ep
			return nil
		}); err != nil {
			return err
		}
	}
	var candidates []uint64
	for n := range proofs {
		candidates = append(candidates, n)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i] < candidates[j] })
	for _, n := range candidates {
		source := proofs[n]
		op := format.OpReencrypt
		if source.Generation == m.tx.Target.Generation {
			op = format.OpRewrap
		}
		cert := format.Transaction{OperationID: m.tx.OperationID, Operation: op, Stage: format.Committed, Source: source, Target: m.tx.Target}
		b, err := format.SealTransaction(cert, m.targetKey, m.targetKey)
		if err != nil {
			return err
		}
		if _, err := m.dir.write(m.a.ctx, fmt.Sprintf("provenance-%020d.state", n), b, true, "admin:certificate", m.store.ops); err != nil {
			return err
		}
	}
	return nil
}

func readProvenance(ctx context.Context, root *directory, ep format.Endpoint, key []byte) (out map[uint64]format.Endpoint, err error) {
	out = make(map[uint64]format.Endpoint)
	rev, err := revisionDir(root, ep.Revision)
	if err != nil {
		return nil, err
	}
	defer closeFile(&err, rev.file)
	dir, err := rev.child("commit")
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	defer closeFile(&err, dir.file)
	err = dir.each(ctx, func(name string) error {
		if !strings.HasPrefix(name, "provenance-") {
			return nil
		}
		b, err := dir.read(ctx, name, format.MaxStateBytes)
		if err != nil {
			return err
		}
		tx, err := format.OpenTransaction(b, key, format.KeyIdentity{VaultID: ep.VaultID, StoreID: ep.StoreID, Generation: ep.Generation}, true)
		if err != nil {
			return err
		}
		if (tx.Operation != format.OpRewrap && tx.Operation != format.OpReencrypt) || tx.Stage != format.Committed || tx.Target.Revision != ep.Revision || tx.Target.MetaHash != ep.MetaHash || name != fmt.Sprintf("provenance-%020d.state", tx.Source.Revision) {
			return format.ErrIdentity
		}
		out[tx.Source.Revision] = tx.Source
		if len(out) > format.MaxEncryptions {
			return format.ErrCorrupt
		}
		return nil
	})
	return out, err
}

func readCleanupCertificates(ctx context.Context, root *directory, ep format.Endpoint, key []byte) ([]uint64, error) {
	proofs, err := readProvenance(ctx, root, ep, key)
	if err != nil {
		return nil, err
	}
	out := make([]uint64, 0, len(proofs))
	for n := range proofs {
		out = append(out, n)
	}
	return out, nil
}

func (m *maintenance) validateSourceMarker() error {
	if (m.tx.Operation != format.OpClone && m.tx.Operation != format.OpRestore) || m.a.store.storeID != m.tx.Source.StoreID {
		return format.ErrIdentity
	}
	current, err := m.a.store.publication(m.a.ctx)
	if err != nil {
		return err
	}
	if current.current.VaultID != m.tx.Source.VaultID || current.current.Revision != m.tx.Source.Revision || current.current.MetaHash != m.tx.Source.MetaHash {
		return format.ErrIdentity
	}
	b, err := m.sourceMarker.read(m.a.ctx, "state", format.MaxStateBytes)
	// Empty marker is the known crash window after deleting state, before rmdir.
	// Only a committed target proof permits finishing this deletion.
	if errors.Is(err, os.ErrNotExist) && m.tx.Stage == format.Committed {
		return nil
	}
	if err != nil {
		return err
	}
	ep := m.tx.Target
	key := m.targetKey
	target := true
	if len(m.a.key) == 32 {
		ep = m.tx.Source
		key = m.a.key
		target = false
	}
	tx, err := format.OpenTransaction(b, key, format.KeyIdentity{VaultID: ep.VaultID, StoreID: ep.StoreID, Generation: ep.Generation}, target)
	if err != nil {
		return err
	}
	if tx.OperationID != m.tx.OperationID || tx.Operation != m.tx.Operation || tx.Source != m.tx.Source || tx.Target.VaultID != m.tx.Target.VaultID || tx.Target.StoreID != m.tx.Target.StoreID {
		return format.ErrIdentity
	}
	return nil
}

func verifyEndpointMeta(data []byte, ep format.Endpoint) error {
	if sha256.Sum256(data) != ep.MetaHash {
		return format.ErrIdentity
	}
	meta, err := format.ParseMeta(data)
	if err != nil {
		return err
	}
	if meta.VaultID != ep.VaultID || meta.StoreID != ep.StoreID || meta.Generation != ep.Generation || meta.Revision != ep.Revision {
		return format.ErrIdentity
	}
	return nil
}
func cleanMaintenanceTemps(ctx context.Context, dir *directory, ops fileOps) error {
	return dir.each(ctx, func(name string) error {
		if !strings.HasPrefix(name, ".tmp-") {
			return nil
		}
		f, err := dir.open(name, unix.O_RDONLY)
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		return unlinkFile(ctx, dir, name, ops)
	})
}
