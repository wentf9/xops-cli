//go:build (linux || darwin || windows) && (amd64 || arm64)

package credentialfile

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/pkg/credential"
)

type manifestRun struct {
	prefix string
	blocks uint32
	items  uint64
	root   [32]byte
}

func blockName(prefix string, index uint32) string {
	return fmt.Sprintf("%s-%08d.manifest", prefix, index)
}

type manifestWriter struct {
	dir     *directory
	ops     fileOps
	run     manifestRun
	entries []format.ManifestEntry
	size    int
	hashes  [][32]byte
}

func (w *manifestWriter) add(ctx context.Context, e format.ManifestEntry) error {
	if w.run.items >= format.MaxEncryptions {
		return ErrKeyUsageExhausted
	}
	if len(w.entries) > 0 && w.size+38+len(e.ItemID) > format.MaxManifestBytes {
		if err := w.flush(ctx); err != nil {
			return err
		}
	}
	if len(w.entries) == 0 {
		w.size = 18
	}
	w.entries = append(w.entries, e)
	w.size += 38 + len(e.ItemID)
	w.run.items++
	return nil
}
func (w *manifestWriter) flush(ctx context.Context) error {
	if len(w.entries) == 0 {
		return nil
	}
	b, err := (format.ManifestBlock{Index: w.run.blocks, Entries: w.entries}).MarshalBinary()
	if err != nil {
		return err
	}
	if _, err := w.dir.write(ctx, blockName(w.run.prefix, w.run.blocks), b, false, "admin:manifest", w.ops); err != nil {
		return err
	}
	w.hashes = append(w.hashes, sha256.Sum256(b))
	w.run.blocks++
	clear(w.entries)
	w.entries = w.entries[:0]
	w.size = 18
	return nil
}
func (w *manifestWriter) finish(ctx context.Context) (manifestRun, error) {
	if err := w.flush(ctx); err != nil {
		return manifestRun{}, err
	}
	root, err := format.ManifestRoot(w.hashes)
	w.run.root = root
	return w.run, err
}

type manifestReader struct {
	dir     *directory
	run     manifestRun
	block   uint32
	entries []format.ManifestEntry
	at      int
	last    string
}

func (r *manifestReader) next(ctx context.Context) (format.ManifestEntry, bool, error) {
	if r.at == len(r.entries) {
		if r.block == r.run.blocks {
			return format.ManifestEntry{}, false, nil
		}
		b, err := r.dir.read(ctx, blockName(r.run.prefix, r.block), format.MaxManifestBytes)
		if err != nil {
			return format.ManifestEntry{}, false, err
		}
		parsed, err := format.ParseManifestBlock(b)
		if err != nil {
			return format.ManifestEntry{}, false, err
		}
		if parsed.Index != r.block {
			return format.ManifestEntry{}, false, format.ErrCorrupt
		}
		r.entries = parsed.Entries
		r.at = 0
		r.block++
	}
	e := r.entries[r.at]
	r.at++
	if r.last != "" && e.ItemID <= r.last {
		return format.ManifestEntry{}, false, format.ErrCorrupt
	}
	r.last = e.ItemID
	return e, true, nil
}

func mergeRuns(ctx context.Context, dir *directory, a, b manifestRun, prefix string, ops fileOps) (manifestRun, error) {
	ra, rb := manifestReader{dir: dir, run: a}, manifestReader{dir: dir, run: b}
	w := manifestWriter{dir: dir, ops: ops, run: manifestRun{prefix: prefix}}
	x, xok, err := ra.next(ctx)
	if err != nil {
		return manifestRun{}, err
	}
	y, yok, err := rb.next(ctx)
	if err != nil {
		return manifestRun{}, err
	}
	for xok || yok {
		if xok && yok && x.ItemID == y.ItemID {
			return manifestRun{}, format.ErrCorrupt
		}
		if xok && (!yok || x.ItemID < y.ItemID) {
			if err := w.add(ctx, x); err != nil {
				return manifestRun{}, err
			}
			x, xok, err = ra.next(ctx)
		} else {
			if err := w.add(ctx, y); err != nil {
				return manifestRun{}, err
			}
			y, yok, err = rb.next(ctx)
		}
		if err != nil {
			return manifestRun{}, err
		}
	}
	return w.finish(ctx)
}

func removeRun(ctx context.Context, dir *directory, run manifestRun, ops fileOps) error {
	for i := uint32(0); i < run.blocks; i++ {
		if err := unlinkFile(ctx, dir, blockName(run.prefix, i), ops); err != nil {
			return err
		}
	}
	return nil
}

func scanSource(ctx context.Context, items, txDir *directory, key []byte, pub publication, ops fileOps, touch func() error) (manifestRun, error) {
	var runs []manifestRun
	var chunk []format.ManifestEntry
	size := 18
	sequence := 0
	total := uint64(0)
	flush := func() error {
		if len(chunk) == 0 {
			return nil
		}
		sort.Slice(chunk, func(i, j int) bool { return chunk[i].ItemID < chunk[j].ItemID })
		w := manifestWriter{dir: txDir, ops: ops, run: manifestRun{prefix: fmt.Sprintf("sort-%08d", sequence)}}
		sequence++
		for _, e := range chunk {
			if err := w.add(ctx, e); err != nil {
				return err
			}
		}
		run, err := w.finish(ctx)
		if err != nil {
			return err
		}
		runs = append(runs, run)
		clear(chunk)
		chunk = chunk[:0]
		size = 18
		return nil
	}
	err := items.each(ctx, func(name string) error {
		if strings.HasPrefix(name, ".tmp-") {
			return ErrMaintenanceRequired
		}
		data, err := items.read(ctx, name, format.MaxItemBytes)
		if err != nil {
			return err
		}
		identity, err := format.InspectItem(data)
		if err != nil {
			return err
		}
		file, err := format.ItemFilename(identity.Ref.ItemID)
		if err != nil {
			return err
		}
		if file != name || identity.VaultID != pub.current.VaultID || identity.Generation != pub.current.Generation || identity.Ref.StoreID != pub.meta.StoreID {
			return format.ErrIdentity
		}
		secret, err := format.OpenItem(data, key, identity)
		secret.Zero()
		if err != nil {
			return err
		}
		total++
		if total > format.MaxEncryptions {
			return ErrKeyUsageExhausted
		}
		if size+38+len(identity.Ref.ItemID) > format.MaxManifestBytes {
			if err := flush(); err != nil {
				return err
			}
		}
		chunk = append(chunk, format.ManifestEntry{ItemID: identity.Ref.ItemID, FileSize: uint32(len(data)), Hash: sha256.Sum256(data)})
		size += 38 + len(identity.Ref.ItemID)
		if touch != nil {
			return touch()
		}
		return nil
	})
	if err != nil {
		return manifestRun{}, err
	}
	if err := flush(); err != nil {
		return manifestRun{}, err
	}
	return finalizeSourceRuns(ctx, txDir, runs, sequence, ops)
}

func finalizeSourceRuns(ctx context.Context, txDir *directory, runs []manifestRun, sequence int, ops fileOps) (manifestRun, error) {
	for len(runs) > 1 {
		var next []manifestRun
		for i := 0; i < len(runs); i += 2 {
			if i+1 == len(runs) {
				next = append(next, runs[i])
				continue
			}
			run, err := mergeRuns(ctx, txDir, runs[i], runs[i+1], fmt.Sprintf("sort-%08d", sequence), ops)
			sequence++
			if err != nil {
				return manifestRun{}, err
			}
			if err := removeRun(ctx, txDir, runs[i], ops); err != nil {
				return manifestRun{}, err
			}
			if err := removeRun(ctx, txDir, runs[i+1], ops); err != nil {
				return manifestRun{}, err
			}
			next = append(next, run)
		}
		runs = next
	}
	if len(runs) == 0 {
		root, err := format.ManifestRoot(nil)
		return manifestRun{prefix: "source", root: root}, err
	}
	reader := manifestReader{dir: txDir, run: runs[0]}
	writer := manifestWriter{dir: txDir, ops: ops, run: manifestRun{prefix: "source"}}
	for {
		e, ok, err := reader.next(ctx)
		if err != nil {
			return manifestRun{}, err
		}
		if !ok {
			break
		}
		if err := writer.add(ctx, e); err != nil {
			return manifestRun{}, err
		}
	}
	result, err := writer.finish(ctx)
	if err != nil {
		return manifestRun{}, err
	}
	return result, removeRun(ctx, txDir, runs[0], ops)
}

func loadManifest(ctx context.Context, dir *directory, prefix string, root [32]byte, items uint64) (manifestRun, error) {
	count := uint32(0)
	var max uint64
	err := dir.each(ctx, func(name string) error {
		if !strings.HasPrefix(name, prefix+"-") {
			return nil
		}
		if !strings.HasSuffix(name, ".manifest") {
			return format.ErrCorrupt
		}
		number := strings.TrimSuffix(strings.TrimPrefix(name, prefix+"-"), ".manifest")
		n, err := strconv.ParseUint(number, 10, 32)
		if err != nil || fmt.Sprintf("%08d", n) != number || n >= format.MaxEncryptions {
			return format.ErrCorrupt
		}
		count++
		if n > max {
			max = n
		}
		return nil
	})
	if err != nil {
		return manifestRun{}, err
	}
	if count > 0 && max != uint64(count-1) {
		return manifestRun{}, format.ErrCorrupt
	}
	v, err := format.NewManifestVerifier(count, items)
	if err != nil {
		return manifestRun{}, err
	}
	for i := uint32(0); i < count; i++ {
		b, err := dir.read(ctx, blockName(prefix, i), format.MaxManifestBytes)
		if err != nil {
			return manifestRun{}, err
		}
		if err := v.Add(b); err != nil {
			return manifestRun{}, err
		}
	}
	if err := v.Finish(root); err != nil {
		return manifestRun{}, err
	}
	return manifestRun{prefix: prefix, blocks: count, items: items, root: root}, nil
}

func readSnapshotItem(ctx context.Context, dir *directory, key []byte, e format.ManifestEntry, ep format.Endpoint) ([]byte, credential.Secret, error) {
	name, err := format.ItemFilename(e.ItemID)
	if err != nil {
		return nil, credential.Secret{}, err
	}
	b, err := dir.read(ctx, name, format.MaxItemBytes)
	if err != nil {
		return nil, credential.Secret{}, err
	}
	if uint32(len(b)) != e.FileSize || sha256.Sum256(b) != e.Hash {
		return nil, credential.Secret{}, ErrConflict
	}
	i := format.ItemIdentity{VaultID: ep.VaultID, Generation: ep.Generation, Ref: credential.Ref{StoreID: ep.StoreID, ItemID: e.ItemID}}
	secret, err := format.OpenItem(b, key, i)
	return b, secret, err
}

func countItems(ctx context.Context, dir *directory, want uint64) error {
	var count uint64
	err := dir.each(ctx, func(name string) error {
		if strings.HasPrefix(name, ".tmp-") {
			return ErrMaintenanceRequired
		}
		count++
		if count > want {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return err
	}
	if count != want {
		return ErrConflict
	}
	return nil
}
