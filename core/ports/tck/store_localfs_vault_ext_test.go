package tck_test

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// 本文件通过纯内存参考桩适配器自测 Store、LocalFS、Vault、KeySigner 与 HostTrust 全部 TCK 契约套件。

func zero[T any]() (z T) { return z }

type memInventoryStore struct {
	mu    sync.Mutex
	ver   int
	rev   ports.Revision
	graph inventory.Graph
}

func newMemInventoryStore(t *testing.T) ports.InventoryStore {
	t.Helper()
	rev, err := ports.ParseRevision("rev-0")
	if err != nil {
		t.Fatal(err)
	}
	return &memInventoryStore{ver: 0, rev: rev, graph: tck.MustGraph(t, "init")}
}

func (s *memInventoryStore) Load(ctx context.Context) (ports.InventorySnapshot, error) {
	if ctx == nil {
		return zero[ports.InventorySnapshot](), ports.ErrNilContext
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return ports.NewInventorySnapshot(s.rev, s.graph)
}

func (s *memInventoryStore) CommitCAS(ctx context.Context, expected ports.Revision, next inventory.Graph) (ports.DurabilityOutcome, error) {
	if ctx == nil {
		return zero[ports.DurabilityOutcome](), ports.ErrNilContext
	}
	if !expected.IsValid() || !next.IsValid() {
		return zero[ports.DurabilityOutcome](), ports.ErrInvalidArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.rev.Equal(expected) {
		return zero[ports.DurabilityOutcome](), ports.ErrRevisionConflict
	}
	s.ver++
	nextRev, err := ports.ParseRevision(fmt.Sprintf("rev-%d", s.ver))
	if err != nil {
		return zero[ports.DurabilityOutcome](), err
	}
	s.rev, s.graph = nextRev, next
	return ports.NewDurabilityCommitted(nextRev)
}

type memGenEntry struct {
	recs    []fsm.TransferJournalRecord
	corrupt error
}

type memJournalStore struct {
	mu   sync.Mutex
	data map[security.OperationID]map[uint64]*memGenEntry
}

func (s *memJournalStore) corruptGen(id security.OperationID, gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gens := s.data[id]; gens != nil && gens[gen] != nil {
		gens[gen].corrupt = ports.ErrCorruptData
	}
}

func (s *memJournalStore) Append(ctx context.Context, rec fsm.TransferJournalRecord) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !rec.IsValid() {
		return ports.ErrInvalidArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	gens := s.data[rec.TransferID()]
	if gens == nil {
		gens = make(map[uint64]*memGenEntry)
		s.data[rec.TransferID()] = gens
	}
	e := gens[rec.Generation()]
	if e == nil {
		e = &memGenEntry{}
		gens[rec.Generation()] = e
	}
	e.recs = append(e.recs, rec)
	return nil
}

func (s *memJournalStore) Load(ctx context.Context, id security.OperationID) ([]fsm.TransferJournalRecord, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	if !id.IsValid() {
		return nil, ports.ErrInvalidArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	gens, ok := s.data[id]
	if !ok || len(gens) == 0 {
		return nil, ports.ErrNotFound
	}
	keys := slices.Sorted(maps.Keys(gens))
	var out []fsm.TransferJournalRecord
	for _, g := range keys {
		e := gens[g]
		if e.corrupt != nil {
			return nil, fmt.Errorf("%w: %w", ports.ErrCorruptData, e.corrupt)
		}
		recs := slices.Clone(e.recs)
		slices.SortFunc(recs, func(a, b fsm.TransferJournalRecord) int { return cmp.Compare(a.Seq(), b.Seq()) })
		out = append(out, recs...)
	}
	return out, nil
}

func (s *memJournalStore) LoadGenerations(ctx context.Context, id security.OperationID) ([]ports.JournalGenerationSnapshot, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	if !id.IsValid() {
		return nil, ports.ErrInvalidArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	gens, ok := s.data[id]
	if !ok || len(gens) == 0 {
		return nil, ports.ErrNotFound
	}
	keys := slices.Sorted(maps.Keys(gens))
	out := make([]ports.JournalGenerationSnapshot, 0, len(keys))
	for _, g := range keys {
		e := gens[g]
		recs := slices.Clone(e.recs)
		slices.SortFunc(recs, func(a, b fsm.TransferJournalRecord) int { return cmp.Compare(a.Seq(), b.Seq()) })
		if e.corrupt != nil {
			snap, err := ports.NewCorruptJournalGenerationSnapshot(g, e.corrupt, recs...)
			if err != nil {
				return nil, err
			}
			out = append(out, snap)
			continue
		}
		snap, err := ports.NewJournalGenerationSnapshot(g, recs)
		if err != nil {
			return nil, err
		}
		out = append(out, snap)
	}
	return out, nil
}

func (s *memJournalStore) PruneGeneration(ctx context.Context, id security.OperationID, gen uint64) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !id.IsValid() || gen == 0 {
		return ports.ErrInvalidArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	gens, ok := s.data[id]
	if !ok || gens[gen] == nil {
		return ports.ErrNotFound
	}
	delete(gens, gen)
	if len(gens) == 0 {
		delete(s.data, id)
	}
	return nil
}

func (s *memJournalStore) ListActive(ctx context.Context) ([]security.OperationID, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := slices.Collect(maps.Keys(s.data))
	slices.SortFunc(ids, security.OperationID.Compare)
	return ids, nil
}

func (s *memJournalStore) Delete(ctx context.Context, id security.OperationID) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !id.IsValid() {
		return ports.ErrInvalidArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[id]; !ok {
		return ports.ErrNotFound
	}
	delete(s.data, id)
	return nil
}

type memFormatImporter struct{}

func (memFormatImporter) Format() string { return "csv" }
func (memFormatImporter) Import(ctx context.Context, _ string, r io.Reader) (inventory.ImportBundle, error) {
	if ctx == nil {
		return zero[inventory.ImportBundle](), ports.ErrNilContext
	}
	if r == nil {
		return zero[inventory.ImportBundle](), ports.ErrInvalidArgument
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return zero[inventory.ImportBundle](), err
	}
	if !bytes.HasPrefix(raw, []byte("host,")) {
		return zero[inventory.ImportBundle](), ports.ErrCorruptData
	}
	return inventory.NewImportBundle(inventory.ImportBundleSpec{SourceFormat: "csv"})
}

type memOpenSSHSource struct {
	hosts []ports.OpenSSHVirtualHost
}

func (s memOpenSSHSource) ListVirtualHosts(ctx context.Context) ([]ports.OpenSSHVirtualHost, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	return slices.Clone(s.hosts), nil
}

func (s memOpenSSHSource) ResolveTier4(ctx context.Context, target option.OriginalHostSpec, endpoint algebraic.Option[netaddr.Endpoint]) (option.OptionLayer, error) {
	if ctx == nil {
		return option.UnsetOptionLayer(), ports.ErrNilContext
	}
	if ep, ok := endpoint.Get(); !target.IsValid() || (ok && !ep.IsValid()) {
		return option.UnsetOptionLayer(), ports.ErrInvalidArgument
	}
	return option.UnsetOptionLayer(), nil
}

type memLockState struct {
	shared    int
	exclusive bool
}

// memScopedRootFS 是纯内存 ScopedRootFS 参考桩，模拟常规文件、软链校验、有界读取、原子替换与共享/独占锁。
type memScopedRootFS struct {
	mu       sync.Mutex
	files    map[string][]byte
	modTimes map[string]time.Time
	symlinks map[string]string
	dirs     map[string]bool
	locks    map[string]memLockState
}

func newMemScopedRootFS() *memScopedRootFS {
	return &memScopedRootFS{
		files:    make(map[string][]byte),
		modTimes: make(map[string]time.Time),
		symlinks: make(map[string]string),
		dirs:     map[string]bool{".": true},
		locks:    make(map[string]memLockState),
	}
}

func (m *memScopedRootFS) EnsureRoot(dir pathalg.LocalDir, perm fs.FileMode) error {
	if !dir.IsValid() || perm == 0 || perm != perm.Perm() {
		return ports.ErrInvalidArgument
	}
	return nil
}

func (m *memScopedRootFS) WithRoot(dir pathalg.LocalDir, fn func(root ports.RootHandle) error) error {
	if fn == nil {
		return ports.ErrNilCallback
	}
	if !dir.IsValid() {
		return ports.ErrInvalidArgument
	}
	return fn(&memRootHandle{fs: m})
}

type memRootHandle struct{ fs *memScopedRootFS }

func (h *memRootHandle) ReadAllBounded(rel pathalg.LocalRootedDest, limits ports.ReadLimits) ([]byte, error) {
	if !rel.IsValid() || !limits.IsValid() {
		return nil, ports.ErrInvalidArgument
	}
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	data, ok := h.fs.files[rel.String()]
	if !ok {
		return nil, ports.ErrNotFound
	}
	if int64(len(data)) > limits.MaxBytes() {
		return nil, ports.ErrLimitExceeded
	}
	return bytes.Clone(data), nil
}

func (h *memRootHandle) WithReadRegular(rel pathalg.LocalRootedDest, limits ports.ReadLimits, fn func(r ports.BoundedReadHandle, size int64) error) error {
	if fn == nil {
		return ports.ErrNilCallback
	}
	data, err := h.ReadAllBounded(rel, limits)
	if err != nil {
		return err
	}
	return fn(bytes.NewReader(data), int64(len(data)))
}

func (h *memRootHandle) WriteChunk(rel pathalg.LocalRootedDest, offset int64, r io.Reader, length int64, perm fs.FileMode) (int64, error) {
	if !rel.IsValid() || offset < 0 || length < 0 || r == nil || perm == 0 || perm != perm.Perm() {
		return 0, ports.ErrInvalidArgument
	}
	buf := make([]byte, length)
	n, rErr := io.ReadFull(r, buf)
	if errors.Is(rErr, io.EOF) && length > 0 {
		rErr = io.ErrUnexpectedEOF
	}
	if rErr != nil && !errors.Is(rErr, io.ErrUnexpectedEOF) {
		return 0, rErr
	}
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	key := rel.String()
	data := h.fs.files[key]
	end := int(offset) + n
	if len(data) < end {
		grown := make([]byte, end)
		copy(grown, data)
		data = grown
	}
	copy(data[offset:], buf[:n])
	h.fs.files[key] = data
	return int64(n), rErr
}

func (h *memRootHandle) Rename(oldRel, newRel pathalg.LocalRootedDest) error {
	if !oldRel.IsValid() || !newRel.IsValid() {
		return ports.ErrInvalidArgument
	}
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	oldKey, newKey := oldRel.String(), newRel.String()
	if _, isSym := h.fs.symlinks[oldKey]; isSym {
		return ports.ErrSymlinkRejected
	}
	if _, isSym := h.fs.symlinks[newKey]; isSym {
		return ports.ErrSymlinkRejected
	}
	data, ok := h.fs.files[oldKey]
	if !ok {
		return ports.ErrNotFound
	}
	delete(h.fs.files, oldKey)
	h.fs.files[newKey] = data
	return nil
}

func (h *memRootHandle) AtomicReplace(rel pathalg.LocalRootedDest, _ fs.FileMode, fn func(w io.Writer) error) error {
	if fn == nil {
		return ports.ErrNilCallback
	}
	if !rel.IsValid() {
		return ports.ErrInvalidArgument
	}
	var buf bytes.Buffer
	if err := fn(&buf); err != nil {
		return err
	}
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	h.fs.files[rel.String()] = bytes.Clone(buf.Bytes())
	return nil
}

func (h *memRootHandle) CreateExclusive(rel pathalg.LocalRootedDest, _ fs.FileMode, fn func(w io.Writer) error) error {
	if fn == nil {
		return ports.ErrNilCallback
	}
	if !rel.IsValid() {
		return ports.ErrInvalidArgument
	}
	var buf bytes.Buffer
	if err := fn(&buf); err != nil {
		return err
	}
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	if _, exists := h.fs.files[rel.String()]; exists {
		return ports.ErrAlreadyExists
	}
	h.fs.files[rel.String()] = bytes.Clone(buf.Bytes())
	return nil
}

func (h *memRootHandle) WithLockedFile(ctx context.Context, rel pathalg.LocalRootedDest, mode ports.LockMode, create bool, perm fs.FileMode, fn func(lf ports.LockedFile) error) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	acq, err := h.TryWithLockedFile(rel, mode, create, perm, fn)
	if err != nil {
		return err
	}
	if !acq {
		return ports.ErrLockBusy
	}
	return nil
}

func (h *memRootHandle) TryWithLockedFile(rel pathalg.LocalRootedDest, mode ports.LockMode, create bool, _ fs.FileMode, fn func(lf ports.LockedFile) error) (bool, error) {
	if fn == nil {
		return false, ports.ErrNilCallback
	}
	if !rel.IsValid() || !mode.IsValid() {
		return false, ports.ErrInvalidArgument
	}
	key := rel.String()
	acq, err := h.fs.tryAcquireLock(key, mode, create)
	if err != nil || !acq {
		return acq, err
	}
	defer h.fs.releaseLock(key, mode)
	return true, fn(&memLockedFile{fs: h.fs, key: key})
}

func (m *memScopedRootFS) tryAcquireLock(key string, mode ports.LockMode, create bool) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.locks[key]
	if st.exclusive || (mode == ports.LockExclusive && st.shared > 0) {
		return false, nil
	}
	if _, ok := m.files[key]; !ok {
		if !create {
			return false, ports.ErrNotFound
		}
		m.files[key] = nil
	}
	if mode == ports.LockExclusive {
		st.exclusive = true
	} else {
		st.shared++
	}
	m.locks[key] = st
	return true, nil
}

func (m *memScopedRootFS) releaseLock(key string, mode ports.LockMode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.locks[key]
	if mode == ports.LockExclusive {
		cur.exclusive = false
	} else if cur.shared > 0 {
		cur.shared--
	}
	if !cur.exclusive && cur.shared == 0 {
		delete(m.locks, key)
		return
	}
	m.locks[key] = cur
}

func (h *memRootHandle) AppendLine(rel pathalg.LocalRootedDest, _ fs.FileMode, line []byte) error {
	if !rel.IsValid() || bytes.ContainsAny(line, "\r\n") {
		return ports.ErrInvalidArgument
	}
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	h.fs.files[rel.String()] = append(append(h.fs.files[rel.String()], line...), '\n')
	return nil
}

func (h *memRootHandle) Stat(rel pathalg.LocalRootedDest) (ports.LocalFileInfo, error) {
	if !rel.IsValid() {
		return zero[ports.LocalFileInfo](), ports.ErrInvalidArgument
	}
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	key := rel.String()
	mt := h.fs.modTimes[key]
	if mt.IsZero() {
		mt = tck.BaseTime()
	}
	if data, ok := h.fs.files[key]; ok {
		return ports.NewLocalFileInfo(ports.LocalFileInfoSpec{
			Name: baseNameSlash(key), Size: int64(len(data)), Mode: 0o600, ModTime: mt,
		})
	}
	if h.fs.dirs[key] {
		return ports.NewLocalFileInfo(ports.LocalFileInfoSpec{
			Name: baseNameSlash(key), Size: 0, Mode: fs.ModeDir | 0o700, ModTime: mt,
		})
	}
	return zero[ports.LocalFileInfo](), ports.ErrNotFound
}

func (h *memRootHandle) Chtimes(rel pathalg.LocalRootedDest, atime, mtime time.Time) error {
	if !rel.IsValid() || !isValidMemRFC3339(atime) || !isValidMemRFC3339(mtime) {
		return ports.ErrInvalidArgument
	}
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	key := rel.String()
	if _, isSym := h.fs.symlinks[key]; isSym {
		return ports.ErrSymlinkRejected
	}
	if _, isFile := h.fs.files[key]; !isFile && !h.fs.dirs[key] {
		return ports.ErrNotFound
	}
	h.fs.modTimes[key] = mtime.UTC()
	return nil
}
func isValidMemRFC3339(t time.Time) bool {
	return !t.IsZero() && t.UTC().Year() >= 1 && t.UTC().Year() <= 9999
}

func (h *memRootHandle) Lstat(rel pathalg.LocalRootedDest) (ports.LocalFileInfo, error) {
	if !rel.IsValid() {
		return zero[ports.LocalFileInfo](), ports.ErrInvalidArgument
	}
	h.fs.mu.Lock()
	if target, ok := h.fs.symlinks[rel.String()]; ok {
		h.fs.mu.Unlock()
		return ports.NewLocalFileInfo(ports.LocalFileInfoSpec{
			Name: baseNameSlash(rel.String()), Size: int64(len(target)), Mode: fs.ModeSymlink | 0o777, ModTime: tck.BaseTime(),
		})
	}
	h.fs.mu.Unlock()
	return h.Stat(rel)
}

func (h *memRootHandle) ReadDir(dir algebraic.Option[pathalg.LocalRootedDest]) ([]ports.LocalDirEntry, error) {
	prefix := ""
	if d, ok := dir.Get(); ok {
		if !d.IsValid() {
			return nil, ports.ErrInvalidArgument
		}
		prefix = d.String() + "/"
	}
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	var out []ports.LocalDirEntry
	for k, data := range h.fs.files {
		if rest, ok := strings.CutPrefix(k, prefix); ok && rest != "" && !strings.Contains(rest, "/") {
			e, err := ports.NewLocalDirEntry(rest, 0o600, int64(len(data)))
			if err != nil {
				return nil, err
			}
			out = append(out, e)
		}
	}
	return out, nil
}

func (h *memRootHandle) MkdirAll(rel pathalg.LocalRootedDest, _ fs.FileMode) error {
	if !rel.IsValid() {
		return ports.ErrInvalidArgument
	}
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	h.fs.dirs[rel.String()] = true
	return nil
}

func (h *memRootHandle) CreateSymlink(link pathalg.LocalRootedDest, target string) error {
	if !link.IsValid() || !isContainedRelativeTarget(link.String(), target) {
		return ports.ErrInvalidArgument
	}
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	key := link.String()
	if _, exists := h.fs.files[key]; exists {
		return ports.ErrAlreadyExists
	}
	if _, exists := h.fs.symlinks[key]; exists {
		return ports.ErrAlreadyExists
	}
	h.fs.symlinks[key] = target
	return nil
}

func isContainedRelativeTarget(linkPath, target string) bool {
	if target == "" || strings.HasPrefix(target, "/") || strings.ContainsAny(target, "\\:") {
		return false
	}
	depth := strings.Count(linkPath, "/")
	for _, seg := range strings.Split(target, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			depth--
			if depth < 0 {
				return false
			}
		default:
			depth++
		}
	}
	return depth >= 0
}

func (h *memRootHandle) Remove(rel pathalg.LocalRootedDest) error {
	if !rel.IsValid() {
		return ports.ErrInvalidArgument
	}
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	key := rel.String()
	if _, ok := h.fs.files[key]; ok {
		delete(h.fs.files, key)
		return nil
	}
	if _, ok := h.fs.symlinks[key]; ok {
		delete(h.fs.symlinks, key)
		return nil
	}
	return ports.ErrNotFound
}

type memLockedFile struct {
	fs  *memScopedRootFS
	key string
	off int64
}

func (f *memLockedFile) Read(p []byte) (int, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	data := f.fs.files[f.key]
	if f.off >= int64(len(data)) {
		return 0, io.EOF
	}
	n := copy(p, data[f.off:])
	f.off += int64(n)
	return n, nil
}

func (f *memLockedFile) Write(p []byte) (int, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	data := f.fs.files[f.key]
	end := int(f.off) + len(p)
	if len(data) < end {
		grown := make([]byte, end)
		copy(grown, data)
		data = grown
	}
	copy(data[f.off:], p)
	f.fs.files[f.key] = data
	f.off += int64(len(p))
	return len(p), nil
}

func (f *memLockedFile) Seek(offset int64, whence int) (int64, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	var base int64
	switch whence {
	case io.SeekStart:
		base = 0
	case io.SeekCurrent:
		base = f.off
	case io.SeekEnd:
		base = int64(len(f.fs.files[f.key]))
	default:
		return 0, ports.ErrInvalidArgument
	}
	next := base + offset
	if next < 0 {
		return 0, ports.ErrInvalidArgument
	}
	f.off = next
	return next, nil
}

func (f *memLockedFile) Truncate(size int64) error {
	if size < 0 {
		return ports.ErrInvalidArgument
	}
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	cur := f.fs.files[f.key]
	if int64(len(cur)) > size {
		f.fs.files[f.key] = cur[:size]
	}
	return nil
}

func (f *memLockedFile) Sync() error { return nil }

func (f *memLockedFile) Stat() (ports.LocalFileInfo, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	return ports.NewLocalFileInfo(ports.LocalFileInfoSpec{
		Name: baseNameSlash(f.key), Size: int64(len(f.fs.files[f.key])), Mode: 0o600, ModTime: tck.BaseTime(),
	})
}

func baseNameSlash(p string) string {
	if idx := strings.LastIndexByte(p, '/'); idx >= 0 {
		return p[idx+1:]
	}
	return p
}

type memOperatorReadFS struct {
	regular pathalg.LocalSourcePath
	symlink pathalg.LocalSourcePath
	content []byte
}

func (m memOperatorReadFS) WithOperatorRead(ctx context.Context, src pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy, fn func(r ports.BoundedReadHandle, size int64) error) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	if !src.IsValid() || !policy.IsValid() {
		return ports.ErrInvalidArgument
	}
	if src.Equal(m.symlink) {
		if policy == pathalg.SymlinkReject {
			return ports.ErrSymlinkRejected
		}
	} else if !src.Equal(m.regular) {
		return ports.ErrNotFound
	}
	return fn(bytes.NewReader(m.content), int64(len(m.content)))
}

// memSecretVault 是仅供 TCK 自检使用的有限测试令牌桩实现（100% 零 box.Use 明文消费，
// 仅通过 secret.WithBytes + SecretBox.Equal 匹配 TCK 固定测试令牌；真实/仿真 Vault 位于白名单包内）。
type memSecretVault struct {
	mu     sync.Mutex
	locked bool
	items  map[secret.Ref]string
}

func (v *memSecretVault) WithSecret(ctx context.Context, ref secret.Ref, fn func(box *secret.SecretBox) error) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	if !ref.IsValid() {
		return ports.ErrInvalidArgument
	}
	v.mu.Lock()
	if v.locked {
		v.mu.Unlock()
		return ports.ErrVaultLocked
	}
	tok, ok := v.items[ref]
	v.mu.Unlock()
	if !ok {
		return ports.ErrSecretNotFound
	}
	return secret.WithBytes([]byte(tok), func(box *secret.SecretBox) error {
		return fn(box)
	})
}

func (v *memSecretVault) PutAndVerify(ctx context.Context, ref secret.Ref, box *secret.SecretBox) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !ref.IsValid() || !box.IsValid() {
		return ports.ErrInvalidArgument
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.locked {
		return ports.ErrVaultLocked
	}
	tok, err := matchTCKSecretToken(box)
	if err != nil {
		return err
	}
	v.items[ref] = tok
	return nil
}

func (v *memSecretVault) Delete(ctx context.Context, ref secret.Ref) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !ref.IsValid() {
		return ports.ErrInvalidArgument
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.locked {
		return ports.ErrVaultLocked
	}
	if _, ok := v.items[ref]; !ok {
		return ports.ErrSecretNotFound
	}
	delete(v.items, ref)
	return nil
}

func matchTCKSecretToken(box *secret.SecretBox) (string, error) {
	for _, cand := range []string{tck.TestSecretTokenA, tck.TestSecretTokenB} {
		var eq bool
		if err := secret.WithBytes([]byte(cand), func(c *secret.SecretBox) error {
			eq = box.Equal(c)
			return nil
		}); err != nil {
			return "", err
		}
		if eq {
			return cand, nil
		}
	}
	return "", ports.ErrSecretVerifyFailed
}

type memKeySigner struct{ key ports.PublicKeyInfo }

func (s memKeySigner) ListPublicKeys(ctx context.Context, auth inventory.AuthMethod) ([]ports.PublicKeyInfo, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	if auth == nil || !auth.IsValid() {
		return nil, ports.ErrInvalidArgument
	}
	return []ports.PublicKeyInfo{s.key}, nil
}

func (s memKeySigner) Sign(ctx context.Context, fp inventory.KeyFingerprint, algo string, data []byte) (ports.Signature, error) {
	if ctx == nil {
		return zero[ports.Signature](), ports.ErrNilContext
	}
	if !fp.IsValid() || algo == "" || len(data) == 0 {
		return zero[ports.Signature](), ports.ErrInvalidArgument
	}
	return ports.NewSignature(algo, []byte("sig-"+fp.String()))
}

func (s memKeySigner) InspectPrivateKeyFingerprint(ctx context.Context, kp inventory.KeyPathSpec, _ algebraic.Option[secret.Ref]) (inventory.KeyFingerprint, error) {
	if ctx == nil {
		return zero[inventory.KeyFingerprint](), ports.ErrNilContext
	}
	if !kp.IsValid() {
		return zero[inventory.KeyFingerprint](), ports.ErrInvalidArgument
	}
	return s.key.Fingerprint(), nil
}

type memHostTrust struct {
	mu      sync.Mutex
	records map[string]ports.PublicKeyInfo
}

func (h *memHostTrust) PreferredAlgorithms(ctx context.Context, ep netaddr.Endpoint, _ option.KnownHostsList) ([]string, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if pk, ok := h.records[ep.String()]; ok {
		return []string{pk.Algorithm()}, nil
	}
	return nil, nil
}

func (h *memHostTrust) VerifyHostKey(ctx context.Context, req ports.HostTrustRequest) (ports.HostTrustCheck, error) {
	if ctx == nil {
		return zero[ports.HostTrustCheck](), ports.ErrNilContext
	}
	if !req.IsValid() {
		return zero[ports.HostTrustCheck](), ports.ErrInvalidArgument
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	existing, ok := h.records[req.Endpoint().String()]
	if !ok {
		return ports.NewHostTrustCheck(ports.HostTrustCheckSpec{
			Status: ports.HostTrustUnknown, Endpoint: req.Endpoint(), Presented: req.Presented(),
		})
	}
	if existing.Fingerprint().Equal(req.Presented().Fingerprint()) {
		return ports.NewHostTrustCheck(ports.HostTrustCheckSpec{
			Status: ports.HostTrustTrusted, Endpoint: req.Endpoint(), Presented: req.Presented(),
		})
	}
	return ports.NewHostTrustCheck(ports.HostTrustCheckSpec{
		Status: ports.HostTrustMismatch, Endpoint: req.Endpoint(), Presented: req.Presented(),
		ExpectedFingerprints: []inventory.KeyFingerprint{existing.Fingerprint()}, Reason: "fingerprint mismatch",
	})
}

func (h *memHostTrust) RecordHostKey(ctx context.Context, ep netaddr.Endpoint, key ports.PublicKeyInfo, _ option.KnownHostsList) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !ep.IsValid() || !key.IsValid() {
		return ports.ErrInvalidArgument
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records[ep.String()] = key
	return nil
}

func TestTCKStoreAndOpenSSHSuites(t *testing.T) {
	tck.RunInventoryStoreSuite(t, newMemInventoryStore)
	tck.RunJournalStoreSuite(t, tck.JournalStoreFixture{
		NewStore: func(*testing.T) ports.JournalStore {
			return &memJournalStore{data: make(map[security.OperationID]map[uint64]*memGenEntry)}
		},
		CorruptGeneration: func(_ *testing.T, s ports.JournalStore, id security.OperationID, gen uint64) {
			s.(*memJournalStore).corruptGen(id, gen)
		},
	})
	tck.RunFormatImporterSuite(t, tck.FormatImporterFixture{
		NewImporter:  func(*testing.T) ports.FormatImporter { return memFormatImporter{} },
		ValidInput:   func() io.Reader { return strings.NewReader("host,198.51.100.1,22\n") },
		InvalidInput: func() io.Reader { return strings.NewReader("bad-header\n") },
	})

	vh, err := ports.NewOpenSSHVirtualHost(ports.OpenSSHVirtualHostSpec{
		Alias: "bastion", Endpoint: algebraic.Some(tck.MustEndpoint(t, "198.51.100.1", 22)),
	})
	if err != nil {
		t.Fatal(err)
	}
	orig, err := option.ParseOriginalHost("bastion")
	if err != nil {
		t.Fatal(err)
	}
	tck.RunOpenSSHConfigSourceSuite(t, tck.OpenSSHConfigFixture{
		NewSource: func(*testing.T) ports.OpenSSHConfigSource {
			return memOpenSSHSource{hosts: []ports.OpenSSHVirtualHost{vh}}
		},
		TargetHost: orig,
		Endpoint:   tck.MustEndpoint(t, "198.51.100.1", 22),
	})
}

func TestTCKLocalFSSuites(t *testing.T) {
	rootDir, err := pathalg.ParseLocalDir("/tmp/xops-tck-sandbox")
	if err != nil {
		t.Fatal(err)
	}
	tck.RunScopedRootFSSuite(t, tck.ScopedRootFSFixture{
		NewRoot: func(*testing.T) (ports.ScopedRootFS, pathalg.LocalDir) {
			return newMemScopedRootFS(), rootDir
		},
		CheckSymlink: true,
	})

	regPath, err := pathalg.ParseLocalSourcePath("/etc/ssh/tck_config")
	if err != nil {
		t.Fatal(err)
	}
	symPath, err := pathalg.ParseLocalSourcePath("/etc/ssh/tck_config.link")
	if err != nil {
		t.Fatal(err)
	}
	missPath, err := pathalg.ParseLocalSourcePath("/etc/ssh/tck_missing")
	if err != nil {
		t.Fatal(err)
	}
	tck.RunOperatorReadFSSuite(t, tck.OperatorReadFSFixture{
		NewReader: func(*testing.T) ports.OperatorReadFS {
			return memOperatorReadFS{regular: regPath, symlink: symPath, content: []byte("Host bastion\n")}
		},
		RegularFile:     regPath,
		ExpectedContent: []byte("Host bastion\n"),
		MissingFile:     missPath,
		SymlinkFile:     symPath,
	})
}

func TestTCKVaultSignerAndTrustSuites(t *testing.T) {
	tck.RunSecretVaultSuite(t, tck.SecretVaultFixture{
		NewVault: func(*testing.T) ports.SecretVault {
			return &memSecretVault{items: make(map[secret.Ref]string)}
		},
		NewLockedVault: func(*testing.T) ports.SecretVault {
			return &memSecretVault{locked: true, items: make(map[secret.Ref]string)}
		},
	})

	auth, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	if err != nil {
		t.Fatal(err)
	}
	kp, err := inventory.ParseKeyPathSpec("~/.ssh/id_ed25519")
	if err != nil {
		t.Fatal(err)
	}
	tck.RunKeySignerSuite(t, tck.KeySignerFixture{
		NewSigner: func(t *testing.T) ports.KeySignerPort {
			return memKeySigner{key: tck.MustPublicKey(t, tck.TestFingerprintA, 0x07)}
		},
		Auth:    auth,
		KeyPath: algebraic.Some(kp),
	})

	tck.RunHostTrustSuite(t, tck.HostTrustFixture{
		NewTrust: func(*testing.T) ports.HostTrustPort {
			return &memHostTrust{records: make(map[string]ports.PublicKeyInfo)}
		},
	})

	// 消除未用错误引用并验证错误哨兵类型完整。
	if errors.Is(ports.ErrSecretNotFound, ports.ErrVaultLocked) {
		t.Fatal("哨兵错误不得相等")
	}
}
