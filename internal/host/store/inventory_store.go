package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

// YAMLInventoryStore 实现 ports.InventoryStore，提供 YAML vNext（version: 2）乐观并发 CAS 持久化：
//   - 所有读写与原子替换严格通过 ports.ScopedRootFS + core/osfs 旁路锁（<config>.lock）协调，
//     绝不对数据文件本身加锁后再执行 Root.Rename（消除 Windows 共享冲突）；
//   - Revision 融合单调修订序号与配置正文 SHA-256 摘要，既能检测并发 CAS 竞争，
//     也能识别磁盘外手工编辑引发的漂移；
//   - 替换失败时在持旁路独占锁态下复核磁盘现状，精确区分 NotApplied / AppliedNotDurable / OutcomeUnknown（INV-F3）。
//
//xops:opaque
//xops:failclosed
type YAMLInventoryStore struct {
	fs         ports.ScopedRootFS
	rootDir    pathalg.LocalDir
	configDest pathalg.LocalRootedDest
	limits     ports.ReadLimits
	valid      bool
}

// NewYAMLInventoryStore 校验沙箱端口、根目录、配置文件相对路径与字节读取上限后构造 YAMLInventoryStore。
func NewYAMLInventoryStore(spec InventoryStoreSpec) (*YAMLInventoryStore, error) {
	if spec.ScopedFS == nil || !spec.RootDir.IsValid() {
		return nil, fmt.Errorf("%w: ScopedFS 或 RootDir 无效", ports.ErrInvalidArgument)
	}
	cfgDest, err := resolveRootedPath(spec.ConfigFile, defaultConfigFileName, "ConfigFile")
	if err != nil {
		return nil, err
	}
	maxBytes, err := normalizeBoundedLimit(spec.MaxFileBytes, defaultMaxConfigBytes, maxAllowedConfigBytes, "MaxFileBytes")
	if err != nil {
		return nil, err
	}
	limits, err := ports.NewReadLimits(maxBytes)
	if err != nil {
		return nil, err
	}
	return &YAMLInventoryStore{
		fs:         spec.ScopedFS,
		rootDir:    spec.RootDir,
		configDest: cfgDest,
		limits:     limits,
		valid:      true,
	}, nil
}

// Load 在旁路共享锁保护下（若目录与父目录存在）加载当前 YAML vNext 配置快照与 CAS Revision；
// 若根目录或配置文件尚未创建，则安全返回空资产图与初始空 Revision（零副作用、不创建文件）。
func (s *YAMLInventoryStore) Load(ctx context.Context) (ports.InventorySnapshot, error) {
	if err := checkCtxReady(ctx, s != nil && s.valid, "YAMLInventoryStore"); err != nil {
		return zeroVal[ports.InventorySnapshot](), err
	}
	var snap ports.InventorySnapshot
	err := s.fs.WithRoot(s.rootDir, func(root ports.RootHandle) error {
		var lErr error
		snap, lErr = s.loadInRoot(ctx, root)
		return lErr
	})
	if errors.Is(err, ports.ErrNotFound) {
		return emptyInventorySnapshot()
	}
	return snap, err
}

// CommitCAS 在旁路独占锁 <config>.lock 下比对期望 Revision，保留现有文档的 vault/policy 顶层段，
// 递增修订号并以原子临时文件替换落盘；若落盘出现异常则精确返回 INV-F3 DurabilityOutcome。
func (s *YAMLInventoryStore) CommitCAS(ctx context.Context, expected ports.Revision, next inventory.Graph) (ports.DurabilityOutcome, error) {
	if err := checkCtxReady(ctx, s != nil && s.valid, "YAMLInventoryStore"); err != nil {
		return zeroVal[ports.DurabilityOutcome](), err
	}
	if !expected.IsValid() {
		return zeroVal[ports.DurabilityOutcome](), fmt.Errorf("%w: expected Revision 无效", ports.ErrInvalidRevision)
	}
	if !next.IsValid() {
		return zeroVal[ports.DurabilityOutcome](), fmt.Errorf("%w: %w", ports.ErrInvalidArgument, inventory.ErrInvalidGraph)
	}
	if err := s.fs.EnsureRoot(s.rootDir, storeDirPerm); err != nil {
		return zeroVal[ports.DurabilityOutcome](), err
	}
	var outcome ports.DurabilityOutcome
	err := s.fs.WithRoot(s.rootDir, func(root ports.RootHandle) error {
		if parent, hasParent := s.configDest.Parent(); hasParent {
			if mErr := root.MkdirAll(parent, storeDirPerm); mErr != nil {
				return mErr
			}
		}
		return osfs.WithSidecarLock(ctx, root, s.configDest, ports.LockExclusive, storeFilePerm, func(ports.LockedFile) error {
			var cErr error
			outcome, cErr = s.commitLocked(root, expected, next)
			return cErr
		})
	})
	return outcome, err
}

type loadedConfigState struct {
	rev    ports.Revision
	doc    ConfigDocument
	graph  inventory.Graph
	raw    []byte
	exists bool
}

func (s *YAMLInventoryStore) loadInRoot(ctx context.Context, root ports.RootHandle) (ports.InventorySnapshot, error) {
	ancestorsOK, err := checkLstatAncestors(root, s.configDest)
	if err != nil {
		return zeroVal[ports.InventorySnapshot](), err
	}
	if !ancestorsOK {
		return emptyInventorySnapshot()
	}
	exists, err := checkLstatRegular(root, s.configDest)
	if err != nil {
		return zeroVal[ports.InventorySnapshot](), err
	}
	if !exists {
		return emptyInventorySnapshot()
	}
	var snap ports.InventorySnapshot
	err = osfs.WithSidecarLock(ctx, root, s.configDest, ports.LockShared, storeFilePerm, func(ports.LockedFile) error {
		st, rErr := s.readCurrentLocked(root)
		if rErr != nil {
			return rErr
		}
		var sErr error
		snap, sErr = ports.NewInventorySnapshot(st.rev, st.graph)
		return sErr
	})
	return snap, err
}

func (s *YAMLInventoryStore) commitLocked(root ports.RootHandle, expected ports.Revision, next inventory.Graph) (ports.DurabilityOutcome, error) {
	st, err := s.readCurrentLocked(root)
	if err != nil {
		return zeroVal[ports.DurabilityOutcome](), err
	}
	if !st.rev.Equal(expected) {
		return zeroVal[ports.DurabilityOutcome](), ports.ErrRevisionConflict
	}
	if st.doc.Revision == math.MaxUint64 {
		return zeroVal[ports.DurabilityOutcome](), fmt.Errorf("%w: 配置修订号已达 uint64 上限", ports.ErrInvalidRevision)
	}
	nextInvDTO, err := EncodeInventoryGraphDTO(next)
	if err != nil {
		return zeroVal[ports.DurabilityOutcome](), err
	}
	nextDoc := ConfigDocument{
		Version:   SchemaVersionV2,
		Revision:  st.doc.Revision + 1,
		Vault:     st.doc.Vault,
		Policy:    st.doc.Policy,
		Inventory: nextInvDTO,
	}
	encoded, err := EncodeConfigDocumentYAML(nextDoc)
	if err != nil {
		return zeroVal[ports.DurabilityOutcome](), err
	}
	nextRev, err := computeRevision(nextDoc.Revision, encoded)
	if err != nil {
		return zeroVal[ports.DurabilityOutcome](), err
	}
	replaceErr := root.AtomicReplace(s.configDest, storeFilePerm, func(w io.Writer) error {
		return writeAll(w, encoded)
	})
	if replaceErr == nil {
		return ports.NewDurabilityCommitted(nextRev)
	}
	return s.classifyReplaceFailure(root, st.raw, st.exists, encoded, nextRev, replaceErr)
}

func (s *YAMLInventoryStore) classifyReplaceFailure(
	root ports.RootHandle, prevRaw []byte, prevExists bool,
	nextRaw []byte, nextRev ports.Revision, cause error,
) (ports.DurabilityOutcome, error) {
	detail := sanitizeDurabilityDetail("atomic replace failed", cause)
	afterRaw, readErr := root.ReadAllBounded(s.configDest, s.limits)
	if readErr == nil && bytes.Equal(afterRaw, nextRaw) {
		// 磁盘正文已原子切换为 nextRaw，但后续目录 fsync 等持久化步骤失败 -> Applied && !Durable（禁重试）。
		out, oErr := ports.NewDurabilityAppliedNotDurable(algebraic.Some(nextRev), detail)
		return out, errors.Join(cause, oErr)
	}
	if (!prevExists && errors.Is(readErr, ports.ErrNotFound)) || (prevExists && readErr == nil && bytes.Equal(afterRaw, prevRaw)) {
		out, oErr := ports.NewDurabilityNotApplied(detail)
		return out, errors.Join(cause, oErr)
	}
	out, oErr := ports.NewDurabilityOutcomeUnknown(detail)
	return out, errors.Join(cause, oErr)
}

func (s *YAMLInventoryStore) readCurrentLocked(root ports.RootHandle) (loadedConfigState, error) {
	raw, err := root.ReadAllBounded(s.configDest, s.limits)
	if errors.Is(err, ports.ErrNotFound) {
		rev, rErr := initialEmptyRevision()
		return loadedConfigState{rev: rev, doc: ConfigDocument{Version: SchemaVersionV2}, graph: inventory.EmptyGraph()}, rErr
	}
	if err != nil {
		return loadedConfigState{}, err
	}
	doc, graph, err := DecodeConfigDocumentYAML(raw)
	if err != nil {
		return loadedConfigState{}, err
	}
	rev, err := computeRevision(doc.Revision, raw)
	if err != nil {
		return loadedConfigState{}, err
	}
	return loadedConfigState{rev: rev, doc: doc, graph: graph, raw: raw, exists: true}, nil
}

func initialEmptyRevision() (ports.Revision, error) {
	return ports.ParseRevision(emptyRevisionTokenPrefix)
}

func emptyInventorySnapshot() (ports.InventorySnapshot, error) {
	rev, err := initialEmptyRevision()
	if err != nil {
		return zeroVal[ports.InventorySnapshot](), err
	}
	return ports.NewInventorySnapshot(rev, inventory.EmptyGraph())
}

func computeRevision(seq uint64, raw []byte) (ports.Revision, error) {
	sum := sha256.Sum256(raw)
	tok := fmt.Sprintf("v2-%d-%s", seq, hex.EncodeToString(sum[:16]))
	return ports.ParseRevision(tok)
}
