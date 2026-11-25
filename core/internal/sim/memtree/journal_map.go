package memtree

import (
	"cmp"
	"fmt"
	"maps"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
)

type journalBucket struct {
	records []fsm.TransferJournalRecord
	corrupt bool
	cause   error
}

// JournalMap 封装按 (TransferID, Generation) 分代存储的纯内存 WAL 引擎，
// 支持确定性 (Generation, Seq) 排序加载、单代损坏隔离快照与按代清理（ADR-016）。
type JournalMap struct {
	byID map[security.OperationID]map[uint64]*journalBucket
}

// NewJournalMap 创建空白双代传输日志映射。
func NewJournalMap() *JournalMap {
	return &JournalMap{byID: make(map[security.OperationID]map[uint64]*journalBucket)}
}

// AppendLocked 按 (TransferID, Generation) 追加单条有效记录。
func (m *JournalMap) AppendLocked(rec fsm.TransferJournalRecord) {
	gens := m.byID[rec.TransferID()]
	if gens == nil {
		gens = make(map[uint64]*journalBucket)
		m.byID[rec.TransferID()] = gens
	}
	b := gens[rec.Generation()]
	if b == nil {
		b = &journalBucket{}
		gens[rec.Generation()] = b
	}
	b.records = append(b.records, rec)
}

// CorruptGenerationLocked 将指定 (transferID, generation) 标记为损坏态以支持单侧损坏隔离测试。
func (m *JournalMap) CorruptGenerationLocked(id security.OperationID, generation uint64, cause error) {
	if !id.IsValid() || generation == 0 {
		return
	}
	if cause == nil {
		cause = ports.ErrCorruptData
	}
	gens := m.byID[id]
	if gens == nil {
		gens = make(map[uint64]*journalBucket)
		m.byID[id] = gens
	}
	b := gens[generation]
	if b == nil {
		b = &journalBucket{}
		gens[generation] = b
	}
	b.corrupt, b.cause = true, cause
}

// LoadLocked 按 (Generation 升序, Seq 升序) 合并返回全部记录；任一世代损坏时返回 ErrCorruptData。
func (m *JournalMap) LoadLocked(id security.OperationID) ([]fsm.TransferJournalRecord, error) {
	gens, ok := m.byID[id]
	if !ok || len(gens) == 0 {
		return nil, ports.ErrNotFound
	}
	genKeys := sortedGenKeys(gens)
	var out []fsm.TransferJournalRecord
	for _, g := range genKeys {
		b := gens[g]
		if b.corrupt {
			return nil, fmt.Errorf("%w: generation %d: %w", ports.ErrCorruptData, g, b.cause)
		}
		out = append(out, sortedSeqClone(b.records)...)
	}
	return out, nil
}

// LoadGenerationsLocked 按 Generation 升序返回逐代隔离快照（单侧损坏不影响其他健康世代读取）。
func (m *JournalMap) LoadGenerationsLocked(id security.OperationID) ([]ports.JournalGenerationSnapshot, error) {
	gens, ok := m.byID[id]
	if !ok || len(gens) == 0 {
		return nil, ports.ErrNotFound
	}
	genKeys := sortedGenKeys(gens)
	out := make([]ports.JournalGenerationSnapshot, 0, len(genKeys))
	for _, g := range genKeys {
		b := gens[g]
		var snap ports.JournalGenerationSnapshot
		var err error
		if b.corrupt {
			snap, err = ports.NewCorruptJournalGenerationSnapshot(g, b.cause, sortedSeqClone(b.records)...)
		} else {
			snap, err = ports.NewJournalGenerationSnapshot(g, sortedSeqClone(b.records))
		}
		if err != nil {
			return nil, err
		}
		out = append(out, snap)
	}
	return out, nil
}

// PruneGenerationLocked 移除指定 (transferID, generation)；若该传输无剩余世代则一并移出活跃集。
func (m *JournalMap) PruneGenerationLocked(id security.OperationID, generation uint64) error {
	gens, ok := m.byID[id]
	if !ok {
		return ports.ErrNotFound
	}
	if _, exists := gens[generation]; !exists {
		return ports.ErrNotFound
	}
	delete(gens, generation)
	if len(gens) == 0 {
		delete(m.byID, id)
	}
	return nil
}

// ListActiveLocked 返回按字典序排序的全部活跃传输 ID。
func (m *JournalMap) ListActiveLocked() []security.OperationID {
	ids := slices.Collect(maps.Keys(m.byID))
	slices.SortFunc(ids, security.OperationID.Compare)
	return ids
}

// DeleteLocked 删除指定传输的全部世代日志；不存在返回 ports.ErrNotFound。
func (m *JournalMap) DeleteLocked(id security.OperationID) error {
	if _, ok := m.byID[id]; !ok {
		return ports.ErrNotFound
	}
	delete(m.byID, id)
	return nil
}

func sortedGenKeys(gens map[uint64]*journalBucket) []uint64 {
	keys := slices.Collect(maps.Keys(gens))
	slices.Sort(keys)
	return keys
}

func sortedSeqClone(recs []fsm.TransferJournalRecord) []fsm.TransferJournalRecord {
	cloned := slices.Clone(recs)
	slices.SortStableFunc(cloned, func(a, b fsm.TransferJournalRecord) int { return cmp.Compare(a.Seq(), b.Seq()) })
	return cloned
}
