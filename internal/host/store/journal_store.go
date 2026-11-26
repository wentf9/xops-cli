package store

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"maps"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	walKeyPrefix       = "j_"
	walFileSuffix      = ".wal"
	walGenMarker       = ".g"
	walLockExt         = ".lock"
	walLockStripeCount = 64
	walMinFrameLen     = len(walFrameVersionPrefix) + walCRC32HexLen + 1
)

// WALJournalStore 实现 ports.JournalStore，提供面向 10 GiB 可恢复分片传输的双代（active/staging）
// CRC32 校验 WAL 持久化存储：
//   - 按 (TransferID, Generation) 物理分文件存储（j_<base32(id)>.g<gen>.wal），
//     单侧损坏严格隔离于对应世代，绝不毒化同传输的其他健康世代；
//   - 每条记录以 "v1:<8位小写CRC32-IEEE>:<jsonv2 Deterministic(true)>\n" 帧写入，
//     读取时同时校验帧格式、CRC32、TransferJournalRecord SHA-256 自校验摘要与 (TransferID, Generation) 归属；
//   - 某世代遇 CRC/截断/格式损坏时，LoadGenerations 在 PartialRecords() 中精确保留损坏点前全部有效前缀，
//     供上层 TransferService 识别 CommitStarted / UncertainCommit 并禁止回退低世代；
//   - 并发协调采用固定数量、永不删除的分片条带旁路锁 journals/.stripe_<00..3f>.lock，
//     彻底根除 POSIX flock+unlink 竞态且对只读未命中绝不遗留孤儿锁文件；绝不对 .wal 数据文件本身加锁。
//
//xops:opaque
//xops:failclosed
type WALJournalStore struct {
	fs         ports.ScopedRootFS
	rootDir    pathalg.LocalDir
	journalDir pathalg.LocalRootedDest
	limits     ports.ReadLimits
	valid      bool
}

// NewWALJournalStore 校验沙箱端口、根目录、日志子目录与单文件上限后构造 WALJournalStore。
func NewWALJournalStore(spec JournalStoreSpec) (*WALJournalStore, error) {
	if spec.ScopedFS == nil || !spec.RootDir.IsValid() {
		return nil, fmt.Errorf("%w: ScopedFS 或 RootDir 无效", ports.ErrInvalidArgument)
	}
	dirDest, err := resolveRootedPath(spec.JournalDir, defaultJournalDirName, "JournalDir")
	if err != nil {
		return nil, err
	}
	maxBytes, err := normalizeBoundedLimit(spec.MaxFileBytes, defaultMaxJournalBytes, maxAllowedJournalBytes, "MaxFileBytes")
	if err != nil {
		return nil, err
	}
	limits, err := ports.NewReadLimits(maxBytes)
	if err != nil {
		return nil, err
	}
	return &WALJournalStore{
		fs:         spec.ScopedFS,
		rootDir:    spec.RootDir,
		journalDir: dirDest,
		limits:     limits,
		valid:      true,
	}, nil
}

// JournalGenerationFile 返回指定 (transferID, generation) 对应的沙箱内相对 WAL 文件路径。
func (s *WALJournalStore) JournalGenerationFile(transferID security.OperationID, generation uint64) (pathalg.LocalRootedDest, error) {
	if s == nil || !s.valid || !transferID.IsValid() || generation == 0 {
		return zeroVal[pathalg.LocalRootedDest](), fmt.Errorf("%w: WALJournalStore、transferID 或 generation 无效", ports.ErrInvalidArgument)
	}
	return s.walFileDest(transferID, generation)
}

// Append 在该传输旁路独占锁保护下，将单条有效 TransferJournalRecord 编码为 CRC32 校验帧并同步追加落盘。
func (s *WALJournalStore) Append(ctx context.Context, record fsm.TransferJournalRecord) error {
	if err := checkCtxReady(ctx, s != nil && s.valid, "WALJournalStore"); err != nil {
		return err
	}
	if !record.IsValid() {
		return fmt.Errorf("%w: TransferJournalRecord 无效", ports.ErrInvalidArgument)
	}
	frame, err := encodeWALFrame(record)
	if err != nil {
		return err
	}
	lockTarget, err := s.transferLockTarget(record.TransferID())
	if err != nil {
		return err
	}
	walDest, err := s.walFileDest(record.TransferID(), record.Generation())
	if err != nil {
		return err
	}
	if err := s.fs.EnsureRoot(s.rootDir, storeDirPerm); err != nil {
		return err
	}
	return s.fs.WithRoot(s.rootDir, func(root ports.RootHandle) error {
		if mErr := root.MkdirAll(s.journalDir, storeDirPerm); mErr != nil {
			return mErr
		}
		return osfs.WithSidecarLock(ctx, root, lockTarget, ports.LockExclusive, storeFilePerm, func(ports.LockedFile) error {
			return root.AppendLine(walDest, storeFilePerm, frame)
		})
	})
}

// Load 按 (Generation 升序, Seq 升序) 合并返回指定传输的全部保留记录；
// 若传输不存在返回 ports.ErrNotFound，若任一世代发生 CRC/截断/格式损坏则失败关闭返回 ports.ErrCorruptData。
func (s *WALJournalStore) Load(ctx context.Context, transferID security.OperationID) ([]fsm.TransferJournalRecord, error) {
	snaps, err := s.LoadGenerations(ctx, transferID)
	if err != nil {
		return nil, err
	}
	var out []fsm.TransferJournalRecord
	for _, snap := range snaps {
		if snap.Corrupt() {
			return nil, fmt.Errorf("%w: generation %d: %w", ports.ErrCorruptData, snap.Generation(), snap.Err())
		}
		out = append(out, snap.Records()...)
	}
	return out, nil
}

// LoadGenerations 按 Generation 升序返回逐代隔离的只读快照：
// 健康世代返回完整排序记录；损坏世代返回 Corrupt()==true、Records()==nil，
// 并在 PartialRecords() 中保留损坏点前已通过全部完整性校验的同代前缀记录。
func (s *WALJournalStore) requireJournalDir(root ports.RootHandle) error {
	exists, err := checkLstatDir(root, s.journalDir)
	if err != nil {
		return err
	}
	if !exists {
		return ports.ErrNotFound
	}
	return nil
}

func (s *WALJournalStore) LoadGenerations(ctx context.Context, transferID security.OperationID) ([]ports.JournalGenerationSnapshot, error) {
	lockTarget, err := s.prepareTransferOp(ctx, transferID)
	if err != nil {
		return nil, err
	}
	var snaps []ports.JournalGenerationSnapshot
	err = s.fs.WithRoot(s.rootDir, func(root ports.RootHandle) error {
		// 先经 Lstat 校验目录与预检目标世代存在性，拒绝悬空符号链接且绝不为不存在的传输创建条带锁文件。
		if dErr := s.requireJournalDir(root); dErr != nil {
			return dErr
		}
		if gens, gErr := s.listGenerationsLocked(root, transferID); gErr != nil {
			return gErr
		} else if len(gens) == 0 {
			return ports.ErrNotFound
		}
		return osfs.WithSidecarLock(ctx, root, lockTarget, ports.LockShared, storeFilePerm, func(ports.LockedFile) error {
			var lErr error
			snaps, lErr = s.loadGenerationsLocked(root, transferID)
			return lErr
		})
	})
	return snaps, err
}

// PruneGeneration 仅移除指定 (transferID, generation) 对应的 WAL 文件；
// 若不存在则返回 ports.ErrNotFound；固定条带旁路锁永不删除以杜绝 POSIX flock+unlink 竞态。
func (s *WALJournalStore) PruneGeneration(ctx context.Context, transferID security.OperationID, generation uint64) error {
	lockTarget, err := s.prepareTransferOp(ctx, transferID)
	if err != nil {
		return err
	}
	if generation == 0 {
		return fmt.Errorf("%w: generation 不能为 0", ports.ErrInvalidArgument)
	}
	walDest, err := s.walFileDest(transferID, generation)
	if err != nil {
		return err
	}
	return s.fs.WithRoot(s.rootDir, func(root ports.RootHandle) error {
		return s.pruneInRoot(ctx, root, lockTarget, walDest)
	})
}

func (s *WALJournalStore) pruneInRoot(ctx context.Context, root ports.RootHandle, lockTarget, walDest pathalg.LocalRootedDest) error {
	if err := s.requireJournalDir(root); err != nil {
		return err
	}
	if exists, cErr := checkLstatRegular(root, walDest); cErr != nil {
		return cErr
	} else if !exists {
		return ports.ErrNotFound
	}
	return osfs.WithSidecarLock(ctx, root, lockTarget, ports.LockExclusive, storeFilePerm, func(ports.LockedFile) error {
		return root.Remove(walDest)
	})
}

// ListActive 按 OperationID 字典序确定性列举当前磁盘上存在任意世代 WAL 的全部活跃传输标识；
// 根目录或 journals 目录尚未创建时返回空切片与 nil；匹配 WAL 命名但非正规文件的条目严格失败关闭。
func (s *WALJournalStore) ListActive(ctx context.Context) ([]security.OperationID, error) {
	if err := checkCtxReady(ctx, s != nil && s.valid, "WALJournalStore"); err != nil {
		return nil, err
	}
	var ids []security.OperationID
	err := s.fs.WithRoot(s.rootDir, func(root ports.RootHandle) error {
		if exists, cErr := checkLstatDir(root, s.journalDir); cErr != nil || !exists {
			return cErr
		}
		entries, rErr := root.ReadDir(algebraic.Some(s.journalDir))
		if rErr != nil {
			return rErr
		}
		var lErr error
		ids, lErr = collectActiveTransferIDs(entries)
		return lErr
	})
	if errors.Is(err, ports.ErrNotFound) {
		return nil, nil
	}
	return ids, err
}

func collectActiveTransferIDs(entries []ports.LocalDirEntry) ([]security.OperationID, error) {
	seen := make(map[security.OperationID]struct{})
	for _, e := range entries {
		id, _, pErr := parseWALFileName(e.Name())
		if pErr != nil {
			continue
		}
		if err := ensureRegularWALEntry(e); err != nil {
			return nil, err
		}
		seen[id] = struct{}{}
	}
	if len(seen) == 0 {
		return nil, nil
	}
	ids := slices.Collect(maps.Keys(seen))
	slices.SortFunc(ids, security.OperationID.Compare)
	return ids, nil
}

// Delete 移除指定传输的全部世代 WAL 文件；若该传输不存在任何世代文件则返回 ports.ErrNotFound 且不创建锁文件。
func (s *WALJournalStore) Delete(ctx context.Context, transferID security.OperationID) error {
	lockTarget, err := s.prepareTransferOp(ctx, transferID)
	if err != nil {
		return err
	}
	return s.fs.WithRoot(s.rootDir, func(root ports.RootHandle) error {
		return s.deleteInRoot(ctx, root, transferID, lockTarget)
	})
}

func (s *WALJournalStore) prepareTransferOp(ctx context.Context, transferID security.OperationID) (pathalg.LocalRootedDest, error) {
	if err := checkCtxReady(ctx, s != nil && s.valid, "WALJournalStore"); err != nil {
		return zeroVal[pathalg.LocalRootedDest](), err
	}
	if !transferID.IsValid() {
		return zeroVal[pathalg.LocalRootedDest](), fmt.Errorf("%w: transferID 无效", ports.ErrInvalidArgument)
	}
	return s.transferLockTarget(transferID)
}

func (s *WALJournalStore) deleteInRoot(ctx context.Context, root ports.RootHandle, transferID security.OperationID, lockTarget pathalg.LocalRootedDest) error {
	if err := s.requireJournalDir(root); err != nil {
		return err
	}
	if gens, gErr := s.listGenerationsLocked(root, transferID); gErr != nil {
		return gErr
	} else if len(gens) == 0 {
		return ports.ErrNotFound
	}
	return osfs.WithSidecarLock(ctx, root, lockTarget, ports.LockExclusive, storeFilePerm, func(ports.LockedFile) error {
		return s.removeAllGenerationsLocked(root, transferID)
	})
}

func (s *WALJournalStore) removeAllGenerationsLocked(root ports.RootHandle, transferID security.OperationID) error {
	gens, err := s.listGenerationsLocked(root, transferID)
	if err != nil {
		return err
	}
	if len(gens) == 0 {
		return ports.ErrNotFound
	}
	for _, gen := range gens {
		walDest, dErr := s.walFileDest(transferID, gen)
		if dErr != nil {
			return dErr
		}
		if rmErr := root.Remove(walDest); rmErr != nil && !errors.Is(rmErr, ports.ErrNotFound) {
			return rmErr
		}
	}
	return nil
}

func (s *WALJournalStore) loadGenerationsLocked(root ports.RootHandle, transferID security.OperationID) ([]ports.JournalGenerationSnapshot, error) {
	gens, err := s.listGenerationsLocked(root, transferID)
	if err != nil {
		return nil, err
	}
	if len(gens) == 0 {
		return nil, ports.ErrNotFound
	}
	snaps := make([]ports.JournalGenerationSnapshot, 0, len(gens))
	for _, gen := range gens {
		snap, gErr := s.readSingleGenerationLocked(root, transferID, gen)
		if gErr != nil {
			return nil, gErr
		}
		snaps = append(snaps, snap)
	}
	return snaps, nil
}

func (s *WALJournalStore) listGenerationsLocked(root ports.RootHandle, transferID security.OperationID) ([]uint64, error) {
	entries, err := root.ReadDir(algebraic.Some(s.journalDir))
	if errors.Is(err, ports.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var gens []uint64
	for _, e := range entries {
		id, gen, pErr := parseWALFileName(e.Name())
		if pErr != nil || !id.Equal(transferID) {
			continue
		}
		// 先匹配 WAL 文件名再校验常规文件类型，防止高世代被替换为目录或符号链接时静默回退至低世代（ADR-016）。
		if err := ensureRegularWALEntry(e); err != nil {
			return nil, err
		}
		gens = append(gens, gen)
	}
	slices.Sort(gens)
	return slices.Compact(gens), nil
}

func ensureRegularWALEntry(e ports.LocalDirEntry) error {
	if e.IsRegular() {
		return nil
	}
	if e.IsSymlink() {
		return fmt.Errorf("%w: WAL 条目 %q 为符号链接", ports.ErrSymlinkRejected, e.Name())
	}
	return fmt.Errorf("%w: WAL 条目 %q 不是常规文件", ports.ErrNotRegularFile, e.Name())
}

func (s *WALJournalStore) readSingleGenerationLocked(root ports.RootHandle, transferID security.OperationID, gen uint64) (ports.JournalGenerationSnapshot, error) {
	walDest, err := s.walFileDest(transferID, gen)
	if err != nil {
		return zeroVal[ports.JournalGenerationSnapshot](), err
	}
	raw, err := root.ReadAllBounded(walDest, s.limits)
	if err != nil {
		if errors.Is(err, ports.ErrLimitExceeded) || errors.Is(err, ports.ErrCorruptData) {
			return ports.NewCorruptJournalGenerationSnapshot(gen, fmt.Errorf("%w: %w", ports.ErrCorruptData, err))
		}
		return zeroVal[ports.JournalGenerationSnapshot](), err
	}
	return parseWALGenerationBytes(transferID, gen, raw)
}

// transferLockTarget 将 TransferID 哈希映射至 64 个固定永不删除的条带锁目标（journals/.stripe_<00..3f>.lock），
// 消除可复锁文件删除引起的 POSIX flock+unlink 竞态与只读孤儿锁泄漏。
func (s *WALJournalStore) transferLockTarget(id security.OperationID) (pathalg.LocalRootedDest, error) {
	bucket := crc32.ChecksumIEEE([]byte(id.String())) % walLockStripeCount
	return s.journalDir.JoinComponent(fmt.Sprintf(".stripe_%02x", bucket))
}

func (s *WALJournalStore) walFileDest(id security.OperationID, gen uint64) (pathalg.LocalRootedDest, error) {
	name := fmt.Sprintf("%s%s%d%s", encodeJournalKey(id), walGenMarker, gen, walFileSuffix)
	return s.journalDir.JoinComponent(name)
}
