package store

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base32"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"hash/crc32"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	walKeyPrefix   = "j_"
	walFileSuffix  = ".wal"
	walGenMarker   = ".g"
	walLockExt     = ".lock"
	walMinFrameLen = len(walFrameVersionPrefix) + walCRC32HexLen + 1
)

// WALJournalStore 实现 ports.JournalStore，提供面向 10 GiB 可恢复分片传输的双代（active/staging）
// CRC32 校验 WAL 持久化存储：
//   - 按 (TransferID, Generation) 物理分文件存储（j_<base32(id)>.g<gen>.wal），
//     单侧损坏严格隔离于对应世代，绝不毒化同传输的其他健康世代；
//   - 每条记录以 "v1:<8位小写CRC32-IEEE>:<jsonv2 Deterministic(true)>\n" 帧写入，
//     读取时同时校验帧格式、CRC32、TransferJournalRecord SHA-256 自校验摘要与 (TransferID, Generation) 归属；
//   - 某世代遇 CRC/截断/格式损坏时，LoadGenerations 在 PartialRecords() 中精确保留损坏点前全部有效前缀，
//     供上层 TransferService 识别 CommitStarted / UncertainCommit 并禁止回退低世代；
//   - 并发协调统一使用每个 TransferID 的旁路锁 j_<base32(id)>.lock，绝不对 .wal 数据文件本身加锁。
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
func (s *WALJournalStore) LoadGenerations(ctx context.Context, transferID security.OperationID) ([]ports.JournalGenerationSnapshot, error) {
	lockTarget, err := s.prepareTransferOp(ctx, transferID)
	if err != nil {
		return nil, err
	}
	var snaps []ports.JournalGenerationSnapshot
	err = s.fs.WithRoot(s.rootDir, func(root ports.RootHandle) error {
		if _, stErr := root.Stat(s.journalDir); stErr != nil {
			return stErr
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
// 若不存在则返回 ports.ErrNotFound；当该传输已无剩余世代时顺带按三平台安全协议清理其旁路锁。
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
		return s.pruneInRoot(ctx, root, transferID, lockTarget, walDest)
	})
}

func (s *WALJournalStore) pruneInRoot(
	ctx context.Context,
	root ports.RootHandle,
	transferID security.OperationID,
	lockTarget, walDest pathalg.LocalRootedDest,
) error {
	if _, stErr := root.Stat(s.journalDir); stErr != nil {
		return stErr
	}
	shouldCleanLock := false
	err := osfs.WithSidecarLock(ctx, root, lockTarget, ports.LockExclusive, storeFilePerm, func(ports.LockedFile) error {
		if rmErr := root.Remove(walDest); rmErr != nil {
			return rmErr
		}
		rem, fErr := s.listGenerationsLocked(root, transferID)
		if fErr != nil {
			return fErr
		}
		shouldCleanLock = len(rem) == 0
		return nil
	})
	if err != nil {
		return err
	}
	if shouldCleanLock {
		s.cleanupSidecarLock(root, lockTarget)
	}
	return nil
}

func (s *WALJournalStore) cleanupSidecarLock(root ports.RootHandle, lockTarget pathalg.LocalRootedDest) {
	if lockDest, lErr := osfs.SidecarLockDest(lockTarget); lErr == nil {
		_, _ = osfs.RemoveLockedFileSafely(root, lockDest)
	}
}

// ListActive 按 OperationID 字典序确定性列举当前磁盘上存在任意世代 WAL 的全部活跃传输标识；
// 根目录或 journals 目录尚未创建时返回空切片与 nil。
func (s *WALJournalStore) ListActive(ctx context.Context) ([]security.OperationID, error) {
	if err := checkCtxReady(ctx, s != nil && s.valid, "WALJournalStore"); err != nil {
		return nil, err
	}
	var ids []security.OperationID
	err := s.fs.WithRoot(s.rootDir, func(root ports.RootHandle) error {
		entries, rErr := root.ReadDir(algebraic.Some(s.journalDir))
		if rErr != nil {
			return rErr
		}
		seen := make(map[security.OperationID]struct{})
		for _, e := range entries {
			if !e.IsRegular() {
				continue
			}
			if id, _, pErr := parseWALFileName(e.Name()); pErr == nil {
				seen[id] = struct{}{}
			}
		}
		if len(seen) > 0 {
			ids = slices.Collect(maps.Keys(seen))
			slices.SortFunc(ids, security.OperationID.Compare)
		}
		return nil
	})
	if errors.Is(err, ports.ErrNotFound) {
		return nil, nil
	}
	return ids, err
}

// Delete 移除指定传输的全部世代 WAL 文件并在释放旁路锁后安全清理其旁路锁文件；
// 若该传输不存在任何世代文件则返回 ports.ErrNotFound。
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
	if _, stErr := root.Stat(s.journalDir); stErr != nil {
		return stErr
	}
	err := osfs.WithSidecarLock(ctx, root, lockTarget, ports.LockExclusive, storeFilePerm, func(ports.LockedFile) error {
		return s.removeAllGenerationsLocked(root, transferID)
	})
	if err != nil {
		return err
	}
	s.cleanupSidecarLock(root, lockTarget)
	return nil
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
		if !e.IsRegular() {
			continue
		}
		if id, gen, pErr := parseWALFileName(e.Name()); pErr == nil && id.Equal(transferID) {
			gens = append(gens, gen)
		}
	}
	slices.Sort(gens)
	return slices.Compact(gens), nil
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

// parseWALGenerationBytes 逐行校验 CRC32 与记录摘要；遇首处截断或损坏立即停机并返回带有效前缀的损坏快照。
func parseWALGenerationBytes(transferID security.OperationID, gen uint64, raw []byte) (ports.JournalGenerationSnapshot, error) {
	if len(raw) == 0 {
		return ports.NewCorruptJournalGenerationSnapshot(gen, fmt.Errorf("%w: %w: 世代 %d WAL 文件为空", ports.ErrCorruptData, ErrCorruptJournalFrame, gen))
	}
	hasTrailingNL := bytes.HasSuffix(raw, []byte{'\n'})
	body := bytes.TrimSuffix(raw, []byte{'\n'})
	lines := bytes.Split(body, []byte{'\n'})
	prefix := make([]fsm.TransferJournalRecord, 0, len(lines))
	for i, line := range lines {
		if i == len(lines)-1 && !hasTrailingNL {
			cause := fmt.Errorf("%w: %w: 第 %d 行缺少尾随换行符（疑似写入截断）", ports.ErrCorruptData, ErrCorruptJournalFrame, i+1)
			return ports.NewCorruptJournalGenerationSnapshot(gen, cause, sortJournalRecordsStable(prefix)...)
		}
		rec, err := decodeWALFrame(line, transferID, gen)
		if err != nil {
			cause := fmt.Errorf("%w: 第 %d 行: %w", ports.ErrCorruptData, i+1, err)
			return ports.NewCorruptJournalGenerationSnapshot(gen, cause, sortJournalRecordsStable(prefix)...)
		}
		prefix = append(prefix, rec)
	}
	return ports.NewJournalGenerationSnapshot(gen, sortJournalRecordsStable(prefix))
}

func sortJournalRecordsStable(in []fsm.TransferJournalRecord) []fsm.TransferJournalRecord {
	if len(in) <= 1 {
		return in
	}
	out := slices.Clone(in)
	slices.SortStableFunc(out, func(a, b fsm.TransferJournalRecord) int { return cmp.Compare(a.Seq(), b.Seq()) })
	return out
}

func encodeWALFrame(rec fsm.TransferJournalRecord) ([]byte, error) {
	payload, err := jsonv2.Marshal(rec, jsonv2.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("%w: 序列化 Journal 记录失败: %w", ports.ErrInvalidArgument, err)
	}
	if bytes.ContainsAny(payload, "\r\n") {
		return nil, fmt.Errorf("%w: 规范 JSON 记录包含非法换行符", ports.ErrInvalidArgument)
	}
	sum := crc32.ChecksumIEEE(payload)
	buf := make([]byte, 0, len(walFrameVersionPrefix)+walCRC32HexLen+1+len(payload))
	buf = append(buf, walFrameVersionPrefix...)
	buf = fmt.Appendf(buf, "%08x:", sum)
	buf = append(buf, payload...)
	return buf, nil
}

func decodeWALFrame(rawLine []byte, wantID security.OperationID, wantGen uint64) (fsm.TransferJournalRecord, error) {
	line := bytes.TrimSuffix(rawLine, []byte{'\r'})
	if len(line) < walMinFrameLen || !bytes.HasPrefix(line, []byte(walFrameVersionPrefix)) {
		return zeroVal[fsm.TransferJournalRecord](), fmt.Errorf("%w: 帧头缺失或版本前缀非法", ErrCorruptJournalFrame)
	}
	rest := line[len(walFrameVersionPrefix):]
	if len(rest) <= walCRC32HexLen+1 || rest[walCRC32HexLen] != ':' {
		return zeroVal[fsm.TransferJournalRecord](), fmt.Errorf("%w: CRC32 分隔符缺失", ErrCorruptJournalFrame)
	}
	crcHex := string(rest[:walCRC32HexLen])
	wantCRC, err := strconv.ParseUint(crcHex, 16, 32)
	if err != nil || crcHex != strings.ToLower(crcHex) {
		return zeroVal[fsm.TransferJournalRecord](), fmt.Errorf("%w: CRC32 十六进制格式非法", ErrCorruptJournalFrame)
	}
	payload := rest[walCRC32HexLen+1:]
	if uint64(crc32.ChecksumIEEE(payload)) != wantCRC {
		return zeroVal[fsm.TransferJournalRecord](), fmt.Errorf("%w: CRC32 校验和不匹配", ErrCorruptJournalFrame)
	}
	var rec fsm.TransferJournalRecord
	if err := jsonv2.Unmarshal(payload, &rec); err != nil {
		return zeroVal[fsm.TransferJournalRecord](), fmt.Errorf("%w: 载荷反序列化或摘要校验失败: %w", ErrCorruptJournalFrame, err)
	}
	if !rec.IsValid() || !rec.TransferID().Equal(wantID) || rec.Generation() != wantGen {
		return zeroVal[fsm.TransferJournalRecord](), fmt.Errorf("%w: 记录归属 (transfer_id/generation) 与文件不匹配", ErrCorruptJournalFrame)
	}
	return rec, nil
}

func (s *WALJournalStore) transferLockTarget(id security.OperationID) (pathalg.LocalRootedDest, error) {
	return s.journalDir.JoinComponent(encodeJournalKey(id))
}

func (s *WALJournalStore) walFileDest(id security.OperationID, gen uint64) (pathalg.LocalRootedDest, error) {
	name := fmt.Sprintf("%s%s%d%s", encodeJournalKey(id), walGenMarker, gen, walFileSuffix)
	return s.journalDir.JoinComponent(name)
}

// encodeJournalKey 使用无填充小写 Base32（字母表 [a-z2-7]）双射编码 OperationID，
// 确保在 Linux/macOS(APFS)/Windows(NTFS) 大小写不敏感文件系统下零碰撞且满足 255 字节分量上限。
func encodeJournalKey(id security.OperationID) string {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(id.String()))
	return walKeyPrefix + strings.ToLower(enc)
}

func parseWALFileName(name string) (security.OperationID, uint64, error) {
	if strings.HasSuffix(name, walLockExt) {
		return zeroVal[security.OperationID](), 0, ErrCorruptJournalFrame
	}
	stem, ok := strings.CutSuffix(name, walFileSuffix)
	if !ok {
		return zeroVal[security.OperationID](), 0, ErrCorruptJournalFrame
	}
	keyPart, genStr, ok := strings.Cut(stem, walGenMarker)
	if !ok || !strings.HasPrefix(keyPart, walKeyPrefix) || genStr == "" {
		return zeroVal[security.OperationID](), 0, ErrCorruptJournalFrame
	}
	gen, err := strconv.ParseUint(genStr, 10, 64)
	if err != nil || gen == 0 || strconv.FormatUint(gen, 10) != genStr {
		return zeroVal[security.OperationID](), 0, fmt.Errorf("%w: 非法世代号 %q", ErrCorruptJournalFrame, genStr)
	}
	rawBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimPrefix(keyPart, walKeyPrefix)))
	if err != nil {
		return zeroVal[security.OperationID](), 0, err
	}
	id, err := security.ParseOperationID(string(rawBytes))
	if err != nil {
		return zeroVal[security.OperationID](), 0, err
	}
	if encodeJournalKey(id) != keyPart {
		return zeroVal[security.OperationID](), 0, ErrCorruptJournalFrame
	}
	return id, gen, nil
}
