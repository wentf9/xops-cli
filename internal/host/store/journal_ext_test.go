package store_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/store"
	"go.uber.org/goleak"
)

// TestTCKJournalStoreWithRealDiskCorruption 验证真实 WALJournalStore 100% 通过 core/ports/tck 双代日志契约套件，
// 含磁盘真实字节篡改驱动的单侧损坏隔离测试。
func TestTCKJournalStoreWithRealDiskCorruption(t *testing.T) {
	defer goleak.VerifyNone(t)
	var curDir string
	var curStore *store.WALJournalStore

	tck.RunJournalStoreSuite(t, tck.JournalStoreFixture{
		NewStore: func(t *testing.T) ports.JournalStore {
			dir, rootDir := newPrivateStoreRoot(t)
			st, err := store.NewWALJournalStore(store.JournalStoreSpec{
				ScopedFS: osfs.NewScopedRootFS(),
				RootDir:  rootDir,
			})
			if err != nil {
				t.Fatalf("NewWALJournalStore 失败: %v", err)
			}
			curDir = dir
			curStore = st
			return st
		},
		CorruptGeneration: func(t *testing.T, _ ports.JournalStore, id security.OperationID, gen uint64) {
			t.Helper()
			rel, err := curStore.JournalGenerationFile(id, gen)
			if err != nil {
				t.Fatalf("JournalGenerationFile 失败: %v", err)
			}
			full := filepath.Join(curDir, filepath.FromSlash(rel.String()))
			raw, err := os.ReadFile(full)
			if err != nil {
				t.Fatalf("读取 WAL 文件失败: %v", err)
			}
			// 在文件末尾追加无有效 CRC32 的损坏帧，既触发损坏检测又保留前缀有效记录。
			corrupted := append(bytes.Clone(raw), []byte("v1:deadbeef:{\"corrupt\":true}\n")...)
			if err := os.WriteFile(full, corrupted, 0o600); err != nil {
				t.Fatalf("写入损坏 WAL 文件失败: %v", err)
			}
		},
	})
}

// TestWALPartialRecordsAndCorruptionModes 验证 10 GiB 传输崩溃恢复所需的全部 WAL 完整性不变量：
//   - CommitStarted 后尾行截断/损坏：LoadGenerations 精确保留 [Init, Chunk, Verified, CommitStarted] 至 PartialRecords()，
//     供上层识别并停于 TransferUncertainCommit，绝不回退 Gen 1；
//   - 首行 CRC32 翻转与 0 字节空文件：Corrupt()==true 且 PartialRecords()==nil；
//   - 跨世代帧搬运攻击（将 Gen 1 合法帧塞入 Gen 2 文件）：归属校验拒绝并标记损坏；
//   - 特殊字符与大小写敏感 OperationID（如 "op/a:b*C" vs "op/a:b*c"）：Base32 命名三平台零碰撞；
//   - 多协程并发双代 Append 与 PruneGeneration 零数据竞争、零协程泄漏。
func TestWALPartialRecordsAndCorruptionModes(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	dir, rootDir := newPrivateStoreRoot(t)
	st, err := store.NewWALJournalStore(store.JournalStoreSpec{
		ScopedFS: osfs.NewScopedRootFS(),
		RootDir:  rootDir,
	})
	if err != nil {
		t.Fatalf("NewWALJournalStore 失败: %v", err)
	}

	t.Run("TailTruncationAfterCommitStartedPreservesPartialRecords", func(t *testing.T) {
		verifyTailTruncationPartialPrefix(t, ctx, dir, st)
	})
	t.Run("HeadCorruptionEmptyFileAndCrossGenSwap", func(t *testing.T) {
		verifyHeadEmptyAndCrossGenCorruption(t, ctx, dir, st)
	})
	t.Run("SpecialAndCaseVariantOperationIDsAreBijective", func(t *testing.T) {
		verifyBijectiveWALKeys(t, ctx, st)
	})
	t.Run("ConcurrentAppendAndPrune", func(t *testing.T) {
		verifyConcurrentWALOperations(t, ctx, st)
	})
}

func verifyTailTruncationPartialPrefix(t *testing.T, ctx context.Context, dir string, st *store.WALJournalStore) {
	t.Helper()
	id, err := security.NewOperationIDFrom(tck.NewDeterministicEntropy(101))
	if err != nil {
		t.Fatal(err)
	}
	gen1 := tck.MustV2JournalChainGen(t, id, 1)[:2]
	gen2 := tck.MustV2JournalChainGen(t, id, 2)
	if err := appendAllWALRecords(ctx, st, append(slices.Clone(gen1), gen2...)); err != nil {
		t.Fatalf("Append 失败: %v", err)
	}
	// 截断 Gen 2 末行（Committed 记录的后 12 字节），模拟写 Committed 途中遇 SIGKILL。
	truncateWALTail(t, dir, st, id, 2, 12)

	if _, err := st.Load(ctx, id); !errors.Is(err, ports.ErrCorruptData) {
		t.Fatalf("存在尾截断时合并 Load 返回 %v, 期望 ErrCorruptData", err)
	}
	snaps, err := st.LoadGenerations(ctx, id)
	if err != nil || len(snaps) != 2 {
		t.Fatalf("LoadGenerations 失败: len=%d err=%v", len(snaps), err)
	}
	if snaps[0].Corrupt() || !slices.EqualFunc(snaps[0].Records(), gen1, fsm.TransferJournalRecord.Equal) {
		t.Fatalf("健康 Gen 1 不得受 Gen 2 截断影响: corrupt=%v", snaps[0].Corrupt())
	}
	wantPrefix := gen2[:4] // Init, Chunk, Verified, CommitStarted
	if !snaps[1].Corrupt() || snaps[1].Records() != nil || !slices.EqualFunc(snaps[1].PartialRecords(), wantPrefix, fsm.TransferJournalRecord.Equal) {
		t.Fatalf("Gen 2 PartialRecords 未精确保留 CommitStarted 前缀: corrupt=%v got=%d want=%d", snaps[1].Corrupt(), len(snaps[1].PartialRecords()), len(wantPrefix))
	}
	// 确认上层纯函数恢复识别 CommitStarted 并停于 UncertainCommit。
	recovered, _, _, rErr := fsm.RecoverTransferFromJournal(snaps[1].PartialRecords())
	if rErr != nil || recovered.Kind() != fsm.TransferKindUncertainCommit {
		t.Fatalf("PartialRecords 恢复结果 = (%v, %v), 期望 TransferKindUncertainCommit", recovered, rErr)
	}
}

func truncateWALTail(t *testing.T, dir string, st *store.WALJournalStore, id security.OperationID, gen uint64, dropBytes int) {
	t.Helper()
	rel, err := st.JournalGenerationFile(id, gen)
	if err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(dir, filepath.FromSlash(rel.String()))
	raw, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, raw[:len(raw)-dropBytes], 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendAllWALRecords(ctx context.Context, st *store.WALJournalStore, recs []fsm.TransferJournalRecord) error {
	for _, r := range recs {
		if err := st.Append(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

func verifyHeadEmptyAndCrossGenCorruption(t *testing.T, ctx context.Context, dir string, st *store.WALJournalStore) {
	t.Helper()
	ent := tck.NewDeterministicEntropy(115)
	idHead, _ := security.NewOperationIDFrom(ent)
	chain := tck.MustV2JournalChainGen(t, idHead, 1)
	if err := st.Append(ctx, chain[0]); err != nil {
		t.Fatal(err)
	}
	rel1, _ := st.JournalGenerationFile(idHead, 1)
	full1 := filepath.Join(dir, filepath.FromSlash(rel1.String()))
	raw, _ := os.ReadFile(full1)
	// 1. 翻转首行 CRC32 校验和字节 -> 空前缀损坏。
	tampered := bytes.Clone(raw)
	if tampered[3] == '0' {
		tampered[3] = '1'
	} else {
		tampered[3] = '0'
	}
	if err := os.WriteFile(full1, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	snaps, err := st.LoadGenerations(ctx, idHead)
	if err != nil || len(snaps) != 1 || !snaps[0].Corrupt() || snaps[0].PartialRecords() != nil || !errors.Is(snaps[0].Err(), store.ErrCorruptJournalFrame) {
		t.Fatalf("首行 CRC 翻转期望空前缀损坏: snaps=%v err=%v", snaps, err)
	}

	// 2. 0 字节空文件 -> 空前缀损坏且仍出现在 ListActive 中。
	if err := os.WriteFile(full1, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	snapsEmpty, err := st.LoadGenerations(ctx, idHead)
	if err != nil || len(snapsEmpty) != 1 || !snapsEmpty[0].Corrupt() || snapsEmpty[0].PartialRecords() != nil {
		t.Fatalf("空 WAL 文件期望空前缀损坏: snaps=%v err=%v", snapsEmpty, err)
	}

	// 3. 将 Gen 1 合法帧写入 Gen 2 文件 -> 归属检查拒绝。
	rel2, _ := st.JournalGenerationFile(idHead, 2)
	full2 := filepath.Join(dir, filepath.FromSlash(rel2.String()))
	if err := os.WriteFile(full2, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	snapsSwap, err := st.LoadGenerations(ctx, idHead)
	if err != nil || len(snapsSwap) != 2 || !snapsSwap[1].Corrupt() || snapsSwap[1].PartialRecords() != nil {
		t.Fatalf("跨世代搬运帧必须被归属校验拦截: snaps=%v err=%v", snapsSwap, err)
	}
}

func verifyBijectiveWALKeys(t *testing.T, ctx context.Context, st *store.WALJournalStore) {
	t.Helper()
	idUpper, err := security.ParseOperationID("op/a:b*C?1")
	if err != nil {
		t.Fatal(err)
	}
	idLower, err := security.ParseOperationID("op/a:b*c?1")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Append(ctx, tck.MustV2JournalChain(t, idUpper)[0]); err != nil {
		t.Fatalf("Append(idUpper) 失败: %v", err)
	}
	if err := st.Append(ctx, tck.MustV2JournalChain(t, idLower)[0]); err != nil {
		t.Fatalf("Append(idLower) 失败: %v", err)
	}
	active, err := st.ListActive(ctx)
	if err != nil {
		t.Fatalf("ListActive 失败: %v", err)
	}
	if !slices.ContainsFunc(active, idUpper.Equal) || !slices.ContainsFunc(active, idLower.Equal) {
		t.Fatalf("大小写变体与特殊字符 OperationID 须三平台无碰撞双射恢复: active=%v", active)
	}
}

func verifyConcurrentWALOperations(t *testing.T, ctx context.Context, st *store.WALJournalStore) {
	t.Helper()
	id, _ := security.NewOperationIDFrom(tck.NewDeterministicEntropy(141))
	g1 := tck.MustV2JournalChainGen(t, id, 1)
	g2 := tck.MustV2JournalChainGen(t, id, 2)
	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(c context.Context) error { return appendAllWALRecords(c, st, g1) }); gErr != nil {
			return gErr
		}
		return n.Go(func(c context.Context) error { return appendAllWALRecords(c, st, g2) })
	})
	if err != nil {
		t.Fatalf("并发双代 Append 失败: %v", err)
	}
	snaps, err := st.LoadGenerations(ctx, id)
	if err != nil || len(snaps) != 2 || len(snaps[0].Records()) != len(g1) || len(snaps[1].Records()) != len(g2) {
		t.Fatalf("并发双代加载结果不符: snaps=%v err=%v", snaps, err)
	}
	if err := st.PruneGeneration(ctx, id, 1); err != nil {
		t.Fatalf("PruneGeneration(1) 失败: %v", err)
	}
	if err := st.Delete(ctx, id); err != nil {
		t.Fatalf("Delete 失败: %v", err)
	}
}
