package tck

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
)

// FormatImporterFixture 描述 FormatImporter 契约测试夹具。
type FormatImporterFixture struct {
	// NewImporter 返回待测导入器实例。
	NewImporter func(t *testing.T) ports.FormatImporter
	// ValidInput 返回合法格式输入流工厂。
	ValidInput func() io.Reader
	// InvalidInput 返回语法或语义非法输入流工厂（可选）。
	InvalidInput func() io.Reader
	// SourceName 用于调用 Import 的源名称标识（为空时默认 "tck-source"）。
	SourceName string
}

// OpenSSHConfigFixture 描述 OpenSSHConfigSource 契约测试夹具。
type OpenSSHConfigFixture struct {
	// NewSource 返回已加载测试配置（含至少 1 条虚拟主机）的 OpenSSHConfigSource。
	NewSource func(t *testing.T) ports.OpenSSHConfigSource
	// TargetHost 与 Endpoint 指定用于 ResolveTier4 的已知原始主机与规范化端点。
	TargetHost option.OriginalHostSpec
	Endpoint   netaddr.Endpoint
}

// RunInventoryStoreSuite 验证任意 InventoryStore 实现的加载、CAS 提交、冲突拒绝、无效入参拦截与并发 CAS 竞争契约。
func RunInventoryStoreSuite(t *testing.T, newStore func(t *testing.T) ports.InventoryStore) {
	t.Helper()
	requireTrue(t, newStore != nil, "newStore 工厂不能为 nil")

	t.Run("InvalidInputsFailClosed", func(t *testing.T) {
		store := newStore(t)
		var zeroRev ports.Revision
		var zeroGraph inventory.Graph
		var nilCtx context.Context

		_, err := store.Load(nilCtx)
		requireErrIs(t, err, ports.ErrNilContext, "Load(nil)")

		snap, err := store.Load(context.Background())
		requireNoErr(t, err, "Load(initial)")
		requireTrue(t, snap.IsValid(), "初始快照必须有效")

		_, err = store.CommitCAS(nilCtx, snap.Revision(), MustGraph(t, "a"))
		requireErrIs(t, err, ports.ErrNilContext, "CommitCAS(nil)")
		_, err = store.CommitCAS(context.Background(), zeroRev, MustGraph(t, "a"))
		requireErr(t, err, "CommitCAS(zeroRev)")
		_, err = store.CommitCAS(context.Background(), snap.Revision(), zeroGraph)
		requireErr(t, err, "CommitCAS(zeroGraph)")
	})

	t.Run("CommitCASAndConflict", func(t *testing.T) {
		ctx := context.Background()
		store := newStore(t)
		snap0, err := store.Load(ctx)
		requireNoErr(t, err, "Load(0)")

		g1 := MustGraph(t, "v1")
		out, err := store.CommitCAS(ctx, snap0.Revision(), g1)
		requireNoErr(t, err, "CommitCAS(v1)")
		requireTrue(t, out.IsValid() && out.Applied() && out.Durable(), "成功提交必须返回 Committed 结果")
		rev1, ok := out.Revision().Get()
		requireTrue(t, ok && rev1.IsValid() && !rev1.Equal(snap0.Revision()), "提交后必须推进 Revision")

		snap1, err := store.Load(ctx)
		requireNoErr(t, err, "Load(1)")
		requireTrue(t, snap1.Revision().Equal(rev1) && graphsEqual(snap1.Graph(), g1), "重新加载必须严格反映已提交快照")

		_, err = store.CommitCAS(ctx, snap0.Revision(), MustGraph(t, "stale"))
		requireErrIs(t, err, ports.ErrRevisionConflict, "使用过期 Revision 必须返回 ErrRevisionConflict")
	})

	t.Run("ConcurrentCASOnlyOneWinner", func(t *testing.T) {
		verifyConcurrentCAS(t, newStore)
	})
}

func verifyConcurrentCAS(t *testing.T, newStore func(t *testing.T) ports.InventoryStore) {
	t.Helper()
	defer VerifyNoLeaks(t)
	ctx := context.Background()
	store := newStore(t)
	snap, err := store.Load(ctx)
	requireNoErr(t, err, "Load(base)")

	// 在测试主协程预先构造全部候选资产图，杜绝在子协程内触发 t.Fatalf。
	candidates := make([]inventory.Graph, 6)
	for i := range candidates {
		candidates[i] = MustGraph(t, string(rune('a'+i)))
	}

	var wins, conflicts atomic.Int32
	err = conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		for _, g := range candidates {
			if gErr := n.Go(func(c context.Context) error {
				return attemptCASCommit(c, store, snap.Revision(), g, &wins, &conflicts)
			}); gErr != nil {
				return gErr
			}
		}
		return nil
	})
	requireNoErr(t, err, "并发 CAS 执行")
	requireTrue(t, wins.Load() == 1 && conflicts.Load() == 5, "同 Revision 并发 CAS 必须恰好 1 胜 5 冲突")
}

func attemptCASCommit(ctx context.Context, store ports.InventoryStore, rev ports.Revision, g inventory.Graph, wins, conflicts *atomic.Int32) error {
	out, err := store.CommitCAS(ctx, rev, g)
	if err == nil && out.Applied() && out.Durable() {
		wins.Add(1)
		return nil
	}
	if errors.Is(err, ports.ErrRevisionConflict) {
		conflicts.Add(1)
		return nil
	}
	return err
}

// RunJournalStoreSuite 验证任意 JournalStore 实现的追加、按序加载、V2 哈希链恢复、列表与删除契约。
func RunJournalStoreSuite(t *testing.T, newStore func(t *testing.T) ports.JournalStore) {
	t.Helper()
	requireTrue(t, newStore != nil, "newStore 工厂不能为 nil")

	t.Run("InvalidInputsAndNotFound", func(t *testing.T) {
		store := newStore(t)
		var nilCtx context.Context
		var zeroID security.OperationID
		var zeroRec fsm.TransferJournalRecord

		requireErrIs(t, store.Append(nilCtx, zeroRec), ports.ErrNilContext, "Append(nil)")
		requireErr(t, store.Append(context.Background(), zeroRec), "Append(zeroRec)")
		_, err := store.Load(nilCtx, zeroID)
		requireErrIs(t, err, ports.ErrNilContext, "Load(nil)")
		_, err = store.Load(context.Background(), zeroID)
		requireErr(t, err, "Load(zeroID)")
		_, err = store.ListActive(nilCtx)
		requireErrIs(t, err, ports.ErrNilContext, "ListActive(nil)")
		requireErrIs(t, store.Delete(nilCtx, zeroID), ports.ErrNilContext, "Delete(nil)")
		requireErr(t, store.Delete(context.Background(), zeroID), "Delete(zeroID)")

		missingID, err := security.NewOperationIDFrom(NewDeterministicEntropy(9))
		requireNoErr(t, err, "NewOperationIDFrom")
		_, err = store.Load(context.Background(), missingID)
		requireErrIs(t, err, ports.ErrNotFound, "Load(missing)")
		requireErrIs(t, store.Delete(context.Background(), missingID), ports.ErrNotFound, "Delete(missing)")
	})

	t.Run("AppendLoadRecoverAndDelete", func(t *testing.T) {
		ctx := context.Background()
		store := newStore(t)
		ent := NewDeterministicEntropy(21)
		idA, err := security.NewOperationIDFrom(ent)
		requireNoErr(t, err, "opA")
		idB, err := security.NewOperationIDFrom(ent)
		requireNoErr(t, err, "opB")

		chainA := MustV2JournalChain(t, idA)
		for _, rec := range chainA {
			requireNoErr(t, store.Append(ctx, rec), "Append(chainA)")
		}
		chainB := MustV2JournalChain(t, idB)
		requireNoErr(t, store.Append(ctx, chainB[0]), "Append(chainB[0])")

		loaded, err := store.Load(ctx, idA)
		requireNoErr(t, err, "Load(idA)")
		requireTrue(t, slices.EqualFunc(loaded, chainA, fsm.TransferJournalRecord.Equal), "加载序列须与写入记录逐条一致")

		state, _, _, err := fsm.RecoverTransferFromJournal(loaded)
		requireNoErr(t, err, "RecoverTransferFromJournal")
		requireTrue(t, state.Kind() == fsm.TransferKindCommitted, "完整 V2 链必须恢复为 Committed 态")

		active, err := store.ListActive(ctx)
		requireNoErr(t, err, "ListActive")
		requireTrue(t, len(active) == 2 && active[0].Compare(active[1]) < 0, "ListActive 须确定性排序返回活跃传输 ID")

		requireNoErr(t, store.Delete(ctx, idA), "Delete(idA)")
		_, err = store.Load(ctx, idA)
		requireErrIs(t, err, ports.ErrNotFound, "删除后 Load 须返回 ErrNotFound")
		requireErrIs(t, store.Delete(ctx, idA), ports.ErrNotFound, "重复删除须返回 ErrNotFound")
	})
}

// RunFormatImporterSuite 验证任意 FormatImporter 实现的格式命名规范、参数拒绝与有效 ImportBundle 产出契约。
func RunFormatImporterSuite(t *testing.T, fx FormatImporterFixture) {
	t.Helper()
	requireTrue(t, fx.NewImporter != nil && fx.ValidInput != nil, "FormatImporterFixture 必须提供 NewImporter 与 ValidInput")
	srcName := fx.SourceName
	if srcName == "" {
		srcName = "tck-source"
	}

	t.Run("FormatAndValidation", func(t *testing.T) {
		imp := fx.NewImporter(t)
		fmtName := imp.Format()
		requireTrue(t, fmtName != "" && fmtName == strings.ToLower(strings.TrimSpace(fmtName)), "Format() 须返回规范小写非空格式名")

		var nilCtx context.Context
		_, err := imp.Import(nilCtx, srcName, fx.ValidInput())
		requireErrIs(t, err, ports.ErrNilContext, "Import(nil ctx)")
		_, err = imp.Import(context.Background(), srcName, nil)
		requireErr(t, err, "Import(nil reader)")

		bundle, err := imp.Import(context.Background(), srcName, fx.ValidInput())
		requireNoErr(t, err, "Import(valid)")
		requireTrue(t, bundle.IsValid() && bundle.SourceFormat() == fmtName, "导入结果须有效且 SourceFormat 与 Format() 一致")

		if fx.InvalidInput != nil {
			_, err = imp.Import(context.Background(), srcName, fx.InvalidInput())
			requireErr(t, err, "Import(invalid)")
		}
	})
}

// RunOpenSSHConfigSourceSuite 验证任意 OpenSSHConfigSource 实现的虚拟主机列举与 Tier-4 选项折叠契约。
func RunOpenSSHConfigSourceSuite(t *testing.T, fx OpenSSHConfigFixture) {
	t.Helper()
	requireTrue(t, fx.NewSource != nil && fx.TargetHost.IsValid() && fx.Endpoint.IsValid(), "OpenSSHConfigFixture 缺少有效夹具字段")

	t.Run("ListAndResolveTier4", func(t *testing.T) {
		src := fx.NewSource(t)
		var nilCtx context.Context
		var zeroTarget option.OriginalHostSpec
		var zeroEP netaddr.Endpoint

		_, err := src.ListVirtualHosts(nilCtx)
		requireErrIs(t, err, ports.ErrNilContext, "ListVirtualHosts(nil)")
		_, err = src.ResolveTier4(nilCtx, fx.TargetHost, fx.Endpoint)
		requireErrIs(t, err, ports.ErrNilContext, "ResolveTier4(nil)")
		_, err = src.ResolveTier4(context.Background(), zeroTarget, fx.Endpoint)
		requireErr(t, err, "ResolveTier4(zeroTarget)")
		_, err = src.ResolveTier4(context.Background(), fx.TargetHost, zeroEP)
		requireErr(t, err, "ResolveTier4(zeroEndpoint)")

		hosts, err := src.ListVirtualHosts(context.Background())
		requireNoErr(t, err, "ListVirtualHosts")
		requireTrue(t, len(hosts) > 0, "测试配置至少应解析出 1 条 OpenSSHVirtualHost")
		for _, h := range hosts {
			requireTrue(t, h.IsValid(), "列举出的每条 OpenSSHVirtualHost 均须有效")
			jn, jErr := h.JumpNode()
			requireNoErr(t, jErr, "JumpNode")
			requireTrue(t, jn.IsValid(), "JumpNode 投影必须有效")
		}

		layer, err := src.ResolveTier4(context.Background(), fx.TargetHost, fx.Endpoint)
		requireNoErr(t, err, "ResolveTier4")
		requireNoErr(t, layer.Validate(), "ResolveTier4 产出的 OptionLayer 须通过 Validate")
	})
}

func graphsEqual(a, b inventory.Graph) bool {
	return a.IsValid() && b.IsValid() &&
		slices.EqualFunc(a.Hosts(), b.Hosts(), inventory.Host.Equal) &&
		slices.EqualFunc(a.Identities(), b.Identities(), inventory.Identity.Equal) &&
		slices.EqualFunc(a.Nodes(), b.Nodes(), inventory.Node.Equal)
}
