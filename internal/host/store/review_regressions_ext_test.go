package store_test

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/store"
	"go.uber.org/goleak"
)

// TestDurabilityOutcomeSanitizesMultilineAndOverlongErrors 验证 #34 Major #1：
// AtomicReplace 返回多行 errors.Join、控制/Bidi 字符、非法 UTF-8 或超 512 字节错误时，
// CommitCAS 仍产出有效 INV-F3 DurabilityOutcome（绝不因 detail 校验失败退化为零值）。
func TestDurabilityOutcomeSanitizesMultilineAndOverlongErrors(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	_, rootDir := newPrivateStoreRoot(t)
	longMsg := strings.Repeat("x", 900)
	dirtyErr := errors.Join(
		errors.New("sync failed\r\t\x00\u202e\xff"),
		errors.New("close failed: "+longMsg),
	)
	for _, tc := range []struct {
		mode string
		want fsm.DurabilityStatus
	}{
		{"not_applied", fsm.DurabilityNotApplied},
		{"applied_not_durable", fsm.DurabilityAppliedNotDurable},
		{"unknown", fsm.DurabilityOutcomeUnknown},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			cfgDest, _ := pathalg.ParseLocalRootedDest("dirty_" + tc.mode + ".yaml")
			faultFS := &dirtyErrFaultFS{
				faultScopedFS: faultScopedFS{mode: tc.mode, files: make(map[string][]byte)},
				cause:         dirtyErr,
			}
			st, err := store.NewYAMLInventoryStore(store.InventoryStoreSpec{
				ScopedFS: faultFS, RootDir: rootDir, ConfigFile: algebraic.Some(cfgDest),
			})
			if err != nil {
				t.Fatal(err)
			}
			snap, err := st.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			out, cErr := st.CommitCAS(ctx, snap.Revision(), tck.MustGraph(t, tc.mode))
			if cErr == nil || !out.IsValid() || out.Status() != tc.want || errors.Is(cErr, ports.ErrInvalidDurability) {
				t.Fatalf("dirty cause (%s) -> out=(valid=%v,status=%s) err=%v", tc.mode, out.IsValid(), out.Status(), cErr)
			}
		})
	}
}

type dirtyErrFaultFS struct {
	faultScopedFS
	cause error
}

//xops:syncclosure
//xops:borrowed
func (f *dirtyErrFaultFS) WithRoot(_ pathalg.LocalDir, fn func(root ports.RootHandle) error) error {
	return fn(&dirtyErrRootHandle{faultRootHandle: faultRootHandle{fs: &f.faultScopedFS}, cause: f.cause})
}

type dirtyErrRootHandle struct {
	faultRootHandle
	cause error
}

//xops:syncclosure
//xops:borrowed
func (h *dirtyErrRootHandle) AtomicReplace(dest pathalg.LocalRootedDest, _ fs.FileMode, fn func(w io.Writer) error) error {
	var buf strings.Builder
	if err := fn(&buf); err != nil {
		return err
	}
	switch h.fs.mode {
	case "applied_not_durable":
		h.fs.files[dest.String()] = []byte(buf.String())
	case "unknown":
		h.fs.readFailed = true
	}
	return h.cause
}

// TestYAMLCodecRejectsSpoofedDiscriminatorsAndEnforcesVaultInvariants 验证 #34 Major #2/#3 + #35 Minor #7/#8：
//   - AlgoPolicyDTO 拒绝 exact 令牌走私 +/-/^ 或内嵌逗号；
//   - PathListDTO / KnownHostsListDTO 在 state: set 下拒绝 "none"、首尾空白走私与非法状态组合；
//   - vault.default_store 必须存在于 vault.stores，新增 vault.stores 与 inventory.known_stores 取并集；
//   - Revision == math.MaxUint64 溢出保护失败关闭返回 ErrInvalidRevision。
func TestYAMLCodecRejectsSpoofedDiscriminatorsAndEnforcesVaultInvariants(t *testing.T) {
	defer goleak.VerifyNone(t)
	badYAMLs := []struct {
		name string
		doc  string
	}{
		{"algo_exact_plus", "version: 2\ninventory:\n  hosts:\n    h1: { address: 192.0.2.1 }\n  identities:\n    i1: { user: ops, auth: { kind: agent } }\n  nodes:\n    n1:\n      host: h1\n      identity: i1\n      options:\n        ciphers: { op: exact, tokens: ['+aes128-ctr'] }\n"},
		{"algo_exact_spaced_minus", "version: 2\ninventory:\n  hosts:\n    h1: { address: 192.0.2.1 }\n  identities:\n    i1: { user: ops, auth: { kind: agent } }\n  nodes:\n    n1:\n      host: h1\n      identity: i1\n      options:\n        ciphers: { op: exact, tokens: [' -*sha1*'] }\n"},
		{"algo_exact_comma", "version: 2\ninventory:\n  hosts:\n    h1: { address: 192.0.2.1 }\n  identities:\n    i1: { user: ops, auth: { kind: agent } }\n  nodes:\n    n1:\n      host: h1\n      identity: i1\n      options:\n        ciphers: { op: exact, tokens: ['aes128-ctr,aes256-ctr'] }\n"},
		{"pathlist_set_none", "version: 2\ninventory:\n  hosts:\n    h1: { address: 192.0.2.1 }\n  identities:\n    i1: { user: ops, auth: { kind: agent } }\n  nodes:\n    n1:\n      host: h1\n      identity: i1\n      options:\n        identity_files: { state: set, items: ['none'] }\n"},
		{"pathlist_set_mid_none", "version: 2\ninventory:\n  hosts:\n    h1: { address: 192.0.2.1 }\n  identities:\n    i1: { user: ops, auth: { kind: agent } }\n  nodes:\n    n1:\n      host: h1\n      identity: i1\n      options:\n        identity_files: { state: set, items: ['~/.ssh/a', 'none', '~/.ssh/b'] }\n"},
		{"knownhosts_set_none", "version: 2\ninventory:\n  hosts:\n    h1: { address: 192.0.2.1 }\n  identities:\n    i1: { user: ops, auth: { kind: agent } }\n  nodes:\n    n1:\n      host: h1\n      identity: i1\n      options:\n        user_known_hosts_files: { state: set, items: ['none'] }\n"},
		{"knownhosts_set_padded", "version: 2\ninventory:\n  hosts:\n    h1: { address: 192.0.2.1 }\n  identities:\n    i1: { user: ops, auth: { kind: agent } }\n  nodes:\n    n1:\n      host: h1\n      identity: i1\n      options:\n        user_known_hosts_files: { state: set, items: [' ~/.ssh/kh1'] }\n"},
		{"knownhosts_disabled_with_items", "version: 2\ninventory:\n  hosts:\n    h1: { address: 192.0.2.1 }\n  identities:\n    i1: { user: ops, auth: { kind: agent } }\n  nodes:\n    n1:\n      host: h1\n      identity: i1\n      options:\n        user_known_hosts_files: { state: disabled, items: ['~/.ssh/kh1'] }\n"},
		{"invalid_vault_default_store", "version: 2\nvault:\n  default_store: missing\n  stores:\n    local: { kind: offline_aead }\ninventory: {}\n"},
	}
	for _, tc := range badYAMLs {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := store.DecodeConfigDocumentYAML([]byte(tc.doc)); !errors.Is(err, ports.ErrCorruptData) {
				t.Fatalf("%s 解码返回 %v, 期望 ErrCorruptData", tc.name, err)
			}
		})
	}
	verifyKnownStoresUnionAndRevisionCap(t)
}

func verifyKnownStoresUnionAndRevisionCap(t *testing.T) {
	t.Helper()
	// 验证 inventory.known_stores 与 vault.stores 取并集。
	unionYAML := `version: 2
vault:
  default_store: extra-store
  stores:
    local: { kind: offline_aead }
    extra-store: { kind: os_keychain }
inventory:
  known_stores: [local]
  hosts:
    h1: { address: 192.0.2.1 }
  identities:
    i1:
      user: ops
      auth:
        kind: password
        password_ref: { store: extra-store, item: pw1 }
  nodes:
    n1: { host: h1, identity: i1 }
`
	_, g, err := store.DecodeConfigDocumentYAML([]byte(unionYAML))
	if err != nil {
		t.Fatalf("KnownStores 并集解析失败: %v", err)
	}
	if !slices.Contains(g.KnownStores(), "extra-store") || !slices.Contains(g.KnownStores(), "local") {
		t.Fatalf("KnownStores 缺少并集项: %v", g.KnownStores())
	}

	// 验证 Revision == math.MaxUint64 溢出保护。
	dir, rootDir := newPrivateStoreRoot(t)
	fsPort := osfs.NewScopedRootFS()
	if err := fsPort.EnsureRoot(rootDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("version: 2\nrevision: 18446744073709551615\ninventory: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.NewYAMLInventoryStore(store.InventoryStoreSpec{ScopedFS: fsPort, RootDir: rootDir})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := st.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CommitCAS(context.Background(), snap.Revision(), tck.MustGraph(t, "cap")); !errors.Is(err, ports.ErrInvalidRevision) {
		t.Fatalf("MaxUint64 Revision CommitCAS 返回 %v, 期望 ErrInvalidRevision", err)
	}
}

// TestSymlinkFailClosedAndWALIntegrityHardening 验证 #34 Major #3 + #35 Major #1/#2：
//   - config.yaml 与 journals 悬空/存活符号链接严格返回 ErrSymlinkRejected 且不创建 .lock；
//   - 只读未命中（Load/LoadGenerations/PruneGeneration/Delete）零孤儿 .lock；
//   - 高世代 .wal 被替换为目录或符号链接时严格失败关闭（绝不静默回退 Gen 1）；
//   - 并发 Append(Gen 2) + PruneGeneration(Gen 1) + LoadGenerations 在固定条带锁下零竞态。
func TestSymlinkFailClosedAndWALIntegrityHardening(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	verifyWALNoOrphanLocksAndNonRegularFailClosed(t, ctx)
	verifyWALStripedLockConcurrency(t, ctx)
	if runtime.GOOS != "windows" {
		verifyDanglingAndLiveSymlinksFailClosed(t, ctx)
	}
}

func verifyWALNoOrphanLocksAndNonRegularFailClosed(t *testing.T, ctx context.Context) {
	t.Helper()
	dir, rootDir := newPrivateStoreRoot(t)
	fsPort := osfs.NewScopedRootFS()
	if err := fsPort.EnsureRoot(rootDir, 0o700); err != nil {
		t.Fatal(err)
	}
	journalsDir := filepath.Join(dir, "journals")
	if err := os.MkdirAll(journalsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	wal, err := store.NewWALJournalStore(store.JournalStoreSpec{ScopedFS: fsPort, RootDir: rootDir})
	if err != nil {
		t.Fatal(err)
	}
	missingID, _ := security.NewOperationIDFrom(tck.NewDeterministicEntropy(211))
	if _, err := wal.LoadGenerations(ctx, missingID); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("LoadGenerations(missing) = %v, 期望 ErrNotFound", err)
	}
	if err := wal.PruneGeneration(ctx, missingID, 1); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("PruneGeneration(missing) = %v, 期望 ErrNotFound", err)
	}
	if err := wal.Delete(ctx, missingID); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("Delete(missing) = %v, 期望 ErrNotFound", err)
	}
	entries, err := os.ReadDir(journalsDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("不存在 ID 的读/删操作不得遗留孤儿锁文件: entries=%v err=%v", entries, err)
	}

	// 健康 Gen 1 + 非常规目录占坑 Gen 2 -> ListActive/Load/LoadGenerations 一律失败关闭返回 ErrNotRegularFile。
	id, _ := security.NewOperationIDFrom(tck.NewDeterministicEntropy(212))
	if err := wal.Append(ctx, tck.MustV2JournalChainGen(t, id, 1)[0]); err != nil {
		t.Fatal(err)
	}
	gen2Rel, err := wal.JournalGenerationFile(id, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, filepath.FromSlash(gen2Rel.String())), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := wal.ListActive(ctx); !errors.Is(err, ports.ErrNotRegularFile) {
		t.Fatalf("ListActive 遇非常规高世代 .wal 返回 %v, 期望 ErrNotRegularFile", err)
	}
	if _, err := wal.LoadGenerations(ctx, id); !errors.Is(err, ports.ErrNotRegularFile) {
		t.Fatalf("LoadGenerations 遇非常规高世代 .wal 返回 %v, 期望 ErrNotRegularFile", err)
	}
}

func verifyWALStripedLockConcurrency(t *testing.T, ctx context.Context) {
	t.Helper()
	_, rootDir := newPrivateStoreRoot(t)
	wal, err := store.NewWALJournalStore(store.JournalStoreSpec{ScopedFS: osfs.NewScopedRootFS(), RootDir: rootDir})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := security.NewOperationIDFrom(tck.NewDeterministicEntropy(213))
	g1 := tck.MustV2JournalChainGen(t, id, 1)
	g2 := tck.MustV2JournalChainGen(t, id, 2)
	if err := wal.Append(ctx, g1[0]); err != nil {
		t.Fatal(err)
	}
	if err := wal.Append(ctx, g2[0]); err != nil {
		t.Fatal(err)
	}
	// 并发执行 Gen 2 续写、Gen 1 清理与 LoadGenerations，验证固定条带锁绝不发生 flock+unlink 竞态。
	err = conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(c context.Context) error { return appendAllWALRecords(c, wal, g2[1:]) }); gErr != nil {
			return gErr
		}
		if gErr := n.Go(func(c context.Context) error { return wal.PruneGeneration(c, id, 1) }); gErr != nil {
			return gErr
		}
		return n.Go(func(c context.Context) error { return loadWALRepeatedly(c, wal, id, 8) })
	})
	if err != nil {
		t.Fatalf("固定条带锁并发竞争失败: %v", err)
	}
	snaps, err := wal.LoadGenerations(ctx, id)
	if err != nil || len(snaps) != 1 || snaps[0].Generation() != 2 || len(snaps[0].Records()) != len(g2) {
		t.Fatalf("并发后 Gen 2 状态异常: snaps=%v err=%v", snaps, err)
	}
}

func loadWALRepeatedly(ctx context.Context, wal *store.WALJournalStore, id security.OperationID, count int) error {
	for range count {
		if _, err := wal.LoadGenerations(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func verifyDanglingAndLiveSymlinksFailClosed(t *testing.T, ctx context.Context) {
	t.Helper()
	dir, rootDir := newPrivateStoreRoot(t)
	fsPort := osfs.NewScopedRootFS()
	if err := fsPort.EnsureRoot(rootDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.Symlink("does_not_exist.yaml", cfgPath); err != nil {
		t.Skipf("环境不支持创建符号链接: %v", err)
	}
	inv, err := store.NewYAMLInventoryStore(store.InventoryStoreSpec{ScopedFS: fsPort, RootDir: rootDir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inv.Load(ctx); !errors.Is(err, ports.ErrSymlinkRejected) {
		t.Fatalf("悬空 config.yaml 符号链接 Load 返回 %v, 期望 ErrSymlinkRejected", err)
	}
	if _, stErr := os.Stat(filepath.Join(dir, "config.yaml.lock")); !errors.Is(stErr, os.ErrNotExist) {
		t.Fatalf("拒绝符号链接前不得创建 config.yaml.lock: stErr=%v", stErr)
	}
	// 悬空 journals 目录符号链接。
	if err := os.Symlink("missing_journals", filepath.Join(dir, "journals")); err != nil {
		t.Fatal(err)
	}
	wal, err := store.NewWALJournalStore(store.JournalStoreSpec{ScopedFS: fsPort, RootDir: rootDir})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := security.NewOperationIDFrom(tck.NewDeterministicEntropy(214))
	if _, err := wal.LoadGenerations(ctx, id); !errors.Is(err, ports.ErrSymlinkRejected) {
		t.Fatalf("悬空 journals 符号链接 LoadGenerations 返回 %v, 期望 ErrSymlinkRejected", err)
	}
	if _, err := wal.ListActive(ctx); !errors.Is(err, ports.ErrSymlinkRejected) {
		t.Fatalf("悬空 journals 符号链接 ListActive 返回 %v, 期望 ErrSymlinkRejected", err)
	}
	// 多段自定义 JournalDir（nested/journals）祖先目录为悬空符号链接时亦须失败关闭。
	if err := os.Symlink("missing_nested", filepath.Join(dir, "nested")); err != nil {
		t.Fatal(err)
	}
	nestedDir, err := pathalg.ParseLocalRootedDest("nested/journals")
	if err != nil {
		t.Fatal(err)
	}
	walNested, err := store.NewWALJournalStore(store.JournalStoreSpec{
		ScopedFS:   fsPort,
		RootDir:    rootDir,
		JournalDir: algebraic.Some(nestedDir),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := walNested.LoadGenerations(ctx, id); !errors.Is(err, ports.ErrSymlinkRejected) {
		t.Fatalf("多段 JournalDir 悬空祖先 LoadGenerations 返回 %v, 期望 ErrSymlinkRejected", err)
	}
	if _, err := walNested.ListActive(ctx); !errors.Is(err, ports.ErrSymlinkRejected) {
		t.Fatalf("多段 JournalDir 悬空祖先 ListActive 返回 %v, 期望 ErrSymlinkRejected", err)
	}
}

// TestImporterHardeningEdgeCases 验证 #34 Minor #2 / Nit #2 + #35 Minor #8：
//   - 表头 CSV 严格校验每行列数（拒绝多余尾列）；
//   - 支持任意列顺序表头（user,name,address,port）且不误判名为 "host" 的无表头 4 列数据行；
//   - 128 字节合法 NodeID 派生 HostID/IdentityID 零溢出；
//   - OpenSSHImporter 在全部 IdentityFile 均为模板时仍发出 template_cert_skipped 告警。
func TestImporterHardeningEdgeCases(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	csvImp, err := store.NewCSVImporter(store.CSVImporterSpec{})
	if err != nil {
		t.Fatal(err)
	}
	// 1. 表头 CSV 多余尾列严格拒绝。
	if _, err := csvImp.Import(ctx, "extra.csv", strings.NewReader("name,address,port,user\na,192.0.2.1,22,ops,extra_leak\n")); !errors.Is(err, ports.ErrCorruptData) {
		t.Fatalf("表头 CSV 多余尾列返回 %v, 期望 ErrCorruptData", err)
	}
	// 2. 重排表头列顺序 user,name,address,port 正常导入。
	bReordered, err := csvImp.Import(ctx, "reordered.csv", strings.NewReader("user,name,address,port\nops,edge-9,192.0.2.9,2209\n"))
	if err != nil || len(bReordered.Nodes()) != 1 || bReordered.Nodes()[0].ID().String() != "edge-9" {
		t.Fatalf("重排表头导入失败: bundle=%v err=%v", bReordered, err)
	}
	// 3. 无表头 4 列数据行首列名为 "host" 正常作为节点名导入。
	bNamedHost, err := csvImp.Import(ctx, "named_host.csv", strings.NewReader("host,192.0.2.7,22,ops\n"))
	if err != nil || len(bNamedHost.Nodes()) != 1 || bNamedHost.Nodes()[0].ID().String() != "host" {
		t.Fatalf("节点名 host 无表头 CSV 导入失败: bundle=%v err=%v", bNamedHost, err)
	}
	// 4. 128 字节最大长度合法 NodeID 在 CSV 与 OpenSSH 导入器均正常派生 <= 128 字节 HostID/IdentityID。
	longID := strings.Repeat("a", 128)
	bLongCSV, err := csvImp.Import(ctx, "long.csv", strings.NewReader("name,address,port,user\n"+longID+",192.0.2.8,22,ops\n"))
	if err != nil || len(bLongCSV.Nodes()) != 1 || len(bLongCSV.Hosts()[0].ID().String()) > 128 || len(bLongCSV.Identities()[0].ID().String()) > 128 {
		t.Fatalf("128B NodeID CSV 导入失败: bundle=%v err=%v", bLongCSV, err)
	}
	defUser, _ := option.ParseUsername("ops")
	sshImp, err := store.NewOpenSSHImporter(store.OpenSSHImporterSpec{DefaultUser: algebraic.Some(defUser)})
	if err != nil {
		t.Fatal(err)
	}
	sshCfg := "Host " + longID + "\n  HostName 192.0.2.8\n  IdentityFile ~/.ssh/id_%r\n  CertificateFile ~/.ssh/cert_%r\n"
	bLongSSH, err := sshImp.Import(ctx, "long.conf", strings.NewReader(sshCfg))
	if err != nil || len(bLongSSH.Nodes()) != 1 {
		t.Fatalf("128B NodeID OpenSSH 导入失败: bundle=%v err=%v", bLongSSH, err)
	}
	verifyOpenSSHImportWarnings(t, bLongSSH.Warnings(), []string{"template_key_skipped", "template_cert_skipped"})
}

// TestPhase5Readiness_PolicySchemaOptionsOverridesAndLoadDocument 验证 #160 Major-1：
//   - policy.guardrail.no_elicit_fallback 仅接受 deny / challenge，严格拒绝非法 "ask"；
//   - cli_default / mcp_default 对齐 engine.ParsePolicyProfile（direct_operator/strict/strict_operator/strict_agent）；
//   - ConfigDocument.Options（Tier-3 XOpsGlobal）与 GuardrailConfigDTO.NodeOverrides（标量简写 + 完整映射）编解码校验且跨 CommitCAS 完整保留；
//   - YAMLInventoryStore.LoadDocument 在目录/文件缺失、正常存在、文件损坏及零值接收者下的行为。
func TestPhase5Readiness_PolicySchemaOptionsOverridesAndLoadDocument(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	assertPolicyEnumAndOverrideValidation(t)
	assertStoreLoadDocumentAndCommitCASPreservesTopSections(t, ctx)
}

func assertPolicyEnumAndOverrideValidation(t *testing.T) {
	t.Helper()
	validYAML := `version: 2
policy:
  cli_default: strict_operator
  mcp_default: strict
  guardrail:
    approval_threshold: moderate
    no_elicit_fallback: challenge
    node_overrides:
      "staging-*": moderate
      "prod-*":
        approval_threshold: safe
        decision_floor: deny
options:
  identities_only: true
  strict_host_key_checking: accept-new
  connect_timeout: 15s
inventory: {}
`
	doc, _, err := store.DecodeConfigDocumentYAML([]byte(validYAML))
	if err != nil {
		t.Fatalf("合法 version:2 配置解码失败: %v", err)
	}
	if doc.Policy == nil || doc.Policy.Guardrail == nil || doc.Policy.Guardrail.NoElicitFallback != "challenge" {
		t.Fatalf("Policy/Guardrail 解码失配: %+v", doc.Policy)
	}
	layer, err := store.DecodeOptionLayerDTO(doc.Options)
	if err != nil || layer.IsUnset() || !layer.IdentitiesOnly().OrElse(false) {
		t.Fatalf("DecodeOptionLayerDTO 失配: layer=%+v err=%v", layer, err)
	}
	if _, err := store.EncodeOptionLayerDTO(layer); err != nil {
		t.Fatalf("EncodeOptionLayerDTO 失败: %v", err)
	}
	ov, err := store.DecodeNodeOverridesDTO(doc.Policy.Guardrail.NodeOverrides)
	if err != nil || ov.Len() != 2 {
		t.Fatalf("DecodeNodeOverridesDTO 失配: len=%d err=%v", ov.Len(), err)
	}
	if dec := ov.EvaluateNode(security.RiskModerate, security.RiskSafe, "prod-db-1"); dec.Kind() != security.DecisionKindDeny {
		t.Fatalf("prod-* 决策下限应为 Deny，实际=%s", dec.Kind())
	}
	if encOv, err := store.EncodeNodeOverridesDTO(ov); err != nil || len(encOv) != 2 || encOv["prod-*"].DecisionFloor != "deny" {
		t.Fatalf("EncodeNodeOverridesDTO 失配: %+v err=%v", encOv, err)
	}

	invalidCases := []struct {
		name string
		raw  string
	}{
		{"reject_ask_fallback", "version: 2\npolicy:\n  guardrail:\n    no_elicit_fallback: ask\ninventory: {}\n"},
		{"reject_bad_cli_profile", "version: 2\npolicy:\n  cli_default: superuser\ninventory: {}\n"},
		{"reject_bad_override_floor", "version: 2\npolicy:\n  guardrail:\n    node_overrides:\n      \"prod-*\":\n        approval_threshold: safe\n        decision_floor: allow_all\ninventory: {}\n"},
		{"reject_unknown_override_key", "version: 2\npolicy:\n  guardrail:\n    node_overrides:\n      \"prod-*\":\n        approval_threshold: safe\n        bogus: true\ninventory: {}\n"},
		{"reject_bad_global_options", "version: 2\noptions:\n  port: 0\ninventory: {}\n"},
	}
	for _, tc := range invalidCases {
		if _, _, err := store.DecodeConfigDocumentYAML([]byte(tc.raw)); !errors.Is(err, ports.ErrCorruptData) {
			t.Fatalf("%s 期望 ErrCorruptData，实际=%v", tc.name, err)
		}
	}
}

func assertStoreLoadDocumentAndCommitCASPreservesTopSections(t *testing.T, ctx context.Context) {
	t.Helper()
	var zeroStore store.YAMLInventoryStore
	if _, _, err := zeroStore.LoadDocument(ctx); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 YAMLInventoryStore.LoadDocument 期望 ErrInvalidArgument，实际=%v", err)
	}

	fsPort := osfs.NewScopedRootFS()
	dir, rootDir := newPrivateStoreRoot(t)
	s, err := store.NewYAMLInventoryStore(store.InventoryStoreSpec{ScopedFS: fsPort, RootDir: rootDir})
	if err != nil {
		t.Fatalf("NewYAMLInventoryStore: %v", err)
	}
	// 1. 缺失配置文件：返回默认 version:2 文档与空快照，且不创建任何文件。
	absentDoc, absentSnap, err := s.LoadDocument(ctx)
	if err != nil || absentDoc.Version != store.SchemaVersionV2 || len(absentSnap.Graph().Nodes()) != 0 {
		t.Fatalf("缺失文件 LoadDocument 失配: doc=%+v err=%v", absentDoc, err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "config.yaml")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("缺失文件 LoadDocument 不得创建文件: statErr=%v", statErr)
	}

	// 2. 写入含 policy.guardrail(challenge + node_overrides) 与顶层 options 的文档，验证 LoadDocument 及 CommitCAS 保留。
	seedYAML := `version: 2
policy:
  cli_default: strict_operator
  mcp_default: strict_agent
  guardrail:
    approval_threshold: moderate
    no_elicit_fallback: challenge
    node_overrides:
      "prod-*":
        approval_threshold: safe
        decision_floor: deny
options:
  forward_agent: false
  identities_only: true
inventory: {}
`
	if err := fsPort.EnsureRoot(rootDir, 0o700); err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(seedYAML), 0o600); err != nil {
		t.Fatalf("WriteFile(config.yaml): %v", err)
	}
	doc1, snap1, err := s.LoadDocument(ctx)
	if err != nil || doc1.Options == nil || doc1.Policy == nil || doc1.Policy.Guardrail == nil ||
		doc1.Policy.Guardrail.NoElicitFallback != "challenge" || len(doc1.Policy.Guardrail.NodeOverrides) != 1 {
		t.Fatalf("存在文件 LoadDocument 失配: doc=%+v err=%v", doc1, err)
	}
	if _, err := s.CommitCAS(ctx, snap1.Revision(), snap1.Graph()); err != nil {
		t.Fatalf("CommitCAS: %v", err)
	}
	doc2, _, err := s.LoadDocument(ctx)
	if err != nil || doc2.Revision != 1 || doc2.Options == nil || !*doc2.Options.IdentitiesOnly ||
		doc2.Policy == nil || doc2.Policy.Guardrail == nil ||
		doc2.Policy.Guardrail.NoElicitFallback != "challenge" || doc2.Policy.Guardrail.NodeOverrides["prod-*"].DecisionFloor != "deny" {
		t.Fatalf("CommitCAS 后必须完整保留 options 与 node_overrides: doc2=%+v err=%v", doc2, err)
	}

	// 3. 损坏文档：LoadDocument 必须失败关闭返回 ErrCorruptData。
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("version: 2\npolicy:\n  guardrail:\n    no_elicit_fallback: ask\ninventory: {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(corrupt): %v", err)
	}
	if _, _, err := s.LoadDocument(ctx); !errors.Is(err, ports.ErrCorruptData) {
		t.Fatalf("损坏文件 LoadDocument 期望 ErrCorruptData，实际=%v", err)
	}
}
