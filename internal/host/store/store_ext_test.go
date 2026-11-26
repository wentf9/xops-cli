package store_test

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/store"
	"go.uber.org/goleak"
)

// 编译期接口契约断言（ADR-006 / ADR-007 / P4-T3）。
var (
	_ ports.InventoryStore = (*store.YAMLInventoryStore)(nil)
	_ ports.JournalStore   = (*store.WALJournalStore)(nil)
	_ ports.FormatImporter = (*store.CSVImporter)(nil)
	_ ports.FormatImporter = (*store.OpenSSHImporter)(nil)
)

func newPrivateStoreRoot(t *testing.T) (string, pathalg.LocalDir) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "xops-store")
	d, err := pathalg.ParseLocalDir(dir)
	if err != nil {
		t.Fatalf("ParseLocalDir(%q) 失败: %v", dir, err)
	}
	return dir, d
}

// TestTCKInventoryStore 验证真实 YAMLInventoryStore 100% 通过 core/ports/tck 资产存储契约套件
// （含无效入参拒绝、CAS 版本推进、冲突拒绝与高并发 6 协程竞争仅 1 胜 5 冲突）。
func TestTCKInventoryStore(t *testing.T) {
	defer goleak.VerifyNone(t)
	tck.RunInventoryStoreSuite(t, func(t *testing.T) ports.InventoryStore {
		_, rootDir := newPrivateStoreRoot(t)
		st, err := store.NewYAMLInventoryStore(store.InventoryStoreSpec{
			ScopedFS: osfs.NewScopedRootFS(),
			RootDir:  rootDir,
		})
		if err != nil {
			t.Fatalf("NewYAMLInventoryStore 失败: %v", err)
		}
		return st
	})
}

// TestYAMLvNextFullLosslessRoundTripAndPreservation 验证 YAML vNext version: 2 全量变体无损往返：
//   - 覆盖全部 5 类 AuthMethod（含全部 4 类 ChallengeRule 与 algebraic.Duration 超时）、全部 4 类 ProxyRoute（含遮蔽命令槽）、
//     全部 25 项 OptionLayer 字段（含 algebraic.Duration）、LaunchProfile、4 类 NodeOrigin 与 KnownStores；
//   - 校验 CommitCAS 完整保留磁盘已有的 vault 与 policy 顶层配置段，且输出规范含 version: 2。
func TestYAMLvNextFullLosslessRoundTripAndPreservation(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	dir, rootDir := newPrivateStoreRoot(t)
	fsPort := osfs.NewScopedRootFS()
	if err := fsPort.EnsureRoot(rootDir, 0o700); err != nil {
		t.Fatalf("EnsureRoot 失败: %v", err)
	}

	// 预先写入带 vault 与 policy 顶层段的合法 YAML vNext version: 2 配置文件。
	seedYAML := `version: 2
vault:
  default_store: local-offline
  remember_prompted: ask
  stores:
    local-offline:
      kind: offline_aead
      path: ~/.xops/vault
      timeout: 5s
    os-kc:
      kind: os_keychain
policy:
  cli_default: direct_operator
  mcp_default: strict_agent
  guardrail:
    approval_threshold: moderate
    no_elicit_fallback: deny
    audit_log: ~/.xops/audit.jsonl
    protected_paths:
      - /etc/**
      - /root/**
    approval_ttl: 3m
inventory: {}
`
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(seedYAML), 0o600); err != nil {
		t.Fatalf("写入种子配置失败: %v", err)
	}

	st, err := store.NewYAMLInventoryStore(store.InventoryStoreSpec{ScopedFS: fsPort, RootDir: rootDir})
	if err != nil {
		t.Fatalf("NewYAMLInventoryStore 失败: %v", err)
	}
	snap0, err := st.Load(ctx)
	if err != nil {
		t.Fatalf("Load(seed) 失败: %v", err)
	}
	if !slices.Equal(snap0.Graph().KnownStores(), []string{"local-offline", "os-kc"}) {
		t.Fatalf("从 vault.stores 推导 KnownStores = %v, 期望 [local-offline os-kc]", snap0.Graph().KnownStores())
	}

	richGraph := buildRichInventoryGraph(t)
	out, err := st.CommitCAS(ctx, snap0.Revision(), richGraph)
	if err != nil || !out.Applied() || !out.Durable() {
		t.Fatalf("CommitCAS(richGraph) 失败: out=%v err=%v", out, err)
	}

	rawAfter, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("读取落盘 YAML 失败: %v", err)
	}
	text := string(rawAfter)
	if !strings.Contains(text, "version: 2") || !strings.Contains(text, "local-offline") || !strings.Contains(text, "approval_ttl: 3m0s") {
		t.Fatalf("落盘 YAML 未保留 version: 2 / vault / policy 顶层段:\n%s", text)
	}

	snap1, err := st.Load(ctx)
	if err != nil {
		t.Fatalf("Load(after commit) 失败: %v", err)
	}
	verifyRichGraphEqual(t, snap1.Graph(), richGraph)

	// 验证同图幂等再提交仍推进 Revision（不因内容相同导致 Revision 停滞）。
	out2, err := st.CommitCAS(ctx, snap1.Revision(), richGraph)
	if err != nil || !out2.Applied() || !out2.Durable() {
		t.Fatalf("二次 CommitCAS 失败: out=%v err=%v", out2, err)
	}
	rev2, ok := out2.Revision().Get()
	if !ok || rev2.Equal(snap1.Revision()) {
		t.Fatalf("二次 CommitCAS 必须推进 Revision: rev1=%s rev2=%s", snap1.Revision(), rev2)
	}
}

func buildRichInventoryGraph(t *testing.T) inventory.Graph {
	t.Helper()
	h1 := mustRichHost(t, "bastion-host", "198.51.100.1", 22, "bh1", "bastion", []string{"edge", "prod"})
	h2 := mustRichHost(t, "app-host", "2001:db8::10", 2222, "", "app server", []string{"app"})
	h3 := mustRichHost(t, "win-host", "app.corp.example", 2200, "wh1", "", nil)

	id1, id2, id3, id4, id5 := buildRichIdentities(t)
	nodes := buildRichNodes(t, h1.ID(), h2.ID(), h3.ID(), id1.ID(), id2.ID(), id3.ID(), id4.ID(), id5.ID())

	g, err := inventory.NewGraph(inventory.GraphSpec{
		Hosts:       []inventory.Host{h1, h2, h3},
		Identities:  []inventory.Identity{id1, id2, id3, id4, id5},
		Nodes:       nodes,
		KnownStores: []string{"local-offline", "os-kc"},
	})
	if err != nil {
		t.Fatalf("NewGraph(rich) 失败: %v", err)
	}
	return g
}

func mustRichHost(t *testing.T, idRaw, addr string, port uint16, aliasRaw, desc string, tagStrs []string) inventory.Host {
	t.Helper()
	hid, err := inventory.ParseHostID(idRaw)
	if err != nil {
		t.Fatal(err)
	}
	var aliasOpt algebraic.Option[inventory.Alias]
	if aliasRaw != "" {
		a, aErr := inventory.ParseAlias(aliasRaw)
		if aErr != nil {
			t.Fatal(aErr)
		}
		aliasOpt = algebraic.Some(a)
	}
	var tags []inventory.Tag
	for _, s := range tagStrs {
		tg, tErr := inventory.ParseTag(s)
		if tErr != nil {
			t.Fatal(tErr)
		}
		tags = append(tags, tg)
	}
	h, err := inventory.NewHost(inventory.HostSpec{
		ID: hid, Endpoint: tck.MustEndpoint(t, addr, port), Alias: aliasOpt, Description: desc, Tags: tags,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func buildRichIdentities(t *testing.T) (inventory.Identity, inventory.Identity, inventory.Identity, inventory.Identity, inventory.Identity) {
	t.Helper()
	uOps, _ := option.ParseUsername("deploy")
	authPwd, err := inventory.NewAuthPassword(tck.MustRef(t, "local-offline", "pwd-1"))
	if err != nil {
		t.Fatal(err)
	}
	kp1, _ := inventory.ParseKeyPathSpec("~/.ssh/id_ed25519")
	kp2, _ := inventory.ParseKeyPathSpec("~/.ssh/id_rsa")
	cp1, _ := inventory.ParseCertPathSpec("~/.ssh/id_ed25519-cert.pub")
	pb, err := inventory.NewKeyPassphraseBinding(tck.MustRef(t, "local-offline", "pass-1"), tck.MustFingerprint(t, tck.TestFingerprintA))
	if err != nil {
		t.Fatal(err)
	}
	neKeys, _ := algebraic.NonEmptyFromSlice([]inventory.KeyPathSpec{kp1, kp2})
	authKey, err := inventory.NewAuthPrivateKey(neKeys, algebraic.Some(pb), []inventory.CertPathSpec{cp1})
	if err != nil {
		t.Fatal(err)
	}
	agentSp, _ := inventory.ParseAgentSpec("ssh-agent://default")
	authAgent, err := inventory.NewAuthAgent(algebraic.Some(agentSp))
	if err != nil {
		t.Fatal(err)
	}
	authKI := buildRichKeyboardInteractive(t)
	neComp, _ := algebraic.NonEmptyFromSlice([]inventory.AuthMethod{authKey, authKI})
	authComp, err := inventory.NewAuthComposite(neComp)
	if err != nil {
		t.Fatal(err)
	}
	return mustIdentity(t, "id-pwd", uOps, authPwd),
		mustIdentity(t, "id-key", uOps, authKey),
		mustIdentity(t, "id-agent", uOps, authAgent),
		mustIdentity(t, "id-ki", uOps, authKI),
		mustIdentity(t, "id-comp", uOps, authComp)
}

func buildRichKeyboardInteractive(t *testing.T) *inventory.AuthKeyboardInteractive {
	t.Helper()
	r1, err := inventory.NewRuleTOTP(inventory.ChallengeRuleMeta{Name: "otp", PromptPattern: "OTP:"}, tck.MustRef(t, "os-kc", "totp-1"))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := inventory.NewRuleSecretRef(inventory.ChallengeRuleMeta{Name: "pin", PromptPattern: "PIN:", InstructionPattern: "Auth"}, tck.MustRef(t, "local-offline", "pin-1"))
	if err != nil {
		t.Fatal(err)
	}
	r3, err := inventory.NewRuleCommand(inventory.ChallengeRuleMeta{Name: "cmd", PromptPattern: "Token:"}, "ykman", []string{"oath", "code"}, algebraic.Some(algebraic.FromStdDuration(12*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	r4, err := inventory.NewRuleLoginPassword(inventory.ChallengeRuleMeta{Name: "login", PromptPattern: "Password:"})
	if err != nil {
		t.Fatal(err)
	}
	ne, _ := algebraic.NonEmptyFromSlice([]inventory.ChallengeRule{r1, r2, r3, r4})
	authKI, err := inventory.NewAuthKeyboardInteractive(ne)
	if err != nil {
		t.Fatal(err)
	}
	return authKI
}

func mustIdentity(t *testing.T, idRaw string, u option.Username, auth inventory.AuthMethod) inventory.Identity {
	t.Helper()
	iid, _ := inventory.ParseIdentityID(idRaw)
	id, err := inventory.NewIdentity(inventory.IdentitySpec{ID: iid, User: u, Auth: auth, Description: "desc-" + idRaw})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func buildRichNodes(t *testing.T, h1, h2, h3 inventory.HostID, id1, id2, id3, id4, id5 inventory.IdentityID) []inventory.Node {
	t.Helper()
	nidBastion, _ := inventory.ParseNodeID("bastion-01")
	nidApp, _ := inventory.ParseNodeID("app-01")
	nidCmd, _ := inventory.ParseNodeID("cmd-01")
	nidOff, _ := inventory.ParseNodeID("off-01")
	nidAdHoc, _ := inventory.ParseNodeID("adhoc-01")

	lpPOSIX, err := execution.POSIXLaunchProfile(execution.InterpreterSH, execution.LoginModeDisabled)
	if err != nil {
		t.Fatal(err)
	}
	lpPwsh, err := execution.NewLaunchProfile(execution.LaunchProfileSpec{
		Dialect: algebraic.Some(execution.DialectPowerShell), Interpreter: execution.InterpreterPwsh, Login: execution.LoginModeInherit,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 构造含遮蔽命令槽的 ProxyJumpChain 验证双槽无损往返。
	pj, _ := option.ParseProxyJump("bastion-01")
	pc, _ := option.ParseProxyCommand("ssh -W %h:%p gw.example")
	shadowedJump := option.ComposeProxyRoute(pj, pc)

	fullOpts := buildFullOptionLayer(t)
	origVirt, _ := inventory.NewOriginOpenSSHVirtual("app-*", "~/.ssh/config")
	origDer, _ := inventory.NewOriginOpenSSHDerived("cmd-01", "~/.ssh/config")
	origAdHoc, _ := inventory.NewOriginAdHoc(algebraic.Some(nidBastion))

	a1, _ := inventory.ParseAlias("b1")
	tg1, _ := inventory.ParseTag("tier1")

	n1 := mustNode(t, inventory.NodeSpec{
		ID: nidBastion, HostRef: h1, IdentityRef: id1, Aliases: []inventory.Alias{a1}, Tags: []inventory.Tag{tg1},
		Proxy: option.NewProxyUnset(), Execution: algebraic.Some(lpPOSIX), Options: option.UnsetOptionLayer(),
		PrivilegePasswordRef: algebraic.Some(tck.MustRef(t, "local-offline", "sudo-1")),
		Origin:               inventory.NewOriginManaged(), Description: "jump host",
	})
	n2 := mustNode(t, inventory.NodeSpec{
		ID: nidApp, HostRef: h2, IdentityRef: id2, Proxy: shadowedJump,
		Execution: algebraic.Some(lpPwsh), Options: fullOpts, Origin: origVirt,
	})
	n3 := mustNode(t, inventory.NodeSpec{
		ID: nidCmd, HostRef: h3, IdentityRef: id3, Proxy: pc, Options: option.UnsetOptionLayer(), Origin: origDer,
	})
	n4 := mustNode(t, inventory.NodeSpec{
		ID: nidOff, HostRef: h3, IdentityRef: id4, Proxy: option.NewProxyJumpDisabled(),
		Options: option.UnsetOptionLayer(), Origin: inventory.NewOriginManaged(),
	})
	n5 := mustNode(t, inventory.NodeSpec{
		ID: nidAdHoc, HostRef: h1, IdentityRef: id5, Proxy: option.NewProxyDisabled(),
		Options: option.UnsetOptionLayer(), Origin: origAdHoc,
	})
	return []inventory.Node{n1, n2, n3, n4, n5}
}

func buildFullOptionLayer(t *testing.T) option.OptionLayer {
	t.Helper()
	l, err := option.ParseOptionLayer(
		"HostName %h.corp.example",
		"Port 2244",
		"User secops",
		"ControlMaster autoask",
		"ControlPath ~/.xops/cm-%C",
		"ControlPersist 10m",
		"ConnectTimeout 15",
		"ServerAliveInterval 30",
		"ServerAliveCountMax 4",
		"Ciphers +aes256-ctr",
		"MACs -*sha1*",
		"KexAlgorithms ^curve25519-sha256",
		"HostKeyAlgorithms ssh-ed25519,rsa-sha2-512",
		"IdentityFile ~/.ssh/id_a",
		"IdentityFile none",
		"CertificateFile ~/.ssh/cert_a",
		"IdentitiesOnly yes",
		"BatchMode yes",
		"StrictHostKeyChecking accept-new",
		"UserKnownHostsFile ~/.ssh/kh1 ~/.ssh/kh2",
		"ForwardAgent yes",
		"SendEnv LANG LC_* FOO",
		"SendEnv -LC_TIME -FOO BAR",
		"PermitLocalCommand yes",
		"LocalCommand echo ok-%h",
	)
	if err != nil {
		t.Fatalf("ParseOptionLayer(full) 失败: %v", err)
	}
	return l
}

func mustNode(t *testing.T, spec inventory.NodeSpec) inventory.Node {
	t.Helper()
	n, err := inventory.NewNode(spec)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func verifyRichGraphEqual(t *testing.T, got, want inventory.Graph) {
	t.Helper()
	if !slices.EqualFunc(got.Hosts(), want.Hosts(), inventory.Host.Equal) {
		t.Fatalf("Hosts 往返不一致: got=%d want=%d", len(got.Hosts()), len(want.Hosts()))
	}
	if !slices.EqualFunc(got.Identities(), want.Identities(), inventory.Identity.Equal) {
		t.Fatalf("Identities 往返不一致: got=%d want=%d", len(got.Identities()), len(want.Identities()))
	}
	if !slices.EqualFunc(got.Nodes(), want.Nodes(), inventory.Node.Equal) {
		t.Fatalf("Nodes 往返不一致: got=%d want=%d", len(got.Nodes()), len(want.Nodes()))
	}
	if !slices.Equal(got.KnownStores(), want.KnownStores()) {
		t.Fatalf("KnownStores 往返不一致: got=%v want=%v", got.KnownStores(), want.KnownStores())
	}
}

// TestYAMLRejectsV1AndMalformedConfigsFailClosed 验证 100% 零 v1 兼容：
// 拒绝 version: 1、缺失 version、v1 字段、未知字段、重复键、多文档 YAML、孤立口令引用与零端口。
func TestYAMLRejectsV1AndMalformedConfigsFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	badDocs := []struct {
		name string
		yaml string
		want error
	}{
		{"v1_schema", "version: 1\ninventory: {}\n", store.ErrUnsupportedSchemaVersion},
		{"missing_version", "inventory: {}\n", store.ErrUnsupportedSchemaVersion},
		{"v3_schema", "version: 3\ninventory: {}\n", store.ErrUnsupportedSchemaVersion},
		{"unknown_v1_field", "version: 2\nservers:\n  - name: old\n", ports.ErrCorruptData},
		{"trailing_doc", "version: 2\ninventory: {}\n---\nversion: 2\n", ports.ErrCorruptData},
		{"duplicate_key", "version: 2\ninventory:\n  hosts:\n    a: { address: 192.0.2.1, port: 22 }\n    a: { address: 192.0.2.2, port: 22 }\n", ports.ErrCorruptData},
		{"zero_port", "version: 2\ninventory:\n  hosts:\n    a: { address: 192.0.2.1, port: 0 }\n", ports.ErrCorruptData},
		{"half_passphrase_binding", "version: 2\ninventory:\n  identities:\n    i1:\n      user: ops\n      auth:\n        kind: private_key\n        key_paths: [~/.ssh/id_ed25519]\n        passphrase_ref: { store: local, item: p1 }\n", ports.ErrCorruptData},
		{"empty_file", "   \n", ports.ErrCorruptData},
	}
	for _, tc := range badDocs {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := store.DecodeConfigDocumentYAML([]byte(tc.yaml))
			if !errors.Is(err, ports.ErrCorruptData) || !errors.Is(err, tc.want) {
				t.Fatalf("%s 解码返回 %v, 期望同时匹配 ErrCorruptData 与 %v", tc.name, err, tc.want)
			}
		})
	}
}

// TestCASDetectsExternalEditAndClassifiesDurabilityOutcomes 验证磁盘外部编辑触发 CAS 冲突，
// 以及 AtomicReplace 故障下的 INV-F3 三态区分（NotApplied / AppliedNotDurable / OutcomeUnknown）。
func TestCASDetectsExternalEditAndClassifiesDurabilityOutcomes(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	dir, rootDir := newPrivateStoreRoot(t)
	fsPort := osfs.NewScopedRootFS()
	st, err := store.NewYAMLInventoryStore(store.InventoryStoreSpec{ScopedFS: fsPort, RootDir: rootDir})
	if err != nil {
		t.Fatalf("NewYAMLInventoryStore 失败: %v", err)
	}
	snap0, err := st.Load(ctx)
	if err != nil {
		t.Fatalf("Load(0) 失败: %v", err)
	}
	out1, err := st.CommitCAS(ctx, snap0.Revision(), tck.MustGraph(t, "v1"))
	if err != nil || !out1.Applied() || !out1.Durable() {
		t.Fatalf("CommitCAS(v1) 失败: out=%v err=%v", out1, err)
	}
	rev1, _ := out1.Revision().Get()

	// 模拟外部手工修改 config.yaml（追加注释行）：旧 Revision 必须被 CAS 拒绝。
	cfgPath := filepath.Join(dir, "config.yaml")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("读取 config.yaml 失败: %v", err)
	}
	if err := os.WriteFile(cfgPath, append(raw, []byte("# manual edit\n")...), 0o600); err != nil {
		t.Fatalf("外部修改 config.yaml 失败: %v", err)
	}
	if _, err := st.CommitCAS(ctx, rev1, tck.MustGraph(t, "v2")); !errors.Is(err, ports.ErrRevisionConflict) {
		t.Fatalf("外部编辑后 CAS 返回 %v, 期望 ErrRevisionConflict", err)
	}

	// 验证 INV-F3 DurabilityOutcome 精确分类。
	verifyDurabilityClassification(t, ctx, rootDir, "not_applied", fsm.DurabilityNotApplied)
	verifyDurabilityClassification(t, ctx, rootDir, "applied_not_durable", fsm.DurabilityAppliedNotDurable)
	verifyDurabilityClassification(t, ctx, rootDir, "unknown", fsm.DurabilityOutcomeUnknown)
}

// faultScopedFS 是测试专用的轻量 ScopedRootFS 故障注入桩（零借用 RootHandle 封装，100% 过 linearlease）。
type faultScopedFS struct {
	mode       string
	files      map[string][]byte
	readFailed bool
}

func (f *faultScopedFS) EnsureRoot(pathalg.LocalDir, fs.FileMode) error { return nil }

//xops:syncclosure
//xops:borrowed
func (f *faultScopedFS) WithRoot(_ pathalg.LocalDir, fn func(root ports.RootHandle) error) error {
	return fn(&faultRootHandle{fs: f})
}

type faultRootHandle struct{ fs *faultScopedFS }

func (h *faultRootHandle) ReadAllBounded(dest pathalg.LocalRootedDest, _ ports.ReadLimits) ([]byte, error) {
	if h.fs.readFailed {
		return nil, errors.New("simulated post-failure read error")
	}
	data, ok := h.fs.files[dest.String()]
	if !ok {
		return nil, ports.ErrNotFound
	}
	return slices.Clone(data), nil
}

//xops:syncclosure
//xops:borrowed
func (h *faultRootHandle) WithReadRegular(pathalg.LocalRootedDest, ports.ReadLimits, func(ports.BoundedReadHandle, int64) error) error {
	return ports.ErrUnsupported
}

//xops:syncclosure
//xops:borrowed
func (h *faultRootHandle) CreateExclusive(pathalg.LocalRootedDest, fs.FileMode, func(io.Writer) error) error {
	return ports.ErrUnsupported
}

//xops:syncclosure
//xops:borrowed
func (h *faultRootHandle) AtomicReplace(dest pathalg.LocalRootedDest, _ fs.FileMode, fn func(w io.Writer) error) error {
	var buf strings.Builder
	if err := fn(&buf); err != nil {
		return err
	}
	switch h.fs.mode {
	case "not_applied":
		return errors.New("simulated pre-rename write failure")
	case "applied_not_durable":
		h.fs.files[dest.String()] = []byte(buf.String())
		return errors.New("simulated post-rename dir fsync failure")
	case "unknown":
		h.fs.readFailed = true
		return errors.New("simulated io timeout")
	default:
		h.fs.files[dest.String()] = []byte(buf.String())
		return nil
	}
}

func (h *faultRootHandle) WriteChunk(pathalg.LocalRootedDest, int64, io.Reader, int64, fs.FileMode) (int64, error) {
	return 0, ports.ErrUnsupported
}
func (h *faultRootHandle) Rename(pathalg.LocalRootedDest, pathalg.LocalRootedDest) error {
	return ports.ErrUnsupported
}

//xops:syncclosure
//xops:borrowed
func (h *faultRootHandle) WithLockedFile(_ context.Context, _ pathalg.LocalRootedDest, _ ports.LockMode, _ bool, _ fs.FileMode, fn func(ports.LockedFile) error) error {
	return fn(nil)
}

//xops:syncclosure
//xops:borrowed
func (h *faultRootHandle) TryWithLockedFile(_ pathalg.LocalRootedDest, _ ports.LockMode, _ bool, _ fs.FileMode, fn func(ports.LockedFile) error) (bool, error) {
	return true, fn(nil)
}

func (h *faultRootHandle) AppendLine(pathalg.LocalRootedDest, fs.FileMode, []byte) error {
	return ports.ErrUnsupported
}
func (h *faultRootHandle) Stat(dest pathalg.LocalRootedDest) (ports.LocalFileInfo, error) {
	data, ok := h.fs.files[dest.String()]
	if !ok {
		var zero ports.LocalFileInfo
		return zero, ports.ErrNotFound
	}
	return ports.NewLocalFileInfo(ports.LocalFileInfoSpec{Name: dest.Base(), Size: int64(len(data)), Mode: 0o600})
}
func (h *faultRootHandle) Lstat(dest pathalg.LocalRootedDest) (ports.LocalFileInfo, error) {
	return h.Stat(dest)
}
func (h *faultRootHandle) ReadDir(algebraic.Option[pathalg.LocalRootedDest]) ([]ports.LocalDirEntry, error) {
	return nil, nil
}
func (h *faultRootHandle) MkdirAll(pathalg.LocalRootedDest, fs.FileMode) error { return nil }
func (h *faultRootHandle) CreateSymlink(pathalg.LocalRootedDest, string) error {
	return ports.ErrUnsupported
}
func (h *faultRootHandle) Chtimes(pathalg.LocalRootedDest, time.Time, time.Time) error {
	return ports.ErrUnsupported
}
func (h *faultRootHandle) Remove(pathalg.LocalRootedDest) error { return ports.ErrNotFound }

func verifyDurabilityClassification(t *testing.T, ctx context.Context, rootDir pathalg.LocalDir, mode string, want fsm.DurabilityStatus) {
	t.Helper()
	cfgDest, _ := pathalg.ParseLocalRootedDest("dur_" + mode + ".yaml")
	faultFS := &faultScopedFS{mode: mode, files: make(map[string][]byte)}
	st, err := store.NewYAMLInventoryStore(store.InventoryStoreSpec{
		ScopedFS: faultFS, RootDir: rootDir, ConfigFile: algebraic.Some(cfgDest),
	})
	if err != nil {
		t.Fatalf("NewYAMLInventoryStore(%s) 失败: %v", mode, err)
	}
	snap, err := st.Load(ctx)
	if err != nil {
		t.Fatalf("Load(%s) 失败: %v", mode, err)
	}
	out, cErr := st.CommitCAS(ctx, snap.Revision(), tck.MustGraph(t, mode))
	if cErr == nil || !out.IsValid() || out.Status() != want {
		t.Fatalf("故障模式 %s 返回 (status=%s, err=%v), 期望 status=%s 且非 nil error", mode, out.Status(), cErr, want)
	}
}

// TestStoreZeroValuesAndInvalidSpecsFailClosed 验证全包零值与非法构造规格严格失败关闭。
func TestStoreZeroValuesAndInvalidSpecsFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	var zInv store.YAMLInventoryStore
	if _, err := zInv.Load(ctx); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 YAMLInventoryStore.Load = %v, 期望 ErrInvalidArgument", err)
	}
	var zWal store.WALJournalStore
	if _, err := zWal.ListActive(ctx); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 WALJournalStore.ListActive = %v, 期望 ErrInvalidArgument", err)
	}
	var zCSV store.CSVImporter
	if _, err := zCSV.Import(ctx, "x", strings.NewReader("a")); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 CSVImporter.Import = %v, 期望 ErrInvalidArgument", err)
	}
	var zSSH store.OpenSSHImporter
	if _, err := zSSH.Import(ctx, "x", strings.NewReader("a")); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 OpenSSHImporter.Import = %v, 期望 ErrInvalidArgument", err)
	}
	_, rootDir := newPrivateStoreRoot(t)
	if _, err := store.NewYAMLInventoryStore(store.InventoryStoreSpec{ScopedFS: osfs.NewScopedRootFS(), RootDir: rootDir, MaxFileBytes: -1}); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("负 MaxFileBytes 期望 ErrInvalidArgument, 实际 %v", err)
	}
	if _, err := store.NewWALJournalStore(store.JournalStoreSpec{ScopedFS: osfs.NewScopedRootFS(), RootDir: rootDir, MaxFileBytes: -1}); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("负 Journal MaxFileBytes 期望 ErrInvalidArgument, 实际 %v", err)
	}
	if _, err := store.NewCSVImporter(store.CSVImporterSpec{MaxImportBytes: -1}); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("负 CSV MaxImportBytes 期望 ErrInvalidArgument, 实际 %v", err)
	}
	if _, err := store.NewOpenSSHImporter(store.OpenSSHImporterSpec{MaxImportBytes: -1}); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("负 OpenSSH MaxImportBytes 期望 ErrInvalidArgument, 实际 %v", err)
	}
}
