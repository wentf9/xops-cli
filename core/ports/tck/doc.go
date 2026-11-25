// Package tck 提供面向 core/ports 全部出站端口的可复用测试契约夹具套件（Test Compatibility Kit，ADR-002 / Plan P2-T1）。
//
// 本包仅允许被测试代码导入（0 生产可达，由 xopsvet/archbound 在编译期强制），可供以下适配层直接复用：
//   - core/osfs（ScopedRootFS / OperatorReadFS / 旁路锁与崩溃清理契约）
//   - core/internal/sim（全部端口的确定性仿真适配器）
//   - internal/host/{store,openssh,vault,sys,audit}（本机真实宿主适配器）
//   - core/internal/sshnet/{dial,priv,mux,sftp}（真实 SSH / SFTP 传输适配器）
//
// 关键工程与静态分析不变量：
//   - 并发契约测试统一通过 core/conc.RunWait / RunScoped 驱动并搭配 go.uber.org/goleak 验证零协程泄漏（0 裸 go）；
//   - SecretVault 与 InteractionPort 套件严禁消费明文（零 box.Use 调用、零 fmt/testing 格式化 SecretBox），
//     且每次 secret.WithBytes 调用均严格内嵌于单个 t.Run 回调内部，避免借用 *secret.SecretBox 跨越非 syncclosure 闭包边界；
//   - 全包零行内 nolint 豁免、0 path/filepath 依赖。
package tck

import (
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
)

// BaseTime 返回 TCK 确定性基准 UTC 时间（采用纯函数避免包级可变 var，满足 xopsvet/noimplicit）。
func BaseTime() time.Time {
	return time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC)
}

const (
	// TestSecretTokenA 与 TestSecretTokenB 供 SecretVault 与 InteractionPort TCK 套件构造受管 SecretBox。
	TestSecretTokenA = "tck-secret-payload-alpha-v2"
	TestSecretTokenB = "tck-secret-payload-beta-v2"
	// TestFingerprintA 与 TestFingerprintB 为合法的 43 字符无填充 Base64 SHA-256 主机密钥指纹。
	TestFingerprintA = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	TestFingerprintB = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"
)

// VerifyNoLeaks 使用 go.uber.org/goleak 校验当前测试未残留后台协程。
func VerifyNoLeaks(t *testing.T) {
	t.Helper()
	goleak.VerifyNone(t)
}

// DeterministicEntropy 提供并发安全的确定性递增字节流，用于 TCK 测试中零隐式随机源地生成 ID 与 Nonce。
type DeterministicEntropy struct {
	mu   sync.Mutex
	next byte
}

// NewDeterministicEntropy 返回从给定非零种子字节开始的确定性熵源读取器。
func NewDeterministicEntropy(seed byte) *DeterministicEntropy {
	if seed == 0 {
		seed = 1
	}
	return &DeterministicEntropy{next: seed}
}

// Read 以互斥锁保护按确定性步进序列填充 p，永不返回全零 16 字节块；对 nil 接收者失败关闭。
func (e *DeterministicEntropy) Read(p []byte) (int, error) {
	if e == nil {
		return 0, ports.ErrInvalidArgument
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range p {
		e.next++
		if e.next == 0 {
			e.next = 1
		}
		p[i] = e.next
	}
	return len(p), nil
}

// MustEndpoint 构造合法测试端点，失败时立即终止当前测试。
func MustEndpoint(t *testing.T, host string, port uint16) netaddr.Endpoint {
	t.Helper()
	ch, err := netaddr.ParseCanonicalHost(host)
	requireNoErr(t, err, "ParseCanonicalHost")
	ep, err := netaddr.NewEndpoint(ch, port)
	requireNoErr(t, err, "NewEndpoint")
	return ep
}

// MustRef 构造合法测试机密引用。
func MustRef(t *testing.T, store, id string) secret.Ref {
	t.Helper()
	ref, err := secret.NewRef(store, id)
	requireNoErr(t, err, "secret.NewRef")
	return ref
}

// MustFingerprint 构造合法测试公钥指纹。
func MustFingerprint(t *testing.T, raw string) inventory.KeyFingerprint {
	t.Helper()
	fp, err := inventory.ParseKeyFingerprint(raw)
	requireNoErr(t, err, "ParseKeyFingerprint")
	return fp
}

// MustPublicKey 构造合法测试 PublicKeyInfo（使用不同种子区分公钥内容）。
func MustPublicKey(t *testing.T, fpRaw string, seed byte) ports.PublicKeyInfo {
	t.Helper()
	pk, err := ports.NewPublicKeyInfo(ports.PublicKeyInfoSpec{
		Algorithm:   "ssh-ed25519",
		Fingerprint: MustFingerprint(t, fpRaw),
		WireBlob:    []byte{0x00, 0x00, 0x00, 0x0b, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', seed},
		Comment:     "tck@example",
	})
	requireNoErr(t, err, "NewPublicKeyInfo")
	return pk
}

// MustGraph 构造携带指定节点标签的最小合法资产图（供 InventoryStore 契约套件使用）。
func MustGraph(t *testing.T, suffix string) inventory.Graph {
	t.Helper()
	hid, err := inventory.ParseHostID("host-" + suffix)
	requireNoErr(t, err, "ParseHostID")
	iid, err := inventory.ParseIdentityID("ident-" + suffix)
	requireNoErr(t, err, "ParseIdentityID")
	nid, err := inventory.ParseNodeID("node-" + suffix)
	requireNoErr(t, err, "ParseNodeID")
	user, err := option.ParseUsername("ops")
	requireNoErr(t, err, "ParseUsername")
	auth, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	requireNoErr(t, err, "NewAuthAgent")

	host, err := inventory.NewHost(inventory.HostSpec{ID: hid, Endpoint: MustEndpoint(t, "198.51.100.10", 22)})
	requireNoErr(t, err, "NewHost")
	ident, err := inventory.NewIdentity(inventory.IdentitySpec{ID: iid, User: user, Auth: auth})
	requireNoErr(t, err, "NewIdentity")
	node, err := inventory.NewNode(inventory.NodeSpec{
		ID: nid, HostRef: hid, IdentityRef: iid,
		Proxy: option.NewProxyUnset(), Options: option.UnsetOptionLayer(), Origin: inventory.NewOriginManaged(),
	})
	requireNoErr(t, err, "NewNode")
	graph, err := inventory.NewGraph(inventory.GraphSpec{
		Hosts: []inventory.Host{host}, Identities: []inventory.Identity{ident}, Nodes: []inventory.Node{node},
	})
	requireNoErr(t, err, "NewGraph")
	return graph
}

// MustHopAndPlan 构造合法的单跳与两跳 SealedConnectionPlan（供 DialerPort 契约套件使用）。
func MustHopAndPlan(t *testing.T) (plan.SealedConnectionPlan, plan.SealedConnectionPlan) {
	t.Helper()
	hop0 := mustHopSpec(t, 0, "bastion", "198.51.100.1", 22)
	hop1 := mustHopSpec(t, 1, "app-01", "198.51.100.2", 2222)
	single, err := plan.SealConnectionPlan(hop0)
	requireNoErr(t, err, "SealConnectionPlan(single)")
	multi, err := plan.SealConnectionPlan(hop0, hop1)
	requireNoErr(t, err, "SealConnectionPlan(multi)")
	return single, multi
}

func mustHopSpec(t *testing.T, idx uint32, nodeID, host string, port uint16) plan.HopSpec {
	t.Helper()
	ep := MustEndpoint(t, host, port)
	user, err := option.ParseUsername("deploy")
	requireNoErr(t, err, "ParseUsername")
	auth, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	requireNoErr(t, err, "NewAuthAgent")
	unset := option.UnsetOptionLayer()
	eff, err := option.ResolveEffectivePolicy(option.OriginManaged, ep, unset, unset, unset, unset)
	requireNoErr(t, err, "ResolveEffectivePolicy")
	hop, err := plan.NewHopSpecFromAuth(idx, nodeID, user, auth, eff)
	requireNoErr(t, err, "NewHopSpecFromAuth")
	return hop
}

// MustCommandPlan 构造简单的只读测试命令计划。
func MustCommandPlan(t *testing.T, cmd string) execution.CommandPlan {
	t.Helper()
	cp, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:    execution.PlanKindCommand,
		Profile: execution.DefaultServerLaunchProfile(),
		Command: cmd,
	})
	requireNoErr(t, err, "NewCommandPlan")
	return cp
}

// MustBinding 构造合法的操作绑定快照（供 Audit 与 Interaction 套件复用）。
func MustBinding(t *testing.T, tool, action string) security.OperationBinding {
	t.Helper()
	b, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute,
		Tool:       tool,
		Action:     action,
		NodeID:     "node-tck",
		Endpoint:   algebraic.Some(MustEndpoint(t, "198.51.100.10", 22)),
	})
	requireNoErr(t, err, "NewOperationBinding")
	return b
}

// MustApprovalEnvelope 构造合法的待审批挑战信封（供 InteractionPort 套件使用）。
func MustApprovalEnvelope(t *testing.T, entropy io.Reader) security.ApprovalEnvelope {
	t.Helper()
	opID, err := security.NewOperationIDFrom(entropy)
	requireNoErr(t, err, "NewOperationIDFrom")
	nonce, err := security.NewApprovalNonceFrom(entropy)
	requireNoErr(t, err, "NewApprovalNonceFrom")
	dec, err := security.NewDecisionNeedApproval(security.RiskDangerous, "tck approval required")
	requireNoErr(t, err, "NewDecisionNeedApproval")
	env, err := security.NewApprovalEnvelope(security.ApprovalEnvelopeSpec{
		OperationID:  opID,
		Binding:      MustBinding(t, "sftp", "upload"),
		Risk:         security.RiskDangerous,
		Decision:     dec,
		ScopeSummary: "upload /tmp/tck.bin to node-tck",
		IssuedAt:     BaseTime(),
		TTL:          algebraic.FromStdDuration(5 * time.Minute),
		Nonce:        nonce,
	})
	requireNoErr(t, err, "NewApprovalEnvelope")
	return env
}

// MustAuditEntry 构造合法的测试审计记录（供 AuditSink 套件使用）。
func MustAuditEntry(t *testing.T, procID ports.ProcessInstanceID, traceID security.TraceID, opID security.OperationID, phase ports.AuditPhase, outcome ports.AuditOutcome) ports.AuditEntry {
	t.Helper()
	entry, err := ports.NewAuditEntry(ports.AuditEntrySpec{
		ProcessID:   procID,
		TraceID:     traceID,
		OperationID: opID,
		Phase:       phase,
		Outcome:     outcome,
		Risk:        security.RiskSafe,
		Decision:    security.DecisionKindAllow,
		Binding:     MustBinding(t, "exec", "run"),
		Timestamp:   BaseTime(),
		Duration:    algebraic.Some(algebraic.FromStdDuration(25 * time.Millisecond)),
	})
	requireNoErr(t, err, "NewAuditEntry")
	return entry
}

// MustV2JournalChain 构造合法的 V2 哈希链式传输 Journal 记录序列（Init -> Chunk -> Verified -> CommitStarted -> Committed）。
func MustV2JournalChain(t *testing.T, transferID security.OperationID) []fsm.TransferJournalRecord {
	t.Helper()
	remote, err := pathalg.ParseRemotePath("/var/tmp/tck-upload.bin")
	requireNoErr(t, err, "ParseRemotePath")
	dest, err := fsm.NewUploadDest(remote)
	requireNoErr(t, err, "NewUploadDest")
	chunkDig := security.DigestFromSHA256(sha256.Sum256([]byte("tck-chunk-payload")))

	r1, err := fsm.NewTransferJournalRecord(fsm.TransferJournalRecordSpec{
		Version: fsm.JournalVersionV2, Generation: 1, Seq: 1, Kind: fsm.JournalRecordInit,
		TransferID: transferID, Dest: algebraic.Some(dest), TotalBytes: 17, Digest: algebraic.Some(chunkDig),
	})
	requireNoErr(t, err, "JournalInit")
	r2, err := fsm.NewTransferJournalRecord(fsm.TransferJournalRecordSpec{
		Version: fsm.JournalVersionV2, Generation: 1, Seq: 2, Kind: fsm.JournalRecordChunk,
		TransferID: transferID, Offset: 0, Length: 17, TotalBytes: 17,
		Digest: algebraic.Some(chunkDig), PrevDigest: algebraic.Some(r1.RecordDigest()),
	})
	requireNoErr(t, err, "JournalChunk")
	r3, err := fsm.NewTransferJournalRecord(fsm.TransferJournalRecordSpec{
		Version: fsm.JournalVersionV2, Generation: 1, Seq: 3, Kind: fsm.JournalRecordVerified,
		TransferID: transferID, TotalBytes: 17, Digest: algebraic.Some(chunkDig), PrevDigest: algebraic.Some(r2.RecordDigest()),
	})
	requireNoErr(t, err, "JournalVerified")
	r4, err := fsm.NewTransferJournalRecord(fsm.TransferJournalRecordSpec{
		Version: fsm.JournalVersionV2, Generation: 1, Seq: 4, Kind: fsm.JournalRecordCommitStarted,
		TransferID: transferID, TotalBytes: 17, PrevDigest: algebraic.Some(r3.RecordDigest()),
	})
	requireNoErr(t, err, "JournalCommitStarted")
	r5, err := fsm.NewTransferJournalRecord(fsm.TransferJournalRecordSpec{
		Version: fsm.JournalVersionV2, Generation: 1, Seq: 5, Kind: fsm.JournalRecordCommitted,
		TransferID: transferID, TotalBytes: 17, PrevDigest: algebraic.Some(r4.RecordDigest()),
	})
	requireNoErr(t, err, "JournalCommitted")
	return []fsm.TransferJournalRecord{r1, r2, r3, r4, r5}
}

// 内部轻量化断言辅助，统一控制各套件函数认知复杂度（gocognit <= 15）。
func requireNoErr(t *testing.T, err error, label string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s 返回非预期错误: %v", label, err)
	}
}

func requireErr(t *testing.T, err error, label string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s 期望返回错误，但得到 nil", label)
	}
}

func requireErrIs(t *testing.T, err, target error, label string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s 期望错误匹配 %v，实际得到 %v", label, target, err)
	}
}

func requireTrue(t *testing.T, cond bool, msg string) {
	t.Helper()
	if !cond {
		t.Fatal(msg)
	}
}
