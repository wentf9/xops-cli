package inventory_test

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/usecase/credential"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	"github.com/wentf9/xops-cli/core/ports"
)

// 编译期契约断言：验证 *ucinv.Service 满足 credential.PendingSecretRefProvider，自定义错误满足 Unwrap 与 LocalizableNode 契约。
var (
	_ credential.PendingSecretRefProvider = (*ucinv.Service)(nil)
	_ interface{ Unwrap() error }         = (*ucinv.AssetReferencedError)(nil)
	_ interface{ Unwrap() error }         = (*ucinv.SecretReferencedError)(nil)
	_ domi18n.LocalizableNode             = (*ucinv.AssetReferencedError)(nil)
	_ domi18n.LocalizableNode             = (*ucinv.SecretReferencedError)(nil)
)

const testStoreName = "sim-aes256gcm"

type invTestHarness struct {
	clock   *sim.SimClock
	rng     *sim.SeededRand
	vault   *sim.SimVault
	store   *sim.SimInventoryStore
	cluster *sim.SimAuditCluster
	gate    *gate.Gate
	ui      *sim.SimInteractionPort
	signer  *passphraseCheckingKeySigner
	credSvc *credential.Service
	svc     *ucinv.Service
}

func zeroTest[T any]() (z T) { return z }

type passphraseCheckingKeySigner struct {
	mu          sync.Mutex
	vault       ports.SecretVault
	expected    map[string]keyPassEntry
	inspectHits atomic.Int32
}

type keyPassEntry struct {
	passphrase string
	fp         inventory.KeyFingerprint
}

func newPassphraseCheckingKeySigner(v ports.SecretVault) *passphraseCheckingKeySigner {
	return &passphraseCheckingKeySigner{vault: v, expected: make(map[string]keyPassEntry)}
}

func (k *passphraseCheckingKeySigner) Register(path, passphrase string, fp inventory.KeyFingerprint) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.expected[path] = keyPassEntry{passphrase: passphrase, fp: fp}
}

func (*passphraseCheckingKeySigner) ListPublicKeys(context.Context, inventory.AuthMethod) ([]ports.PublicKeyInfo, error) {
	return nil, nil
}

func (*passphraseCheckingKeySigner) Sign(context.Context, inventory.KeyFingerprint, string, []byte) (ports.Signature, error) {
	return zeroTest[ports.Signature](), ports.ErrSignerUnavailable
}

func (k *passphraseCheckingKeySigner) InspectPrivateKeyFingerprint(ctx context.Context, keyPath inventory.KeyPathSpec, passRef algebraic.Option[secret.Ref]) (inventory.KeyFingerprint, error) {
	k.inspectHits.Add(1)
	k.mu.Lock()
	entry, ok := k.expected[keyPath.String()]
	k.mu.Unlock()
	if !ok {
		return zeroTest[inventory.KeyFingerprint](), ports.ErrNotFound
	}
	ref, hasRef := passRef.Get()
	if !hasRef {
		return zeroTest[inventory.KeyFingerprint](), ports.ErrAuthFailed
	}
	var matched bool
	err := k.vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
		return secret.WithBytes([]byte(entry.passphrase), func(want *secret.SecretBox) error {
			matched = box.Equal(want)
			return nil
		})
	})
	if err != nil {
		return zeroTest[inventory.KeyFingerprint](), err
	}
	if !matched {
		return zeroTest[inventory.KeyFingerprint](), ports.ErrAuthFailed
	}
	return entry.fp, nil
}

type staticBundleImporter struct {
	format string
	bundle inventory.ImportBundle
}

func (s staticBundleImporter) Format() string { return s.format }
func (s staticBundleImporter) Import(context.Context, string, io.Reader) (inventory.ImportBundle, error) {
	return s.bundle, nil
}

func newInvHarness(t *testing.T, extraImporters []ports.FormatImporter, vhs ...ports.OpenSSHVirtualHost) *invTestHarness {
	t.Helper()
	clock := sim.NewSimClock(time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC))
	rng := sim.NewSeededRand(20261126)
	vault := sim.NewSimVault(rng.Fork())
	store, err := sim.NewSimInventoryStore(inventory.EmptyGraph())
	if err != nil {
		t.Fatalf("NewSimInventoryStore: %v", err)
	}
	procID, err := ports.ParseProcessInstanceID("proc-inv-test")
	if err != nil {
		t.Fatalf("ParseProcessInstanceID: %v", err)
	}
	cluster := sim.NewSimAuditCluster()
	sink, err := cluster.NewSink(procID)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	ui := sim.NewSimInteractionPort(true)
	pol, err := gate.NewGuardrailPolicy(gate.GuardrailPolicySpec{
		ApprovalThreshold: security.RiskDangerous, NoElicitFallback: gate.NoElicitFallbackDeny,
	})
	if err != nil {
		t.Fatalf("NewGuardrailPolicy: %v", err)
	}
	g, err := gate.NewGate(gate.GateConfig{
		Profile: gate.PolicyProfileDirectOperator, Policy: pol, AuditSink: sink, Interaction: ui, Clock: clock, Entropy: rng.Fork(),
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	signer := newPassphraseCheckingKeySigner(vault)
	importers := append([]ports.FormatImporter{sim.NewSimFormatImporter("csv")}, extraImporters...)
	var openSSH ports.OpenSSHConfigSource
	if len(vhs) > 0 {
		openSSH = sim.NewSimOpenSSHConfigSource(vhs...)
	}
	svc, err := ucinv.NewService(ucinv.ServiceConfig{
		OpenSSH: openSSH, Env: mustLocalEnv(t, nil), Store: store, Gate: g, Vault: vault,
		VaultControl: vault, KeySigner: signer, Interaction: ui, Clock: clock, Entropy: rng.Fork(),
		Importers: importers, KnownStores: []string{testStoreName},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	credSvc, err := credential.NewService(credential.ServiceConfig{
		Gate: g, Vault: vault, VaultControl: vault, Store: store,
		Interaction: ui, Clock: clock, Entropy: rng.Fork(), PendingRefs: svc,
	})
	if err != nil {
		t.Fatalf("credential.NewService: %v", err)
	}
	return &invTestHarness{clock, rng, vault, store, cluster, g, ui, signer, credSvc, svc}
}

func putTestSecret(t *testing.T, v ports.SecretVault, ref secret.Ref, plain string) {
	t.Helper()
	if err := secret.WithBytes([]byte(plain), func(box *secret.SecretBox) error {
		return v.PutAndVerify(context.Background(), ref, box)
	}); err != nil {
		t.Fatalf("PutAndVerify(%s): %v", ref, err)
	}
}

func mustTestRef(t *testing.T, key string) secret.Ref {
	t.Helper()
	ref, err := secret.NewRef(testStoreName, key)
	if err != nil {
		t.Fatalf("NewRef(%q): %v", key, err)
	}
	return ref
}

func mustTestFP(t *testing.T, seed byte) inventory.KeyFingerprint {
	t.Helper()
	var sum [32]byte
	for i := range sum {
		sum[i] = seed + byte(i)
	}
	return inventory.KeyFingerprintFromSHA256(sum)
}

func mustTestHost(t *testing.T, id, hostStr string, port uint16) inventory.Host {
	t.Helper()
	hid, err := inventory.ParseHostID(id)
	if err != nil {
		t.Fatalf("ParseHostID(%q): %v", id, err)
	}
	ch, err := netaddr.ParseCanonicalHost(hostStr)
	if err != nil {
		t.Fatalf("ParseCanonicalHost(%q): %v", hostStr, err)
	}
	ep, err := netaddr.NewEndpoint(ch, port)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	h, err := inventory.NewHost(inventory.HostSpec{ID: hid, Endpoint: ep})
	if err != nil {
		t.Fatalf("NewHost(%q): %v", id, err)
	}
	return h
}

func mustTestIdentity(t *testing.T, id, user string, auth inventory.AuthMethod) inventory.Identity {
	t.Helper()
	iid, err := inventory.ParseIdentityID(id)
	if err != nil {
		t.Fatalf("ParseIdentityID(%q): %v", id, err)
	}
	u, err := option.ParseUsername(user)
	if err != nil {
		t.Fatalf("ParseUsername(%q): %v", user, err)
	}
	ident, err := inventory.NewIdentity(inventory.IdentitySpec{ID: iid, User: u, Auth: auth})
	if err != nil {
		t.Fatalf("NewIdentity(%q): %v", id, err)
	}
	return ident
}

func mustTestNode(t *testing.T, id, hostID, identID string, aliases []string, proxy option.ProxyRoute, priv algebraic.Option[secret.Ref], origin inventory.NodeOrigin) inventory.Node {
	t.Helper()
	nid, err := inventory.ParseNodeID(id)
	if err != nil {
		t.Fatalf("ParseNodeID(%q): %v", id, err)
	}
	hid, _ := inventory.ParseHostID(hostID)
	iid, _ := inventory.ParseIdentityID(identID)
	var aliasVals []inventory.Alias
	for _, raw := range aliases {
		a, aErr := inventory.ParseAlias(raw)
		if aErr != nil {
			t.Fatalf("ParseAlias(%q): %v", raw, aErr)
		}
		aliasVals = append(aliasVals, a)
	}
	if origin == nil {
		origin = inventory.NewOriginManaged()
	}
	n, err := inventory.NewNode(inventory.NodeSpec{
		ID: nid, HostRef: hid, IdentityRef: iid, Aliases: aliasVals, Proxy: proxy, PrivilegePasswordRef: priv, Origin: origin,
	})
	if err != nil {
		t.Fatalf("NewNode(%q): %v", id, err)
	}
	return n
}

func mustAgentAuth(t *testing.T) inventory.AuthMethod {
	t.Helper()
	a, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	if err != nil {
		t.Fatalf("NewAuthAgent: %v", err)
	}
	return a
}

func TestResolveTarget_ManagedAndCrossNamespaceProxyJump(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	oshLayer := option.UnsetOptionLayer().WithProxyRoute(mustProxyJump(t, "m-jump")).WithForwardAgent(true)
	oshBastion := mustVirtualHost(t, "osh-bastion", "198.51.100.20", 2222, "bastion", oshLayer)
	derivedBase := mustVirtualHost(t, "osh-derived-base", "198.51.100.30", 2202, "derived-t4", option.UnsetOptionLayer().WithForwardAgent(true))
	h := newInvHarness(t, nil, oshBastion, derivedBase)

	hJump := mustTestHost(t, "h-jump", "198.51.100.10", 2201)
	hApp := mustTestHost(t, "h-app", "198.51.100.30", 2202)
	idOps := mustTestIdentity(t, "id-ops", "ops", mustAgentAuth(t))
	nJump := mustTestNode(t, "m-jump", "h-jump", "id-ops", nil, nil, algebraic.None[secret.Ref](), nil)
	nApp := mustTestNode(t, "app-node", "h-app", "id-ops", []string{"app-alias"}, mustProxyJump(t, "osh-bastion"), algebraic.None[secret.Ref](), nil)
	derivedOrigin, err := inventory.NewOriginOpenSSHDerived("osh-derived-base", "/home/localops/.ssh/config")
	if err != nil {
		t.Fatalf("NewOriginOpenSSHDerived: %v", err)
	}
	nDerived := mustTestNode(t, "derived-node", "h-app", "id-ops", nil, nil, algebraic.None[secret.Ref](), derivedOrigin)

	for _, host := range []inventory.Host{hJump, hApp} {
		if _, err := h.svc.CreateHost(ctx, ucinv.HostMutationRequest{Host: host}); err != nil {
			t.Fatalf("CreateHost: %v", err)
		}
	}
	if _, err := h.svc.CreateIdentity(ctx, ucinv.IdentityMutationRequest{Identity: idOps}); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	for _, node := range []inventory.Node{nJump, nApp, nDerived} {
		if _, err := h.svc.CreateNode(ctx, ucinv.NodeMutationRequest{Node: node}); err != nil {
			t.Fatalf("CreateNode(%s): %v", node.ID(), err)
		}
	}

	res, err := h.svc.ResolveTarget(ctx, ucinv.ResolveTargetRequest{Target: "app-alias"})
	if err != nil {
		t.Fatalf("ResolveTarget(app-alias): %v", err)
	}
	if res.NodeID() != "app-node" || res.OriginKind() != option.OriginManaged || res.Plan().Len() != 3 {
		t.Fatalf("托管节点跨命名空间跳板解析不符: id=%q origin=%s hops=%d", res.NodeID(), res.OriginKind(), res.Plan().Len())
	}
	hops := res.Plan().HopSlice()
	if hops[0].NodeID() != "m-jump" || hops[1].NodeID() != "osh-bastion" || hops[2].NodeID() != "app-node" {
		t.Fatalf("3 跳顺序错误: %s -> %s -> %s", hops[0].NodeID(), hops[1].NodeID(), hops[2].NodeID())
	}
	assertDerivedAndCrossNamespaceDeleteGuard(t, ctx, h, nJump.ID())
}

func assertDerivedAndCrossNamespaceDeleteGuard(t *testing.T, ctx context.Context, h *invTestHarness, jumpID inventory.NodeID) {
	t.Helper()
	resDerived, err := h.svc.ResolveTarget(ctx, ucinv.ResolveTargetRequest{
		Target: "derived-node", ExplicitOrigin: algebraic.Some(option.OriginOpenSSHDerived),
	})
	if err != nil || !resDerived.Policy().ForwardAgent() {
		t.Fatalf("OriginOpenSSHDerived 应继承 BaseAlias Tier-4 ForwardAgent: err=%v fa=%v", err, resDerived.Policy().ForwardAgent())
	}
	// 删除被跨命名空间 app-node -> osh-bastion -> m-jump 间接引用的 m-jump 必须被 Tarjan/DAG 校验拒绝。
	if _, err := h.svc.DeleteNode(ctx, ucinv.DeleteNodeRequest{ID: jumpID}); !errors.Is(err, inventory.ErrMissingProxyHop) {
		t.Fatalf("被跨命名空间 OpenSSH 跳板间接引用的 m-jump 应拒绝删除，实际=%v", err)
	}
}

func TestCRUD_CASRaceAndDurabilityFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	h := newInvHarness(t, nil)

	host1 := mustTestHost(t, "h1", "198.51.100.1", 22)
	r1, err := h.svc.CreateHost(ctx, ucinv.HostMutationRequest{Host: host1})
	if err != nil || !r1.IsValid() {
		t.Fatalf("CreateHost: res=%+v err=%v", r1, err)
	}
	gotHost, rev, err := h.svc.GetHost(ctx, host1.ID(), ucinv.QueryRequest{})
	if err != nil || !gotHost.Equal(host1) || !rev.Equal(r1.Revision()) {
		t.Fatalf("GetHost mismatch: err=%v rev=%v", err, rev)
	}
	// 并发 CAS 竞争：6 个协程持相同 ExpectedRevision 仅允许 1 个成功，其余 5 个严格 ErrRevisionConflict。
	assertConcurrentCASRace(t, ctx, h, rev)
	// 反向引用保护与 AppliedNotDurable / OutcomeUnknown 失败关闭审计上报。
	assertReverseRefAndUncertainDurability(t, ctx, h, host1)
}

func assertConcurrentCASRace(t *testing.T, ctx context.Context, h *invTestHarness, rev ports.Revision) {
	t.Helper()
	var wins, conflicts atomic.Int32
	if err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		for i := range 6 {
			idx := i
			if goErr := n.Go(func(c context.Context) error {
				hx := mustTestHost(t, fmt.Sprintf("race-h-%d", idx), fmt.Sprintf("198.51.100.%d", 10+idx), 22)
				_, mErr := h.svc.CreateHost(c, ucinv.HostMutationRequest{Host: hx, ExpectedRevision: algebraic.Some(rev)})
				if mErr == nil {
					wins.Add(1)
				} else if errors.Is(mErr, ports.ErrRevisionConflict) {
					conflicts.Add(1)
				}
				return nil
			}); goErr != nil {
				return goErr
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("conc.RunWait: %v", err)
	}
	if wins.Load() != 1 || conflicts.Load() != 5 {
		t.Fatalf("并发 CAS 竞争结果不符: wins=%d conflicts=%d", wins.Load(), conflicts.Load())
	}
}

func assertReverseRefAndUncertainDurability(t *testing.T, ctx context.Context, h *invTestHarness, host1 inventory.Host) {
	t.Helper()
	id1 := mustTestIdentity(t, "id1", "ops", mustAgentAuth(t))
	if _, err := h.svc.CreateIdentity(ctx, ucinv.IdentityMutationRequest{Identity: id1}); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	n1 := mustTestNode(t, "n1", "h1", "id1", nil, nil, algebraic.None[secret.Ref](), nil)
	n2 := mustTestNode(t, "n2", "h1", "id1", nil, mustProxyJump(t, "n1"), algebraic.None[secret.Ref](), nil)
	for _, n := range []inventory.Node{n1, n2} {
		if _, err := h.svc.CreateNode(ctx, ucinv.NodeMutationRequest{Node: n}); err != nil {
			t.Fatalf("CreateNode(%s): %v", n.ID(), err)
		}
	}
	_, err := h.svc.DeleteHost(ctx, ucinv.DeleteHostRequest{ID: host1.ID()})
	assertInvAssetRefErr(t, err, "host", host1.ID().String())
	_, err = h.svc.DeleteIdentity(ctx, ucinv.DeleteIdentityRequest{ID: id1.ID()})
	assertInvAssetRefErr(t, err, "identity", id1.ID().String())
	_, err = h.svc.DeleteNode(ctx, ucinv.DeleteNodeRequest{ID: n1.ID()})
	assertInvAssetRefErr(t, err, "node", n1.ID().String())

	// 注入 AppliedNotDurable：返回 ErrUncertainDurability，不删除凭据并上报 AuditOutcomeUnknown。
	uncRev, _ := ports.ParseRevision("rev-uncertain")
	uncOut, err := ports.NewDurabilityAppliedNotDurable(algebraic.Some(uncRev), "fsync failed after rename")
	if err != nil {
		t.Fatalf("NewDurabilityAppliedNotDurable: %v", err)
	}
	h.store.InjectNextDurability(uncOut)
	if _, err := h.svc.DeleteNode(ctx, ucinv.DeleteNodeRequest{ID: n2.ID()}); !errors.Is(err, ucinv.ErrUncertainDurability) {
		t.Fatalf("AppliedNotDurable 期望 ErrUncertainDurability，实际=%v", err)
	}
	var sawUnknown bool
	for _, entry := range h.cluster.Entries() {
		if entry.Outcome() == ports.AuditOutcomeUnknown {
			sawUnknown = true
		}
	}
	if !sawUnknown {
		t.Fatalf("AppliedNotDurable 必须向 AuditSink 上报 AuditOutcomeUnknown")
	}
}

func TestDAG_TarjanCycleDanglingAndDepthEnforcement(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	oshLoop := mustVirtualHost(t, "osh-loop", "198.51.100.50", 22, "ops", option.UnsetOptionLayer().WithProxyRoute(mustProxyJump(t, "m-a")))
	h := newInvHarness(t, nil, oshLoop)

	host := mustTestHost(t, "h-dag", "198.51.100.51", 22)
	ident := mustTestIdentity(t, "id-dag", "ops", mustAgentAuth(t))
	if _, err := h.svc.CreateHost(ctx, ucinv.HostMutationRequest{Host: host}); err != nil {
		t.Fatalf("CreateHost(h-dag): %v", err)
	}
	if _, err := h.svc.CreateIdentity(ctx, ucinv.IdentityMutationRequest{Identity: ident}); err != nil {
		t.Fatalf("CreateIdentity(id-dag): %v", err)
	}

	// 1. 自环拒绝。
	nSelf := mustTestNode(t, "self", "h-dag", "id-dag", nil, mustProxyJump(t, "self"), algebraic.None[secret.Ref](), nil)
	if _, err := h.svc.CreateNode(ctx, ucinv.NodeMutationRequest{Node: nSelf}); !errors.Is(err, inventory.ErrProxyJumpCycle) {
		t.Fatalf("自环应被 Tarjan DAG 拒绝，实际=%v", err)
	}
	// 2. 悬空跳板拒绝。
	nDangling := mustTestNode(t, "dang", "h-dag", "id-dag", nil, mustProxyJump(t, "no-such-hop"), algebraic.None[secret.Ref](), nil)
	if _, err := h.svc.CreateNode(ctx, ucinv.NodeMutationRequest{Node: nDangling}); !errors.Is(err, inventory.ErrMissingProxyHop) {
		t.Fatalf("悬空跳板应返回 ErrMissingProxyHop，实际=%v", err)
	}
	// 3. 跨命名空间环路（m-a -> osh-loop -> m-a）拒绝。
	nCross := mustTestNode(t, "m-a", "h-dag", "id-dag", nil, mustProxyJump(t, "osh-loop"), algebraic.None[secret.Ref](), nil)
	if _, err := h.svc.CreateNode(ctx, ucinv.NodeMutationRequest{Node: nCross}); !errors.Is(err, inventory.ErrProxyJumpCycle) {
		t.Fatalf("跨命名空间环路应返回 ErrProxyJumpCycle，实际=%v", err)
	}
	// 4. 合法链 m-a(直连) <- m-b，再通过 UpdateNode 把 m-a 指向 m-b 应被拒绝。
	nA := mustTestNode(t, "m-a", "h-dag", "id-dag", nil, nil, algebraic.None[secret.Ref](), nil)
	nB := mustTestNode(t, "m-b", "h-dag", "id-dag", nil, mustProxyJump(t, "m-a"), algebraic.None[secret.Ref](), nil)
	if _, err := h.svc.CreateNode(ctx, ucinv.NodeMutationRequest{Node: nA}); err != nil {
		t.Fatalf("CreateNode(m-a): %v", err)
	}
	if _, err := h.svc.CreateNode(ctx, ucinv.NodeMutationRequest{Node: nB}); err != nil {
		t.Fatalf("CreateNode(m-b): %v", err)
	}
	nABad := mustTestNode(t, "m-a", "h-dag", "id-dag", nil, mustProxyJump(t, "m-b"), algebraic.None[secret.Ref](), nil)
	if _, err := h.svc.UpdateNode(ctx, ucinv.NodeMutationRequest{Node: nABad}); !errors.Is(err, inventory.ErrProxyJumpCycle) {
		t.Fatalf("UpdateNode 构造 2 跳环应返回 ErrProxyJumpCycle，实际=%v", err)
	}
	rep, err := h.svc.ValidateDAG(ctx, ucinv.QueryRequest{})
	if err != nil || rep.MaxObservedDepth != 1 {
		t.Fatalf("ValidateDAG 期望有效且深度=1，实际 rep=%+v err=%v", rep, err)
	}
}

func TestDelete_FiveLocationAndPendingSecretIntegrity(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	h := newInvHarness(t, nil)

	rPwd := mustTestRef(t, "loc1-pwd")
	rKey := mustTestRef(t, "loc2-key")
	rTOTP := mustTestRef(t, "loc3-totp")
	rChal := mustTestRef(t, "loc4-chal")
	rPriv := mustTestRef(t, "loc5-priv")
	rPend := mustTestRef(t, "loc6-pend")
	for _, r := range []secret.Ref{rPwd, rKey, rTOTP, rChal, rPriv, rPend} {
		putTestSecret(t, h.vault, r, "secret-value-"+r.Item())
	}

	host := mustTestHost(t, "h-sec", "198.51.100.60", 22)
	if _, err := h.svc.CreateHost(ctx, ucinv.HostMutationRequest{Host: host}); err != nil {
		t.Fatalf("CreateHost(h-sec): %v", err)
	}

	authAll := buildFiveLocationCompositeAuth(t, rPwd, rKey, rTOTP, rChal)
	idDel := mustTestIdentity(t, "id-del", "ops", authAll)
	// idKeep 共享 rPwd 以测试安全保留；其余 rKey/rTOTP/rChal 独占可被 GC。
	authShared, err := inventory.NewAuthPassword(rPwd)
	if err != nil {
		t.Fatalf("NewAuthPassword: %v", err)
	}
	idKeep := mustTestIdentity(t, "id-keep", "ops", authShared)
	if _, err := h.svc.CreateIdentity(ctx, ucinv.IdentityMutationRequest{Identity: idDel}); err != nil {
		t.Fatalf("CreateIdentity(id-del): %v", err)
	}
	if _, err := h.svc.CreateIdentity(ctx, ucinv.IdentityMutationRequest{Identity: idKeep}); err != nil {
		t.Fatalf("CreateIdentity(id-keep): %v", err)
	}

	nPriv := mustTestNode(t, "n-priv", "h-sec", "id-keep", nil, nil, algebraic.Some(rPriv), nil)
	if _, err := h.svc.CreateNode(ctx, ucinv.NodeMutationRequest{Node: nPriv}); err != nil {
		t.Fatalf("CreateNode(n-priv): %v", err)
	}

	extraPend := []inventory.PendingSecretRef{{OwnerID: "pending:test", Ref: rPend}}
	storeRefs, err := h.svc.CheckSecretReferences(ctx, ucinv.SecretRefCheckRequest{StoreID: testStoreName, ExtraPending: extraPend})
	if err != nil || len(storeRefs) != 7 {
		t.Fatalf("全图 5 位置+Pending 应命中 7 条引用，实际=%d err=%v", len(storeRefs), err)
	}
	// RequireSecretsUnreferenced=true 在 rPwd 仍被 idKeep 共享时拒绝删除。
	_, err = h.svc.DeleteIdentity(ctx, ucinv.DeleteIdentityRequest{ID: idDel.ID(), RequireSecretsUnreferenced: true})
	assertInvSecretRefErr(t, err, rPwd.String())
	// DeleteUnusedSecrets=true 仅删除独占凭据（rKey/rTOTP/rChal），安全保留共享的 rPwd！
	delRes, err := h.svc.DeleteIdentity(ctx, ucinv.DeleteIdentityRequest{ID: idDel.ID(), DeleteUnusedSecrets: true})
	if err != nil || len(delRes.DeletedSecrets()) != 3 || len(delRes.RetainedSecrets()) != 1 || !delRes.RetainedSecrets()[0].Ref.Equal(rPwd) {
		t.Fatalf("DeleteIdentity 凭据回收摘要不符: err=%v del=%v ret=%v", err, delRes.DeletedSecrets(), delRes.RetainedSecrets())
	}
	// DeleteNode 对 rPriv 执行回收：当存在 SecretLocPending 保护时保留，解除后彻底删除。
	pendPriv := []inventory.PendingSecretRef{{OwnerID: "pending:hold-priv", Ref: rPriv}}
	_, err = h.svc.DeleteNode(ctx, ucinv.DeleteNodeRequest{ID: nPriv.ID(), RequireSecretsUnreferenced: true, ExtraPending: pendPriv})
	assertInvSecretRefErr(t, err, rPriv.String())
	dnRes, err := h.svc.DeleteNode(ctx, ucinv.DeleteNodeRequest{ID: nPriv.ID(), DeleteUnusedSecrets: true})
	if err != nil || len(dnRes.DeletedSecrets()) != 1 || !dnRes.DeletedSecrets()[0].Equal(rPriv) {
		t.Fatalf("DeleteNode 应安全回收无引用提权凭据 rPriv: err=%v del=%v", err, dnRes.DeletedSecrets())
	}
}

func assertInvAssetRefErr(t *testing.T, err error, wantKind, wantID string) {
	t.Helper()
	ae, ok := errors.AsType[*ucinv.AssetReferencedError](err)
	if !ok || !ae.IsValid() || !errors.Is(err, ucinv.ErrAssetStillReferenced) || ae.AssetKind() != wantKind || ae.AssetID() != wantID {
		t.Fatalf("期望 AssetReferencedError(%s/%s)，实际=%v", wantKind, wantID, err)
	}
	view, okV := domi18n.InspectNode(ae)
	if !okV || !errors.Is(view.Sentinel, ucinv.ErrAssetStillReferenced) || view.Message.ID() != domi18n.KeyUCInvAssetRefDetail {
		t.Fatalf("AssetReferencedError.LocalizableView 失配: ok=%v view=%+v", okV, view)
	}
	if id, okID := domi18n.ErrorID(err); !okID || id != domi18n.KeyUCInvAssetRefDetail {
		t.Fatalf("ErrorID 期望 %s，实际 ok=%v id=%s", domi18n.KeyUCInvAssetRefDetail, okID, id)
	}
	if ae.Error() != domi18n.CanonicalError(ae) || !strings.Contains(ae.Error(), wantID) {
		t.Fatalf("AssetReferencedError.Error 失配: %q", ae.Error())
	}
}

func assertInvSecretRefErr(t *testing.T, err error, wantSubj string) {
	t.Helper()
	se, ok := errors.AsType[*ucinv.SecretReferencedError](err)
	if !ok || !se.IsValid() || !errors.Is(err, ucinv.ErrSecretStillReferenced) || se.Subject() != wantSubj {
		t.Fatalf("期望 SecretReferencedError(%s)，实际=%v", wantSubj, err)
	}
	view, okV := domi18n.InspectNode(se)
	if !okV || !errors.Is(view.Sentinel, ucinv.ErrSecretStillReferenced) || view.Message.ID() != domi18n.KeyUCInvSecretRefDetail {
		t.Fatalf("SecretReferencedError.LocalizableView 失配: ok=%v view=%+v", okV, view)
	}
	if id, okID := domi18n.ErrorID(err); !okID || id != domi18n.KeyUCInvSecretRefDetail {
		t.Fatalf("ErrorID 期望 %s，实际 ok=%v id=%s", domi18n.KeyUCInvSecretRefDetail, okID, id)
	}
	if se.Error() != domi18n.CanonicalError(se) || !strings.Contains(se.Error(), wantSubj) {
		t.Fatalf("SecretReferencedError.Error 失配: %q", se.Error())
	}
}

func TestReferencedErrors_NilAndZeroLocalizableSafety(t *testing.T) {
	defer goleak.VerifyNone(t)
	var nilAsset *ucinv.AssetReferencedError
	var zeroAssetVal ucinv.AssetReferencedError
	assertInvalidRefErr(t, "nil AssetReferencedError", nilAsset, ucinv.ErrAssetStillReferenced, domi18n.KeyUCInvAssetReferenced)
	assertInvalidRefErr(t, "zero AssetReferencedError", &zeroAssetVal, ucinv.ErrAssetStillReferenced, domi18n.KeyUCInvAssetReferenced)

	var nilSec *ucinv.SecretReferencedError
	var zeroSecVal ucinv.SecretReferencedError
	assertInvalidRefErr(t, "nil SecretReferencedError", nilSec, ucinv.ErrSecretStillReferenced, domi18n.KeyUCInvSecretReferenced)
	assertInvalidRefErr(t, "zero SecretReferencedError", &zeroSecVal, ucinv.ErrSecretStillReferenced, domi18n.KeyUCInvSecretReferenced)
}

type invalidRefErrNode interface {
	error
	domi18n.LocalizableNode
	IsValid() bool
	Unwrap() error
}

func assertInvalidRefErr(t *testing.T, label string, e invalidRefErrNode, wantSentinel error, wantKey domi18n.MessageID) {
	t.Helper()
	if e.IsValid() || e.Unwrap() != nil || errors.Is(e, wantSentinel) {
		t.Fatalf("%s 必须零值失效且 Unwrap==nil", label)
	}
	if v := e.LocalizableView(); v.Sentinel != nil || !v.Message.IsValid() || v.Message.ID() != wantKey {
		t.Fatalf("%s LocalizableView 失配: %+v", label, v)
	}
	want := wantSentinel.Error()
	if e.Error() != want || domi18n.CanonicalError(e) != want {
		t.Fatalf("%s Error 失配: err=%q canon=%q want=%q", label, e.Error(), domi18n.CanonicalError(e), want)
	}
}

func buildFiveLocationCompositeAuth(t *testing.T, rPwd, rKey, rTOTP, rChal secret.Ref) inventory.AuthMethod {
	t.Helper()
	aPwd, _ := inventory.NewAuthPassword(rPwd)
	kp, _ := inventory.ParseKeyPathSpec("~/.ssh/id_ed25519")
	pb, _ := inventory.NewKeyPassphraseBinding(rKey, mustTestFP(t, 1))
	aKey, _ := inventory.NewAuthPrivateKey(algebraic.NewNonEmpty(kp), algebraic.Some(pb), nil)
	r1, _ := inventory.NewRuleTOTP(inventory.ChallengeRuleMeta{Name: "totp", PromptPattern: "OTP:"}, rTOTP)
	r2, _ := inventory.NewRuleSecretRef(inventory.ChallengeRuleMeta{Name: "pin", PromptPattern: "PIN:"}, rChal)
	aKI, _ := inventory.NewAuthKeyboardInteractive(algebraic.NewNonEmpty[inventory.ChallengeRule](r1, r2))
	comp, err := inventory.NewAuthComposite(algebraic.NewNonEmpty[inventory.AuthMethod](aPwd, aKey, aKI))
	if err != nil {
		t.Fatalf("NewAuthComposite: %v", err)
	}
	return comp
}

func TestImport_FormatImporterAndImportBundleDispatch(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	hCustom := mustTestHost(t, "c-host", "198.51.100.77", 22)
	idCustom := mustTestIdentity(t, "c-id", "deploy", mustAgentAuth(t))
	nCustom := mustTestNode(t, "c-node", "c-host", "c-id", nil, nil, algebraic.None[secret.Ref](), nil)
	customBundle, err := inventory.NewImportBundle(inventory.ImportBundleSpec{
		SourceFormat: "custom", Hosts: []inventory.Host{hCustom}, Identities: []inventory.Identity{idCustom}, Nodes: []inventory.Node{nCustom},
	})
	if err != nil {
		t.Fatalf("NewImportBundle: %v", err)
	}
	h := newInvHarness(t, []ports.FormatImporter{staticBundleImporter{format: "custom", bundle: customBundle}})
	if fmts := h.svc.SupportedImportFormats(); len(fmts) != 2 || fmts[0] != "csv" || fmts[1] != "custom" {
		t.Fatalf("SupportedImportFormats 期望 [csv custom]，实际=%v", fmts)
	}
	if _, err := h.svc.PlanImport(ctx, ucinv.ImportSourceRequest{Format: "unknown", Reader: strings.NewReader("x")}); !errors.Is(err, ucinv.ErrUnknownImportFormat) {
		t.Fatalf("未注册格式应返回 ErrUnknownImportFormat，实际=%v", err)
	}
	// CSV DryRun 不写入，真实 Apply 写入，二次导入幂等不写。
	csvData := "web1,198.51.100.71,22,ops\nweb2,198.51.100.72,2222,ops\n"
	dryRes, err := h.svc.ApplyImport(ctx, ucinv.ApplyImportRequest{
		Source: ucinv.ImportSourceRequest{Format: "csv", SourceName: "hosts.csv", Reader: strings.NewReader(csvData)}, DryRun: true,
	})
	if err != nil || dryRes.Applied() || dryRes.Report().AddCount == 0 {
		t.Fatalf("DryRun 不应写入存储: res=%+v err=%v", dryRes, err)
	}
	appRes, err := h.svc.ApplyImport(ctx, ucinv.ApplyImportRequest{
		Source: ucinv.ImportSourceRequest{Format: "csv", SourceName: "hosts.csv", Reader: strings.NewReader(csvData)},
	})
	if err != nil || !appRes.Applied() || !appRes.IsValid() {
		t.Fatalf("CSV ApplyImport 失败: err=%v", err)
	}
	idemRes, err := h.svc.ApplyImport(ctx, ucinv.ApplyImportRequest{
		Source: ucinv.ImportSourceRequest{Format: "csv", Reader: strings.NewReader(csvData)},
	})
	if err != nil || idemRes.Applied() {
		t.Fatalf("重复导入应幂等跳过: applied=%v err=%v", idemRes.Applied(), err)
	}
	// 冲突导入必须失败关闭返回 ErrImportConflict。
	conflictCSV := "web1,198.51.100.99,22,ops\n"
	if _, err := h.svc.ApplyImport(ctx, ucinv.ApplyImportRequest{
		Source: ucinv.ImportSourceRequest{Format: "csv", Reader: strings.NewReader(conflictCSV)},
	}); !errors.Is(err, ucinv.ErrImportConflict) {
		t.Fatalf("冲突导入期望 ErrImportConflict，实际=%v", err)
	}
	// 自定义 FormatImporter 与直接 ImportBundle 调度均工作。
	if res, err := h.svc.ApplyImport(ctx, ucinv.ApplyImportRequest{
		Source: ucinv.ImportSourceRequest{Format: "custom", Reader: strings.NewReader("ignored")},
	}); err != nil || !res.Applied() {
		t.Fatalf("自定义导入器失败: err=%v", err)
	}
}

func TestDoctor_ReadOnlyZeroLeakAndDiagnostics(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	shadowVH := mustVirtualHost(t, "shadowed", "198.51.100.88", 22, "ops", option.UnsetOptionLayer())
	h := newInvHarness(t, nil, shadowVH)

	const topSecret = "ULTRA-SENSITIVE-DOCTOR-PASS-99999"
	rGood := mustTestRef(t, "doc-good")
	rMiss := mustTestRef(t, "doc-missing")
	putTestSecret(t, h.vault, rGood, topSecret)

	kp, _ := inventory.ParseKeyPathSpec("~/.ssh/doc_key")
	h.signer.Register(kp.String(), topSecret, mustTestFP(t, 9))
	pbWrong, _ := inventory.NewKeyPassphraseBinding(rGood, mustTestFP(t, 2))
	aKey, _ := inventory.NewAuthPrivateKey(algebraic.NewNonEmpty(kp), algebraic.Some(pbWrong), nil)
	aPwdMiss, _ := inventory.NewAuthPassword(rMiss)
	compAuth, _ := inventory.NewAuthComposite(algebraic.NewNonEmpty[inventory.AuthMethod](aKey, aPwdMiss))

	hUsed := mustTestHost(t, "h-used", "198.51.100.81", 22)
	hUnused := mustTestHost(t, "h-unused", "198.51.100.82", 22)
	idUsed := mustTestIdentity(t, "id-used", "ops", compAuth)
	nShadow := mustTestNode(t, "shadowed", "h-used", "id-used", nil, nil, algebraic.None[secret.Ref](), nil)
	if _, err := h.svc.CreateHost(ctx, ucinv.HostMutationRequest{Host: hUsed}); err != nil {
		t.Fatalf("CreateHost(h-used): %v", err)
	}
	if _, err := h.svc.CreateHost(ctx, ucinv.HostMutationRequest{Host: hUnused}); err != nil {
		t.Fatalf("CreateHost(h-unused): %v", err)
	}
	if _, err := h.svc.CreateIdentity(ctx, ucinv.IdentityMutationRequest{Identity: idUsed}); err != nil {
		t.Fatalf("CreateIdentity(id-used): %v", err)
	}
	lastMut, err := h.svc.CreateNode(ctx, ucinv.NodeMutationRequest{Node: nShadow})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	rep, err := h.svc.Doctor(ctx, ucinv.DoctorRequest{CheckVaultSecrets: true, CheckPrivateKeys: true})
	if err != nil {
		t.Fatalf("Doctor: %v", err)
	}
	if rep.Healthy || rep.ErrorCount < 2 || rep.WarnCount < 1 || rep.InfoCount < 1 {
		t.Fatalf("Doctor 诊断计数异常: %+v", rep)
	}
	// 验证严格只读：资产 Revision 与凭据库均未被修改。
	snapAfter, _ := h.store.Load(ctx)
	if !snapAfter.Revision().Equal(lastMut.Revision()) {
		t.Fatalf("Doctor 不得修改存储 Revision")
	}
	// 验证 JSON 编码绝对不含明文。
	encoded, err := jsonv2.Marshal(rep)
	if err != nil {
		t.Fatalf("jsonv2.Marshal(DoctorReport): %v", err)
	}
	assertInvDoctorReportContract(t, encoded, topSecret, rep.Findings, []string{
		"openssh_alias_shadowed", "secret_not_found", "private_key_fingerprint_mismatch", "unused_host",
	})
}

func assertInvDoctorReportContract(t *testing.T, encoded []byte, topSecret string, findings []ucinv.DoctorFinding, wantCodes []string) {
	t.Helper()
	raw := string(encoded)
	if strings.Contains(raw, topSecret) {
		t.Fatalf("DoctorReport 泄露了机密明文!")
	}
	if strings.Contains(raw, `"Localized"`) || strings.Contains(raw, `"Cause"`) {
		t.Fatalf("DoctorReport JSON 不得暴露 json:\"-\" 双轨字段: %s", raw)
	}
	codes := make(map[string]bool, len(findings))
	for _, f := range findings {
		if msg, ok := f.Localized.Get(); !ok || !msg.IsValid() {
			t.Fatalf("DoctorFinding(%s) 必须携带有效 Localized 结构化消息: %+v", f.Code, f)
		}
		codes[f.Code] = true
	}
	for _, want := range wantCodes {
		if !codes[want] {
			t.Fatalf("Doctor 遗漏预期告警 %q，实际=%v", want, findings)
		}
	}
}
