package plan

import (
	"bytes"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
)

func mustHop(t *testing.T, idx uint32, nodeID, epStr, userStr string, auth inventory.AuthMethod, t1 option.OptionLayer) HopSpec {
	t.Helper()
	ep, err := netaddr.ParseEndpoint(epStr)
	if err != nil {
		t.Fatalf("ParseEndpoint(%q) 失败: %v", epStr, err)
	}
	pol, err := option.ResolveEffectivePolicy(option.OriginManaged, ep, t1, option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer())
	if err != nil {
		t.Fatalf("ResolveEffectivePolicy 失败: %v", err)
	}
	user, err := option.ParseUsername(userStr)
	if err != nil {
		t.Fatalf("ParseUsername(%q) 失败: %v", userStr, err)
	}
	hop, err := NewHopSpecFromAuth(idx, nodeID, user, auth, pol)
	if err != nil {
		t.Fatalf("NewHopSpecFromAuth 失败: %v", err)
	}
	return hop
}

func TestMerklePlanAvalanchePrefixSharingAndTamperRejection(t *testing.T) {
	if (SealedConnectionPlan{}).IsValid() || (HopSpec{}).IsValid() || (HopDigest{}).IsValid() || (PlanDigest{}).IsValid() {
		t.Fatal("零值 plan 类型均必须无效")
	}
	authA, _ := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	pwRef, _ := secret.NewRef("local", "pw1")
	authB, _ := inventory.NewAuthPassword(pwRef)

	hop0 := mustHop(t, 0, "bastion-01", "192.0.2.1:22", "jump", authA, option.UnsetOptionLayer())
	hop1A := mustHop(t, 1, "app-01", "192.0.2.10:22", "deploy", authB, option.UnsetOptionLayer())
	hop1B := mustHop(t, 1, "app-02", "192.0.2.11:22", "deploy", authB, option.UnsetOptionLayer())

	planA := mustSealPlan(t, hop0, hop1A)
	planB := mustSealPlan(t, hop0, hop1B)
	assertMerklePrefixSharing(t, planA, planB)
	assertUpstreamMutationsCascade(t, planA, hop1A, authA, authB)
	assertShadowedProxyCanonicalAndAlgoReject(t, authA)
	assertPlanCodecAndTamperRejection(t, planA, hop1A)
}

func mustSealPlan(t *testing.T, hops ...HopSpec) SealedConnectionPlan {
	t.Helper()
	pl, err := SealConnectionPlan(hops...)
	if err != nil {
		t.Fatalf("SealConnectionPlan 失败: %v", err)
	}
	return pl
}

func assertMerklePrefixSharing(t *testing.T, planA, planB SealedConnectionPlan) {
	t.Helper()
	hdA0, _ := planA.HopDigestAt(0)
	hdB0, _ := planB.HopDigestAt(0)
	hdA1, _ := planA.HopDigestAt(1)
	hdB1, _ := planB.HopDigestAt(1)
	if !hdA0.Equal(hdB0) {
		t.Fatal("共享相同上游跳板时 HopDigest[0] 必须完全一致以支持连接池前缀复用")
	}
	if hdA1.Equal(hdB1) || planA.PlanDigest().Equal(planB.PlanDigest()) {
		t.Fatal("不同目标主机必须产生不同下游 HopDigest 与 PlanDigest")
	}
	prefix1, err := planA.Prefix(1)
	if err != nil {
		t.Fatalf("Prefix(1) 失败: %v", err)
	}
	if hdP0, _ := prefix1.HopDigestAt(0); !hdP0.Equal(hdA0) {
		t.Fatal("Prefix(1) 必须保持 HopDigest[0] 完全一致")
	}
}

func assertUpstreamMutationsCascade(t *testing.T, base SealedConnectionPlan, hop1A HopSpec, authA, authB inventory.AuthMethod) {
	t.Helper()
	hdA0, _ := base.HopDigestAt(0)
	hdA1, _ := base.HopDigestAt(1)
	ciph, _ := option.ParseAlgoPolicy("aes256-gcm@openssh.com")
	kh, _ := option.ParseKnownHostsList([]string{"/etc/ssh/custom_known_hosts"})
	cpPath, _ := option.ParseControlPath("~/.xops/mux-%C")
	ef, _ := option.ParseEnvFilter("LANG LC_*")
	lc, _ := option.NewLocalSanitizedCmd("echo %h")
	mutations := []struct {
		name string
		hop0 HopSpec
	}{
		{"port", mustHop(t, 0, "bastion-01", "192.0.2.1:2222", "jump", authA, option.UnsetOptionLayer())},
		{"user", mustHop(t, 0, "bastion-01", "192.0.2.1:22", "other", authA, option.UnsetOptionLayer())},
		{"auth", mustHop(t, 0, "bastion-01", "192.0.2.1:22", "jump", authB, option.UnsetOptionLayer())},
		{"cipher", mustHop(t, 0, "bastion-01", "192.0.2.1:22", "jump", authA, option.UnsetOptionLayer().WithCiphers(ciph))},
		{"strict_hk", mustHop(t, 0, "bastion-01", "192.0.2.1:22", "jump", authA, option.UnsetOptionLayer().WithStrictHostKeyChecking(option.StrictHostKeyCheckingYes))},
		{"known_hosts", mustHop(t, 0, "bastion-01", "192.0.2.1:22", "jump", authA, option.UnsetOptionLayer().WithUserKnownHostsFiles(kh))},
		{"forward_agent", mustHop(t, 0, "bastion-01", "192.0.2.1:22", "jump", authA, option.UnsetOptionLayer().WithForwardAgent(true))},
		{"timeout", mustHop(t, 0, "bastion-01", "192.0.2.1:22", "jump", authA, option.UnsetOptionLayer().WithConnectTimeout(algebraic.FromStdDuration(10*time.Second)))},
		{"alive_count_max", mustHop(t, 0, "bastion-01", "192.0.2.1:22", "jump", authA, option.UnsetOptionLayer().WithServerAliveCountMax(7))},
		{"control", mustHop(t, 0, "bastion-01", "192.0.2.1:22", "jump", authA, option.UnsetOptionLayer().WithControlPolicy(option.UnsetControlPolicy().WithMaster(option.ControlMasterAuto).WithPath(cpPath)))},
		{"send_env", mustHop(t, 0, "bastion-01", "192.0.2.1:22", "jump", authA, option.UnsetOptionLayer().WithSendEnv(ef))},
		{"local_cmd", mustHop(t, 0, "bastion-01", "192.0.2.1:22", "jump", authA, option.UnsetOptionLayer().WithPermitLocalCommand(true).WithLocalCommand(lc))},
	}
	for _, tc := range mutations {
		mutPlan := mustSealPlan(t, tc.hop0, hop1A)
		m0, _ := mutPlan.HopDigestAt(0)
		m1, _ := mutPlan.HopDigestAt(1)
		if m0.Equal(hdA0) || m1.Equal(hdA1) || mutPlan.PlanDigest().Equal(base.PlanDigest()) {
			t.Fatalf("%s: 上游跳板变更未级联刷新下游摘要", tc.name)
		}
	}
}

func assertShadowedProxyCanonicalAndAlgoReject(t *testing.T, auth inventory.AuthMethod) {
	t.Helper()
	pj, _ := option.ParseProxyJump("bastion-01")
	pc, _ := option.ParseProxyCommand("ssh -W %h:%p gw-01")
	shadowed := option.ComposeProxyRoute(pj, pc)

	hPlain := mustHop(t, 0, "app-01", "192.0.2.10:22", "deploy", auth, option.UnsetOptionLayer().WithProxyRoute(pj))
	hShadow := mustHop(t, 0, "app-01", "192.0.2.10:22", "deploy", auth, option.UnsetOptionLayer().WithProxyRoute(shadowed))
	pPlain := mustSealPlan(t, hPlain)
	pShadow := mustSealPlan(t, hShadow)
	if pPlain.PlanDigest().Equal(pShadow.PlanDigest()) {
		t.Fatal("shadowed ProxyCommand 变更必须刷新 HopDigest 与 PlanDigest")
	}
	rawShadow, err := pShadow.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON(pShadow) 失败: %v", err)
	}
	tampered := strings.Replace(string(rawShadow), "gw-01", "gw-02", 1)
	var decPlan SealedConnectionPlan
	if err := jsonv2.Unmarshal([]byte(tampered), &decPlan); !errors.Is(err, ErrTamperedPlanDigest) {
		t.Fatalf("篡改 shadowed_cmd 期望 ErrTamperedPlanDigest，实际=%v", err)
	}

	// 校验 TransportPolicySpec JSON 解码严格复用 option.ParseAlgoPolicy 精确策略
	rawTP, err := jsonv2.Marshal(hPlain.Transport(), jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("Marshal TransportPolicySpec 失败: %v", err)
	}
	validCipher := hPlain.Transport().Ciphers()[0]
	origCiphers, _ := jsonv2.Marshal(hPlain.Transport().Ciphers(), jsonv2.Deterministic(true))
	for _, badList := range []string{
		`["aes*"]`,
		`["-` + validCipher + `"]`,
		`["+` + validCipher + `"]`,
		`["` + validCipher + `,aes128-ctr"]`,
		`["` + validCipher + ` "]`,
		`["` + validCipher + `","` + validCipher + `"]`,
		`["非法算法"]`,
	} {
		badJSON := strings.Replace(string(rawTP), `"ciphers":`+string(origCiphers), `"ciphers":`+badList, 1)
		var tp TransportPolicySpec
		if err := jsonv2.Unmarshal([]byte(badJSON), &tp); !errors.Is(err, ErrInvalidTransportPolicy) || tp.IsValid() {
			t.Fatalf("非法算法列表 %s 期望 ErrInvalidTransportPolicy，实际 err=%v valid=%v", badList, err, tp.IsValid())
		}
	}
}

func assertPlanCodecAndTamperRejection(t *testing.T, planA SealedConnectionPlan, hop1A HopSpec) {
	t.Helper()
	if _, err := SealConnectionPlan(hop1A); err == nil {
		t.Fatal("hopIndex=1 作为第 0 跳必须被拒绝")
	}
	raw, err := planA.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON 失败: %v", err)
	}
	var decoded SealedConnectionPlan
	if err := jsonv2.Unmarshal(raw, &decoded); err != nil || !decoded.Equal(planA) {
		t.Fatalf("SealedConnectionPlan JSON 往返失败: err=%v", err)
	}
	fakeDigest := PlanDigestFromSHA256([32]byte{1, 2, 3}).String()
	tampered := strings.Replace(string(raw), planA.PlanDigest().String(), fakeDigest, 1)
	if err := jsonv2.Unmarshal([]byte(tampered), &decoded); !errors.Is(err, ErrTamperedPlanDigest) {
		t.Fatalf("篡改 plan_digest 期望 ErrTamperedPlanDigest，实际=%v", err)
	}
	nullDigest := strings.Replace(string(raw), `"`+planA.PlanDigest().String()+`"`, `null`, 1)
	if err := jsonv2.Unmarshal([]byte(nullDigest), &decoded); !errors.Is(err, ErrTamperedPlanDigest) {
		t.Fatalf("置空 plan_digest 期望 ErrTamperedPlanDigest，实际=%v", err)
	}
	// 验证 HopSpec 内嵌不可变 AuthMethod 访问、非 RFC1123 OpenSSH 别名 OriginalHost、ServerAliveCountMax 投影及 auth/auth_digest 篡改拒绝
	assertHopSpecAuthAliasAndTamper(t, hop1A)
	var can1, can2 bytes.Buffer
	if err := planA.WriteCanonical(&can1); err != nil {
		t.Fatalf("WriteCanonical(planA) 失败: %v", err)
	}
	if err := planA.WriteCanonical(&can2); err != nil || !bytes.Equal(can1.Bytes(), can2.Bytes()) {
		t.Fatalf("WriteCanonical 不具备确定性: err=%v", err)
	}
}

func assertHopSpecAuthAliasAndTamper(t *testing.T, hop HopSpec) {
	t.Helper()
	if hop.Auth() == nil || !hop.Auth().IsValid() || hop.Auth().Kind() != hop.AuthKind() {
		t.Fatalf("HopSpec.Auth() 必须返回与 AuthKind 一致的有效不可变认证方式")
	}
	if hop.Transport().ServerAliveCountMax() != option.DefaultServerAliveCountMax {
		t.Fatalf("默认 ServerAliveCountMax 期望 %d，实际 %d", option.DefaultServerAliveCountMax, hop.Transport().ServerAliveCountMax())
	}
	// OpenSSH 非 RFC1123 别名 OriginalHost（如 prod_db）经 HostName 192.0.2.10 解析后完整保真透传到 HopSpec
	origAlias, err := option.ParseOriginalHost("prod_db")
	if err != nil {
		t.Fatalf("ParseOriginalHost(prod_db) 失败: %v", err)
	}
	hn, err := option.ParseHostNameSpec("192.0.2.10")
	if err != nil {
		t.Fatalf("ParseHostNameSpec 失败: %v", err)
	}
	pol, err := option.ResolveEffectivePolicyWithOriginalHost(
		option.OriginOpenSSHVirtual, origAlias, 22,
		option.UnsetOptionLayer().WithHostName(hn).WithServerAliveCountMax(5),
		option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer(),
	)
	if err != nil {
		t.Fatalf("ResolveEffectivePolicyWithOriginalHost 失败: %v", err)
	}
	user, _ := option.ParseUsername("deploy")
	hopAlias, err := NewHopSpecFromAuth(0, "prod_db", user, hop.Auth(), pol)
	if err != nil || hopAlias.OriginalHost().String() != "prod_db" || hopAlias.Endpoint().String() != "192.0.2.10:22" || hopAlias.Transport().ServerAliveCountMax() != 5 {
		t.Fatalf("别名 HopSpec 构造异常: err=%v orig=%q ep=%q aliveMax=%d", err, hopAlias.OriginalHost(), hopAlias.Endpoint(), hopAlias.Transport().ServerAliveCountMax())
	}
	rawHop, err := jsonv2.Marshal(hopAlias, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("Marshal HopSpec 失败: %v", err)
	}
	var rtHop HopSpec
	if err := jsonv2.Unmarshal(rawHop, &rtHop); err != nil || !rtHop.Equal(hopAlias) || !inventory.EqualAuthMethod(rtHop.Auth(), hopAlias.Auth()) {
		t.Fatalf("HopSpec JSON 往返失败: err=%v", err)
	}
	// 篡改 auth_digest 与真实 auth 派生产物不一致必须拒绝
	fakeAuthDigest := security.DigestFromSHA256([32]byte{0xaa}).String()
	tamperedAuth := strings.Replace(string(rawHop), hopAlias.AuthDigest().String(), fakeAuthDigest, 1)
	if err := jsonv2.Unmarshal([]byte(tamperedAuth), &rtHop); !errors.Is(err, ErrTamperedPlanDigest) || rtHop.IsValid() {
		t.Fatalf("篡改 HopSpec.auth_digest 期望 ErrTamperedPlanDigest，实际 err=%v valid=%v", err, rtHop.IsValid())
	}
	// 未知字段必须被 RejectUnknownMembers 拒绝
	extraField := strings.TrimSuffix(string(rawHop), "}") + `,"unknown_extra":1}`
	if err := jsonv2.Unmarshal([]byte(extraField), &rtHop); err == nil || rtHop.IsValid() {
		t.Fatalf("HopSpec 含未知字段必须拒绝，实际 err=%v", err)
	}
}

func TestManagedHandleGenerationBindingAndKindIsolation(t *testing.T) {
	if (ManagedHandle[KindPTY]{}).IsValid() || (ManagedHandle[KindPTY]{}).Generation() != 0 {
		t.Fatal("零值 ManagedHandle 必须无效且世代为 0")
	}
	pl, binding, hid := buildHandleFixtures(t)
	if _, err := NewManagedHandle[KindPTY](hid, 0, pl.PlanDigest(), binding); err == nil {
		t.Fatal("gen=0 的 ManagedHandle 必须拒绝")
	}
	if _, err := NewManagedHandle[KindPTY](hid, 1, PlanDigestFromSHA256([32]byte{9, 9, 9}), binding); err == nil {
		t.Fatal("PlanDigest 与 OperationBinding.PlanDigest 不一致必须拒绝")
	}
	unboundBinding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute, Tool: "terminal_session", Action: "open",
		NodeID: "web-01", PlanDigest: algebraic.None[security.Digest](),
	})
	if err != nil {
		t.Fatalf("构造未绑定 PlanDigest 的 OperationBinding 失败: %v", err)
	}
	if _, err := NewManagedHandle[KindPTY](hid, 1, pl.PlanDigest(), unboundBinding); !errors.Is(err, ErrInvalidManagedHandle) {
		t.Fatalf("缺失 PlanDigest 的 OperationBinding 期望 ErrInvalidManagedHandle，实际=%v", err)
	}
	h, err := NewManagedHandle[KindPTY](hid, 42, pl.PlanDigest(), binding)
	if err != nil || !h.IsValid() || !h.MatchesGeneration(42) || h.MatchesGeneration(41) || !h.MatchesPlan(pl.PlanDigest()) {
		t.Fatalf("ManagedHandle 构造或断言异常: err=%v", err)
	}
	assertHandleCodecsAndKindIsolation(t, h, hid)
}

func buildHandleFixtures(t *testing.T) (SealedConnectionPlan, security.OperationBinding, HandleID) {
	t.Helper()
	auth, _ := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	hop0 := mustHop(t, 0, "web-01", "192.0.2.10:22", "deploy", auth, option.UnsetOptionLayer())
	pl := mustSealPlan(t, hop0)
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute, Tool: "terminal_session", Action: "open",
		NodeID: "web-01", PlanDigest: algebraic.Some(pl.PlanDigest().SecurityDigest()),
	})
	if err != nil {
		t.Fatalf("NewOperationBinding 失败: %v", err)
	}
	hid, err := NewHandleIDFrom(bytes.NewReader([]byte("0123456789abcdef")))
	if err != nil {
		t.Fatalf("NewHandleIDFrom 失败: %v", err)
	}
	return pl, binding, hid
}

func assertHandleCodecsAndKindIsolation(t *testing.T, h ManagedHandle[KindPTY], hid HandleID) {
	t.Helper()
	tok, err := h.MarshalText()
	if err != nil || !strings.HasPrefix(string(tok), "pty:"+hid.String()+":g42:sha256:") {
		t.Fatalf("ManagedHandle MarshalText 格式异常: tok=%q err=%v", tok, err)
	}
	raw, err := jsonv2.Marshal(h, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("Marshal ManagedHandle 失败: %v", err)
	}
	var sameKind ManagedHandle[KindPTY]
	if err := jsonv2.Unmarshal(raw, &sameKind); err != nil || !sameKind.Equal(h) {
		t.Fatalf("同类别 ManagedHandle JSON 往返失败: err=%v", err)
	}
	var wrongKind ManagedHandle[KindTunnel]
	if err := jsonv2.Unmarshal(raw, &wrongKind); !errors.Is(err, ErrInvalidHandleKind) || wrongKind.IsValid() {
		t.Fatalf("跨类别句柄反序列化期望 ErrInvalidHandleKind，实际 err=%v valid=%v", err, wrongKind.IsValid())
	}
	var buf bytes.Buffer
	if err := h.WriteCanonical(&buf); err != nil || buf.Len() == 0 {
		t.Fatalf("ManagedHandle.WriteCanonical 失败: err=%v", err)
	}
}
