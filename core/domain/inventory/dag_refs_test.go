package inventory

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
)

func makeTestNode(t *testing.T, id, hostID, identID string, aliases []string, proxyJump string, privRef algebraic.Option[secret.Ref]) Node {
	t.Helper()
	nid, _ := ParseNodeID(id)
	hid, _ := ParseHostID(hostID)
	iid, _ := ParseIdentityID(identID)
	var als []Alias
	for _, a := range aliases {
		al, err := ParseAlias(a)
		if err != nil {
			t.Fatalf("ParseAlias(%q) 失败: %v", a, err)
		}
		als = append(als, al)
	}
	var route option.ProxyRoute = option.NewProxyUnset()
	if proxyJump != "" {
		var err error
		route, err = option.ParseProxyJump(proxyJump)
		if err != nil {
			t.Fatalf("ParseProxyJump(%q) 失败: %v", proxyJump, err)
		}
	}
	n, err := NewNode(NodeSpec{
		ID: nid, HostRef: hid, IdentityRef: iid, Aliases: als,
		Proxy: route, PrivilegePasswordRef: privRef, Origin: NewOriginManaged(),
	})
	if err != nil {
		t.Fatalf("NewNode(%q) 失败: %v", id, err)
	}
	return n
}

func TestTarjanProxyDAGCyclesMissingAndCrossNamespace(t *testing.T) {
	noneRef := algebraic.None[secret.Ref]()

	// 1. 合法跨命名空间链路：managed:app -> managed:jump(经别名 j1) -> openssh:corp-gw
	nJump := makeTestNode(t, "jump-01", "h1", "i1", []string{"j1"}, "corp-gw", noneRef)
	nApp := makeTestNode(t, "app-01", "h1", "i1", nil, "j1", noneRef)
	sshGW, err := NewOpenSSHJumpNode("corp-gw", option.NewProxyUnset())
	if err != nil {
		t.Fatalf("NewOpenSSHJumpNode 失败: %v", err)
	}
	rep, err := ValidateProxyDAG([]Node{nApp, nJump}, []OpenSSHJumpNode{sshGW}, DefaultMaxJumpDepth)
	if err != nil || rep.MaxObservedDepth != 2 {
		t.Fatalf("合法跨命名空间 DAG 失败: err=%v depth=%d", err, rep.MaxObservedDepth)
	}
	startKey, _ := NewTargetKey(NamespaceManaged, "app-01")
	assertTargetKeyCodecsAndNumericJump(t, startKey)
	chain, err := ResolveJumpDAG([]Node{nApp, nJump}, []OpenSSHJumpNode{sshGW}, startKey, DefaultMaxJumpDepth)
	if err != nil || len(chain) != 3 || chain[0].String() != "openssh:corp-gw" || chain[1].String() != "managed:jump-01" || chain[2].String() != "managed:app-01" {
		t.Fatalf("ResolveJumpDAG 跳板序异常: err=%v chain=%v", err, chain)
	}

	// 2. 跨命名空间环路：managed:a -> openssh:gw -> managed:a
	nA := makeTestNode(t, "node-a", "h1", "i1", nil, "gw", noneRef)
	pjBack, _ := option.ParseProxyJump("node-a")
	sshLoop, _ := NewOpenSSHJumpNode("gw", pjBack)
	if _, err := ValidateProxyDAG([]Node{nA}, []OpenSSHJumpNode{sshLoop}, DefaultMaxJumpDepth); !errors.Is(err, ErrProxyJumpCycle) {
		t.Fatalf("跨命名空间环路期望 ErrProxyJumpCycle，实际=%v", err)
	}

	// 3. 自环检测（通过自身别名）
	nSelf := makeTestNode(t, "self-node", "h1", "i1", []string{"s1"}, "s1", noneRef)
	if _, err := ValidateProxyDAG([]Node{nSelf}, nil, DefaultMaxJumpDepth); !errors.Is(err, ErrProxyJumpCycle) {
		t.Fatalf("别名自环期望 ErrProxyJumpCycle，实际=%v", err)
	}

	// 4. 缺失跳板引用检测
	nMiss := makeTestNode(t, "orphan", "h1", "i1", nil, "ghost-bastion", noneRef)
	if _, err := ValidateProxyDAG([]Node{nMiss}, nil, DefaultMaxJumpDepth); !errors.Is(err, ErrMissingProxyHop) {
		t.Fatalf("缺失跳板期望 ErrMissingProxyHop，实际=%v", err)
	}

	// 5. 深度超限检测（maxDepth=1 拒绝 2 跳链）
	if _, err := ValidateProxyDAG([]Node{nApp, nJump}, []OpenSSHJumpNode{sshGW}, 1); !errors.Is(err, ErrProxyJumpDepthExceeded) {
		t.Fatalf("超深链路期望 ErrProxyJumpDepthExceeded，实际=%v", err)
	}

	// 6. Alias 与已有 NodeID 碰撞检测
	nCol1 := makeTestNode(t, "box-1", "h1", "i1", nil, "", noneRef)
	nCol2 := makeTestNode(t, "box-2", "h1", "i1", []string{"box-1"}, "", noneRef)
	if _, err := ValidateProxyDAG([]Node{nCol1, nCol2}, nil, DefaultMaxJumpDepth); !errors.Is(err, ErrDuplicateAssetID) {
		t.Fatalf("别名与 NodeID 碰撞期望 ErrDuplicateAssetID，实际=%v", err)
	}
	assertDiamondAndSequentialHopDepth(t)
}

func assertDiamondAndSequentialHopDepth(t *testing.T) {
	t.Helper()
	noneRef := algebraic.None[secret.Ref]()
	// 7. 菱形 DAG 去重解析（app -> b1,b2 且 b2 -> b1）：确保线性时间且不重复发射 b1，跳数=2
	nB1 := makeTestNode(t, "b1", "h1", "i1", nil, "", noneRef)
	nB2 := makeTestNode(t, "b2", "h1", "i1", nil, "b1", noneRef)
	nB3 := makeTestNode(t, "b3", "h1", "i1", nil, "", noneRef)
	nDia := makeTestNode(t, "dia-app", "h1", "i1", nil, "b1,b2", noneRef)
	diaKey, _ := NewTargetKey(NamespaceManaged, "dia-app")
	diaRep, err := ValidateProxyDAG([]Node{nDia, nB2, nB1}, nil, 2)
	if err != nil || diaRep.MaxObservedDepth != 2 {
		t.Fatalf("菱形 DAG 跳数应为 2: err=%v depth=%d", err, diaRep.MaxObservedDepth)
	}
	diaChain, err := ResolveJumpDAG([]Node{nDia, nB2, nB1}, nil, diaKey, DefaultMaxJumpDepth)
	if err != nil || len(diaChain) != 3 || diaChain[0].Name() != "b1" || diaChain[1].Name() != "b2" || diaChain[2].Name() != "dia-app" {
		t.Fatalf("菱形 DAG 去重解析异常: err=%v chain=%v", err, diaChain)
	}

	// 8. 逗号串联多跳 ProxyJump b1,b2,b3 实际跳数为 3：maxDepth=2 必须拒绝，maxDepth=3 通过
	nSeq := makeTestNode(t, "seq-app", "h1", "i1", nil, "b1,b2,b3", noneRef)
	if _, err := ValidateProxyDAG([]Node{nSeq, nB1, nB2, nB3}, nil, 2); !errors.Is(err, ErrProxyJumpDepthExceeded) {
		t.Fatalf("ProxyJump b1,b2,b3 在 maxDepth=2 期望 ErrProxyJumpDepthExceeded，实际=%v", err)
	}
	if seqRep, err := ValidateProxyDAG([]Node{nSeq, nB1, nB2, nB3}, nil, 3); err != nil || seqRep.MaxObservedDepth != 3 {
		t.Fatalf("ProxyJump b1,b2,b3 在 maxDepth=3 期望 depth=3，实际 err=%v depth=%d", err, seqRep.MaxObservedDepth)
	}
}

func TestFiveLocationSecretAndAssetReferences(t *testing.T) {
	refs := [5]secret.Ref{
		mustSecretRef(t, "vault-a", "pw"),
		mustSecretRef(t, "vault-a", "pass"),
		mustSecretRef(t, "vault-a", "totp"),
		mustSecretRef(t, "vault-a", "chsec"),
		mustSecretRef(t, "vault-b", "sudo"),
	}
	graph, hid, hid2, bastion, app := buildFiveLocationGraph(t, refs)
	assertSecretRefLocations(t, graph, refs)
	assertDeleteProtections(t, graph, hid, hid2, bastion, app)
}

func buildFiveLocationGraph(t *testing.T, refs [5]secret.Ref) (Graph, HostID, HostID, Node, Node) {
	t.Helper()
	hid, _ := ParseHostID("h1")
	hid2, _ := ParseHostID("h2")
	ep, _ := netaddr.ParseEndpoint("192.0.2.10:22")
	h1, _ := NewHost(HostSpec{ID: hid, Endpoint: ep})
	h2, _ := NewHost(HostSpec{ID: hid2, Endpoint: ep})
	kp, _ := ParseKeyPathSpec("~/.ssh/id_ed25519")
	pb, _ := NewKeyPassphraseBinding(refs[1], mustKeyFP(t, 9))
	aPW, _ := NewAuthPassword(refs[0])
	aKey, _ := NewAuthPrivateKey(algebraic.NewNonEmpty(kp), algebraic.Some(pb), nil)
	rTOTP, _ := NewRuleTOTP(ChallengeRuleMeta{Name: "t", PromptPattern: "OTP"}, refs[2])
	rSec, _ := NewRuleSecretRef(ChallengeRuleMeta{Name: "s", PromptPattern: "PIN"}, refs[3])
	aKBI, _ := NewAuthKeyboardInteractive(algebraic.NewNonEmpty[ChallengeRule](rTOTP, rSec))
	aComp, _ := NewAuthComposite(algebraic.NewNonEmpty[AuthMethod](aPW, aKey, aKBI))
	iid, _ := ParseIdentityID("id1")
	user, _ := option.ParseUsername("ops")
	id1, _ := NewIdentity(IdentitySpec{ID: iid, User: user, Auth: aComp})
	bastion := makeTestNode(t, "bastion", "h1", "id1", []string{"b1"}, "", algebraic.None[secret.Ref]())
	app := makeTestNode(t, "app", "h1", "id1", nil, "b1", algebraic.Some(refs[4]))
	graph, err := NewGraph(GraphSpec{
		Hosts: []Host{h1, h2}, Identities: []Identity{id1}, Nodes: []Node{app, bastion},
		KnownStores: []string{"vault-a", "vault-b"},
	})
	if err != nil {
		t.Fatalf("NewGraph 失败: %v", err)
	}
	return graph, hid, hid2, bastion, app
}

func assertSecretRefLocations(t *testing.T, graph Graph, refs [5]secret.Ref) {
	t.Helper()
	wantLocs := [5]SecretRefLocation{
		SecretLocAuthPassword, SecretLocPrivateKeyPassphrase, SecretLocChallengeTOTP,
		SecretLocChallengeSecret, SecretLocNodePrivilege,
	}
	for i, ref := range refs {
		found := graph.FindSecretReferences(ref)
		if len(found) != 1 || found[0].Location != wantLocs[i] {
			t.Fatalf("凭据引用 %s 定位错误: got=%+v wantLoc=%v", ref, found, wantLocs[i])
		}
		if ok, _ := graph.CanGCSecret(ref); ok {
			t.Fatalf("被引用凭据 %s 严禁允许 GC", ref)
		}
	}
	refPend := mustSecretRef(t, "vault-b", "pending")
	if ok, _ := graph.CanGCSecret(refPend, PendingSecretRef{OwnerID: "sess-1", Ref: refPend}); ok {
		t.Fatal("待确认会话持有的凭据严禁允许 GC")
	}
	if ok, _ := graph.CanGCSecret(mustSecretRef(t, "vault-a", "unused"), PendingSecretRef{}); ok {
		t.Fatal("包含无效 PendingSecretRef 时 CanGCSecret 必须失败关闭返回 false")
	}
	if err := graph.ValidateSecretStores([]string{"vault-a", "vault-b"}, PendingSecretRef{}); !errors.Is(err, ErrInvalidGraph) {
		t.Fatalf("包含无效 PendingSecretRef 时 ValidateSecretStores 期望 ErrInvalidGraph，实际=%v", err)
	}
	if ok, _ := graph.CanGCSecret(mustSecretRef(t, "vault-a", "unused")); !ok {
		t.Fatal("无引用凭据应允许 GC")
	}
	if _, err := NewGraph(GraphSpec{MaxJumpDepth: -1}); !errors.Is(err, ErrInvalidGraph) {
		t.Fatalf("负数 MaxJumpDepth 期望 ErrInvalidGraph，实际=%v", err)
	}
	if len(graph.FindStoreReferences("vault-a")) != 4 || len(graph.FindStoreReferences("vault-b")) != 1 {
		t.Fatalf("FindStoreReferences 统计错误")
	}
	if err := graph.ValidateSecretStores([]string{"vault-a"}); !errors.Is(err, ErrUnknownSecretStore) {
		t.Fatalf("缺少 vault-b 期望 ErrUnknownSecretStore，实际=%v", err)
	}
}

func assertDeleteProtections(t *testing.T, graph Graph, hid, hid2 HostID, bastion, app Node) {
	t.Helper()
	if ok, refs := graph.CanDeleteHost(hid); ok || len(refs) != 2 {
		t.Fatalf("h1 被 2 个节点引用，不应允许删除: ok=%v refs=%+v", ok, refs)
	}
	if ok, _ := graph.CanDeleteHost(hid2); !ok {
		t.Fatal("未被引用的 h2 应允许删除")
	}
	if ok, refs := graph.CanDeleteNode(bastion.ID()); ok || len(refs) != 1 || refs[0].ViaAlias != "b1" {
		t.Fatalf("bastion 被 app 通过别名 b1 引用，不应允许删除: ok=%v refs=%+v", ok, refs)
	}
	if ok, _ := graph.CanDeleteNode(app.ID()); !ok {
		t.Fatal("未被跳板引用的 app 应允许删除")
	}
}

func TestImportBundleAndPlanImport(t *testing.T) {
	hid1, _ := ParseHostID("h1")
	hid2, _ := ParseHostID("h2")
	ep1, _ := netaddr.ParseEndpoint("192.0.2.1:22")
	ep2, _ := netaddr.ParseEndpoint("192.0.2.2:22")
	h1, _ := NewHost(HostSpec{ID: hid1, Endpoint: ep1})
	h1Conflict, _ := NewHost(HostSpec{ID: hid1, Endpoint: ep2})
	h2, _ := NewHost(HostSpec{ID: hid2, Endpoint: ep2})

	iid1, _ := ParseIdentityID("id1")
	user, _ := option.ParseUsername("ops")
	ag, _ := NewAuthAgent(algebraic.None[AgentSpec]())
	id1, _ := NewIdentity(IdentitySpec{ID: iid1, User: user, Auth: ag})

	n1 := makeTestNode(t, "n1", "h1", "id1", []string{"a1"}, "", algebraic.None[secret.Ref]())
	existing, err := NewGraph(GraphSpec{Hosts: []Host{h1}, Identities: []Identity{id1}, Nodes: []Node{n1}})
	if err != nil {
		t.Fatalf("NewGraph 失败: %v", err)
	}

	n2 := makeTestNode(t, "n2", "h2", "id1", nil, "n1", algebraic.None[secret.Ref]())
	warn, _ := NewImportWarning("skipped_option", "n2", "unsupported option ignored")
	bundle, err := NewImportBundle(ImportBundleSpec{
		SourceFormat: "openssh",
		Hosts:        []Host{h1Conflict, h2},
		Identities:   []Identity{id1},
		Nodes:        []Node{n1, n2},
		Warnings:     []ImportWarning{warn},
	})
	if err != nil {
		t.Fatalf("NewImportBundle 失败: %v", err)
	}
	// JSON/v2 往返
	raw, err := jsonv2.Marshal(bundle, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("Marshal ImportBundle 失败: %v", err)
	}
	var dec ImportBundle
	if err := jsonv2.Unmarshal(raw, &dec); err != nil || !dec.Equal(bundle) {
		t.Fatalf("ImportBundle JSON 往返失败: err=%v", err)
	}
	_ = jsontext.Null

	rep, err := PlanImport(existing, bundle)
	if err != nil {
		t.Fatalf("PlanImport 失败: %v", err)
	}
	if !rep.HasConflicts() || rep.AddCount != 2 || rep.UnchangedCount != 2 || rep.ConflictCount != 1 {
		t.Fatalf("PlanImport 统计不符合预期: %+v", rep)
	}
	assertImportAndLocationCodecs(t, rep)
	assertHostAliasAndSecretStoreImportGuards(t)
}

func assertTargetKeyCodecsAndNumericJump(t *testing.T, startKey TargetKey) {
	t.Helper()
	noneRef := algebraic.None[secret.Ref]()
	rawTK, err := jsonv2.Marshal(startKey, jsonv2.Deterministic(true))
	if err != nil || string(rawTK) != `"managed:app-01"` {
		t.Fatalf("TargetKey JSON 编码异常: raw=%s err=%v", rawTK, err)
	}
	var rtKey TargetKey
	if err := jsonv2.Unmarshal(rawTK, &rtKey); err != nil || !rtKey.Equal(startKey) {
		t.Fatalf("TargetKey JSON 往返失败: err=%v rt=%v", err, rtKey)
	}
	for _, badTK := range []string{"", "managed:none", "openssh:NONE", "badns:app", "managed:a&b"} {
		if _, err := ParseTargetKey(badTK); err == nil {
			t.Fatalf("ParseTargetKey(%q) 期望拒绝", badTK)
		}
	}
	if _, err := NewOpenSSHJumpNode("none", option.NewProxyUnset()); err == nil {
		t.Fatal("NewOpenSSHJumpNode(\"none\") 必须拒绝")
	}
	nNumJump := makeTestNode(t, "bastion.01", "h1", "i1", []string{"Prod_Jump"}, "", noneRef)
	nNumApp := makeTestNode(t, "app-num", "h1", "i1", nil, "bastion.01", noneRef)
	if numRep, err := ValidateProxyDAG([]Node{nNumApp, nNumJump}, nil, DefaultMaxJumpDepth); err != nil || numRep.MaxObservedDepth != 1 {
		t.Fatalf("数字后缀跳板 bastion.01 DAG 校验失败: err=%v rep=%+v", err, numRep)
	}
}

func assertImportAndLocationCodecs(t *testing.T, rep ImportReport) {
	t.Helper()
	rawRep, err := jsonv2.Marshal(rep, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("Marshal ImportReport 失败: %v", err)
	}
	var rtRep ImportReport
	if err := jsonv2.Unmarshal(rawRep, &rtRep); err != nil || len(rtRep.Entries) != len(rep.Entries) || rtRep.ConflictCount != rep.ConflictCount {
		t.Fatalf("ImportReport JSON 往返失败: err=%v rt=%+v", err, rtRep)
	}
	for _, loc := range []AssetRefLocation{AssetRefNodeHost, AssetRefNodeIdentity, AssetRefNodeProxyJump} {
		raw, err := loc.MarshalText()
		var dec AssetRefLocation
		if err != nil || dec.UnmarshalText(raw) != nil || dec != loc {
			t.Fatalf("AssetRefLocation(%v) 文本往返失败: raw=%q err=%v", loc, raw, err)
		}
	}
	for _, loc := range []SecretRefLocation{SecretLocAuthPassword, SecretLocPrivateKeyPassphrase, SecretLocChallengeTOTP, SecretLocChallengeSecret, SecretLocNodePrivilege} {
		raw, err := loc.MarshalText()
		var dec SecretRefLocation
		if err != nil || dec.UnmarshalText(raw) != nil || dec != loc {
			t.Fatalf("SecretRefLocation(%v) 文本往返失败: raw=%q err=%v", loc, raw, err)
		}
	}
}

func assertHostAliasAndSecretStoreImportGuards(t *testing.T) {
	t.Helper()
	ep, _ := netaddr.ParseEndpoint("192.0.2.50:22")
	hID1, _ := ParseHostID("db-1")
	hID2, _ := ParseHostID("db-2")
	alSelf, _ := ParseAlias("db-1")
	alShared, _ := ParseAlias("primary")
	if _, err := NewHost(HostSpec{ID: hID1, Endpoint: ep, Alias: algebraic.Some(alSelf)}); !errors.Is(err, ErrInvalidHost) {
		t.Fatalf("Host.Alias 与自身 HostID 重名期望 ErrInvalidHost，实际=%v", err)
	}
	h1, _ := NewHost(HostSpec{ID: hID1, Endpoint: ep, Alias: algebraic.Some(alShared)})
	h2DupAlias, _ := NewHost(HostSpec{ID: hID2, Endpoint: ep, Alias: algebraic.Some(alShared)})
	if _, err := NewGraph(GraphSpec{Hosts: []Host{h1, h2DupAlias}}); !errors.Is(err, ErrDuplicateAssetID) {
		t.Fatalf("重复 Host.Alias 在 NewGraph 期望 ErrDuplicateAssetID，实际=%v", err)
	}
	if _, err := NewImportBundle(ImportBundleSpec{SourceFormat: "csv", Hosts: []Host{h1, h2DupAlias}}); !errors.Is(err, ErrDuplicateAssetID) {
		t.Fatalf("重复 Host.Alias 在 NewImportBundle 期望 ErrDuplicateAssetID，实际=%v", err)
	}
	// PlanImport 检验跨集合 Host.Alias 冲突与 KnownStores 校验
	existing, err := NewGraph(GraphSpec{Hosts: []Host{h1}, KnownStores: []string{"vault-main"}})
	if err != nil {
		t.Fatalf("NewGraph(KnownStores) 失败: %v", err)
	}
	iid, _ := ParseIdentityID("id-ext")
	user, _ := option.ParseUsername("ops")
	pwBadStore, _ := NewAuthPassword(mustSecretRef(t, "unknown-store", "pw"))
	idBad, _ := NewIdentity(IdentitySpec{ID: iid, User: user, Auth: pwBadStore})
	bBad, err := NewImportBundle(ImportBundleSpec{SourceFormat: "openssh", Hosts: []Host{h2DupAlias}, Identities: []Identity{idBad}})
	if err != nil {
		t.Fatalf("NewImportBundle(bBad) 失败: %v", err)
	}
	rep, err := PlanImport(existing, bBad)
	if err != nil || !rep.HasConflicts() || rep.ConflictCount < 2 {
		t.Fatalf("PlanImport 期望检出 Host.Alias 冲突与未知 secret store，实际 err=%v rep=%+v", err, rep)
	}
}
