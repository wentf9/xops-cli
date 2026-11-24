package inventory_test

import (
	"bytes"
	"encoding"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
)

// TestExternalInterfaceContracts 在外部包编译期锁定 inventory 包全部导出类型的接口契约。
func TestExternalInterfaceContracts(t *testing.T) {
	var (
		hid inventory.HostID
		iid inventory.IdentityID
		nid inventory.NodeID
		al  inventory.Alias
		tg  inventory.Tag
		kp  inventory.KeyPathSpec
		cp  inventory.CertPathSpec
		as  inventory.AgentSpec
		fp  inventory.KeyFingerprint
		pb  inventory.KeyPassphraseBinding
		ck  inventory.ChallengeRuleKind
		ak  inventory.AuthMethodKind
		ns  inventory.NamespaceKind
		rt  inventory.RuleTOTP
		rs  inventory.RuleSecretRef
		rc  inventory.RuleCommand
		rl  inventory.RuleLoginPassword
		ap  inventory.AuthPassword
		apk inventory.AuthPrivateKey
		aa  inventory.AuthAgent
		aki inventory.AuthKeyboardInteractive
		ac  inventory.AuthComposite
		om  inventory.OriginManaged
		ov  inventory.OriginOpenSSHVirtual
		od  inventory.OriginOpenSSHDerived
		oa  inventory.OriginAdHoc
		h   inventory.Host
		id  inventory.Identity
		n   inventory.Node
		iw  inventory.ImportWarning
		ib  inventory.ImportBundle
	)
	var (
		_ encoding.TextAppender    = hid
		_ encoding.TextMarshaler   = hid
		_ encoding.TextUnmarshaler = &hid
		_ encoding.TextAppender    = iid
		_ encoding.TextMarshaler   = iid
		_ encoding.TextUnmarshaler = &iid
		_ encoding.TextAppender    = nid
		_ encoding.TextMarshaler   = nid
		_ encoding.TextUnmarshaler = &nid
		_ encoding.TextAppender    = al
		_ encoding.TextMarshaler   = al
		_ encoding.TextUnmarshaler = &al
		_ encoding.TextAppender    = tg
		_ encoding.TextMarshaler   = tg
		_ encoding.TextUnmarshaler = &tg
		_ encoding.TextAppender    = kp
		_ encoding.TextMarshaler   = kp
		_ encoding.TextUnmarshaler = &kp
		_ encoding.TextAppender    = cp
		_ encoding.TextMarshaler   = cp
		_ encoding.TextUnmarshaler = &cp
		_ encoding.TextAppender    = as
		_ encoding.TextMarshaler   = as
		_ encoding.TextUnmarshaler = &as
		_ encoding.TextAppender    = fp
		_ encoding.TextMarshaler   = fp
		_ encoding.TextUnmarshaler = &fp
		_ encoding.TextAppender    = ck
		_ encoding.TextMarshaler   = ck
		_ encoding.TextUnmarshaler = &ck
		_ encoding.TextAppender    = ak
		_ encoding.TextMarshaler   = ak
		_ encoding.TextUnmarshaler = &ak
		_ encoding.TextAppender    = ns
		_ encoding.TextMarshaler   = ns
		_ encoding.TextUnmarshaler = &ns
		_ jsonv2.MarshalerTo       = pb
		_ jsonv2.UnmarshalerFrom   = &pb
		_ inventory.ChallengeRule  = &rt
		_ inventory.ChallengeRule  = &rs
		_ inventory.ChallengeRule  = &rc
		_ inventory.ChallengeRule  = &rl
		_ jsonv2.MarshalerTo       = rt
		_ jsonv2.MarshalerTo       = rs
		_ jsonv2.MarshalerTo       = rc
		_ jsonv2.MarshalerTo       = rl
		_ inventory.AuthMethod     = &ap
		_ inventory.AuthMethod     = &apk
		_ inventory.AuthMethod     = &aa
		_ inventory.AuthMethod     = &aki
		_ inventory.AuthMethod     = &ac
		_ jsonv2.MarshalerTo       = ap
		_ jsonv2.MarshalerTo       = apk
		_ jsonv2.MarshalerTo       = aa
		_ jsonv2.MarshalerTo       = aki
		_ jsonv2.MarshalerTo       = ac
		_ inventory.NodeOrigin     = &om
		_ inventory.NodeOrigin     = &ov
		_ inventory.NodeOrigin     = &od
		_ inventory.NodeOrigin     = &oa
		_ jsonv2.MarshalerTo       = om
		_ jsonv2.MarshalerTo       = ov
		_ jsonv2.MarshalerTo       = od
		_ jsonv2.MarshalerTo       = oa
		_ jsonv2.MarshalerTo       = h
		_ jsonv2.UnmarshalerFrom   = &h
		_ jsonv2.MarshalerTo       = id
		_ jsonv2.UnmarshalerFrom   = &id
		_ jsonv2.MarshalerTo       = n
		_ jsonv2.UnmarshalerFrom   = &n
		_ jsonv2.MarshalerTo       = iw
		_ jsonv2.UnmarshalerFrom   = &iw
		_ jsonv2.MarshalerTo       = ib
		_ jsonv2.UnmarshalerFrom   = &ib
	)
}

// TestExternalInventoryContract 验证外部包经导出构造器、穷尽 switch 与图分析接口使用 inventory 契约。
func TestExternalInventoryContract(t *testing.T) {
	hid, err := inventory.ParseHostID("h-ext")
	if err != nil {
		t.Fatalf("ParseHostID 失败: %v", err)
	}
	ep, err := netaddr.ParseEndpoint("192.0.2.55:2222")
	if err != nil {
		t.Fatalf("ParseEndpoint 失败: %v", err)
	}
	host, err := inventory.NewHost(inventory.HostSpec{ID: hid, Endpoint: ep})
	if err != nil {
		t.Fatalf("NewHost 失败: %v", err)
	}
	iid, _ := inventory.ParseIdentityID("id-ext")
	user, _ := option.ParseUsername("admin")
	auth, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	if err != nil {
		t.Fatalf("NewAuthAgent 失败: %v", err)
	}
	ident, err := inventory.NewIdentity(inventory.IdentitySpec{ID: iid, User: user, Auth: auth})
	if err != nil {
		t.Fatalf("NewIdentity 失败: %v", err)
	}
	nid, _ := inventory.ParseNodeID("n-ext")
	node, err := inventory.NewNode(inventory.NodeSpec{
		ID: nid, HostRef: hid, IdentityRef: iid, Origin: inventory.NewOriginManaged(),
	})
	if err != nil {
		t.Fatalf("NewNode 失败: %v", err)
	}
	g, err := inventory.NewGraph(inventory.GraphSpec{
		Hosts: []inventory.Host{host}, Identities: []inventory.Identity{ident}, Nodes: []inventory.Node{node},
	})
	if err != nil || !g.IsValid() {
		t.Fatalf("NewGraph 失败: %v", err)
	}
	switch v := node.Origin().(type) {
	case *inventory.OriginManaged:
		if v.Kind() != option.OriginManaged {
			t.Fatal("OriginManaged Kind 错误")
		}
	case *inventory.OriginOpenSSHVirtual, *inventory.OriginOpenSSHDerived, *inventory.OriginAdHoc:
		t.Fatalf("非预期节点来源 %T", v)
	default:
		t.Fatal("未知 NodeOrigin 变体")
	}

	var buf bytes.Buffer
	if err := inventory.MarshalAuthMethodTo(jsontext.NewEncoder(&buf), ident.Auth()); err != nil {
		t.Fatalf("MarshalAuthMethodTo 失败: %v", err)
	}
	decAuth, err := inventory.UnmarshalAuthMethodFrom(jsontext.NewDecoder(&buf))
	if err != nil || !inventory.EqualAuthMethod(decAuth, ident.Auth()) {
		t.Fatalf("外部包 AuthMethod 往返失败: err=%v", err)
	}
}
