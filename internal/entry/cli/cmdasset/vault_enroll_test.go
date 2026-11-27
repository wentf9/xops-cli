package cmdasset

import (
	"errors"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/engine"
)

func buildSampleGraph(t *testing.T) (inventory.Graph, inventory.IdentityID, inventory.NodeID) {
	t.Helper()
	hid, _ := inventory.ParseHostID("web-host")
	ep, _ := netaddr.ParseEndpoint("10.0.0.10:22")
	h, _ := inventory.NewHost(inventory.HostSpec{ID: hid, Endpoint: ep})
	iid, _ := inventory.ParseIdentityID("deploy-id")
	user, _ := option.ParseUsername("deploy")
	auth, _ := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	id, _ := inventory.NewIdentity(inventory.IdentitySpec{ID: iid, User: user, Auth: auth})
	nid, _ := inventory.ParseNodeID("web-1")
	n, _ := inventory.NewNode(inventory.NodeSpec{
		ID: nid, HostRef: hid, IdentityRef: iid, Origin: inventory.NewOriginManaged(),
	})
	g, err := inventory.NewGraph(inventory.GraphSpec{
		Hosts: []inventory.Host{h}, Identities: []inventory.Identity{id}, Nodes: []inventory.Node{n}, KnownStores: []string{"offline"},
	})
	if err != nil {
		t.Fatalf("NewGraph 失败: %v", err)
	}
	return g, iid, nid
}

func TestVaultSagaGraphMutators_UpsertAndBindPrivilege(t *testing.T) {
	defer goleak.VerifyNone(t)

	g, existingID, existingNode := buildSampleGraph(t)
	newID, _ := inventory.ParseIdentityID("ops-pw")
	user, _ := option.ParseUsername("ops")
	ref1, _ := secret.ParseRef("offline/pw1")
	ref2, _ := secret.ParseRef("offline/sudo1")

	// 1) 新增密码身份并保留既有 Host/Node/KnownStores。
	g1, err := upsertPasswordIdentityInGraph(g, newID, user, ref1, "login", nil, false)
	if err != nil || len(g1.Identities()) != 2 || len(g1.Hosts()) != 1 || len(g1.KnownStores()) != 1 {
		t.Fatalf("新增密码身份失败或元数据丢失: err=%v idents=%d hosts=%d stores=%d", err, len(g1.Identities()), len(g1.Hosts()), len(g1.KnownStores()))
	}

	// 2) 既有身份未开启 replace 时返回 ErrAlreadyExists；开启 replace=true 时原子覆盖。
	if _, err := upsertPasswordIdentityInGraph(g1, existingID, user, ref1, "dup", nil, false); !errors.Is(err, engine.ErrAlreadyExists) {
		t.Fatalf("未传 --replace 应返回 ErrAlreadyExists，实际=%v", err)
	}
	g2, err := upsertPasswordIdentityInGraph(g1, existingID, user, ref1, "replaced", nil, true)
	if err != nil || len(g2.Identities()) != 2 {
		t.Fatalf("replace=true 覆盖既有身份失败: err=%v idents=%d", err, len(g2.Identities()))
	}

	// 3) 绑定提权密码引用至既有节点；不存在节点返回 ErrNotFound。
	g3, err := bindNodePrivilegeInGraph(g2, existingNode, ref2)
	if err != nil {
		t.Fatalf("bindNodePrivilegeInGraph 失败: %v", err)
	}
	gotRef, hasPriv := g3.Nodes()[0].PrivilegePasswordRef().Get()
	if !hasPriv || !gotRef.Equal(ref2) {
		t.Fatalf("节点提权密码引用未绑定: has=%v ref=%s", hasPriv, gotRef)
	}
	missingNode, _ := inventory.ParseNodeID("ghost-node")
	if _, err := bindNodePrivilegeInGraph(g2, missingNode, ref2); !errors.Is(err, engine.ErrNotFound) {
		t.Fatalf("缺失节点应返回 ErrNotFound，实际=%v", err)
	}
}
