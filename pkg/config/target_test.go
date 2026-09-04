package config

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/wentf9/xops-cli/pkg/models"
)

func newTestRepositoryWithConfig(cfg *Configuration) (*Repository, error) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	return NewRepositoryWithoutOpenSSH(cfg, store)
}

func TestEnsureNodeContext_ExplicitUserReusesHostCreatesIdentityAndNode(t *testing.T) {
	cfg := cloneConfiguration(nil)

	cfg.Hosts.Set("10.238.221.181:22", models.Host{Address: "10.238.221.181", Port: 22})
	cfg.Identities.Set("iaas@10.238.221.181", models.Identity{User: "iaas", AuthType: "auto", Password: "secretPassword"})
	cfg.Nodes.Set("iaas@10.238.221.181:22", models.Node{
		HostRef:     "10.238.221.181:22",
		IdentityRef: "iaas@10.238.221.181",
		ProxyJump:   "jump-01",
		Tags:        []string{"prod"},
		Alias:       []string{"web-iaas"},
	})

	repo, err := newTestRepositoryWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	target := ConnectionTarget{
		Selector: "10.238.221.181",
		User:     "test",
		HasUser:  true,
		Port:     0,
		HasPort:  false,
	}

	res, err := repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
		Target:      target,
		DefaultUser: "localuser",
	})
	if err != nil {
		t.Fatalf("EnsureNodeContext failed: %v", err)
	}

	if !res.Created {
		t.Fatalf("expected node to be created, got created=false")
	}
	expectedNodeID := "test@10.238.221.181:22"
	if res.NodeID != expectedNodeID {
		t.Errorf("got node ID %q, want %q", res.NodeID, expectedNodeID)
	}

	snap := repo.Snapshot()
	// Host must be reused (still 1 host)
	if len(snap.Hosts.Keys()) != 1 {
		t.Errorf("expected 1 host, got %d", len(snap.Hosts.Keys()))
	}
	node, ok := snap.Nodes.Get(expectedNodeID)
	if !ok {
		t.Fatalf("node %q not found", expectedNodeID)
	}
	if node.HostRef != "10.238.221.181:22" {
		t.Errorf("expected host_ref 10.238.221.181:22, got %q", node.HostRef)
	}

	// Identity must be test@10.238.221.181, auth_type auto, not reusing password
	if len(snap.Identities.Keys()) != 2 {
		t.Errorf("expected 2 identities, got %d", len(snap.Identities.Keys()))
	}
	ident, ok := snap.Identities.Get(node.IdentityRef)
	if !ok {
		t.Fatalf("identity %q not found", node.IdentityRef)
	}
	if ident.User != "test" {
		t.Errorf("got user %q, want test", ident.User)
	}
	if ident.AuthType != "auto" {
		t.Errorf("got auth_type %q, want auto", ident.AuthType)
	}
	if ident.Password != "" {
		t.Errorf("password should not be inherited, got %q", ident.Password)
	}

	// ProxyJump should be inherited from existing node on the same host
	if node.ProxyJump != "jump-01" {
		t.Errorf("got proxy jump %q, want jump-01", node.ProxyJump)
	}

	// Tags and Alias must NOT be inherited
	if len(node.Tags) != 0 {
		t.Errorf("tags should not be inherited, got %v", node.Tags)
	}
	if len(node.Alias) != 0 {
		t.Errorf("alias should not be inherited, got %v", node.Alias)
	}
}

func TestEnsureNodeContext_ExplicitUserNeverHitsOtherUser(t *testing.T) {
	cfg := cloneConfiguration(nil)

	cfg.Hosts.Set("10.238.221.181:22", models.Host{Address: "10.238.221.181", Port: 22})
	cfg.Identities.Set("iaas@10.238.221.181", models.Identity{User: "iaas", AuthType: "auto"})
	cfg.Nodes.Set("iaas@10.238.221.181:22", models.Node{
		HostRef:     "10.238.221.181:22",
		IdentityRef: "iaas@10.238.221.181",
	})

	repo, err := newTestRepositoryWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	target := ConnectionTarget{
		Selector: "10.238.221.181",
		User:     "root",
		HasUser:  true,
		Port:     0,
		HasPort:  false,
	}

	res, err := repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
		Target: target,
	})
	if err != nil {
		t.Fatalf("EnsureNodeContext failed: %v", err)
	}

	if res.NodeID == "iaas@10.238.221.181:22" {
		t.Fatalf("explicit user must not fall back to other user node!")
	}
	if res.NodeID != "root@10.238.221.181:22" {
		t.Errorf("got %q, want root@10.238.221.181:22", res.NodeID)
	}
}

func TestEnsureNodeContext_ExactNodeExistsDoesNotRecreate(t *testing.T) {
	cfg := cloneConfiguration(nil)

	cfg.Hosts.Set("10.238.221.181:22", models.Host{Address: "10.238.221.181", Port: 22})
	cfg.Identities.Set("test@10.238.221.181", models.Identity{User: "test", AuthType: "auto"})
	cfg.Nodes.Set("test@10.238.221.181:22", models.Node{
		HostRef:     "10.238.221.181:22",
		IdentityRef: "test@10.238.221.181",
	})

	repo, err := newTestRepositoryWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	target := ConnectionTarget{
		Selector: "10.238.221.181",
		User:     "test",
		HasUser:  true,
		Port:     22,
		HasPort:  true,
	}

	res, err := repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
		Target: target,
	})
	if err != nil {
		t.Fatalf("EnsureNodeContext failed: %v", err)
	}

	if res.Created {
		t.Errorf("expected created=false when node already exists")
	}
	if res.NodeID != "test@10.238.221.181:22" {
		t.Errorf("got node ID %q", res.NodeID)
	}
}

func TestEnsureNodeContext_BareAddressSingleNodeMatches(t *testing.T) {
	cfg := cloneConfiguration(nil)

	cfg.Hosts.Set("10.238.221.181:22", models.Host{Address: "10.238.221.181", Port: 22})
	cfg.Identities.Set("iaas@10.238.221.181", models.Identity{User: "iaas", AuthType: "auto"})
	cfg.Nodes.Set("iaas@10.238.221.181:22", models.Node{
		HostRef:     "10.238.221.181:22",
		IdentityRef: "iaas@10.238.221.181",
	})

	repo, err := newTestRepositoryWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	// No explicit user or port
	target := ConnectionTarget{
		Selector: "10.238.221.181",
		HasUser:  false,
		HasPort:  false,
	}

	res, err := repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
		Target: target,
	})
	if err != nil {
		t.Fatalf("EnsureNodeContext failed: %v", err)
	}

	if res.Created {
		t.Errorf("expected existing node to match, but created was true")
	}
	if res.NodeID != "iaas@10.238.221.181:22" {
		t.Errorf("got %q, want iaas@10.238.221.181:22", res.NodeID)
	}
}

func TestEnsureNodeContext_BareAddressMultiUserReturnsAmbiguous(t *testing.T) {
	cfg := cloneConfiguration(nil)

	cfg.Hosts.Set("10.238.221.181:22", models.Host{Address: "10.238.221.181", Port: 22})
	cfg.Identities.Set("iaas@10.238.221.181", models.Identity{User: "iaas", AuthType: "auto"})
	cfg.Identities.Set("root@10.238.221.181", models.Identity{User: "root", AuthType: "auto"})
	cfg.Nodes.Set("iaas@10.238.221.181:22", models.Node{
		HostRef:     "10.238.221.181:22",
		IdentityRef: "iaas@10.238.221.181",
	})
	cfg.Nodes.Set("root@10.238.221.181:22", models.Node{
		HostRef:     "10.238.221.181:22",
		IdentityRef: "root@10.238.221.181",
	})

	repo, err := newTestRepositoryWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	target := ConnectionTarget{
		Selector: "10.238.221.181",
		HasUser:  false,
		HasPort:  false,
	}

	_, err = repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
		Target: target,
	})
	if err == nil {
		t.Fatalf("expected AmbiguousNodeError, got nil")
	}

	var ambErr *AmbiguousNodeError
	if !strings.Contains(err.Error(), "ambiguous") && !isAmbiguousNodeError(err, &ambErr) {
		t.Errorf("expected ambiguous error, got %v", err)
	}
}

func isAmbiguousNodeError(err error, target **AmbiguousNodeError) bool {
	var e *AmbiguousNodeError
	if errors.As(err, &e) {
		*target = e
		return true
	}
	return false
}

func TestEnsureNodeContext_ExplicitPortDoesNotHitOtherPort(t *testing.T) {
	cfg := cloneConfiguration(nil)

	cfg.Hosts.Set("10.238.221.181:22", models.Host{Address: "10.238.221.181", Port: 22})
	cfg.Identities.Set("test@10.238.221.181", models.Identity{User: "test", AuthType: "auto"})
	cfg.Nodes.Set("test@10.238.221.181:22", models.Node{
		HostRef:     "10.238.221.181:22",
		IdentityRef: "test@10.238.221.181",
	})

	repo, err := newTestRepositoryWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	target := ConnectionTarget{
		Selector: "10.238.221.181",
		User:     "test",
		HasUser:  true,
		Port:     2222,
		HasPort:  true,
	}

	res, err := repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
		Target: target,
	})
	if err != nil {
		t.Fatalf("EnsureNodeContext failed: %v", err)
	}

	if !res.Created {
		t.Fatalf("expected created=true for port 2222")
	}
	expectedNodeID := "test@10.238.221.181:2222"
	if res.NodeID != expectedNodeID {
		t.Errorf("got %q, want %q", res.NodeID, expectedNodeID)
	}

	snap := repo.Snapshot()
	if len(snap.Hosts.Keys()) != 2 {
		t.Errorf("expected 2 hosts (port 22 and port 2222), got %d", len(snap.Hosts.Keys()))
	}
}

func TestEnsureNodeContext_AliasCreationUsesCanonicalAddressAsNodeID(t *testing.T) {
	cfg := cloneConfiguration(nil)

	cfg.Hosts.Set("10.238.221.181:22", models.Host{Address: "10.238.221.181", Port: 22})
	cfg.Identities.Set("iaas@10.238.221.181", models.Identity{User: "iaas", AuthType: "auto"})
	cfg.Nodes.Set("iaas@10.238.221.181:22", models.Node{
		HostRef:     "10.238.221.181:22",
		IdentityRef: "iaas@10.238.221.181",
		Alias:       []string{"web-01"},
	})

	repo, err := newTestRepositoryWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	// ssh test@web-01
	target := ConnectionTarget{
		Selector: "web-01",
		User:     "test",
		HasUser:  true,
		HasPort:  false,
	}

	res, err := repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
		Target: target,
	})
	if err != nil {
		t.Fatalf("EnsureNodeContext failed: %v", err)
	}

	expectedNodeID := "test@10.238.221.181:22"
	if res.NodeID != expectedNodeID {
		t.Errorf("got node ID %q, want %q", res.NodeID, expectedNodeID)
	}

	snap := repo.Snapshot()
	newNode, ok := snap.Nodes.Get(expectedNodeID)
	if !ok {
		t.Fatalf("new node %q not found", expectedNodeID)
	}
	if newNode.HostRef != "10.238.221.181:22" {
		t.Errorf("expected host_ref 10.238.221.181:22, got %q", newNode.HostRef)
	}
}

func TestEnsureNodeContext_ProxyJumpInheritance(t *testing.T) {
	t.Run("inherits unique proxy jump", func(t *testing.T) {
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("10.0.0.1:22", models.Host{Address: "10.0.0.1", Port: 22})
		cfg.Identities.Set("user1@10.0.0.1", models.Identity{User: "user1", AuthType: "auto"})
		cfg.Nodes.Set("user1@10.0.0.1:22", models.Node{
			HostRef:     "10.0.0.1:22",
			IdentityRef: "user1@10.0.0.1",
			ProxyJump:   "bastion",
		})
		repo, err := newTestRepositoryWithConfig(cfg)
		if err != nil {
			t.Fatalf("failed to create test repo: %v", err)
		}

		res, err := repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
			Target: ConnectionTarget{Selector: "10.0.0.1", User: "user2", HasUser: true},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		node, ok := repo.Snapshot().Nodes.Get(res.NodeID)
		if !ok {
			t.Fatalf("node %q not found", res.NodeID)
		}
		if node.ProxyJump != "bastion" {
			t.Errorf("expected proxy jump 'bastion', got %q", node.ProxyJump)
		}
	})

	t.Run("inherits when multiple nodes have same proxy jump", func(t *testing.T) {
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("10.0.0.1:22", models.Host{Address: "10.0.0.1", Port: 22})
		cfg.Identities.Set("user1@10.0.0.1", models.Identity{User: "user1", AuthType: "auto"})
		cfg.Identities.Set("user2@10.0.0.1", models.Identity{User: "user2", AuthType: "auto"})
		cfg.Nodes.Set("user1@10.0.0.1:22", models.Node{
			HostRef:     "10.0.0.1:22",
			IdentityRef: "user1@10.0.0.1",
			ProxyJump:   "bastion",
		})
		cfg.Nodes.Set("user2@10.0.0.1:22", models.Node{
			HostRef:     "10.0.0.1:22",
			IdentityRef: "user2@10.0.0.1",
			ProxyJump:   "bastion",
		})
		repo, err := newTestRepositoryWithConfig(cfg)
		if err != nil {
			t.Fatalf("failed to create test repo: %v", err)
		}

		res, err := repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
			Target: ConnectionTarget{Selector: "10.0.0.1", User: "user3", HasUser: true},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		node, ok := repo.Snapshot().Nodes.Get(res.NodeID)
		if !ok {
			t.Fatalf("node %q not found", res.NodeID)
		}
		if node.ProxyJump != "bastion" {
			t.Errorf("expected proxy jump 'bastion', got %q", node.ProxyJump)
		}
	})

	t.Run("returns ambiguous when multiple nodes have different proxy jumps", func(t *testing.T) {
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("10.0.0.1:22", models.Host{Address: "10.0.0.1", Port: 22})
		cfg.Identities.Set("user1@10.0.0.1", models.Identity{User: "user1", AuthType: "auto"})
		cfg.Identities.Set("user2@10.0.0.1", models.Identity{User: "user2", AuthType: "auto"})
		cfg.Nodes.Set("user1@10.0.0.1:22", models.Node{
			HostRef:     "10.0.0.1:22",
			IdentityRef: "user1@10.0.0.1",
			ProxyJump:   "bastion-1",
		})
		cfg.Nodes.Set("user2@10.0.0.1:22", models.Node{
			HostRef:     "10.0.0.1:22",
			IdentityRef: "user2@10.0.0.1",
			ProxyJump:   "bastion-2",
		})
		repo, err := newTestRepositoryWithConfig(cfg)
		if err != nil {
			t.Fatalf("failed to create test repo: %v", err)
		}

		_, err = repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
			Target: ConnectionTarget{Selector: "10.0.0.1", User: "user3", HasUser: true},
		})
		if err == nil {
			t.Fatalf("expected ambiguous proxy jump error, got nil")
		}
	})

	t.Run("explicit proxy jump overrides inherited", func(t *testing.T) {
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("10.0.0.1:22", models.Host{Address: "10.0.0.1", Port: 22})
		cfg.Nodes.Set("bastion-new", models.Node{
			HostRef:     "10.0.0.1:22",
			IdentityRef: "user1@10.0.0.1",
		})
		cfg.Identities.Set("user1@10.0.0.1", models.Identity{User: "user1", AuthType: "auto"})
		cfg.Nodes.Set("user1@10.0.0.1:22", models.Node{
			HostRef:     "10.0.0.1:22",
			IdentityRef: "user1@10.0.0.1",
			ProxyJump:   "bastion-old",
		})
		repo, err := newTestRepositoryWithConfig(cfg)
		if err != nil {
			t.Fatalf("failed to create test repo: %v", err)
		}

		res, err := repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
			Target: ConnectionTarget{
				Selector:     "10.0.0.1",
				User:         "user2",
				HasUser:      true,
				ProxyJump:    "bastion-new",
				HasProxyJump: true,
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		node, ok := repo.Snapshot().Nodes.Get(res.NodeID)
		if !ok {
			t.Fatalf("node %q not found", res.NodeID)
		}
		if node.ProxyJump != "bastion-new" {
			t.Errorf("expected proxy jump 'bastion-new', got %q", node.ProxyJump)
		}
	})
}

func TestEnsureNodeContext_IdentityConflictGeneratesPrivateRef(t *testing.T) {
	cfg := cloneConfiguration(nil)

	// Suppose test@10.0.0.1 already exists in identities, belonging to something else
	cfg.Identities.Set("test@10.0.0.1", models.Identity{User: "test", AuthType: "password", Password: "oldPassword"})

	repo, err := newTestRepositoryWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	target := ConnectionTarget{
		Selector: "10.0.0.1",
		User:     "test",
		HasUser:  true,
		Port:     22,
		HasPort:  true,
	}

	res, err := repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
		Target: target,
	})
	if err != nil {
		t.Fatalf("EnsureNodeContext failed: %v", err)
	}

	snap := repo.Snapshot()
	node, ok := snap.Nodes.Get(res.NodeID)
	if !ok {
		t.Fatalf("node %q not found", res.NodeID)
	}

	// IdentityRef should not overwrite original test@10.0.0.1
	if node.IdentityRef == "test@10.0.0.1" {
		t.Errorf("expected private identity reference, but got test@10.0.0.1")
	}
	origIdent, ok := snap.Identities.Get("test@10.0.0.1")
	if !ok || origIdent.Password != "oldPassword" {
		t.Errorf("original identity was missing or modified: %+v", origIdent)
	}
	newIdent, ok := snap.Identities.Get(node.IdentityRef)
	if !ok || newIdent.Password != "" || newIdent.AuthType != "auto" {
		t.Errorf("new identity has unexpected attributes: %+v", newIdent)
	}
}

func TestEnsureNodeContext_IPv6Support(t *testing.T) {
	cfg := cloneConfiguration(nil)

	repo, err := newTestRepositoryWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	target := ConnectionTarget{
		Selector: "2001:db8::1",
		User:     "root",
		HasUser:  true,
		Port:     2222,
		HasPort:  true,
	}

	res, err := repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
		Target: target,
	})
	if err != nil {
		t.Fatalf("EnsureNodeContext failed: %v", err)
	}

	expectedNodeID := "root@[2001:db8::1]:2222"
	if res.NodeID != expectedNodeID {
		t.Errorf("got node ID %q, want %q", res.NodeID, expectedNodeID)
	}

	snap := repo.Snapshot()
	host, ok := snap.Hosts.Get("[2001:db8::1]:2222")
	if !ok {
		t.Fatalf("host [2001:db8::1]:2222 not found")
	}
	if host.Address != "2001:db8::1" || host.Port != 2222 {
		t.Errorf("unexpected host: %+v", host)
	}
}

func TestEnsureNodeContext_ConcurrentEnsureSameNode(t *testing.T) {
	cfg := cloneConfiguration(nil)

	repo, err := newTestRepositoryWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	target := ConnectionTarget{
		Selector: "192.168.100.1",
		User:     "test",
		HasUser:  true,
		Port:     22,
		HasPort:  true,
	}

	var wg sync.WaitGroup
	errs := make(chan error, 10)
	results := make(chan EnsureNodeResult, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, ensureErr := repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
				Target: target,
			})
			if ensureErr != nil {
				errs <- ensureErr
				return
			}
			results <- res
		}()
	}

	wg.Wait()
	close(errs)
	close(results)

	for e := range errs {
		t.Errorf("concurrent ensure error: %v", e)
	}

	snap := repo.Snapshot()
	if len(snap.Hosts.Keys()) != 1 {
		t.Errorf("expected exactly 1 host after concurrent ensure, got %d", len(snap.Hosts.Keys()))
	}
	if len(snap.Identities.Keys()) != 1 {
		t.Errorf("expected exactly 1 identity after concurrent ensure, got %d", len(snap.Identities.Keys()))
	}
	if len(snap.Nodes.Keys()) != 1 {
		t.Errorf("expected exactly 1 node after concurrent ensure, got %d", len(snap.Nodes.Keys()))
	}
}

func TestEnsureNodeContext_PersistFailureDoesNotPublish(t *testing.T) {
	cfg := cloneConfiguration(nil)
	store := &repositoryTestStore{err: errRepositoryPersist}
	repo, err := NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	target := ConnectionTarget{
		Selector: "192.168.1.1",
		User:     "test",
		HasUser:  true,
		Port:     22,
		HasPort:  true,
	}

	_, err = repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
		Target: target,
	})
	if !errors.Is(err, errRepositoryPersist) {
		t.Fatalf("expected errRepositoryPersist, got %v", err)
	}

	snap := repo.Snapshot()
	if len(snap.Nodes.Keys()) != 0 {
		t.Errorf("failed persist should not publish node, found: %v", snap.Nodes.Keys())
	}
	if len(snap.Hosts.Keys()) != 0 {
		t.Errorf("failed persist should not publish host, found: %v", snap.Hosts.Keys())
	}
	if len(snap.Identities.Keys()) != 0 {
		t.Errorf("failed persist should not publish identity, found: %v", snap.Identities.Keys())
	}
}

func TestEnsureNodeContext_AppliedUndurableReturnsNodeAndRef(t *testing.T) {
	cfg := cloneConfiguration(nil)
	store := &repositoryTestStore{
		result: PersistResult{Applied: true},
		err:    errRepositoryPersist,
	}
	repo, err := NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	target := ConnectionTarget{
		Selector: "192.168.1.1",
		User:     "test",
		HasUser:  true,
		Port:     22,
		HasPort:  true,
	}

	res, err := repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
		Target: target,
	})
	if err == nil {
		t.Fatalf("expected durability error, got nil")
	}
	var durabilityErr *DurabilityError
	if !errors.As(err, &durabilityErr) {
		t.Fatalf("expected DurabilityError, got %v", err)
	}
	if !res.Created {
		t.Errorf("expected Created to be true")
	}
	if res.NodeID != "test@192.168.1.1:22" {
		t.Errorf("expected NodeID 'test@192.168.1.1:22', got %q", res.NodeID)
	}
	if !res.Mutation.Outcome.Applied || res.Mutation.Outcome.Durable {
		t.Errorf("expected Applied=true, Durable=false, got %+v", res.Mutation.Outcome)
	}
	if res.Mutation.Ref.ID != res.NodeID || res.Mutation.Ref.Version == (Version{}) {
		t.Errorf("expected valid NodeRef, got %+v", res.Mutation.Ref)
	}
}

func TestEnsureNodeContext_AmbiguousMultipleMatchingNodes(t *testing.T) {
	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("10.0.0.1:22", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Identities.Set("test@10.0.0.1", models.Identity{User: "test", AuthType: "auto"})
	// Two nodes sharing same identity (test@10.0.0.1:22)
	cfg.Nodes.Set("node-alpha", models.Node{
		HostRef:     "10.0.0.1:22",
		IdentityRef: "test@10.0.0.1",
	})
	cfg.Nodes.Set("node-beta", models.Node{
		HostRef:     "10.0.0.1:22",
		IdentityRef: "test@10.0.0.1",
	})

	repo, err := newTestRepositoryWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	target := ConnectionTarget{
		Selector: "10.0.0.1",
		User:     "test",
		HasUser:  true,
		Port:     22,
		HasPort:  true,
	}

	_, err = repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
		Target: target,
	})
	if err == nil {
		t.Fatalf("expected ambiguous error when multiple nodes match user+host+port, got nil")
	}
	var ambErr *AmbiguousNodeError
	if !errors.As(err, &ambErr) {
		t.Fatalf("expected *AmbiguousNodeError, got %v", err)
	}
	if len(ambErr.Candidates) != 2 || ambErr.Candidates[0] != "node-alpha" || ambErr.Candidates[1] != "node-beta" {
		t.Errorf("expected candidates [node-alpha node-beta], got %v", ambErr.Candidates)
	}
}

func TestEnsureNodeContext_OpenSSHConfigIntegration(t *testing.T) {
	sshConfigContent := `
Host my-openssh-alias
    HostName 192.168.1.100
    User devops
    Port 2222
    IdentityFile ~/.ssh/id_rsa_custom
    ProxyJump jump-server

Host jump-server
    HostName 1.2.3.4
    User jumpuser
    Port 22
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshConfigContent))
	if err != nil {
		t.Fatalf("failed to parse openssh config: %v", err)
	}

	cfg := cloneConfiguration(nil)
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	// Connect as test@my-openssh-alias
	target := ConnectionTarget{
		Selector: "my-openssh-alias",
		User:     "test",
		HasUser:  true,
	}

	res, err := repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
		Target: target,
	})
	if err != nil {
		t.Fatalf("EnsureNodeContext failed: %v", err)
	}

	if !res.Created {
		t.Fatalf("expected created=true, got false")
	}
	expectedNodeID := "test@192.168.1.100:2222"
	if res.NodeID != expectedNodeID {
		t.Fatalf("expected nodeID=%q, got %q", expectedNodeID, res.NodeID)
	}

	snap := repo.Snapshot()
	node, ok := snap.Nodes.Get(res.NodeID)
	if !ok {
		t.Fatalf("node %q not found in snapshot", res.NodeID)
	}
	host, ok := snap.Hosts.Get(node.HostRef)
	if !ok {
		t.Fatalf("host %q not found in snapshot", node.HostRef)
	}
	if host.Address != "192.168.1.100" || host.Port != 2222 {
		t.Errorf("host has wrong addr/port: %+v", host)
	}
	ident, ok := snap.Identities.Get(node.IdentityRef)
	if !ok {
		t.Fatalf("identity %q not found in snapshot", node.IdentityRef)
	}
	if ident.User != "test" {
		t.Errorf("identity user want 'test', got %q", ident.User)
	}
	if !strings.HasSuffix(ident.KeyPath, "id_rsa_custom") {
		t.Errorf("expected identity keyPath to inherit openssh key, got %q", ident.KeyPath)
	}
	if node.ProxyJump != OpenSSHNodePrefix+"jump-server" {
		t.Errorf("expected proxy jump %q, got %q", OpenSSHNodePrefix+"jump-server", node.ProxyJump)
	}
}

func TestEnsureNodeContext_SudoAndSuPwd(t *testing.T) {
	cfg := cloneConfiguration(nil)
	repo, err := newTestRepositoryWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	target := ConnectionTarget{
		Selector: "10.0.0.1",
		User:     "test",
		HasUser:  true,
		Port:     22,
		HasPort:  true,
	}

	res, err := repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
		Target:   target,
		SudoMode: models.SudoModeSudo,
		SuPwd:    "secretRoot123",
	})
	if err != nil {
		t.Fatalf("EnsureNodeContext failed: %v", err)
	}

	snap := repo.Snapshot()
	node, ok := snap.Nodes.Get(res.NodeID)
	if !ok {
		t.Fatalf("node %q not found in snapshot", res.NodeID)
	}
	if node.SudoMode != models.SudoModeSudo {
		t.Errorf("expected SudoMode=%q, got %q", models.SudoModeSudo, node.SudoMode)
	}
	if node.SuPwd != "secretRoot123" {
		t.Errorf("expected SuPwd='secretRoot123', got %q", node.SuPwd)
	}
}

func TestEnsureNodeContext_OpenSSHInvalidPortError(t *testing.T) {
	sshConfigContent := `
Host broken
    HostName 10.0.0.1
    Port 99999
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshConfigContent))
	if err != nil {
		t.Fatalf("failed to parse openssh config: %v", err)
	}

	cfg := cloneConfiguration(nil)
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	target := ConnectionTarget{
		Selector: "broken",
		User:     "test",
		HasUser:  true,
	}

	_, err = repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
		Target: target,
	})
	if err == nil {
		t.Fatalf("expected error for invalid port 99999, got nil")
	}
	if !strings.Contains(err.Error(), "invalid port") {
		t.Errorf("expected error message containing 'invalid port', got %v", err)
	}
}

func TestEnsureNodeContext_PortOverridePreservesOpenSSHUser(t *testing.T) {
	sshConfigContent := `
Host my-server
    HostName 10.0.0.5
    Port 22
    User devuser
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshConfigContent))
	if err != nil {
		t.Fatalf("failed to parse openssh config: %v", err)
	}

	cfg := cloneConfiguration(nil)
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	// Only override port, no explicit user specified
	target := ConnectionTarget{
		Selector: "my-server",
		Port:     2222,
		HasPort:  true,
		HasUser:  false,
	}

	res, err := repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
		Target: target,
	})
	if err != nil {
		t.Fatalf("EnsureNodeContext failed: %v", err)
	}
	expectedNodeID := "devuser@10.0.0.5:2222"
	if res.NodeID != expectedNodeID {
		t.Fatalf("expected nodeID=%q, got %q", expectedNodeID, res.NodeID)
	}

	snap := repo.Snapshot()
	node, ok := snap.Nodes.Get(res.NodeID)
	if !ok {
		t.Fatalf("node %q not found in snapshot", res.NodeID)
	}
	ident, ok := snap.Identities.Get(node.IdentityRef)
	if !ok {
		t.Fatalf("identity %q not found in snapshot", node.IdentityRef)
	}
	if ident.User != "devuser" {
		t.Errorf("expected ident.User='devuser', got %q", ident.User)
	}
}

func TestEnsureNodeContext_OpenSSHMultiHopProxyJump(t *testing.T) {
	sshConfigContent := `
Host jump1
    HostName 10.1.1.1
    Port 2201
Host jump2
    HostName 10.1.1.2
Host target-server
    HostName 10.1.1.10
    ProxyJump jumpuser@jump1:2201,jump2
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshConfigContent))
	if err != nil {
		t.Fatalf("failed to parse openssh config: %v", err)
	}

	cfg := cloneConfiguration(nil)
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	target := ConnectionTarget{
		Selector: "target-server",
		User:     "root",
		HasUser:  true,
	}

	res, err := repo.EnsureNodeContext(context.Background(), EnsureNodeOptions{
		Target: target,
	})
	if err != nil {
		t.Fatalf("EnsureNodeContext failed: %v", err)
	}

	snap := repo.Snapshot()
	node, ok := snap.Nodes.Get(res.NodeID)
	if !ok {
		t.Fatalf("node %q not found in snapshot", res.NodeID)
	}
	expectedPJ := OpenSSHNodePrefix + "jumpuser@jump1:2201," + OpenSSHNodePrefix + "jump2"
	if node.ProxyJump != expectedPJ {
		t.Errorf("expected node.ProxyJump=%q, got %q", expectedPJ, node.ProxyJump)
	}
}

func TestEnsureNodeContext_PortOverridePreservesLocalNodeAndAliasUser(t *testing.T) {
	ctx := context.Background()

	t.Run("alias_user_preservation", func(t *testing.T) {
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("10.238.221.181:22", models.Host{Address: "10.238.221.181", Port: 22})
		cfg.Identities.Set("iaas@10.238.221.181", models.Identity{User: "iaas", AuthType: "auto"})
		cfg.Nodes.Set("iaas@10.238.221.181:22", models.Node{
			HostRef:     "10.238.221.181:22",
			IdentityRef: "iaas@10.238.221.181",
			Alias:       []string{"web-01"},
		})

		store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
		repo, err := NewRepositoryWithoutOpenSSH(cfg, store)
		if err != nil {
			t.Fatalf("failed to create repo: %v", err)
		}

		// Only override port on alias web-01
		target := ConnectionTarget{
			Selector: "web-01",
			Port:     2222,
			HasPort:  true,
			HasUser:  false,
		}

		res, err := repo.EnsureNodeContext(ctx, EnsureNodeOptions{Target: target})
		if err != nil {
			t.Fatalf("EnsureNodeContext failed: %v", err)
		}

		expectedNodeID := "iaas@10.238.221.181:2222"
		if res.NodeID != expectedNodeID {
			t.Fatalf("expected nodeID=%q, got %q", expectedNodeID, res.NodeID)
		}

		snap := repo.Snapshot()
		node, ok := snap.Nodes.Get(res.NodeID)
		if !ok {
			t.Fatalf("node %q not found in snapshot", res.NodeID)
		}
		ident, ok := snap.Identities.Get(node.IdentityRef)
		if !ok {
			t.Fatalf("identity %q not found in snapshot", node.IdentityRef)
		}
		if ident.User != "iaas" {
			t.Errorf("expected identity user='iaas', got %q", ident.User)
		}
	})

	t.Run("ambiguous_user_across_candidates", func(t *testing.T) {
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("10.238.221.181:22", models.Host{Address: "10.238.221.181", Port: 22})
		cfg.Identities.Set("iaas@10.238.221.181", models.Identity{User: "iaas", AuthType: "auto"})
		cfg.Identities.Set("root@10.238.221.181", models.Identity{User: "root", AuthType: "auto"})
		cfg.Nodes.Set("iaas@10.238.221.181:22", models.Node{
			HostRef:     "10.238.221.181:22",
			IdentityRef: "iaas@10.238.221.181",
		})
		cfg.Nodes.Set("root@10.238.221.181:22", models.Node{
			HostRef:     "10.238.221.181:22",
			IdentityRef: "root@10.238.221.181",
		})

		store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
		repo, err := NewRepositoryWithoutOpenSSH(cfg, store)
		if err != nil {
			t.Fatalf("failed to create repo: %v", err)
		}

		// Only override port on bare address where multiple users exist
		target := ConnectionTarget{
			Selector: "10.238.221.181",
			Port:     2222,
			HasPort:  true,
			HasUser:  false,
		}

		_, err = repo.EnsureNodeContext(ctx, EnsureNodeOptions{Target: target})
		if err == nil {
			t.Fatalf("expected AmbiguousNodeError when candidates have conflicting users, got nil")
		}
		var ambErr *AmbiguousNodeError
		if !errors.As(err, &ambErr) {
			t.Fatalf("expected error to be AmbiguousNodeError, got %v", err)
		}
	})
}

func TestEnsureNodeContext_DirectJumpAddressWithoutSSHConfig(t *testing.T) {
	ctx := context.Background()

	cfg := cloneConfiguration(nil)
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	// Test without ~/.ssh/config: parser with cfg: nil
	repo, err := NewRepositoryWithOpenSSHParser(cfg, store, &OpenSSHParser{cfg: nil})
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	t.Run("direct_user_host_port_jump", func(t *testing.T) {
		target := ConnectionTarget{
			Selector:     "10.0.0.20",
			User:         "root",
			HasUser:      true,
			ProxyJump:    "jumpuser@10.0.0.10:2201",
			HasProxyJump: true,
		}

		res, err := repo.EnsureNodeContext(ctx, EnsureNodeOptions{Target: target})
		if err != nil {
			t.Fatalf("EnsureNodeContext failed for direct jump: %v", err)
		}

		snap := repo.Snapshot()
		node, ok := snap.Nodes.Get(res.NodeID)
		if !ok {
			t.Fatalf("node %q not found in snapshot", res.NodeID)
		}
		expectedPJ := OpenSSHNodePrefix + "jumpuser@10.0.0.10:2201"
		if node.ProxyJump != expectedPJ {
			t.Errorf("expected ProxyJump=%q, got %q", expectedPJ, node.ProxyJump)
		}

		// Verify Resolve succeeds without ~/.ssh/config
		vnode, vhost, vident, rErr := repo.Resolve(node.ProxyJump)
		if rErr != nil {
			t.Fatalf("Resolve virtual node failed without ssh_config: %v", rErr)
		}
		if vhost.Address != "10.0.0.10" || vhost.Port != 2201 {
			t.Errorf("expected 10.0.0.10:2201, got %+v", vhost)
		}
		if vident.User != "jumpuser" {
			t.Errorf("expected jumpuser, got %+v", vident)
		}
		if vnode.HostRef == "" {
			t.Errorf("expected vnode hostRef, got %+v", vnode)
		}
	})

	t.Run("direct_ip_jump", func(t *testing.T) {
		target := ConnectionTarget{
			Selector:     "10.0.0.21",
			User:         "root",
			HasUser:      true,
			ProxyJump:    "10.0.0.10",
			HasProxyJump: true,
		}

		res, err := repo.EnsureNodeContext(ctx, EnsureNodeOptions{Target: target})
		if err != nil {
			t.Fatalf("EnsureNodeContext failed for direct IP jump: %v", err)
		}

		snap := repo.Snapshot()
		node, ok := snap.Nodes.Get(res.NodeID)
		if !ok {
			t.Fatalf("node %q not found in snapshot", res.NodeID)
		}
		expectedPJ := OpenSSHNodePrefix + "10.0.0.10"
		if node.ProxyJump != expectedPJ {
			t.Errorf("expected ProxyJump=%q, got %q", expectedPJ, node.ProxyJump)
		}

		// Verify Resolve succeeds without ~/.ssh/config
		_, vhost, _, rErr := repo.Resolve(node.ProxyJump)
		if rErr != nil {
			t.Fatalf("Resolve virtual node failed without ssh_config: %v", rErr)
		}
		if vhost.Address != "10.0.0.10" || vhost.Port != 22 {
			t.Errorf("expected 10.0.0.10:22, got %+v", vhost)
		}
	})
}

func TestEnsureNodeContext_DirectSingleLabelWithPortJumpWithoutSSHConfig(t *testing.T) {
	ctx := context.Background()

	cfg := cloneConfiguration(nil)
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithOpenSSHParser(cfg, store, &OpenSSHParser{cfg: nil})
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	target := ConnectionTarget{
		Selector:     "10.0.0.26",
		User:         "root",
		HasUser:      true,
		ProxyJump:    "jumphost:22",
		HasProxyJump: true,
	}

	res, err := repo.EnsureNodeContext(ctx, EnsureNodeOptions{Target: target})
	if err != nil {
		t.Fatalf("EnsureNodeContext failed for direct single-label jump with port: %v", err)
	}

	snap := repo.Snapshot()
	node, ok := snap.Nodes.Get(res.NodeID)
	if !ok {
		t.Fatalf("node %q not found in snapshot", res.NodeID)
	}
	expectedPJ := OpenSSHNodePrefix + "jumphost:22"
	if node.ProxyJump != expectedPJ {
		t.Errorf("expected ProxyJump=%q, got %q", expectedPJ, node.ProxyJump)
	}

	// Verify Resolve succeeds without ~/.ssh/config
	_, vhost, _, rErr := repo.Resolve(node.ProxyJump)
	if rErr != nil {
		t.Fatalf("Resolve virtual node failed without ssh_config: %v", rErr)
	}
	if vhost.Address != "jumphost" || vhost.Port != 22 {
		t.Errorf("expected jumphost:22, got %+v", vhost)
	}
}

func TestEnsureNodeContext_DirectDNSJumpAddressWithoutSSHConfig(t *testing.T) {
	ctx := context.Background()

	cfg := cloneConfiguration(nil)
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	// Test without ~/.ssh/config: parser with cfg: nil
	repo, err := NewRepositoryWithOpenSSHParser(cfg, store, &OpenSSHParser{cfg: nil})
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	target := ConnectionTarget{
		Selector:     "10.0.0.24",
		User:         "root",
		HasUser:      true,
		ProxyJump:    "bastion.example.com",
		HasProxyJump: true,
	}

	res, err := repo.EnsureNodeContext(ctx, EnsureNodeOptions{Target: target})
	if err != nil {
		t.Fatalf("EnsureNodeContext failed for direct DNS jump: %v", err)
	}

	snap := repo.Snapshot()
	node, ok := snap.Nodes.Get(res.NodeID)
	if !ok {
		t.Fatalf("node %q not found in snapshot", res.NodeID)
	}
	expectedPJ := OpenSSHNodePrefix + "bastion.example.com"
	if node.ProxyJump != expectedPJ {
		t.Errorf("expected ProxyJump=%q, got %q", expectedPJ, node.ProxyJump)
	}

	// Verify Resolve succeeds on the virtual node even when ssh_config file does not exist
	vnode, vhost, vident, rErr := repo.Resolve(node.ProxyJump)
	if rErr != nil {
		t.Fatalf("repo.Resolve failed for virtual node %q: %v", node.ProxyJump, rErr)
	}
	if vhost.Address != "bastion.example.com" || vhost.Port != 22 {
		t.Errorf("unexpected virtual host: %+v", vhost)
	}
	if vnode.HostRef == "" || vident.User == "" {
		t.Errorf("unexpected virtual node/ident: node=%+v, ident=%+v", vnode, vident)
	}
}

func TestEnsureNodeContext_DirectJumpAddressErrors(t *testing.T) {
	ctx := context.Background()

	cfg := cloneConfiguration(nil)
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(""))
	if err != nil {
		t.Fatalf("failed to create openssh parser: %v", err)
	}
	repo, err := NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	t.Run("unknown_jump_alias_fails", func(t *testing.T) {
		target := ConnectionTarget{
			Selector:     "10.0.0.22",
			User:         "root",
			HasUser:      true,
			ProxyJump:    "unknown-jump-alias",
			HasProxyJump: true,
		}

		_, err := repo.EnsureNodeContext(ctx, EnsureNodeOptions{Target: target})
		if err == nil {
			t.Fatalf("expected error for unknown jump alias, got nil")
		}
		if !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "ssh_err_jump_not_found") {
			t.Errorf("expected error containing 'not found', got %v", err)
		}
	})

	t.Run("invalid_port_in_direct_jump_fails", func(t *testing.T) {
		target := ConnectionTarget{
			Selector:     "10.0.0.23",
			User:         "root",
			HasUser:      true,
			ProxyJump:    "jumpuser@10.0.0.10:99999",
			HasProxyJump: true,
		}

		_, err := repo.EnsureNodeContext(ctx, EnsureNodeOptions{Target: target})
		if err == nil {
			t.Fatalf("expected error for invalid port in jump, got nil")
		}
	})

	t.Run("single_label_jump_fails_without_port", func(t *testing.T) {
		target := ConnectionTarget{
			Selector:     "10.0.0.24",
			User:         "root",
			HasUser:      true,
			ProxyJump:    "jumphost",
			HasProxyJump: true,
		}

		_, err := repo.EnsureNodeContext(ctx, EnsureNodeOptions{Target: target})
		if err == nil {
			t.Fatalf("expected error for single label jump without port, got nil")
		}
		if !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "ssh_err_jump_not_found") {
			t.Errorf("expected error containing 'not found', got %v", err)
		}
	})
}

func TestEnsureNodeContext_DirectConnectionAndProxyJumpConflict(t *testing.T) {
	ctx := context.Background()

	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("10.0.0.1:22", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Identities.Set("user1@10.0.0.1", models.Identity{User: "user1", AuthType: "auto"})
	cfg.Identities.Set("user2@10.0.0.1", models.Identity{User: "user2", AuthType: "auto"})
	// Node 1: direct connection (empty ProxyJump)
	cfg.Nodes.Set("user1@10.0.0.1:22", models.Node{
		HostRef:     "10.0.0.1:22",
		IdentityRef: "user1@10.0.0.1",
		ProxyJump:   "",
	})
	// Node 2: proxy jump (bastion)
	cfg.Nodes.Set("user2@10.0.0.1:22", models.Node{
		HostRef:     "10.0.0.1:22",
		IdentityRef: "user2@10.0.0.1",
		ProxyJump:   "bastion",
	})

	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	// New user on same host without explicit ProxyJump
	target := ConnectionTarget{
		Selector: "10.0.0.1",
		User:     "user3",
		HasUser:  true,
	}

	_, err = repo.EnsureNodeContext(ctx, EnsureNodeOptions{Target: target})
	if err == nil {
		t.Fatalf("expected ambiguous proxy jump error between direct and bastion, got nil")
	}
	if !strings.Contains(err.Error(), "ambiguous proxy jump") {
		t.Errorf("expected error containing 'ambiguous proxy jump', got %v", err)
	}
}
