package host

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func seedIPv6ImportNode(t *testing.T, repo *config.Repository, nodeID string) {
	t.Helper()
	_, err := repo.CreateNodeContext(t.Context(), nodeID,
		models.Node{HostRef: "2001:db8::1:22", IdentityRef: "root@2001:db8::1", Alias: []string{"existing-v6"}},
		models.Host{Address: "2001:db8::1", Port: 22},
		models.Identity{User: "root", AuthType: "password"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestImportIPv6UpdatesExistingNode(t *testing.T) {
	for _, nodeID := range []string{"root@2001:db8::1:22", "custom-ipv6-node", "root@[2001:db8::1]:22"} {
		for _, mode := range []string{"skip", "verify"} {
			t.Run(nodeID+"/"+mode, func(t *testing.T) {
				repo, store := verificationRepository(t)
				seedIPv6ImportNode(t, repo, nodeID)
				verify := func(_ context.Context, _ *config.Repository, id string, bundle *inventoryVerification) error {
					if mode == "skip" {
						t.Error("skip-verify attempted verification")
					}
					if id != nodeID || bundle.Host.Address != "2001:db8::1" || bundle.Host.Port != 22 || bundle.Identity.Password == "old-secret" {
						t.Error("verification did not use the existing IPv6 node and replacement credentials")
					}
					return nil
				}
				rows := []utils.HostInfo{
					{Host: "2001:db8::1", User: "root", Alias: "existing-v6", Password: "first-secret"},
					{Host: "[2001:db8::1]", User: "root", Port: 22, Alias: "added-v6", Password: "last-secret"},
				}
				var out bytes.Buffer
				if err := executeImport(t.Context(), repo, rows, ImportOptions{SkipVerify: mode == "skip", Output: &out}, verify); err != nil {
					t.Fatalf("import existing IPv6 endpoint: %v", err)
				}
				cfg, err := store.Load()
				if err != nil {
					t.Fatal(err)
				}
				assertIPv6ImportUpdated(t, cfg, nodeID)
			})
		}
	}
}

func assertIPv6ImportUpdated(t *testing.T, cfg *config.Configuration, nodeID string) {
	t.Helper()
	if cfg.Nodes.Count() != 1 || cfg.Hosts.Count() != 1 || cfg.Identities.Count() != 2 {
		t.Fatal("IPv6 import added duplicate nodes, hosts or identities")
	}
	node, ok := cfg.Nodes.Get(nodeID)
	if !ok || !reflect.DeepEqual(node.Alias, []string{"existing-v6", "added-v6"}) {
		t.Fatalf("existing node ID or aliases were not preserved: %+v", node)
	}
	identity, ok := cfg.Identities.Get(node.IdentityRef)
	if !ok || persistedTestPassword(t, cfg, identity) != "last-secret" {
		t.Fatal("existing IPv6 credentials were not updated in CSV order")
	}
}

func TestResolveImportIPv6DoesNotMatchOtherUserOrPort(t *testing.T) {
	repo, _ := verificationRepository(t)
	seedIPv6ImportNode(t, repo, "root@2001:db8::1:22")
	for _, addr := range []utils.HostInfo{
		{Host: "2001:db8::1", User: "root", Port: 2222},
		{Host: "[2001:db8::1]", User: "other", Port: 22},
	} {
		id, err := resolveImportNode(repo, addr)
		if err != nil || id != "" {
			t.Fatalf("matched an unrelated endpoint: %q, %v", id, err)
		}
	}
}

func TestImportIPv6PreservesAmbiguousLookup(t *testing.T) {
	repo, store := verificationRepository(t)
	seedIPv6ImportNode(t, repo, "first-ipv6-node")
	node, host, identity, err := repo.Resolve("first-ipv6-node")
	if err != nil {
		t.Fatal(err)
	}
	node.Alias = nil
	if _, err := repo.CreateNodeContext(t.Context(), "second-ipv6-node", node, host, identity); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = executeImport(t.Context(), repo, []utils.HostInfo{{Host: "2001:db8::1", User: "root", Port: 22}}, ImportOptions{SkipVerify: true, Output: &out}, nil)
	var ambiguous *config.AmbiguousNodeError
	if !errors.As(err, &ambiguous) {
		t.Fatalf("ambiguous legacy endpoint was not rejected: %v", err)
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Nodes.Count() != 2 {
		t.Fatal("ambiguous lookup created another IPv6 node")
	}
}
