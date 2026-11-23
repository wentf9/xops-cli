package host

import (
	"bytes"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W17c_L4_17_M4_CSVImportIsolatesAliasedHostsAndConcurrentBatchIdentities(t *testing.T) {
	repo, store := verificationRepository(t)
	repo = seedW17cImportFixture(t, repo, store)

	rows := []utils.HostInfo{
		{Host: "10.70.0.1", Port: 22, User: "alice", Password: "pw-alice"},
		{Host: "10.70.0.1", Port: 22, User: "bob", Password: "pw-bob"},
		{Host: "10.70.0.1", Port: 2222, User: "ops", Password: "pw-ops-2222"},
		{Host: "10.70.0.3", Port: 22, User: "dev", Password: "pw-dev-22"},
		{Host: "10.70.0.3", Port: 2222, User: "dev", Password: "pw-dev-2222"},
		{Host: "10.70.0.2", Port: 22, User: "charlie", Password: "pw-charlie"},
	}

	var out bytes.Buffer
	if err := executeImport(t.Context(), repo, rows, ImportOptions{SkipVerify: true, Output: &out}, nil); err != nil {
		t.Fatalf("executeImport failed: %v\noutput:\n%s", err, out.String())
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	if err := config.ValidateGraph(loaded); err != nil {
		t.Fatalf("ValidateGraph after import: %v", err)
	}

	assertW17cImportHostIsolation(t, loaded, store)
	assertW17cImportIdentityIsolation(t, loaded)
}

func seedW17cImportFixture(t *testing.T, repo *config.Repository, store config.Store) *config.Repository {
	t.Helper()
	if _, err := repo.CreateNodeContext(t.Context(), "ops@10.70.0.1:22",
		models.Node{HostRef: "10.70.0.1:22", IdentityRef: "ops@10.70.0.1", SudoMode: models.SudoModeAuto},
		models.Host{Address: "10.70.0.1", Port: 22, Alias: []string{"web-aliased"}},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("seed ops@10.70.0.1:22: %v", err)
	}
	seedCfg := repo.Snapshot()
	seedCfg.Hosts.Set("10.70.0.2:22", models.Host{Address: "10.70.0.2", Port: 22, Alias: []string{"orphan-alias"}})
	if err := store.Save(seedCfg); err != nil {
		t.Fatalf("store.Save seed: %v", err)
	}
	reloaded, err := config.NewRepositoryWithoutOpenSSH(seedCfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	return reloaded
}

func assertW17cImportHostIsolation(t *testing.T, loaded *config.Configuration, store config.Store) {
	t.Helper()
	aliceNode, ok := loaded.Nodes.Get("alice@10.70.0.1:22")
	if !ok {
		t.Fatal("alice@10.70.0.1:22 missing")
	}
	bobNode, ok := loaded.Nodes.Get("bob@10.70.0.1:22")
	if !ok {
		t.Fatal("bob@10.70.0.1:22 missing")
	}
	if aliceNode.HostRef == "10.70.0.1:22" || bobNode.HostRef == "10.70.0.1:22" {
		t.Fatalf("imported nodes reused aliased HostRef 10.70.0.1:22: alice=%q bob=%q", aliceNode.HostRef, bobNode.HostRef)
	}
	if aliceNode.HostRef != bobNode.HostRef {
		t.Fatalf("multi-row CSV import for same (host, port) did not share unaliased HostRef: alice=%q bob=%q", aliceNode.HostRef, bobNode.HostRef)
	}
	sharedHost, _ := loaded.Hosts.Get(aliceNode.HostRef)
	if len(sharedHost.Alias) != 0 || sharedHost.Address != "10.70.0.1" || sharedHost.Port != 22 {
		t.Fatalf("shared imported host = %+v, want unaliased 10.70.0.1:22", sharedHost)
	}
	reloadedRepo, err := config.NewRepositoryWithoutOpenSSH(loaded, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH(reloaded): %v", err)
	}
	if resolved, err := reloadedRepo.ResolveSelector("web-aliased"); err != nil || resolved != "ops@10.70.0.1:22" {
		t.Fatalf("ResolveSelector(web-aliased) = (%q, %v), want ops@10.70.0.1:22", resolved, err)
	}
	charlieNode, ok := loaded.Nodes.Get("charlie@10.70.0.2:22")
	if !ok || charlieNode.HostRef == "10.70.0.2:22" {
		t.Fatalf("charlie@10.70.0.2:22 = (%+v, %v), must not reuse aliased 10.70.0.2:22", charlieNode, ok)
	}
}

func assertW17cImportIdentityIsolation(t *testing.T, loaded *config.Configuration) {
	t.Helper()
	ops2222, ok := loaded.Nodes.Get("ops@10.70.0.1:2222")
	if !ok || ops2222.IdentityRef == "ops@10.70.0.1" {
		t.Fatalf("ops@10.70.0.1:2222 = (%+v, %v), want private IdentityRef", ops2222, ok)
	}
	ops2222Ident, _ := loaded.Identities.Get(ops2222.IdentityRef)
	if gotPW := persistedTestPassword(t, loaded, ops2222Ident); gotPW != "pw-ops-2222" {
		t.Fatalf("ops@10.70.0.1:2222 password = %q, want pw-ops-2222", gotPW)
	}

	dev22, ok := loaded.Nodes.Get("dev@10.70.0.3:22")
	if !ok {
		t.Fatal("dev@10.70.0.3:22 missing")
	}
	dev2222, ok := loaded.Nodes.Get("dev@10.70.0.3:2222")
	if !ok {
		t.Fatal("dev@10.70.0.3:2222 missing")
	}
	if dev22.IdentityRef == dev2222.IdentityRef {
		t.Fatalf("concurrent CSV rows collided on IdentityRef %q", dev22.IdentityRef)
	}
	dev22Ident, _ := loaded.Identities.Get(dev22.IdentityRef)
	dev2222Ident, _ := loaded.Identities.Get(dev2222.IdentityRef)
	if got := persistedTestPassword(t, loaded, dev22Ident); got != "pw-dev-22" {
		t.Fatalf("dev:22 password = %q, want pw-dev-22", got)
	}
	if got := persistedTestPassword(t, loaded, dev2222Ident); got != "pw-dev-2222" {
		t.Fatalf("dev:2222 password = %q, want pw-dev-2222", got)
	}
}
