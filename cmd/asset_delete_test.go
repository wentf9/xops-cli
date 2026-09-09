package cmd

import (
	"errors"
	"testing"

	hostcmd "github.com/wentf9/xops-cli/cmd/host"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestHostDeleteCleanupFailureRecoversWithFreshService(t *testing.T) {
	setupFirewallCredential(t)
	_, _, cfg, err := utils.GetConfigStore()
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := cfg.Identities.Get("admin")
	ref := *identity.LoginPasswordRef
	t.Setenv("TEST_HELPER_ERROR_CODE", "locked")
	err = executePhase6(t, hostcmd.NewCmdInventoryDelete(), "node")
	var cleanup *credential.CleanupError
	if !errors.As(err, &cleanup) || !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("delete lost cleanup error: %v", err)
	}
	_, repo, cfg, err := utils.GetConfigStore()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Nodes.Count() != 0 || cfg.Identities.Count() != 0 {
		t.Fatal("applied deletion was rolled back")
	}
	service, err := utils.GetCredentialService(repo, cfg)
	if err != nil {
		t.Fatal(err)
	}
	results, err := service.GC(t.Context())
	if err != nil || len(results) != 1 || !errors.Is(results[0].Err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("GC lost cleanup intent: %+v %v", results, err)
	}
	if err := executePhase6(t, newCmdCredentialGC()); !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("GC reported success while cleanup is locked: %v", err)
	}
	t.Setenv("TEST_HELPER_ERROR_CODE", "")
	registry, err := utils.GetCredentialRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := registry.Resolve(t.Context(), ref)
	secret.Zero()
	if err != nil {
		t.Fatalf("locked cleanup lost credential: %v", err)
	}
	if err := executePhase6(t, newCmdCredentialGC()); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Resolve(t.Context(), ref); !errors.Is(err, credential.ErrCredentialNotFound) {
		t.Fatalf("GC retained orphan: %v", err)
	}
}

func TestAssetDeletionRetainsSharedCredential(t *testing.T) {
	setupFirewallCredential(t)
	store, _, cfg, err := utils.GetConfigStore()
	if err != nil {
		t.Fatal(err)
	}
	node, _ := cfg.Nodes.Get("node")
	cfg.Nodes.Set("other", node)
	identity, _ := cfg.Identities.Get(node.IdentityRef)
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	registry, err := utils.GetCredentialRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := executePhase6(t, hostcmd.NewCmdInventoryDelete(), "node"); err != nil {
		t.Fatal(err)
	}
	secret, err := registry.Resolve(t.Context(), *identity.LoginPasswordRef)
	secret.Zero()
	if err != nil {
		t.Fatalf("shared credential removed: %v", err)
	}
	if err := executePhase6(t, NewCmdIdentityDelete(), "admin"); err == nil {
		t.Fatal("deleted referenced identity")
	}
	if err := executePhase6(t, hostcmd.NewCmdInventoryDelete(), "other"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Resolve(t.Context(), *identity.LoginPasswordRef); !errors.Is(err, credential.ErrCredentialNotFound) {
		t.Fatalf("last reference retained backend secret: %v", err)
	}
}

func TestIdentityDeleteCleansStoredCredential(t *testing.T) {
	setupFirewallCredential(t)
	if err := executePhase6(t, NewCmdIdentity(), "add", "--name", "orphan", "--user", "ops", "--password", "identity-secret"); err != nil {
		t.Fatal(err)
	}
	_, _, cfg, err := utils.GetConfigStore()
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := cfg.Identities.Get("orphan")
	registry, err := utils.GetCredentialRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := executePhase6(t, NewCmdIdentityDelete(), "orphan"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Resolve(t.Context(), *identity.LoginPasswordRef); !errors.Is(err, credential.ErrCredentialNotFound) {
		t.Fatalf("identity deletion leaked credential: %v", err)
	}
}
