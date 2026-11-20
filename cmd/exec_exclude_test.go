package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/models"
)

// TestExecExcludeFlagRegistered verifies the --exclude flag is properly registered
// on the exec command and parses comma-separated / repeated values correctly.
func TestExecExcludeFlagRegistered(t *testing.T) {
	if err := i18n.Init("zh"); err != nil {
		t.Fatalf("i18n.Init failed: %v", err)
	}
	c := NewCmdExec()

	flag := c.Flags().Lookup("exclude")
	if flag == nil {
		t.Fatal("expected --exclude flag to be registered on exec command")
	}
	if flag.NoOptDefVal != "" {
		t.Errorf("--exclude should require a value, got NoOptDefVal=%q", flag.NoOptDefVal)
	}

	// Parse args with both comma-separated and repeated --exclude forms
	args := []string{"--exclude", "web-01,web-02", "--exclude", "db-01", "-c", "uptime", "--host", "h1"}
	if err := c.Flags().Parse(args); err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}

	got, err := c.Flags().GetStringSlice("exclude")
	if err != nil {
		t.Fatalf("failed to get exclude slice: %v", err)
	}

	want := []string{"web-01", "web-02", "db-01"}
	if len(got) != len(want) {
		t.Fatalf("expected %d raw exclude entries, got %d (%v)", len(want), len(got), got)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("at index %d: expected %q, got %q", i, v, got[i])
		}
	}
}

func setupExecDiskTestStore(t *testing.T) (string, *config.Configuration, *config.Repository) {
	t.Helper()
	_ = setupTestEnvironment(t)
	if err := i18n.Init("zh"); err != nil {
		t.Fatalf("i18n.Init failed: %v", err)
	}
	cfg := &config.Configuration{
		SchemaVersion: 2,
		Hosts:         concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities:    concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Nodes:         concurrent.NewMap[string, models.Node](concurrent.HashString),
		Credential: &config.CredentialConfig{
			DefaultStore:     "none",
			RememberPrompted: "always",
			Stores:           map[string]config.StoreConfig{"none": {Type: config.StoreTypeNone}},
		},
	}
	cfg.Hosts.Set("h-1", models.Host{Address: "10.238.221.181", Port: 22})
	cfg.Identities.Set("id-1", models.Identity{User: "iaas", AuthType: "auto"})
	cfg.Nodes.Set("iaas@10.238.221.181:22", models.Node{
		HostRef:     "h-1",
		IdentityRef: "id-1",
		ProxyJump:   "jump-old",
		Alias:       []string{"web-1"},
		Tags:        []string{"prod"},
	})
	path, key, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	store := config.NewDefaultStore(path, key)
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	_, repo, loadedCfg, err := utils.GetConfigStore()
	if err != nil {
		t.Fatalf("GetConfigStore: %v", err)
	}
	return path, loadedCfg, repo
}

func TestExecRunContextExcludeAndJumpOverrideNoDiskMutation(t *testing.T) {
	path, _, _ := setupExecDiskTestStore(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(before): %v", err)
	}

	t.Run("excluded saved node with -J override makes zero disk mutations", func(t *testing.T) {
		o := NewExecOptions()
		o.Host = "web-1"
		o.JumpHost = "10.0.0.99:22"
		o.Exclude = []string{"web-1"}
		o.Command = "id"
		o.Remember = "always"
		o.control.ConfigFile = "none"
		if err := o.Complete(NewCmdExec(), nil); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		if err := o.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		err := o.RunContext(t.Context())
		if err == nil || !strings.Contains(err.Error(), i18n.T("err_no_nodes_found")) {
			t.Fatalf("expected err_no_nodes_found when all targets excluded, got: %v", err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(after): %v", err)
		}
		if !bytes.Equal(before, after) {
			t.Fatalf("expected zero disk config mutations when excluded node had -J override")
		}
	})

	t.Run("invalid --exclude fails before materializing -J override on disk", func(t *testing.T) {
		o := NewExecOptions()
		o.Host = "web-1"
		o.JumpHost = "10.0.0.99:22"
		o.Exclude = []string{"missing-node"}
		o.Command = "id"
		o.Remember = "always"
		o.control.ConfigFile = "none"
		if err := o.Complete(NewCmdExec(), nil); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		if err := o.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		err := o.RunContext(t.Context())
		if err == nil || !strings.Contains(err.Error(), i18n.T("exec_err_exclude")) {
			t.Fatalf("expected exec_err_exclude on invalid --exclude, got: %v", err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(after): %v", err)
		}
		if !bytes.Equal(before, after) {
			t.Fatalf("expected zero disk config mutations on invalid --exclude")
		}
	})
}

func TestExecNonInteractiveSuppressNodeConfirmation(t *testing.T) {
	path, cfg, repo := setupExecDiskTestStore(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(before): %v", err)
	}

	target := config.ConnectionTarget{
		Selector: "10.0.0.55",
		User:     "ops",
		HasUser:  true,
		Port:     22,
		HasPort:  true,
	}
	res, err := repo.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{Target: target})
	if err != nil {
		t.Fatalf("PrepareNodeContext: %v", err)
	}

	o := NewExecOptions()
	o.Interactive = false
	o.Remember = "always"
	o.Command = "id"
	o.control.ConfigFile = "none"

	adpOpts, err := o.buildAdapterOptions([]execHostTask{{nodeID: res.NodeID}}, cfg, repo)
	if err != nil {
		t.Fatalf("buildAdapterOptions: %v", err)
	}
	adp := adapter.NewSSHAdapter(repo, adpOpts...)
	if err := adp.ConfirmConnection(t.Context(), res.NodeID); err != nil {
		t.Fatalf("ConfirmConnection: %v", err)
	}

	if _, ok := repo.Snapshot().Nodes.Get(res.NodeID); ok {
		t.Fatalf("expected non-interactive exec (SuppressNodeConfirmation=true) NOT to confirm pending node %q", res.NodeID)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(after): %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("expected non-interactive exec not to write confirmed node to disk")
	}
}

func TestExecNonInteractiveNeverMutatesSavedNodeProxyJumpOrAliasOnDisk(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	path, key, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.SchemaVersion = 2
	cfg.Hosts.Set("10.0.0.10:22", models.Host{Address: "10.0.0.10", Port: 22})
	cfg.Identities.Set("ops@10.0.0.10", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Hosts.Set("10.0.0.1:22", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Identities.Set("jump@10.0.0.1", models.Identity{User: "jump", AuthType: "auto"})
	cfg.Nodes.Set("saved-web", models.Node{HostRef: "10.0.0.10:22", IdentityRef: "ops@10.0.0.10", Alias: []string{"web"}})
	cfg.Nodes.Set("jump@10.0.0.1:22", models.Node{HostRef: "10.0.0.1:22", IdentityRef: "jump@10.0.0.1", Alias: []string{"bastion"}})

	store := config.NewDefaultStore(path, key)
	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save config: %v", err)
	}
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(before): %v", err)
	}

	o := NewExecOptions()
	o.Interactive = false
	o.Host = "saved-web"
	o.JumpHost = "bastion"
	o.Alias = "mutated-alias"
	o.Remember = "always"

	updated, err := o.updateNodeFromHostInfo(t.Context(), "saved-web", repo, utils.HostInfo{Alias: "mutated-alias", Password: "pw"})
	if err != nil {
		t.Fatalf("updateNodeFromHostInfo(non-interactive): %v", err)
	}
	if updated {
		t.Fatal("expected non-interactive updateNodeFromHostInfo to return updated=false")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(after): %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("non-interactive exec mutated saved node config on disk")
	}

	// Verify invalid -J still fails closed under non-interactive / -F none mode.
	oBadJump := NewExecOptions()
	oBadJump.Interactive = false
	oBadJump.JumpHost = "nonexistent-jump-host"
	if _, err := oBadJump.updateNodeFromHostInfo(t.Context(), "saved-web", config.NewProviderWithoutOpenSSH(cfg), utils.HostInfo{}); err == nil {
		t.Fatal("expected invalid -J to fail closed even when Interactive=false and provider is not *Repository")
	}
}
