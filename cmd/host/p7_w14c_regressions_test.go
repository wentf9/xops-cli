package host

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W14c_L4_14_M1_HostEditAllowsJumpClearRepairAndNonRoutingTagEdit(t *testing.T) {
	const sshCfg = `
Host ssh-app-a
    HostName 10.242.0.10
    Port 22
    User ops
`
	homeDir := t.TempDir()
	xopsDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	t.Setenv("XOPS_CONFIG_DIR", xopsDir)

	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("MkdirAll .ssh: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(sshCfg), 0o600); err != nil {
		t.Fatalf("WriteFile ~/.ssh/config: %v", err)
	}

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}

	// Pre-existing broken OpenSSH cycle on disk: app-a -> app-b -> openssh:ssh-app-a (10.242.0.10 == app-a).
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-a", models.Host{Address: "10.242.0.10", Port: 22})
	cfg.Hosts.Set("h-b", models.Host{Address: "10.242.0.11", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("ops@10.242.0.10:22", models.Node{
		HostRef:     "h-a",
		IdentityRef: "id-ops",
		Alias:       []string{"app-a"},
		ProxyJump:   "ops@10.242.0.11:22",
		SudoMode:    models.SudoModeAuto,
	})
	cfg.Nodes.Set("ops@10.242.0.11:22", models.Node{
		HostRef:     "h-b",
		IdentityRef: "id-ops",
		Alias:       []string{"app-b"},
		ProxyJump:   "openssh:ssh-app-a",
		SudoMode:    models.SudoModeAuto,
	})

	store := config.NewDefaultStore(cfgPath, keyPath)
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}

	// 1. Pure non-routing tag edit on app-b must succeed without failing on the pre-existing cycle.
	if err := runHostEditCLI("app-b", "--tags", "maintenance"); err != nil {
		t.Fatalf("host edit app-b --tags maintenance unexpected error: %v", err)
	}

	// 2. Clearing the broken ProxyJump (`-j ""`) on app-b must repair the cycle and succeed.
	if err := runHostEditCLI("app-b", "-j", ""); err != nil {
		t.Fatalf("host edit app-b -j \"\" unexpected error: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	nodeB, ok := loaded.Nodes.Get("ops@10.242.0.11:22")
	if !ok || nodeB.ProxyJump != "" {
		t.Fatalf("repaired app-b = (%+v, %v), want empty ProxyJump", nodeB, ok)
	}
}
