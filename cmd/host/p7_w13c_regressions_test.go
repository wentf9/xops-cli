package host

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W13c_L4_13_M2_HostEditRejectsAddressAndOpenSSHIntermediaryCycles(t *testing.T) {
	const sshCfg = `
Host ssh-app-a
    HostName 10.237.0.10
    Port 22
    User ops

Host ssh-gw-99
    HostName 10.237.0.99
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

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-a", models.Host{Address: "10.237.0.10", Port: 22})
	cfg.Hosts.Set("h-b", models.Host{Address: "10.237.0.11", Port: 22})
	cfg.Hosts.Set("h-dup", models.Host{Address: "10.237.0.12", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	// node-a uses unique Host.Address "10.237.0.11" (node-b) as its ProxyJump!
	cfg.Nodes.Set("ops@10.237.0.10:22", models.Node{
		HostRef:     "h-a",
		IdentityRef: "id-ops",
		Alias:       []string{"app-a"},
		ProxyJump:   "10.237.0.11",
		SudoMode:    models.SudoModeAuto,
	})
	cfg.Nodes.Set("ops@10.237.0.11:22", models.Node{
		HostRef:     "h-b",
		IdentityRef: "id-ops",
		Alias:       []string{"app-b"},
		SudoMode:    models.SudoModeAuto,
	})
	// node-dup jumps via alias "app-b,openssh:ssh-gw-99" (valid while app-b is 10.237.0.11).
	cfg.Nodes.Set("ops@10.237.0.12:22", models.Node{
		HostRef:     "h-dup",
		IdentityRef: "id-ops",
		Alias:       []string{"app-dup"},
		ProxyJump:   "app-b,openssh:ssh-gw-99",
		SudoMode:    models.SudoModeAuto,
	})

	store := config.NewDefaultStore(cfgPath, keyPath)
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}

	// 1. Editing app-b to jump via ssh-app-a (10.237.0.10 == app-a) closes the 2-hop cycle
	//    app-a -> 10.237.0.11 (app-b) -> openssh:ssh-app-a (app-a).
	var cycleErr *ssh.ProxyCycleError
	if err := runHostEditCLI("app-b", "--jump", "ssh-app-a"); !errors.As(err, &cycleErr) {
		t.Errorf("host edit app-b --jump ssh-app-a err = %v, want *ssh.ProxyCycleError", err)
	}

	// 2. Editing app-b's address to 10.237.0.99 creates a duplicate hop in app-dup ("app-b,openssh:ssh-gw-99").
	if err := runHostEditCLI("app-b", "-H", "10.237.0.99"); !errors.As(err, &cycleErr) {
		t.Errorf("host edit app-b -H 10.237.0.99 err = %v, want *ssh.ProxyCycleError", err)
	}

	// 3. Valid unrelated edit on app-b (e.g., adding tags) must still succeed.
	if err := runHostEditCLI("app-b", "--tags", "verified"); err != nil {
		t.Fatalf("host edit app-b --tags verified unexpected error: %v", err)
	}
}
