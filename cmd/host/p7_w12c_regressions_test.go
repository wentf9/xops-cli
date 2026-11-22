package host

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func setupW12cHostOpenSSHTestEnv(t *testing.T, sshCfg string) config.Store {
	t.Helper()
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
	cfg.Hosts.Set("h-existing", models.Host{Address: "10.0.0.10", Port: 22})
	cfg.Hosts.Set("h-peer", models.Host{Address: "10.0.0.11", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("ops@10.0.0.10:22", models.Node{
		HostRef:     "h-existing",
		IdentityRef: "id-ops",
		Alias:       []string{"app-a"},
		SudoMode:    models.SudoModeAuto,
	})
	cfg.Nodes.Set("ops@10.0.0.11:22", models.Node{
		HostRef:     "h-peer",
		IdentityRef: "id-ops",
		Alias:       []string{"app-peer"},
		ProxyJump:   "ops@10.0.0.10:22",
		SudoMode:    models.SudoModeAuto,
	})

	store := config.NewDefaultStore(cfgPath, keyPath)
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	return store
}

func runW12cHostAdd(verify inventoryVerifier, args ...string) error {
	addCmd := newCmdInventoryAdd(verify)
	addCmd.SilenceErrors = true
	addCmd.SilenceUsage = true
	addCmd.SetOut(&bytes.Buffer{})
	addCmd.SetErr(&bytes.Buffer{})
	addCmd.SetArgs(args)
	return addCmd.Execute()
}

func TestP7W12c_FG12M3_HostAddAndEditEnforceTier2ToTier4OpenSSHJumpCycles(t *testing.T) {
	const sshCfg = `
Host ssh-self
    HostName 10.0.0.2
    Port 22
    User ops

Host ssh-back
    HostName 10.0.0.3
    Port 22
    User ops
    ProxyJump ops@10.0.0.2:22

Host ssh-99
    HostName 10.0.0.99
    Port 22
    User ops

Host ssh-port2222
    HostName 10.0.0.10
    Port 2222
    User ops

Host ssh-bob
    HostName 10.0.0.2
    Port 22
    User bob

Host ssh-peer
    HostName 10.0.0.11
    Port 22
    User ops

Host bastion-ext
    HostName 10.0.0.60
    Port 22
    User root
`

	t.Run("host_add_rejects_1hop_and_2hop_openssh_cycles_before_verify_or_commit", func(t *testing.T) {
		assertW12cHostAddOpenSSHCycles(t, sshCfg)
	})

	t.Run("host_edit_rejects_jump_and_endpoint_edits_forming_openssh_cycles", func(t *testing.T) {
		assertW12cHostEditOpenSSHCycles(t, sshCfg)
	})
}

func assertW12cHostAddOpenSSHCycles(t *testing.T, sshCfg string) {
	t.Helper()
	store := setupW12cHostOpenSSHTestEnv(t, sshCfg)

	verifyCalls := 0
	fakeVerify := func(_ context.Context, _ *config.Repository, _ string, _ *inventoryVerification) error {
		verifyCalls++
		return nil
	}

	keyFile := filepath.Join(t.TempDir(), "id_test")
	if err := os.WriteFile(keyFile, []byte("dummy-key"), 0o600); err != nil {
		t.Fatalf("WriteFile keyFile: %v", err)
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"1hop_skip_verify", []string{"web", "ops@10.0.0.2", "--jump", "ssh-self", "--skip-verify"}},
		{"1hop_with_verify", []string{"web", "ops@10.0.0.2", "--key", keyFile, "--jump", "ssh-self"}},
		{"1hop_explicit_openssh", []string{"web", "ops@10.0.0.2", "--jump", "openssh:ssh-self", "--skip-verify"}},
		{"2hop_openssh_backedge", []string{"web", "ops@10.0.0.2", "--jump", "ssh-back", "--skip-verify"}},
	} {
		var cycleErr *ssh.ProxyCycleError
		if err := runW12cHostAdd(fakeVerify, tc.args...); !errors.As(err, &cycleErr) {
			t.Errorf("host add (%s) err = %v, want *ssh.ProxyCycleError", tc.name, err)
		}
	}

	if verifyCalls != 0 {
		t.Fatalf("verifier called %d times on cyclic host add, want 0", verifyCalls)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	if _, exists := loaded.Nodes.Get("ops@10.0.0.2:22"); exists {
		t.Fatal("cyclic host add persisted ops@10.0.0.2:22 into config.yaml")
	}

	// Distinct user same endpoint (ops@10.0.0.2 via bob@10.0.0.2) MUST succeed.
	if err := runW12cHostAdd(fakeVerify, "web-ok", "ops@10.0.0.2", "--jump", "ssh-bob", "--skip-verify"); err != nil {
		t.Fatalf("host add distinct-user jump unexpected error: %v", err)
	}

	// DE12-M2: colliding local alias with explicit openssh: pointing to a different endpoint MUST succeed.
	if err := runW12cHostAdd(fakeVerify, "bastion-ext", "root@10.0.0.88:22", "--jump", "openssh:bastion-ext", "--skip-verify"); err != nil {
		t.Fatalf("host add colliding alias with explicit openssh: unexpected error: %v", err)
	}

	// DE12-L1: padded/malformed openssh: jump must fail closed with ErrSSHOptionsValidation.
	for _, bad := range []string{" openssh:ssh-99", "\u00a0openssh:ssh-99", "openssh:openssh:ssh-99"} {
		if err := runW12cHostAdd(fakeVerify, "web-bad", "ops@10.0.0.77", "--jump", bad, "--skip-verify"); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("host add --jump %q err = %v, want ErrSSHOptionsValidation", bad, err)
		}
	}
}

func assertW12cHostEditOpenSSHCycles(t *testing.T, sshCfg string) {
	t.Helper()
	store := setupW12cHostOpenSSHTestEnv(t, sshCfg)

	// Assign a valid OpenSSH jump (ssh-99 -> 10.0.0.99) to app-a (ops@10.0.0.10:22).
	if err := runHostEditCLI("app-a", "--jump", "ssh-99"); err != nil {
		t.Fatalf("host edit app-a --jump ssh-99 failed: %v", err)
	}

	// Editing ONLY -H to 10.0.0.99 while app-a already has ProxyJump: "openssh:ssh-99"
	// must fail closed with *ssh.ProxyCycleError without mutating config.yaml.
	var cycleErr *ssh.ProxyCycleError
	if err := runHostEditCLI("app-a", "-H", "10.0.0.99"); !errors.As(err, &cycleErr) {
		t.Errorf("host edit app-a -H 10.0.0.99 err = %v, want *ssh.ProxyCycleError", err)
	}

	// Editing app-a --jump ssh-peer (10.0.0.11 == app-peer, which already has ProxyJump: ops@10.0.0.10:22 == app-a)
	// must detect the reverse-reachable 2-hop cycle app-peer -> app-a -> openssh:ssh-peer!
	if err := runHostEditCLI("app-a", "--jump", "ssh-peer"); !errors.As(err, &cycleErr) {
		t.Errorf("host edit app-a --jump ssh-peer err = %v, want *ssh.ProxyCycleError", err)
	}

	// Switch app-a jump to ssh-port2222 (10.0.0.10:2222 -> valid while app-a is on port 22),
	// then editing ONLY -p 2222 must fail closed with *ssh.ProxyCycleError.
	if err := runHostEditCLI("app-a", "--jump", "ssh-port2222"); err != nil {
		t.Fatalf("host edit app-a --jump ssh-port2222 failed: %v", err)
	}
	if err := runHostEditCLI("app-a", "-p", "2222"); !errors.As(err, &cycleErr) {
		t.Errorf("host edit app-a -p 2222 err = %v, want *ssh.ProxyCycleError", err)
	}

	// Verify user-only edit (-u) into a cycle fails closed even when IdentityRef is shared with app-peer.
	if err := runHostEditCLI("app-a", "--jump", "ssh-bob"); err != nil {
		t.Fatalf("host edit app-a --jump ssh-bob failed: %v", err)
	}
	if err := runHostEditCLI("app-a", "-H", "10.0.0.2"); err != nil {
		t.Fatalf("host edit app-a -H 10.0.0.2 (ops != bob) failed: %v", err)
	}
	if err := runHostEditCLI("app-a", "-u", "bob"); !errors.As(err, &cycleErr) {
		t.Errorf("host edit app-a -u bob err = %v, want *ssh.ProxyCycleError", err)
	}

	// Verify rejected edits left ops@10.0.0.2:22 intact and did not persist bob@10.0.0.2:22 or corrupt app-peer.
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	if _, exists := loaded.Nodes.Get("bob@10.0.0.2:22"); exists {
		t.Fatal("rejected -u bob edit persisted cyclic node bob@10.0.0.2:22")
	}
	if n, ok := loaded.Nodes.Get("ops@10.0.0.2:22"); !ok || !strings.Contains(n.ProxyJump, "openssh:ssh-bob") {
		t.Fatalf("ops@10.0.0.2:22 state = (%+v, %v), want intact ProxyJump openssh:ssh-bob", n, ok)
	}
	if peer, ok := loaded.Nodes.Get("ops@10.0.0.11:22"); !ok {
		t.Fatal("app-peer missing after edits")
	} else if ident, iOK := loaded.Identities.Get(peer.IdentityRef); !iOK || ident.User != "ops" {
		t.Fatalf("app-peer identity corrupted: (%+v, %v)", ident, iOK)
	}

	// DE12-L1: padded/malformed openssh: jump in host edit fails closed with ErrSSHOptionsValidation.
	for _, bad := range []string{" openssh:ssh-99", "\u00a0openssh:ssh-99", "openssh:openssh:ssh-99"} {
		if err := runHostEditCLI("app-a", "--jump", bad); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("host edit --jump %q err = %v, want ErrSSHOptionsValidation", bad, err)
		}
	}
}
