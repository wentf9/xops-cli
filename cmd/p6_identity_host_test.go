package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	hostcmd "github.com/wentf9/xops-cli/cmd/host"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/models"
	sshcrypto "golang.org/x/crypto/ssh"
)

func setupP6IsolatedStore(t *testing.T) (string, config.Store, *config.Repository) {
	t.Helper()
	rawDir := t.TempDir()
	physicalDir, err := filepath.EvalSymlinks(rawDir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	cfgDir := filepath.Join(physicalDir, "cfg")
	homeDir := filepath.Join(physicalDir, "home")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatalf("MkdirAll cfgDir: %v", err)
	}
	if err := os.MkdirAll(homeDir, 0o700); err != nil {
		t.Fatalf("MkdirAll homeDir: %v", err)
	}
	t.Setenv("XOPS_CONFIG_DIR", cfgDir)
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	t.Setenv("SSH_AUTH_SOCK", "")
	if err := i18n.Init("en"); err != nil {
		t.Fatalf("i18n.Init: %v", err)
	}

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)
	cfg := &config.Configuration{
		SchemaVersion: 2,
		Nodes:         concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:         concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities:    concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Credential:    config.DefaultCredentialConfig(),
	}
	owner := config.NewEncryptedRuntime(t.Context(), cfgPath, nil)
	detach, err := utils.InstallCredentialRuntime(owner)
	if err != nil {
		t.Fatalf("InstallCredentialRuntime: %v", err)
	}
	t.Cleanup(func() {
		detach()
		if closeErr := owner.Close(); closeErr != nil {
			t.Errorf("owner.Close: %v", closeErr)
		}
	})
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	return homeDir, store, repo
}

func writeTestEd25519Key(t *testing.T, path string, passphrase string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(%s): %v", filepath.Dir(path), err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = sshcrypto.MarshalPrivateKey(priv, "")
	} else {
		block, err = sshcrypto.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

type p6KeyCase struct {
	suffix string
	input  string
	want   string
}

func TestP6_IdentityPathPreservation_HostAddEditImportAndIdentity(t *testing.T) {
	homeDir, store, _ := setupP6IsolatedStore(t)

	// Prepare literal keys under $HOME and a relative path inside a temp CWD.
	tildeKeyAbs := filepath.Join(homeDir, ".ssh", "id_p6_tilde")
	writeTestEd25519Key(t, tildeKeyAbs, "")

	workDir := t.TempDir()
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("Chdir(%s): %v", workDir, err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })
	workDirPhysical, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd after chdir: %v", err)
	}
	relKeyAbs := filepath.Join(workDirPhysical, "id_p6_rel")
	writeTestEd25519Key(t, relKeyAbs, "")

	keyCases := []p6KeyCase{
		{"percent_d", "%d/.ssh/id_ed25519", "%d/.ssh/id_ed25519"},
		{"env_var", "${SSH_KEY_DIR}/id_ed25519", "${SSH_KEY_DIR}/id_ed25519"},
		{"none_lower", "none", "none"},
		{"none_upper", "  NONE  ", "none"},
		{"tilde_literal", "~/.ssh/id_p6_tilde", tildeKeyAbs},
		{"relative_literal", "./id_p6_rel", relKeyAbs},
		{"abs_literal", tildeKeyAbs, tildeKeyAbs},
	}

	assertP6HostAddKeyCases(t, store, keyCases)
	assertP6HostEditKeyCases(t, store, keyCases)
	assertP6HostImportKeyCases(t, store, workDirPhysical, relKeyAbs)
	assertP6IdentityAddEditKeyCases(t, store, keyCases)
}

func assertP6HostAddKeyCases(t *testing.T, store config.Store, keyCases []p6KeyCase) {
	t.Helper()
	for i, tc := range keyCases {
		t.Run("host_add_"+tc.suffix, func(t *testing.T) {
			ip := "192.0.2." + string(rune('1'+i))
			alias := "add-" + tc.suffix
			addCmd := hostcmd.NewCmdInventoryAdd()
			addCmd.SetOut(io.Discard)
			addCmd.SetErr(io.Discard)
			addCmd.SetArgs([]string{alias, "ops@" + ip, "--key", tc.input, "--skip-verify"})
			if err := addCmd.Execute(); err != nil {
				t.Fatalf("host add (%s) failed: %v", tc.input, err)
			}
			cfg, err := store.Load()
			if err != nil {
				t.Fatalf("store.Load: %v", err)
			}
			nodeID := "ops@" + ip + ":22"
			node, ok := cfg.Nodes.Get(nodeID)
			if !ok {
				t.Fatalf("node %q not persisted", nodeID)
			}
			ident, ok := cfg.Identities.Get(node.IdentityRef)
			if !ok {
				t.Fatalf("identity %q not persisted", node.IdentityRef)
			}
			if ident.AuthType != "key" || ident.KeyPath != tc.want {
				t.Fatalf("host add(%q): got (AuthType=%q, KeyPath=%q), want (key, %q)", tc.input, ident.AuthType, ident.KeyPath, tc.want)
			}
		})
	}
}

func assertP6HostEditKeyCases(t *testing.T, store config.Store, keyCases []p6KeyCase) {
	t.Helper()
	for _, tc := range keyCases {
		t.Run("host_edit_"+tc.suffix, func(t *testing.T) {
			editCmd := hostcmd.NewCmdInventoryEdit()
			editCmd.SetOut(io.Discard)
			editCmd.SetErr(io.Discard)
			editCmd.SetArgs([]string{"add-percent_d", "--key", tc.input})
			if err := editCmd.Execute(); err != nil {
				t.Fatalf("host edit (%s) failed: %v", tc.input, err)
			}
			cfg, err := store.Load()
			if err != nil {
				t.Fatalf("store.Load: %v", err)
			}
			node, _ := cfg.Nodes.Get("ops@192.0.2.1:22")
			ident, _ := cfg.Identities.Get(node.IdentityRef)
			if ident.AuthType != "key" || ident.KeyPath != tc.want {
				t.Fatalf("host edit(%q): got (AuthType=%q, KeyPath=%q), want (key, %q)", tc.input, ident.AuthType, ident.KeyPath, tc.want)
			}
		})
	}
}

func assertP6HostImportKeyCases(t *testing.T, store config.Store, workDirPhysical, relKeyAbs string) {
	t.Helper()
	csvPath := filepath.Join(workDirPhysical, "import.csv")
	csvBody := strings.Join([]string{
		"host,port,alias,user,password,key,keypass",
		"192.0.2.41,22,imp-pct,ops,,%d/.ssh/id_ed25519,",
		"192.0.2.42,22,imp-env,ops,,${SSH_KEY_DIR}/id_ed25519,",
		"192.0.2.43,22,imp-none,ops,,none,",
		"192.0.2.44,22,imp-rel,ops,,./id_p6_rel,",
		"192.0.2.41,22,imp-pct,ops,,${UPDATED_KEY}/id_ed25519,",
	}, "\n") + "\n"
	if err := os.WriteFile(csvPath, []byte(csvBody), 0o600); err != nil {
		t.Fatalf("WriteFile import.csv: %v", err)
	}
	importCmd := hostcmd.NewCmdInventoryLoad()
	importCmd.SetOut(&bytes.Buffer{})
	importCmd.SetErr(&bytes.Buffer{})
	importCmd.SetArgs([]string{"--skip-verify", csvPath})
	if err := importCmd.Execute(); err != nil {
		t.Fatalf("host import failed: %v", err)
	}
	cfgAfterImport, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load after import: %v", err)
	}
	for nodeID, wantKey := range map[string]string{
		"ops@192.0.2.41:22": "${UPDATED_KEY}/id_ed25519",
		"ops@192.0.2.42:22": "${SSH_KEY_DIR}/id_ed25519",
		"ops@192.0.2.43:22": "none",
		"ops@192.0.2.44:22": relKeyAbs,
	} {
		node, ok := cfgAfterImport.Nodes.Get(nodeID)
		if !ok {
			t.Fatalf("imported node %q missing", nodeID)
		}
		ident, ok := cfgAfterImport.Identities.Get(node.IdentityRef)
		if !ok {
			t.Fatalf("imported identity %q missing", node.IdentityRef)
		}
		if ident.KeyPath != wantKey {
			t.Fatalf("imported %s KeyPath = %q, want %q", nodeID, ident.KeyPath, wantKey)
		}
	}
}

func assertP6IdentityAddEditKeyCases(t *testing.T, store config.Store, keyCases []p6KeyCase) {
	t.Helper()
	for _, tc := range keyCases {
		t.Run("identity_add_"+tc.suffix, func(t *testing.T) {
			idName := "id-" + tc.suffix
			cmd := NewCmdIdentity()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"add", idName, "ops", "--key", tc.input})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("identity add(%q) failed: %v", tc.input, err)
			}
			cfg, err := store.Load()
			if err != nil {
				t.Fatalf("store.Load: %v", err)
			}
			ident, ok := cfg.Identities.Get(idName)
			if !ok {
				t.Fatalf("identity %q not persisted", idName)
			}
			if ident.AuthType != "key" || ident.KeyPath != tc.want {
				t.Fatalf("identity add(%q): got (%q, %q), want (key, %q)", tc.input, ident.AuthType, ident.KeyPath, tc.want)
			}
		})
	}
	for _, tc := range keyCases {
		t.Run("identity_edit_"+tc.suffix, func(t *testing.T) {
			cmd := NewCmdIdentity()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"edit", "id-percent_d", "--key", tc.input})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("identity edit(%q) failed: %v", tc.input, err)
			}
			cfg, err := store.Load()
			if err != nil {
				t.Fatalf("store.Load: %v", err)
			}
			ident, _ := cfg.Identities.Get("id-percent_d")
			if ident.AuthType != "key" || ident.KeyPath != tc.want {
				t.Fatalf("identity edit(%q): got (%q, %q), want (key, %q)", tc.input, ident.AuthType, ident.KeyPath, tc.want)
			}
		})
	}
}

func TestP6_InventoryCredential_TemplateNoneAndBoundedValidateUnencryptedKey(t *testing.T) {
	_, _, repo := setupP6IsolatedStore(t)

	assertP6TemplateAndInvalidKeyHandling(t, repo)
	assertP6BoundedRegularFileRejection(t, repo)
	assertP6PositiveUnencryptedAndEncryptedKeys(t, repo)
}

func assertP6TemplateAndInvalidKeyHandling(t *testing.T, repo *config.Repository) {
	t.Helper()
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"%d/.ssh/id_ed25519", "%d/.ssh/id_ed25519"},
		{"${SSH_KEY}/id_rsa", "${SSH_KEY}/id_rsa"},
		{"none", "none"},
		{"  NONE  ", "none"},
	} {
		if got := utils.NormalizeIdentityKeyPath(tc.in); got != tc.want {
			t.Fatalf("NormalizeIdentityKeyPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
		needs, err := utils.KeyNeedsPassphrase(tc.in)
		if err != nil || needs {
			t.Fatalf("KeyNeedsPassphrase(%q) = (%v, %v), want (false, nil)", tc.in, needs, err)
		}
		write, err := utils.PrepareInventoryCredential(repo, credential.Target{IdentityID: "tpl-check"}, models.Identity{User: "ops"}, "", "", tc.in, nil)
		if err != nil {
			t.Fatalf("PrepareInventoryCredential(%q) unexpected error: %v", tc.in, err)
		}
		write.Clear()
		if w, err := utils.PrepareInventoryCredential(repo, credential.Target{IdentityID: "tpl-pass"}, models.Identity{User: "ops"}, "", "secret-pass", tc.in, nil); err == nil {
			w.Clear()
			t.Fatalf("PrepareInventoryCredential(%q with passphrase) unexpectedly succeeded", tc.in)
		}
	}

	for _, bad := range []string{"/tmp/bad\nkey", "%z/.ssh/id_ed25519", "   "} {
		if w, err := utils.PrepareInventoryCredential(repo, credential.Target{IdentityID: "bad-key"}, models.Identity{User: "ops"}, "", "", bad, nil); err == nil {
			w.Clear()
			t.Fatalf("PrepareInventoryCredential(%q) unexpectedly succeeded", bad)
		}
		if _, err := utils.KeyNeedsPassphrase(bad); err == nil {
			t.Fatalf("KeyNeedsPassphrase(%q) unexpectedly succeeded", bad)
		}
	}
}

func assertP6PrepareRejectsWithinTimeout(t *testing.T, repo *config.Repository, label, keyPath string) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		w, pErr := utils.PrepareInventoryCredential(repo, credential.Target{IdentityID: label}, models.Identity{User: "ops"}, "", "", keyPath, nil)
		if w != nil {
			w.Clear()
		}
		done <- pErr
	}()
	select {
	case pErr := <-done:
		if pErr == nil {
			t.Fatalf("PrepareInventoryCredential(%s) unexpectedly succeeded", label)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("PrepareInventoryCredential(%s) hung instead of failing closed", label)
	}
}

func assertP6BoundedRegularFileRejection(t *testing.T, repo *config.Repository) {
	t.Helper()
	oversizedPath := filepath.Join(t.TempDir(), "oversized_key")
	if err := os.WriteFile(oversizedPath, make([]byte, (1<<20)+1), 0o600); err != nil {
		t.Fatalf("WriteFile oversized: %v", err)
	}
	assertP6PrepareRejectsWithinTimeout(t, repo, "oversized", oversizedPath)
	if _, err := utils.KeyNeedsPassphrase(oversizedPath); err == nil {
		t.Fatal("KeyNeedsPassphrase accepted >1 MiB key file, want rejection")
	}

	dirTarget := t.TempDir()
	assertP6PrepareRejectsWithinTimeout(t, repo, "directory", dirTarget)
	if _, err := utils.KeyNeedsPassphrase(dirTarget); err == nil {
		t.Fatal("KeyNeedsPassphrase accepted directory as key path, want rejection")
	}

	if _, err := os.Stat("/dev/zero"); err == nil {
		assertP6PrepareRejectsWithinTimeout(t, repo, "/dev/zero", "/dev/zero")
	}

	if runtime.GOOS != "windows" {
		if mkfifoBin, lookErr := exec.LookPath("mkfifo"); lookErr == nil {
			fifoPath := filepath.Join(t.TempDir(), "key.fifo")
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if out, mkErr := exec.CommandContext(ctx, mkfifoBin, fifoPath).CombinedOutput(); mkErr != nil {
				t.Fatalf("mkfifo %s failed: %v (%s)", fifoPath, mkErr, out)
			}
			assertP6PrepareRejectsWithinTimeout(t, repo, "fifo", fifoPath)
		}
	}
}

func assertP6PositiveUnencryptedAndEncryptedKeys(t *testing.T, repo *config.Repository) {
	t.Helper()
	plainKey := filepath.Join(t.TempDir(), "id_plain")
	encKey := filepath.Join(t.TempDir(), "id_encrypted")
	writeTestEd25519Key(t, plainKey, "")
	writeTestEd25519Key(t, encKey, "s3cr3t")

	if needs, err := utils.KeyNeedsPassphrase(plainKey); err != nil || needs {
		t.Fatalf("KeyNeedsPassphrase(plainKey) = (%v, %v), want (false, nil)", needs, err)
	}
	if needs, err := utils.KeyNeedsPassphrase(encKey); err != nil || !needs {
		t.Fatalf("KeyNeedsPassphrase(encKey) = (%v, %v), want (true, nil)", needs, err)
	}
	wPlain, err := utils.PrepareInventoryCredential(repo, credential.Target{IdentityID: "plain"}, models.Identity{User: "ops"}, "", "", plainKey, nil)
	if err != nil {
		t.Fatalf("PrepareInventoryCredential(plainKey) failed: %v", err)
	}
	wPlain.Clear()
	if wEnc, err := utils.PrepareInventoryCredential(repo, credential.Target{IdentityID: "enc"}, models.Identity{User: "ops"}, "", "", encKey, nil); err == nil {
		wEnc.Clear()
		t.Fatal("PrepareInventoryCredential(encKey without passphrase) unexpectedly succeeded")
	}
}

func TestP6_HostAdd_UnifiedProxyJumpSelfReferenceCycleAndAliasValidation(t *testing.T) {
	_, store, _ := setupP6IsolatedStore(t)

	// Seed a valid bastion jump host and a node whose ProxyJump points to the future node ID (for cycle check).
	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	cfg.Hosts.Set("10.10.0.1:22", models.Host{Address: "10.10.0.1", Port: 22})
	cfg.Identities.Set("jump@10.10.0.1", models.Identity{User: "jump", AuthType: "auto"})
	cfg.Nodes.Set("jump@10.10.0.1:22", models.Node{
		HostRef:     "10.10.0.1:22",
		IdentityRef: "jump@10.10.0.1",
		Alias:       []string{"bastion"},
	})
	cfg.Hosts.Set("10.10.0.20:22", models.Host{Address: "10.10.0.20", Port: 22})
	cfg.Identities.Set("ops@10.10.0.20", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("ops@10.10.0.20:22", models.Node{
		HostRef:     "10.10.0.20:22",
		IdentityRef: "ops@10.10.0.20",
		Alias:       []string{"loop-peer"},
		ProxyJump:   "ops@10.10.0.10:22",
	})
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}

	runHostAdd := func(args ...string) error {
		cmd := hostcmd.NewCmdInventoryAdd()
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(args)
		return cmd.Execute()
	}

	// Self-reference, chain self-reference, omitted-port self-reference, IPv6 self-reference, and transitive cycle must all fail closed.
	rejectedCases := []struct {
		name string
		args []string
	}{
		{"self_alias", []string{"app-a", "ops@10.10.0.10:22", "--jump", "app-a", "--skip-verify"}},
		{"self_alias_with_port", []string{"app-a", "ops@10.10.0.10:22", "--jump", "app-a:22", "--skip-verify"}},
		{"self_canonical_node_id", []string{"app-a", "ops@10.10.0.10:22", "--jump", "ops@10.10.0.10:22", "--skip-verify"}},
		{"self_omitted_default_port", []string{"app-a", "ops@10.10.0.10", "--jump", "ops@10.10.0.10", "--skip-verify"}},
		{"self_in_comma_chain", []string{"app-a", "ops@10.10.0.10:22", "--jump", "bastion,app-a", "--skip-verify"}},
		{"self_id_in_comma_chain", []string{"app-a", "ops@10.10.0.10:22", "--jump", "bastion,ops@10.10.0.10:22", "--skip-verify"}},
		{"self_ipv6", []string{"v6-self", "ops@[2001:db8::1]:2222", "--jump", "ops@[2001:db8::1]:2222", "--skip-verify"}},
		{"transitive_cycle_via_existing_peer", []string{"app-a", "ops@10.10.0.10:22", "--jump", "loop-peer", "--skip-verify"}},
		{"transitive_cycle_in_chain", []string{"app-a", "ops@10.10.0.10:22", "--jump", "bastion,loop-peer", "--skip-verify"}},
		{"unknown_jump", []string{"app-a", "ops@10.10.0.10:22", "--jump", "no-such-jump", "--skip-verify"}},
		{"conflicting_alias", []string{"bastion", "ops@10.10.0.99:22", "--skip-verify"}},
		{"reserved_openssh_alias", []string{"ops@10.10.0.99:22", "-a", "openssh:bad", "--skip-verify"}},
	}
	for _, tc := range rejectedCases {
		t.Run("reject_"+tc.name, func(t *testing.T) {
			if err := runHostAdd(tc.args...); err == nil {
				t.Fatalf("host add %v unexpectedly succeeded", tc.args)
			}
		})
	}

	// Verify none of the rejected adds persisted ops@10.10.0.10:22 or ops@10.10.0.99:22.
	cfgAfterReject, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	for _, forbidden := range []string{"ops@10.10.0.10:22", "ops@10.10.0.99:22", "ops@[2001:db8::1]:2222"} {
		if _, exists := cfgAfterReject.Nodes.Get(forbidden); exists {
			t.Fatalf("rejected host add persisted %q", forbidden)
		}
	}

	// Valid jump alias resolves to canonical node ID; --jump none clears ProxyJump.
	if err := runHostAdd("app-ok", "ops@10.10.0.10:22", "--jump", "bastion", "--skip-verify"); err != nil {
		t.Fatalf("host add with valid --jump bastion failed: %v", err)
	}
	if err := runHostAdd("app-none", "ops@10.10.0.11:22", "--jump", "none", "--skip-verify"); err != nil {
		t.Fatalf("host add with --jump none failed: %v", err)
	}
	cfgFinal, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load final: %v", err)
	}
	if n, ok := cfgFinal.Nodes.Get("ops@10.10.0.10:22"); !ok || n.ProxyJump != "jump@10.10.0.1:22" {
		t.Fatalf("app-ok ProxyJump = %q (ok=%v), want jump@10.10.0.1:22", n.ProxyJump, ok)
	}
	if n, ok := cfgFinal.Nodes.Get("ops@10.10.0.11:22"); !ok || n.ProxyJump != "" {
		t.Fatalf("app-none ProxyJump = %q (ok=%v), want empty", n.ProxyJump, ok)
	}
}
