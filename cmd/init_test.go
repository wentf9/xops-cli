package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
)

func TestInitOptions_RunCreatesConfigAndImportsOpenSSH(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	sshConfigPath := filepath.Join(tempDir, "ssh_config")
	sshConfig := []byte("Host jump\n  HostName bastion.example.com\nHost app\n  HostName 10.0.0.10\n  ProxyJump jump\n")
	if err := os.WriteFile(sshConfigPath, sshConfig, 0o600); err != nil {
		t.Fatalf("write SSH config: %v", err)
	}

	o := &InitOptions{
		ConfigPath:    filepath.Join(tempDir, "xops", "xops_config.yaml"),
		KeyPath:       filepath.Join(tempDir, "xops", "secret.key"),
		SSHConfigPath: sshConfigPath,
	}
	result, err := o.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !result.configCreated || result.imported != 2 || result.skipped != 0 {
		t.Fatalf("Run() result = %#v, want created with 2 imports", result)
	}

	store := config.NewDefaultStore(o.ConfigPath, o.KeyPath)
	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("load initialized config: %v", err)
	}
	if len(cfg.Nodes.Keys()) != 2 {
		t.Fatalf("initialized node count = %d, want 2", len(cfg.Nodes.Keys()))
	}
	app, ok := cfg.Nodes.Get("app")
	if !ok {
		t.Fatal("initialized config does not contain app")
	}
	if app.ProxyJump != "jump" {
		t.Errorf("app ProxyJump = %q, want jump", app.ProxyJump)
	}
	if _, err := os.Stat(o.KeyPath); err != nil {
		t.Fatalf("secret key was not created: %v", err)
	}

	result, err = o.Run()
	if err != nil {
		t.Fatalf("second Run() error = %v", err)
	}
	if result.configCreated || result.imported != 0 || result.skipped != 2 {
		t.Fatalf("second Run() result = %#v, want idempotent skips", result)
	}
}

func TestInitOptions_RunExplicitMissingSSHConfigFails(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	o := &InitOptions{
		ConfigPath:       filepath.Join(tempDir, "xops_config.yaml"),
		KeyPath:          filepath.Join(tempDir, "secret.key"),
		SSHConfigPath:    filepath.Join(tempDir, "missing"),
		SSHConfigChanged: true,
	}
	if _, err := o.Run(); err == nil {
		t.Fatal("Run() error = nil, want missing explicit SSH config error")
	}
}

func TestInitOptions_RunSkipsOpenSSHImport(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	o := &InitOptions{
		ConfigPath:    filepath.Join(tempDir, "xops_config.yaml"),
		KeyPath:       filepath.Join(tempDir, "secret.key"),
		SSHConfigPath: filepath.Join(tempDir, "missing"),
		SkipSSHImport: true,
	}
	result, err := o.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !result.configCreated || result.imported != 0 {
		t.Fatalf("Run() result = %#v, want empty initialized config", result)
	}
}
