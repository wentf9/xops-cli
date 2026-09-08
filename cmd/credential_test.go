package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func TestCredentialCommandTree(t *testing.T) {
	root := newRootCmd()
	initRootFlags(root)
	registerCommands(root)

	credCmd, _, err := root.Find([]string{"credential"})
	if err != nil {
		t.Fatalf("find credential command: %v", err)
	}
	if credCmd.Name() != "credential" {
		t.Errorf("credential command name = %q, want credential", credCmd.Name())
	}
	if !slices.Contains(credCmd.Aliases, "cred") {
		t.Errorf("credential aliases = %v, want 'cred'", credCmd.Aliases)
	}

	subCommands := make(map[string]bool)
	for _, sub := range credCmd.Commands() {
		subCommands[sub.Name()] = true
	}

	for _, expected := range []string{"store", "doctor", "gc"} {
		if !subCommands[expected] {
			t.Errorf("expected subcommand %q in credential command", expected)
		}
	}

	storeCmd, _, err := root.Find([]string{"credential", "store"})
	if err != nil {
		t.Fatalf("find credential store command: %v", err)
	}
	storeSub := make(map[string]bool)
	for _, sub := range storeCmd.Commands() {
		storeSub[sub.Name()] = true
	}
	if !storeSub["list"] {
		t.Errorf("expected 'list' subcommand under 'credential store'")
	}
}

func setupTestEnvironment(t *testing.T) string {
	t.Helper()
	tempDir := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", tempDir)
	t.Setenv("XOPS_JOURNAL_DIR", filepath.Join(tempDir, "journals"))
	return tempDir
}

func TestCredentialStoreList(t *testing.T) {
	_ = setupTestEnvironment(t)

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath failed: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Credential: &config.CredentialConfig{
			DefaultStore: "vault-1",
			Stores: map[string]config.StoreConfig{
				"vault-1": {
					Type:     "memory",
					ReadOnly: false,
				},
				"file-backup": {
					Type:     "pass",
					ReadOnly: true,
				},
			},
		},
	}

	if err := store.Save(cfg); err != nil {
		t.Fatalf("failed to save test config: %v", err)
	}

	buf := new(bytes.Buffer)
	cmd := NewCmdCredential()
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"store", "list"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute credential store list failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "vault-1") {
		t.Errorf("output should contain vault-1, got: %s", output)
	}
	if !strings.Contains(output, "file-backup") {
		t.Errorf("output should contain file-backup, got: %s", output)
	}
	if !strings.Contains(output, "STORE") || !strings.Contains(output, "TYPE") {
		t.Errorf("output missing table headers, got: %s", output)
	}
}

func TestCredentialDoctor(t *testing.T) {
	_ = setupTestEnvironment(t)

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath failed: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("failed to save test config: %v", err)
	}

	buf := new(bytes.Buffer)
	cmd := NewCmdCredential()
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"doctor"})

	// doctor 命令执行系统密钥库探测，不应 panic 或崩溃
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute credential doctor failed: %v", err)
	}
}

func TestCredentialGC(t *testing.T) {
	tempDir := setupTestEnvironment(t)

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath failed: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		// 显式指定 none store，防止在 CI headless Linux 环境（无 D-Bus）中尝试初始化 system store 失败
		Credential: &config.CredentialConfig{
			DefaultStore: "none",
			Stores: map[string]config.StoreConfig{
				"none": {Type: config.StoreTypeNone},
			},
		},
	}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("failed to save test config: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(tempDir, "journals"), 0o700); err != nil {
		t.Fatalf("create journals dir failed: %v", err)
	}

	buf := new(bytes.Buffer)
	cmd := NewCmdCredential()
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"gc"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute credential gc failed: %v", err)
	}
}
