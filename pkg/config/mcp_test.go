package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMCPSettingsSurviveV2StoreAndLegacyMigrationDecode(t *testing.T) {
	directory := t.TempDir()
	store := NewDefaultStore(filepath.Join(directory, "config.yaml"), filepath.Join(directory, "secret.key"))
	cfg := NewProviderWithoutOpenSSH(&Configuration{SchemaVersion: 2, Credential: DefaultCredentialConfig(), MCP: &MCPConfig{Transport: "http", TokenEnv: "XOPS_MCP_TOKEN", StateDir: "/state/tasks"}}).Snapshot()
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.MCP == nil || loaded.MCP.Transport != "http" || loaded.MCP.TokenEnv != "XOPS_MCP_TOKEN" {
		t.Fatalf("v2 codec lost MCP settings: %+v", loaded.MCP)
	}
	legacy, err := decodeMigrationLegacy([]byte("schema_version: 1\nmcp:\n  transport: http\n  token_env: XOPS_MCP_TOKEN\n"))
	if err != nil || legacy.MCP == nil || legacy.MCP.TokenEnv != "XOPS_MCP_TOKEN" {
		t.Fatalf("legacy decoder lost MCP settings: %+v %v", legacy, err)
	}
}

func TestReadOnlyConfigurationDoesNotMigratePlaintext(t *testing.T) {
	directory := t.TempDir()
	path, key := filepath.Join(directory, "config.yaml"), filepath.Join(directory, "secret.key")
	data := []byte("schema_version: 1\nidentities:\n  fixture:\n    user: fixture\n    auth_type: password\n    password: readonly-fixture-secret\nmcp:\n  state_dir: /state/tasks\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := ReadOnlyConfiguration(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MCP == nil || cfg.MCP.StateDir != "/state/tasks" {
		t.Fatal("read-only loader lost settings")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(data) {
		t.Fatal("read-only load changed legacy secrets")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("read-only loader created keys or locks: %+v %v", entries, err)
	}
}

func TestMCPSnapshotAndYAMLRoundTrip(t *testing.T) {
	var cfg Configuration
	if err := yaml.Unmarshal([]byte("mcp:\n  transport: http\n  allowed_hosts: [mcp.example:8080]\n  max_sessions: 12\n  token_env: XOPS_MCP_TOKEN\n  transfer_timeout: 1h\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	provider := NewProviderWithoutOpenSSH(&cfg)
	snapshot := provider.Snapshot()
	snapshot.MCP.AllowedHosts[0] = "changed"
	*snapshot.MCP.MaxSessions = 99
	original := provider.Snapshot().MCP
	if original.AllowedHosts[0] != "mcp.example:8080" || *original.MaxSessions != 12 {
		t.Fatal("MCP configuration aliases a mutable snapshot")
	}
	data, err := yaml.Marshal(provider.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	for _, setting := range []string{"transport: http", "token_env: XOPS_MCP_TOKEN", "transfer_timeout: 1h"} {
		if !strings.Contains(string(data), setting) {
			t.Errorf("MCP setting lost during save: %s", setting)
		}
	}
}

func TestRepositoryFrozenDoesNotExposeMutations(t *testing.T) {
	repository := &Repository{provider: newTestProvider()}
	frozen := repository.Frozen()
	if _, ok := frozen.(*Repository); ok {
		t.Fatal("frozen view exposes the writable repository")
	}
	_, host, _, err := frozen.Resolve("web-server")
	if err != nil || host.Address != "10.0.0.1" {
		t.Fatalf("frozen repository lost configuration: %+v %v", host, err)
	}
}
