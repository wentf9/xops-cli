package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
)

func TestConfigDoctorCLI_ReadOnlyAndFix(t *testing.T) {
	cfgDir := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", cfgDir)
	t.Setenv("HOME", t.TempDir())

	cfgPath := filepath.Join(cfgDir, "xops_config.yaml")
	broken := strings.Join([]string{
		"schema_version: 2",
		"credential:",
		"  stores: {}",
		"hosts:",
		"  h1:",
		"    address: 10.0.0.1",
		"    port: 22",
		"identities:",
		"  id1:",
		"    user: ops",
		"    auth_type: auto",
		"nodes:",
		"  n1:",
		"    host_ref: h1",
		"    identity_ref: id1",
		"    alias:",
		"      - bad@alias",
		"    proxy_jump: n1",
		"    sudo_mode: auto",
	}, "\n") + "\n"
	if err := os.WriteFile(cfgPath, []byte(broken), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// 1. Default invocation is read-only and returns non-zero error on issues.
	var out bytes.Buffer
	cmdDiag := NewCmdConfig()
	cmdDiag.SetOut(&out)
	cmdDiag.SetErr(&bytes.Buffer{})
	cmdDiag.SetArgs([]string{"doctor"})
	if err := cmdDiag.Execute(); err == nil {
		t.Fatalf("xops config doctor succeeded on broken config; output:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "invalid_node_alias") || !strings.Contains(out.String(), "proxy_jump_self") {
		t.Fatalf("xops config doctor output missing expected codes:\n%s", out.String())
	}
	afterDiag, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(afterDiag) != broken {
		t.Fatal("xops config doctor without --fix modified config file")
	}

	// 2. Explicit --fix repairs and persists valid configuration.
	out.Reset()
	cmdFix := NewCmdConfig()
	cmdFix.SetOut(&out)
	cmdFix.SetErr(&bytes.Buffer{})
	cmdFix.SetArgs([]string{"doctor", "--fix"})
	if err := cmdFix.Execute(); err != nil {
		t.Fatalf("xops config doctor --fix failed: %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "FIXED") {
		t.Fatalf("xops config doctor --fix output missing FIXED rows:\n%s", out.String())
	}

	// 3. Repaired file loads cleanly through default store and subsequent doctor exits 0.
	store := config.NewDefaultStore(cfgPath, filepath.Join(cfgDir, "secret.key"))
	if _, err := store.Load(); err != nil {
		t.Fatalf("store.Load after doctor --fix: %v", err)
	}
	out.Reset()
	cmdRecheck := NewCmdConfig()
	cmdRecheck.SetOut(&out)
	cmdRecheck.SetErr(&bytes.Buffer{})
	cmdRecheck.SetArgs([]string{"doctor"})
	if err := cmdRecheck.Execute(); err != nil {
		t.Fatalf("xops config doctor recheck failed: %v\noutput:\n%s", err, out.String())
	}
}
