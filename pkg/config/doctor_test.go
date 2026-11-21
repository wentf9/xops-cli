package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctor_DiagnoseIsReadOnlyAndDetectsViolations(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "xops_config.yaml")
	brokenYAML := strings.Join([]string{
		"schema_version: 2",
		"credential:",
		"  stores: {}",
		"hosts:",
		"  h-a:",
		"    address: 10.0.0.1",
		"    port: 22",
		"    alias:",
		"      - bad:host",
		"  h-b:",
		"    address: 10.0.0.2",
		"    port: 22",
		"identities:",
		"  id-a:",
		"    user: ops",
		"    auth_type: auto",
		"nodes:",
		"  node-a:",
		"    host_ref: h-a",
		"    identity_ref: id-a",
		"    alias:",
		"      - web@prod",
		"      - shared-alias",
		"    proxy_jump: node-b,openssh:openssh:22",
		"    sudo_mode: auto",
		"  node-b:",
		"    host_ref: h-b",
		"    identity_ref: id-a",
		"    alias:",
		"      - shared-alias",
		"    proxy_jump: node-a,node-b",
		"    sudo_mode: auto",
	}, "\n") + "\n"
	if err := os.WriteFile(cfgPath, []byte(brokenYAML), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	report, err := DiagnoseConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("DiagnoseConfigFile: %v", err)
	}
	if !report.Exists || !report.HasErrors() || !report.HasFixableIssues() {
		t.Fatalf("unexpected report summary: %+v", report)
	}
	wantCodes := map[string]bool{
		"invalid_host_alias": false,
		"invalid_node_alias": false,
		"duplicate_alias":    false,
		"proxy_jump_invalid": false,
		"proxy_jump_self":    false,
		"proxy_jump_cycle":   false,
	}
	for _, issue := range report.Issues {
		if _, tracked := wantCodes[issue.Code]; tracked {
			wantCodes[issue.Code] = true
		}
	}
	for code, seen := range wantCodes {
		if !seen {
			t.Errorf("expected doctor issue code %q in %+v", code, report.Issues)
		}
	}

	// File on disk must be byte-identical after read-only diagnosis.
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(after) != brokenYAML {
		t.Fatal("DiagnoseConfigFile modified configuration file on disk")
	}
}

func TestDoctor_FixRepairsAndCommitsThroughFullGraphValidation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "xops_config.yaml")
	keyPath := filepath.Join(dir, "secret.key")
	brokenYAML := strings.Join([]string{
		"schema_version: 2",
		"credential:",
		"  stores: {}",
		"hosts:",
		"  h-a:",
		"    address: 10.0.0.1",
		"    port: 22",
		"    alias:",
		"      - good-host",
		"      - bad:host",
		"  h-b:",
		"    address: 10.0.0.2",
		"    port: 22",
		"  h-c:",
		"    address: 10.0.0.3",
		"    port: 22",
		"identities:",
		"  id-a:",
		"    user: ops",
		"    auth_type: auto",
		"nodes:",
		"  node-a:",
		"    host_ref: h-a",
		"    identity_ref: id-a",
		"    alias:",
		"      - web-ok",
		"      - bad@alias",
		"      - dup-alias",
		"    proxy_jump: node-b,openssh:OPENSSH:22",
		"    sudo_mode: auto",
		"  node-b:",
		"    host_ref: h-b",
		"    identity_ref: id-a",
		"    alias:",
		"      - dup-alias",
		"    proxy_jump: node-c,node-b",
		"    sudo_mode: auto",
		"  node-c:",
		"    host_ref: h-c",
		"    identity_ref: id-a",
		"    proxy_jump: node-a",
		"    sudo_mode: auto",
	}, "\n") + "\n"
	if err := os.WriteFile(cfgPath, []byte(brokenYAML), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Precondition: normal load fails closed with doctor hint.
	store := NewDefaultStore(cfgPath, keyPath)
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "xops config doctor") {
		t.Fatalf("store.Load() before fix = %v, want fail-closed error with doctor hint", err)
	}

	fixReport, err := FixConfigFile(t.Context(), cfgPath, keyPath)
	if err != nil {
		t.Fatalf("FixConfigFile: %v (issues=%+v)", err, fixReport.Issues)
	}
	if !fixReport.Healthy() || len(fixReport.Fixes) == 0 {
		t.Fatalf("expected healthy report with applied fixes, got %+v", fixReport)
	}

	// Postcondition: repaired config loads cleanly and passes ValidateGraph + Repository construction.
	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load() after fix: %v", err)
	}
	if _, err := NewRepositoryWithoutOpenSSH(cfg, store); err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH after fix: %v", err)
	}

	// Postcondition: second diagnosis is clean and idempotent.
	recheck, err := DiagnoseConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("DiagnoseConfigFile after fix: %v", err)
	}
	if !recheck.Healthy() {
		t.Fatalf("expected healthy recheck after fix, got %+v", recheck.Issues)
	}
}

func TestDoctor_FixLeavesDiskUntouchedOnUnfixableErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "xops_config.yaml")
	keyPath := filepath.Join(dir, "secret.key")
	unfixableYAML := strings.Join([]string{
		"schema_version: 2",
		"credential:",
		"  stores: {}",
		"hosts: {}",
		"identities:",
		"  id-a:",
		"    user: ops",
		"    auth_type: auto",
		"nodes:",
		"  node-a:",
		"    host_ref: missing-host",
		"    identity_ref: id-a",
		"    alias:",
		"      - bad@alias",
		"    sudo_mode: auto",
	}, "\n") + "\n"
	if err := os.WriteFile(cfgPath, []byte(unfixableYAML), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	report, err := FixConfigFile(t.Context(), cfgPath, keyPath)
	if err == nil {
		t.Fatalf("FixConfigFile unexpectedly succeeded on missing host_ref: %+v", report)
	}
	after, readErr := os.ReadFile(cfgPath)
	if readErr != nil {
		t.Fatalf("ReadFile: %v", readErr)
	}
	if string(after) != unfixableYAML {
		t.Fatal("FixConfigFile modified file on disk despite remaining unfixable schema errors")
	}
}

func TestDoctor_MissingFileIsHealthy(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	report, err := DiagnoseConfigFile(path)
	if err != nil {
		t.Fatalf("DiagnoseConfigFile(missing): %v", err)
	}
	if report.Exists || !report.Healthy() {
		t.Fatalf("unexpected report for missing file: %+v", report)
	}
}
