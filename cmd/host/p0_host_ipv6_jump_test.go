package host

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP0_HostAddEdit_BracketedIPv6WithUserAndPort(t *testing.T) {
	t.Run("applyAddTargetArgs_and_applyEditTargetArgs_accept_bracketed_ipv6_specs", testHostAddEditAcceptsBracketedIPv6)
	t.Run("rejects_openssh_prefix_control_chars_whitespace_and_malformed_specs", testHostAddEditRejectsMalformedSpecs)
	t.Run("cli_end_to_end_host_add_and_edit_bracketed_ipv6", testHostAddEditCLIEndToEndIPv6)
}

func testHostAddEditAcceptsBracketedIPv6(t *testing.T) {
	cases := []struct {
		spec     string
		wantHost string
		wantUser string
		wantPort uint16
	}{
		{spec: "[::1]:2222", wantHost: "::1", wantUser: "", wantPort: 2222},
		{spec: "root@[::1]", wantHost: "::1", wantUser: "root", wantPort: 22},
		{spec: "root@[2001:db8::1]:2222", wantHost: "2001:db8::1", wantUser: "root", wantPort: 2222},
		{spec: "ops@[fe80::1%eth0]:2200", wantHost: "fe80::1%eth0", wantUser: "ops", wantPort: 2200},
		{spec: " [2001:db8::2]:2222 ", wantHost: "2001:db8::2", wantUser: "", wantPort: 2222},
	}

	for _, tc := range cases {
		var aliases []string
		addr, user := "", ""
		port := uint16(22)
		if err := applyAddTargetArgs([]string{tc.spec}, &aliases, &addr, &user, &port, false); err != nil {
			t.Fatalf("applyAddTargetArgs(pos %q) failed: %v", tc.spec, err)
		}
		if addr != tc.wantHost || user != tc.wantUser || port != tc.wantPort {
			t.Fatalf("applyAddTargetArgs(pos %q) = (%q, %q, %d), want (%q, %q, %d)",
				tc.spec, addr, user, port, tc.wantHost, tc.wantUser, tc.wantPort)
		}

		aliases = nil
		addr, user = tc.spec, ""
		port = uint16(22)
		if err := applyAddTargetArgs(nil, &aliases, &addr, &user, &port, false); err != nil {
			t.Fatalf("applyAddTargetArgs(flag %q) failed: %v", tc.spec, err)
		}
		if addr != tc.wantHost || user != tc.wantUser || port != tc.wantPort {
			t.Fatalf("applyAddTargetArgs(flag %q) = (%q, %q, %d), want (%q, %q, %d)",
				tc.spec, addr, user, port, tc.wantHost, tc.wantUser, tc.wantPort)
		}

		wantEditPort := tc.wantPort
		if !strings.Contains(tc.spec, "]:") {
			wantEditPort = 0
		}
		ef := &editFlags{}
		if err := applyEditTargetArgs([]string{tc.spec}, ef, false); err != nil {
			t.Fatalf("applyEditTargetArgs(pos %q) failed: %v", tc.spec, err)
		}
		if ef.address != tc.wantHost || ef.user != tc.wantUser || ef.port != wantEditPort {
			t.Fatalf("applyEditTargetArgs(pos %q) = (%q, %q, %d), want (%q, %q, %d)",
				tc.spec, ef.address, ef.user, ef.port, tc.wantHost, tc.wantUser, wantEditPort)
		}
	}
}

func testHostAddEditRejectsMalformedSpecs(t *testing.T) {
	badSpecs := []string{
		"",
		"   ",
		"openssh:web",
		"OPENSSH:web",
		"OPENSSH:22",
		"openssh:root@[::1]:2222",
		"[badhost]",
		"[::1]:0",
		"[::1]:70000",
		"root@",
		"@[::1]",
		"10.0.0.1\n10.0.0.2",
		"10.0.0.1 10.0.0.2",
		"user name@[::1]:22",
		"10.0.0.1\r",
	}
	for _, spec := range badSpecs {
		var aliases []string
		addr, user := "", ""
		port := uint16(22)
		if err := applyAddTargetArgs([]string{spec}, &aliases, &addr, &user, &port, false); err == nil {
			t.Errorf("applyAddTargetArgs(%q) unexpectedly succeeded (host=%q user=%q port=%d)", spec, addr, user, port)
		}
		ef := &editFlags{}
		if err := applyEditTargetArgs([]string{spec}, ef, false); err == nil {
			t.Errorf("applyEditTargetArgs(%q) unexpectedly succeeded (host=%q user=%q port=%d)", spec, ef.address, ef.user, ef.port)
		}
	}
}

func testHostAddEditCLIEndToEndIPv6(t *testing.T) {
	cfgDir := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", cfgDir)
	t.Setenv("HOME", t.TempDir())

	addCmd := NewCmdInventoryAdd()
	addCmd.SetOut(&bytes.Buffer{})
	addCmd.SetErr(&bytes.Buffer{})
	addCmd.SetArgs([]string{"v6-app", "root@[2001:db8::1]:2222", "--skip-verify"})
	if err := addCmd.Execute(); err != nil {
		t.Fatalf("host add v6-app root@[2001:db8::1]:2222 failed: %v", err)
	}

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)
	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load after add: %v", err)
	}
	const addedID = "root@[2001:db8::1]:2222"
	node, ok := cfg.Nodes.Get(addedID)
	if !ok {
		t.Fatalf("expected saved node %q, got keys %v", addedID, cfg.Nodes.Keys())
	}
	h, ok := cfg.Hosts.Get(node.HostRef)
	if !ok || h.Address != "2001:db8::1" || h.Port != 2222 {
		t.Fatalf("unexpected saved host record: %+v (ok=%v)", h, ok)
	}

	editCmd := NewCmdInventoryEdit()
	editCmd.SetOut(&bytes.Buffer{})
	editCmd.SetErr(&bytes.Buffer{})
	editCmd.SetArgs([]string{"v6-app", "ops@[::1]:2200"})
	if err := editCmd.Execute(); err != nil {
		t.Fatalf("host edit v6-app ops@[::1]:2200 failed: %v", err)
	}

	cfg2, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load after edit: %v", err)
	}
	const editedID = "ops@[::1]:2200"
	node2, ok := cfg2.Nodes.Get(editedID)
	if !ok {
		t.Fatalf("expected edited node %q, got keys %v", editedID, cfg2.Nodes.Keys())
	}
	h2, ok := cfg2.Hosts.Get(node2.HostRef)
	if !ok || h2.Address != "::1" || h2.Port != 2200 {
		t.Fatalf("unexpected edited host record: %+v (ok=%v)", h2, ok)
	}
}

func setupHostEditJumpTestConfig(t *testing.T) (string, config.Store) {
	t.Helper()
	cfgDir := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", cfgDir)
	t.Setenv("HOME", t.TempDir())

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)
	cfg := &config.Configuration{
		SchemaVersion: 2,
		Hosts:         concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities:    concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Nodes:         concurrent.NewMap[string, models.Node](concurrent.HashString),
	}
	cfg.Hosts.Set("10.0.0.1:22", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Hosts.Set("10.0.0.10:22", models.Host{Address: "10.0.0.10", Port: 22})
	cfg.Hosts.Set("10.0.0.20:22", models.Host{Address: "10.0.0.20", Port: 22})
	cfg.Identities.Set("jump@10.0.0.1", models.Identity{User: "jump", AuthType: "auto"})
	cfg.Identities.Set("ops@10.0.0.10", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Identities.Set("ops@10.0.0.20", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("jump@10.0.0.1:22", models.Node{
		HostRef:     "10.0.0.1:22",
		IdentityRef: "jump@10.0.0.1",
		Alias:       []string{"bastion"},
	})
	cfg.Nodes.Set("ops@10.0.0.10:22", models.Node{
		HostRef:     "10.0.0.10:22",
		IdentityRef: "ops@10.0.0.10",
		Alias:       []string{"app-a"},
	})
	cfg.Nodes.Set("ops@10.0.0.20:22", models.Node{
		HostRef:     "10.0.0.20:22",
		IdentityRef: "ops@10.0.0.20",
		Alias:       []string{"app-b"},
		ProxyJump:   "ops@10.0.0.10:22",
	})
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	return cfgDir, store
}

func runHostEditCLI(args ...string) error {
	cmd := NewCmdInventoryEdit()
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestP0_HostEdit_ProxyJumpValidationAndCycles(t *testing.T) {
	_, store := setupHostEditJumpTestConfig(t)

	// 1. Unknown jump host fails closed.
	if err := runHostEditCLI("app-a", "--jump", "does-not-exist"); err == nil {
		t.Fatal("expected error for unknown --jump host, got nil")
	}

	// 2. Direct self-jump by alias, by node ID, by new alias, and inside comma chain fail closed.
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"self_alias", []string{"app-a", "--jump", "app-a"}},
		{"self_node_id", []string{"app-a", "--jump", "ops@10.0.0.10:22"}},
		{"self_in_chain", []string{"app-a", "--jump", "bastion,app-a"}},
		{"self_new_alias", []string{"app-a", "--alias", "app-a-renamed", "--jump", "app-a-renamed"}},
		{"self_old_alias_while_renaming", []string{"app-a", "--alias", "app-a-renamed", "--jump", "app-a"}},
		{"transitive_2hop_cycle", []string{"app-a", "--jump", "app-b"}},
		{"transitive_cycle_in_chain", []string{"app-a", "--jump", "bastion,app-b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := runHostEditCLI(tc.args...); err == nil {
				t.Fatalf("host edit %v expected cycle/self-jump error, got nil", tc.args)
			}
		})
	}

	// Verify app-a was not mutated by any failed edit above.
	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	if n, ok := cfg.Nodes.Get("ops@10.0.0.10:22"); !ok || n.ProxyJump != "" {
		t.Fatalf("failed edits mutated app-a: %+v (ok=%v)", n, ok)
	}

	// 3. Valid jump alias resolves to canonical node ID.
	if err := runHostEditCLI("app-a", "--jump", "bastion"); err != nil {
		t.Fatalf("host edit app-a --jump bastion failed: %v", err)
	}
	cfg, err = store.Load()
	if err != nil {
		t.Fatalf("store.Load after valid jump: %v", err)
	}
	if n, _ := cfg.Nodes.Get("ops@10.0.0.10:22"); n.ProxyJump != "jump@10.0.0.1:22" {
		t.Fatalf("app-a ProxyJump = %q, want %q", n.ProxyJump, "jump@10.0.0.1:22")
	}

	// 4. --jump none clears ProxyJump.
	if err := runHostEditCLI("app-a", "--jump", "none"); err != nil {
		t.Fatalf("host edit app-a --jump none failed: %v", err)
	}
	cfg, err = store.Load()
	if err != nil {
		t.Fatalf("store.Load after --jump none: %v", err)
	}
	if n, _ := cfg.Nodes.Get("ops@10.0.0.10:22"); n.ProxyJump != "" {
		t.Fatalf("app-a ProxyJump after --jump none = %q, want empty", n.ProxyJump)
	}

	// 5. Re-set then clear with --jump "".
	if err := runHostEditCLI("app-a", "--jump", "bastion"); err != nil {
		t.Fatalf("host edit app-a --jump bastion failed: %v", err)
	}
	if err := runHostEditCLI("app-a", "--jump", ""); err != nil {
		t.Fatalf("host edit app-a --jump '' failed: %v", err)
	}
	cfg, err = store.Load()
	if err != nil {
		t.Fatalf("store.Load after --jump '': %v", err)
	}
	if n, _ := cfg.Nodes.Get("ops@10.0.0.10:22"); n.ProxyJump != "" {
		t.Fatalf("app-a ProxyJump after --jump '' = %q, want empty", n.ProxyJump)
	}

	// 6. Malformed --jump chains must fail closed on edit (never silently clear/disable ProxyJump).
	verifyHostEditRejectsMalformedProxyJump(t, runHostEditCLI, store)
}

func verifyHostEditRejectsMalformedProxyJump(t *testing.T, runHostEditCLI func(args ...string) error, store config.Store) {
	t.Helper()
	if err := runHostEditCLI("app-a", "--jump", "bastion"); err != nil {
		t.Fatalf("host edit app-a --jump bastion failed: %v", err)
	}
	for _, badJump := range []string{",", " , ", "none,", "bastion,", "bastion,none", "a,,b"} {
		if err := runHostEditCLI("app-a", "--jump", badJump); err == nil {
			t.Errorf("host edit app-a --jump %q succeeded, want fail-closed error", badJump)
		}
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load after rejected malformed jumps: %v", err)
	}
	if n, _ := cfg.Nodes.Get("ops@10.0.0.10:22"); n.ProxyJump != "jump@10.0.0.1:22" {
		t.Fatalf("app-a ProxyJump was mutated by malformed --jump: got %q, want %q", n.ProxyJump, "jump@10.0.0.1:22")
	}
}
