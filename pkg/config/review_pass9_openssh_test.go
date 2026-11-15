package config

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/models"
)

func TestPass9_H1_ExplicitOpenSSHNotHijackedAndNeverPersisted(t *testing.T) {
	dir := t.TempDir()
	sshCfgPath := filepath.Join(dir, "ssh_config")
	sshCfg := strings.Join([]string{
		"Host web",
		"  HostName 10.0.0.10",
		"  Port 22",
		"  User alice",
		"",
		"Host *",
		"  SetEnv GLOBAL_MARK=1",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}

	repo, _ := pendingDiskRepository(t)
	savedCfg := repo.Snapshot()
	savedCfg.Hosts.Set("h-saved", models.Host{Address: "192.0.2.99", Port: 22})
	savedCfg.Identities.Set("id-saved", models.Identity{User: "saved", AuthType: "auto"})
	savedCfg.Nodes.Set("web-saved", models.Node{
		HostRef:     "h-saved",
		IdentityRef: "id-saved",
		Alias:       []string{"web"},
	})
	store := NewDefaultStore(filepath.Join(dir, "xops_config.yaml"), filepath.Join(dir, "xops.key"))
	savedRepo, err := NewRepositoryWithoutOpenSSH(savedCfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	provider, err := WithOpenSSHConfigOverride(savedRepo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}
	preparer := provider.(interface {
		PrepareNodeContext(ctx context.Context, opts EnsureNodeOptions) (EnsureNodeResult, error)
	})
	_ = preparer

	// 1. Explicit openssh:web resolves to OpenSSH Host web (10.0.0.10), not saved alias "web" (192.0.2.99).
	resDirect, err := ResolveTarget(provider, ConnectionTarget{Selector: "openssh:web", RawSelector: "openssh:web"})
	if err != nil {
		t.Fatalf("ResolveTarget(openssh:web): %v", err)
	}
	if resDirect.NodeID != OpenSSHNodePrefix+"web" {
		t.Fatalf("ResolveTarget(openssh:web).NodeID = %q, want %q", resDirect.NodeID, OpenSSHNodePrefix+"web")
	}
	snapDirect, err := provider.ResolveConnection(resDirect.NodeID)
	if err != nil {
		t.Fatalf("ResolveConnection(%q): %v", resDirect.NodeID, err)
	}
	if snapDirect.Host.Address != "10.0.0.10" {
		t.Errorf("openssh:web host = %q, want 10.0.0.10", snapDirect.Host.Address)
	}
	if snapDirect.Node.SSHOptions == nil || !slices.Contains(snapDirect.Node.SSHOptions.SetEnvDirectives(), "GLOBAL_MARK=1") {
		t.Errorf("openssh:web missing Host * SetEnv GLOBAL_MARK=1: %v", snapDirect.Node.SSHOptions)
	}

	// 2. Explicit openssh:ops@web:2222 preserves wildcard options and never persists.
	overrideRepo := provider.(*openSSHOverrideProvider).repo
	ensured, err := overrideRepo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "openssh:ops@web:2222", RawSelector: "openssh:ops@web:2222"},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(openssh:ops@web:2222): %v", err)
	}
	if !strings.HasPrefix(ensured.NodeID, OpenSSHNodePrefix) {
		t.Fatalf("ensured.NodeID = %q, want %s prefix", ensured.NodeID, OpenSSHNodePrefix)
	}
	snapOvr, err := provider.ResolveConnection(ensured.NodeID)
	if err != nil {
		t.Fatalf("ResolveConnection(%q): %v", ensured.NodeID, err)
	}
	if snapOvr.Host.Address != "10.0.0.10" || snapOvr.Host.Port != 2222 || snapOvr.Identity.User != "ops" {
		t.Errorf("snapOvr = host:%q port:%d user:%q, want 10.0.0.10:2222 ops", snapOvr.Host.Address, snapOvr.Host.Port, snapOvr.Identity.User)
	}
	if snapOvr.Node.SSHOptions == nil || !slices.Contains(snapOvr.Node.SSHOptions.SetEnvDirectives(), "GLOBAL_MARK=1") {
		t.Errorf("openssh:ops@web:2222 missing Host * GLOBAL_MARK=1")
	}
	if err := overrideRepo.ConfirmNodeContext(t.Context(), ensured.NodeID); err != nil {
		t.Fatalf("ConfirmNodeContext(openssh:...): %v", err)
	}
	if _, persisted := overrideRepo.Snapshot().Nodes.Get(ensured.NodeID); persisted {
		t.Fatalf("explicit openssh node %q must never be persisted to saved config", ensured.NodeID)
	}
}

func TestPass9_H2_IdentityPathNormalizationAndAutoAuthInheritance(t *testing.T) {
	dir := t.TempDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("UserHomeDir unavailable: %v", err)
	}
	sshCfgPath := filepath.Join(dir, "ssh_config")
	sshCfg := strings.Join([]string{
		"Host none-host",
		"  HostName 10.0.0.2",
		"  IdentityFile none",
		"",
		"Host token-host",
		"  HostName 10.0.0.3",
		"  IdentityFile %d/.ssh/id_%r",
		"",
		"Host env-host",
		"  HostName 10.0.0.4",
		"  IdentityFile ${SSH_KEY}",
		"",
		"Host unknown-user-host",
		"  HostName 10.0.0.6",
		"  IdentityFile ~nonexistent_xops_user_999/id_ed25519",
		"",
		"Host inherit-host",
		"  HostName 10.0.0.5",
		"  User defaultuser",
		"  IdentityFile ~/.ssh/id_pass9",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}

	parser, err := NewOpenSSHParserFromPath(sshCfgPath)
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromPath: %v", err)
	}

	for _, alias := range []string{"none-host", "token-host", "env-host", "unknown-user-host"} {
		_, _, ident, gErr := parser.GetVirtualNode(alias)
		if gErr != nil {
			t.Fatalf("GetVirtualNode(%s): %v", alias, gErr)
		}
		if ident.KeyPath != "" {
			t.Errorf("%s Identity.KeyPath = %q, want empty (non-persistable)", alias, ident.KeyPath)
		}
	}

	imported, err := ParseOpenSSHHosts(strings.NewReader(sshCfg), "fallback")
	if err != nil {
		t.Fatalf("ParseOpenSSHHosts: %v", err)
	}
	byName := make(map[string]OpenSSHHost, len(imported))
	for _, h := range imported {
		byName[h.Name] = h
	}
	for _, alias := range []string{"none-host", "token-host", "env-host"} {
		if got := byName[alias].Identity.KeyPath; got != "" {
			t.Errorf("ParseOpenSSHHosts(%s).Identity.KeyPath = %q, want empty", alias, got)
		}
	}

	// Inherited IdentityFile from ssh_config on pending user override keeps AuthType = "auto".
	repo, _ := pendingDiskRepository(t)
	provider, err := WithOpenSSHConfigOverride(repo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}
	overrideRepo := provider.(*openSSHOverrideProvider).repo
	prepared, err := overrideRepo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "inherit-host", User: "ops", HasUser: true},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(ops@inherit-host): %v", err)
	}
	snap, err := provider.ResolveConnection(prepared.NodeID)
	if err != nil {
		t.Fatalf("ResolveConnection(%q): %v", prepared.NodeID, err)
	}
	wantExpanded := filepath.Join(home, ".ssh", "id_pass9")
	if snap.Identity.KeyPath != wantExpanded {
		t.Errorf("inherited KeyPath = %q, want %q", snap.Identity.KeyPath, wantExpanded)
	}
	if snap.Identity.AuthType != "auto" {
		t.Errorf("inherited AuthType = %q, want auto (must allow password/agent fallback)", snap.Identity.AuthType)
	}

	// Passing non-persistable IdentityFile="none" via PrepareNodeContext does not store <cwd>/none.
	prepNone, err := overrideRepo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target:       ConnectionTarget{Selector: "10.0.0.99", User: "ops", HasUser: true},
		IdentityFile: "none",
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(10.0.0.99, IdentityFile=none): %v", err)
	}
	snapNone, err := provider.ResolveConnection(prepNone.NodeID)
	if err != nil {
		t.Fatalf("ResolveConnection(prepNone): %v", err)
	}
	if snapNone.Identity.KeyPath != "" {
		t.Errorf("IdentityFile=none polluted Identity.KeyPath = %q, want empty", snapNone.Identity.KeyPath)
	}
}

func TestPass9_H3_MultiPatternIncludeOrderAndQuotedDirectives(t *testing.T) {
	dir := t.TempDir()
	zDir := filepath.Join(dir, "z_override")
	aDir := filepath.Join(dir, "a_default")
	for _, sub := range []string{zDir, aDir} {
		if err := os.MkdirAll(sub, 0o700); err != nil {
			t.Fatalf("MkdirAll(%s): %v", sub, err)
		}
	}
	if err := os.WriteFile(filepath.Join(zDir, "10.conf"), []byte(strings.Join([]string{
		"Host inc-multi",
		"  ConnectTimeout 7",
		"  SendEnv FOO_1",
	}, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write z_override: %v", err)
	}
	if err := os.WriteFile(filepath.Join(aDir, "10.conf"), []byte(strings.Join([]string{
		"Host inc-multi",
		"  ConnectTimeout 19",
		"  SendEnv -FOO_*",
	}, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write a_default: %v", err)
	}

	mainPath := filepath.Join(dir, "ssh_config")
	mainCfg := strings.Join([]string{
		"Include " + filepath.Join(zDir, "*.conf") + " " + filepath.Join(aDir, "*.conf"),
		"",
		"Host inc-multi",
		"  HostName 10.0.0.20",
		"  SetEnv \"FOO=hello world\"",
		"  SendEnv \"LC_*\" \"LANG\"",
		"  ProxyCommand \"/usr/bin/nc\" \"%h\" \"%p\"",
		"",
		"Host multi-setenv",
		"  HostName 10.0.0.21",
		"  SetEnv \"FOO=hello\" \"BAR=world\"",
		"",
		"Host bad-setenv",
		"  HostName 10.0.0.22",
		"  SetEnv INVALID_NO_EQ",
		"",
		"Host *",
		"  SetEnv FALLBACK=yes",
	}, "\n") + "\n"
	if err := os.WriteFile(mainPath, []byte(mainCfg), 0o600); err != nil {
		t.Fatalf("write mainPath: %v", err)
	}

	parser, err := NewOpenSSHParserFromPath(mainPath)
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromPath: %v", err)
	}

	node, _, _, err := parser.GetVirtualNode("inc-multi")
	if err != nil {
		t.Fatalf("GetVirtualNode(inc-multi): %v", err)
	}
	opts := node.SSHOptions
	if opts == nil {
		t.Fatal("inc-multi SSHOptions nil")
	}
	if got := opts.ConnectTimeout(); got != 7*time.Second {
		t.Errorf("ConnectTimeout = %v, want 7s (z_override before a_default)", got)
	}
	wantSendEnv := []string{"FOO_1", "-FOO_*", "LC_*", "LANG"}
	if !slices.Equal(opts.SendEnvPatterns(), wantSendEnv) {
		t.Errorf("SendEnvPatterns = %#v, want %#v", opts.SendEnvPatterns(), wantSendEnv)
	}
	if !slices.Equal(opts.SetEnvDirectives(), []string{`"FOO=hello world"`}) {
		t.Errorf("SetEnvDirectives = %#v, want [\"FOO=hello world\"]", opts.SetEnvDirectives())
	}
	if got := opts.ActiveProxyCommand(); got != `"/usr/bin/nc" "%h" "%p"` {
		t.Errorf("ActiveProxyCommand = %q, want quoted command preserved", got)
	}

	nodeMulti, _, _, err := parser.GetVirtualNode("multi-setenv")
	if err != nil {
		t.Fatalf("GetVirtualNode(multi-setenv): %v", err)
	}
	if got := nodeMulti.SSHOptions.SetEnvDirectives(); !slices.Equal(got, []string{`"FOO=hello" "BAR=world"`}) {
		t.Errorf("multi-setenv SetEnv = %#v, want [\"FOO=hello\" \"BAR=world\"]", got)
	}

	nodeBad, _, _, err := parser.GetVirtualNode("bad-setenv")
	if err != nil {
		t.Fatalf("GetVirtualNode(bad-setenv): %v", err)
	}
	if got := nodeBad.SSHOptions.SetEnvDirectives(); len(got) != 0 {
		t.Errorf("malformed first SetEnv must block Host * fallback, got %#v", got)
	}
}

func TestPass9_H4_M1_M4_L2_HostNameZone_ProxyPrecedence_Alias_IncludePattern(t *testing.T) {
	// H4.1: resolveOpenSSHHostName leaves bare IPv6 %zone untouched without HostName.
	verifyPass9H4HostNameZone(t)

	// M1: ProxyCommand none in Host block prevents lower-tier Host * ProxyJump,
	// and CanonicalizeHost evaluates CLI -o first-match-wins.
	sshCfg := strings.Join([]string{
		"Host app-none",
		"  HostName 10.0.0.30",
		"  ProxyCommand none",
		"",
		"Host *",
		"  ProxyJump bastion",
	}, "\n") + "\n"
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	node, _, _, err := parser.GetVirtualNode("app-none")
	if err != nil {
		t.Fatalf("GetVirtualNode(app-none): %v", err)
	}
	if node.ProxyJump != "" {
		t.Errorf("app-none ProxyJump = %q, want empty (blocked by ProxyCommand none)", node.ProxyJump)
	}
	imported, err := ParseOpenSSHHosts(strings.NewReader(sshCfg), "ops")
	if err != nil {
		t.Fatalf("ParseOpenSSHHosts: %v", err)
	}
	if len(imported) == 0 || imported[0].Name != "app-none" || imported[0].Node.ProxyJump != "" {
		t.Errorf("imported app-none unexpected: %+v", imported)
	}

	repo, _ := pendingDiskRepository(t)
	cfgPath := filepath.Join(t.TempDir(), "canon_cfg")
	canonCfg := "Host *\n  ProxyCommand nc %h %p\n"
	if err := os.WriteFile(cfgPath, []byte(canonCfg), 0o600); err != nil {
		t.Fatalf("write canon_cfg: %v", err)
	}
	canonProv, err := WithOpenSSHConfigOverride(repo, cfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}
	canonRes, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
		Provider: canonProv,
		Host:     "web",
		RawCLIOptions: []string{
			"CanonicalizeHostname=yes",
			"CanonicalDomains=first.example.com",
			"CanonicalDomains=second.example.com",
			"CanonicalizeFallbackLocal=no",
			"CanonicalizeFallbackLocal=yes",
			"ProxyCommand=none",
			"ProxyJump=bastion",
		},
		Resolver: &fakeCanonicalResolver{
			hosts: map[string][]string{
				"web.first.example.com": {"192.0.2.50"},
			},
		},
	})
	if err != nil {
		t.Fatalf("CanonicalizeHost: %v", err)
	}
	if !canonRes.Canonicalized || canonRes.CanonicalHost != "web.first.example.com" {
		t.Errorf("CanonicalizeHost = %+v, want Canonicalized=true host=web.first.example.com", canonRes)
	}

	// M4 + L2.1: ValidateNodeAlias and Include pattern expansion.
	verifyPass9M4AliasAndL2IncludePatterns(t)
}

func verifyPass9H4HostNameZone(t *testing.T) {
	t.Helper()
	for _, tc := range []struct {
		alias string
		want  string
	}{
		{alias: "[fe80::1%eth0]", want: "fe80::1%eth0"},
		{alias: "fe80::1%hn0", want: "fe80::1%hn0"},
	} {
		got, err := resolveOpenSSHHostName(nil, tc.alias)
		if err != nil {
			t.Fatalf("resolveOpenSSHHostName(nil, %q) error = %v", tc.alias, err)
		}
		if got != tc.want {
			t.Errorf("resolveOpenSSHHostName(nil, %q) = %q, want %q", tc.alias, got, tc.want)
		}
	}
}

func verifyPass9M4AliasAndL2IncludePatterns(t *testing.T) {
	t.Helper()
	// M4: ValidateNodeAlias rejects reserved openssh namespace.
	for _, bad := range []string{"openssh", "OPENSSH", "openssh:web", "OpenSSH:ops@web"} {
		if err := ValidateNodeAlias(bad); err == nil {
			t.Errorf("ValidateNodeAlias(%q) succeeded, want reserved namespace error", bad)
		}
	}
	if err := ValidateNodeAlias("openssh-dev"); err != nil {
		t.Errorf("ValidateNodeAlias(openssh-dev) unexpected error: %v", err)
	}

	// L2.1: expandOpenSSHIncludePattern skips ~ in system configs and expands ${ENV}/%u before ~.
	patSys, skip, err := expandOpenSSHIncludePattern("~/inc.conf", true)
	if err != nil || !skip || patSys != "" {
		t.Errorf("expandOpenSSHIncludePattern(system=true, ~/inc.conf) = (%q, %v, %v), want skipped (\"\", true, nil)", patSys, skip, err)
	}
	home, err := os.UserHomeDir()
	if err == nil {
		t.Setenv("XOPS_PASS9_INC", "~/from_env.conf")
		patEnv, skipEnv, errEnv := expandOpenSSHIncludePattern("${XOPS_PASS9_INC}", false)
		wantEnv := filepath.Join(home, "from_env.conf")
		if errEnv != nil || skipEnv || patEnv != wantEnv {
			t.Errorf("expandOpenSSHIncludePattern(${XOPS_PASS9_INC}) = (%q, %v, %v), want %q", patEnv, skipEnv, errEnv, wantEnv)
		}
	}
}
