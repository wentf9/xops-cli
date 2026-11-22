package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

func TestP7W5c_TargetRefRejectsInvalidIPv6Zones(t *testing.T) {
	t.Parallel()

	badTargets := []string{
		"[::%[]",
		"[::%]]",
		"[::%@]",
		"[::%,]",
		"[::%:]",
		"[::%/]",
		`[::%\]`,
		"[::%%]",
		"::%[",
		"::%:",
		"::%/",
		`::%\`,
		"::%%",
		"ops@[::%[]]:22",
		"openssh:[::%[]",
		"openssh:[::%@]",
		"[fe80::1%eth:0]:22",
		"[fe80::1%eth/0]:22",
		"[fe80::1%eth@0]:22",
	}
	for _, raw := range badTargets {
		if ref, err := ParseTargetRef(raw); err == nil {
			t.Errorf("ParseTargetRef(%q) succeeded (%+v), want error", raw, ref)
		}
		if host, port, hasPort, err := ParseHostPort(raw); err == nil {
			t.Errorf("ParseHostPort(%q) succeeded (%q, %d, %v), want error", raw, host, port, hasPort)
		}
		if IsPlainOpenSSHHostSelector(raw) {
			t.Errorf("IsPlainOpenSSHHostSelector(%q) = true, want false", raw)
		}
	}

	for _, ok := range []string{"fe80::1%eth0", "[fe80::1%eth0]", "[fe80::1%en0]:2222", "ops@[fe80::1%eth0]:22", "openssh:fe80::1%eth0"} {
		ref, err := ParseTargetRef(ok)
		if err != nil {
			t.Errorf("ParseTargetRef(%q) unexpected error: %v", ok, err)
			continue
		}
		if err := ref.Validate(); err != nil {
			t.Errorf("ParseTargetRef(%q).Validate() failed: %v", ok, err)
		}
	}
}

func TestP7W5c_MalformedProxyJumpFailClosedAcrossConfigEntrypoints(t *testing.T) {
	t.Parallel()

	badJumps := []string{",", " , ", "none,", ",none", "bastion,", ",bastion", "a,,b", "bastion,none", "none,bastion", "bastion\n"}

	t.Run("CanonicalizeHost rejects malformed CLIProxyJump and -o ProxyJump", func(t *testing.T) {
		testP7W5cCanonicalizeMalformedProxyJumps(t, badJumps)
	})
	t.Run("ResolveProxyJumpChainWithConfig fails closed on malformed chains", func(t *testing.T) {
		testP7W5cResolveMalformedProxyJumps(t, badJumps)
	})
	t.Run("ValidateV2 and ValidateGraph reject malformed node.ProxyJump and doctor --fix repairs them", func(t *testing.T) {
		testP7W5cValidateAndDoctorMalformedProxyJumps(t)
	})
}

func testP7W5cCanonicalizeMalformedProxyJumps(t *testing.T, badJumps []string) {
	t.Parallel()
	parser, err := NewOpenSSHParserFromReader(strings.NewReader("Host *\n  CanonicalizeHostname yes\n  CanonicalDomains corp.example\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := NewProviderWithOpenSSHParser(nil, parser)
	res := &fakeCanonicalResolver{hosts: map[string][]string{"web.corp.example": {"10.0.0.1"}}}
	for _, bad := range badJumps {
		if _, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider:     prov,
			Host:         "web",
			CLIProxyJump: bad,
			Resolver:     res,
		}); err == nil {
			t.Errorf("CanonicalizeHost(CLIProxyJump=%q) succeeded, want fail-closed error", bad)
		}
		if _, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider:      prov,
			Host:          "web",
			RawCLIOptions: []string{"ProxyJump=" + bad},
			Resolver:      res,
		}); err == nil {
			t.Errorf("CanonicalizeHost(-o ProxyJump=%q) succeeded, want fail-closed error", bad)
		}
	}
}

func testP7W5cResolveMalformedProxyJumps(t *testing.T, badJumps []string) {
	t.Parallel()
	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("h-b", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Identities.Set("id-b", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("bastion", models.Node{HostRef: "h-b", IdentityRef: "id-b"})
	cfg.Nodes.Set("a", models.Node{HostRef: "h-b", IdentityRef: "id-b"})
	cfg.Nodes.Set("b", models.Node{HostRef: "h-b", IdentityRef: "id-b"})

	for _, disabled := range []string{"", "none", "NONE", "none,none"} {
		got, err := ResolveProxyJumpChainWithConfig(cfg, nil, disabled)
		if err != nil || got != "" {
			t.Errorf("ResolveProxyJumpChainWithConfig(%q) = (%q, %v), want (\"\", nil)", disabled, got, err)
		}
	}
	for _, bad := range badJumps {
		if got, err := ResolveProxyJumpChainWithConfig(cfg, nil, bad); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ResolveProxyJumpChainWithConfig(%q) = (%q, %v), want ErrSSHOptionsValidation", bad, got, err)
		}
	}
}

func testP7W5cValidateAndDoctorMalformedProxyJumps(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		rawJump      string
		wantRepaired string
	}{
		{"trailing_comma", "bastion,", "bastion"},
		{"double_comma", "bastion,,jump2", "bastion,jump2"},
		{"mixed_none", "bastion,none", "bastion"},
		{"bare_comma", ",", ""},
		{"none_trailing_comma", "none,", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertP7W5cMalformedNodeJumpDiagnosedAndRepaired(t, tc.rawJump, tc.wantRepaired)
		})
	}
}

func assertP7W5cMalformedNodeJumpDiagnosedAndRepaired(t *testing.T, rawJump, wantRepaired string) {
	t.Helper()
	t.Parallel()
	v2 := &ConfigurationV2{
		SchemaVersion: 2,
		Credential:    CredentialConfig{Stores: map[string]StoreConfig{}},
		Hosts: map[string]models.Host{
			"h-b":   {Address: "10.0.0.1", Port: 22},
			"h-j2":  {Address: "10.0.0.2", Port: 22},
			"h-app": {Address: "10.0.0.3", Port: 22},
		},
		Identities: map[string]IdentityV2{
			"id-a": {User: "ops", AuthType: "auto"},
		},
		Nodes: map[string]NodeV2{
			"bastion": {HostRef: "h-b", IdentityRef: "id-a", SudoMode: models.SudoModeAuto},
			"jump2":   {HostRef: "h-j2", IdentityRef: "id-a", SudoMode: models.SudoModeAuto},
			"app":     {HostRef: "h-app", IdentityRef: "id-a", ProxyJump: rawJump, SudoMode: models.SudoModeAuto},
		},
	}

	if err := ValidateV2(v2); !errors.Is(err, ErrSchemaValidation) {
		t.Fatalf("ValidateV2(ProxyJump=%q) = %v, want ErrSchemaValidation", rawJump, err)
	}
	if err := ValidateGraph(configurationFromV2Unchecked(v2)); !errors.Is(err, ErrSchemaValidation) {
		t.Fatalf("ValidateGraph(ProxyJump=%q) = %v, want ErrSchemaValidation", rawJump, err)
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "xops_config.yaml")
	keyPath := filepath.Join(dir, "secret.key")
	rawBytes, err := yaml.Marshal(v2)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	if err := os.WriteFile(cfgPath, rawBytes, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	diag, err := DiagnoseConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("DiagnoseConfigFile: %v", err)
	}
	if !diag.HasErrors() || !diag.HasFixableIssues() {
		t.Fatalf("expected fixable proxy_jump_invalid diagnostic for %q, got %+v", rawJump, diag.Issues)
	}

	fixReport, err := FixConfigFile(t.Context(), cfgPath, keyPath)
	if err != nil {
		t.Fatalf("FixConfigFile(%q): %v (issues=%+v)", rawJump, err, fixReport.Issues)
	}
	if !fixReport.Healthy() || len(fixReport.Fixes) == 0 {
		t.Fatalf("expected healthy report after fix for %q, got %+v", rawJump, fixReport)
	}

	loaded, err := NewDefaultStore(cfgPath, keyPath).Load()
	if err != nil {
		t.Fatalf("Load after fix(%q): %v", rawJump, err)
	}
	appNode, ok := loaded.Nodes.Get("app")
	if !ok {
		t.Fatal("app node missing after fix")
	}
	if appNode.ProxyJump != wantRepaired {
		t.Fatalf("repaired ProxyJump = %q, want %q", appNode.ProxyJump, wantRepaired)
	}

	recheck, err := DiagnoseConfigFile(cfgPath)
	if err != nil || !recheck.Healthy() {
		t.Fatalf("DiagnoseConfigFile after fix(%q) = (%+v, %v), want healthy", rawJump, recheck, err)
	}
}

func TestP7W5c_D5M1_ImportOpenSSHHostsDropsDefaultAlgoPolicyAndMatchesYAMLReload(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host legacy-only
    HostName 10.0.0.10
    User ops
    MACs +umac-64@openssh.com

Host legacy-with-timeout
    HostName 10.0.0.11
    User ops
    MACs +umac-64@openssh.com
    ConnectTimeout 15
`
	hosts, err := ParseOpenSSHHosts(strings.NewReader(sshCfg), "ops")
	if err != nil {
		t.Fatalf("ParseOpenSSHHosts: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(hosts))
	}

	legacyOnly := hosts[0]
	if legacyOnly.Node.SSHOptions != nil {
		t.Fatalf("legacy-only imported SSHOptions = %+v, want nil (AlgoOpDefault must be dropped)", legacyOnly.Node.SSHOptions)
	}

	legacyWithTimeout := hosts[1]
	if legacyWithTimeout.Node.SSHOptions == nil || legacyWithTimeout.Node.SSHOptions.Get(ssh.OptionConnectTimeout) != "15" {
		t.Fatalf("legacy-with-timeout imported SSHOptions = %+v, want ConnectTimeout=15", legacyWithTimeout.Node.SSHOptions)
	}
	if pol, ok := legacyWithTimeout.Node.SSHOptions.AlgoPolicy(ssh.OptionMACs); ok {
		t.Fatalf("legacy-with-timeout retained AlgoOpDefault(MACs): %+v", pol)
	}

	// Verify Tier-3 global MACs is NOT shadowed in memory AND in-memory Node matches YAML reload 100%.
	supportedMACs := cryptoSSH.SupportedAlgorithms().MACs
	if len(supportedMACs) == 0 {
		t.Fatal("expected supported MACs")
	}
	tier3Global := ssh.MustOptions(ssh.OptionMACs, supportedMACs[0])

	for _, h := range hosts {
		mergedInMemory := ssh.MergeOptions(h.Node.SSHOptions, tier3Global)
		if mergedInMemory == nil || mergedInMemory.MACs() != supportedMACs[0] {
			t.Fatalf("%s: in-memory Tier-2 shadowed Tier-3 global MACs: got %q, want %q", h.Name, mergedInMemory.MACs(), supportedMACs[0])
		}

		// Round-trip through YAML V2 persistence.
		v2 := &ConfigurationV2{
			SchemaVersion: 2,
			Credential:    CredentialConfig{Stores: map[string]StoreConfig{}},
			Hosts:         map[string]models.Host{"h1": h.Host},
			Identities:    map[string]IdentityV2{"id1": {User: h.Identity.User, AuthType: h.Identity.AuthType}},
			Nodes: map[string]NodeV2{
				h.Name: {
					HostRef:     "h1",
					IdentityRef: "id1",
					SudoMode:    h.Node.SudoMode,
					SSHOptions:  h.Node.SSHOptions,
				},
			},
			SSHOptions: tier3Global,
		}
		raw, err := yaml.Marshal(v2)
		if err != nil {
			t.Fatalf("%s: yaml.Marshal: %v", h.Name, err)
		}
		reloadedV2, err := UnmarshalV2(raw)
		if err != nil {
			t.Fatalf("%s: UnmarshalV2: %v", h.Name, err)
		}
		reloadedCfg, err := FromV2(reloadedV2)
		if err != nil {
			t.Fatalf("%s: FromV2: %v", h.Name, err)
		}
		reloadedNode, ok := reloadedCfg.Nodes.Get(h.Name)
		if !ok {
			t.Fatalf("%s missing after YAML reload", h.Name)
		}
		if !h.Node.SSHOptions.Equal(reloadedNode.SSHOptions) {
			t.Fatalf("%s: in-memory SSHOptions (%+v) != YAML reloaded (%+v)", h.Name, h.Node.SSHOptions, reloadedNode.SSHOptions)
		}
		dMem := ssh.DigestClientConfig(ssh.NewClientConfig(ssh.ClientConfig{NodeID: h.Name, Address: h.Host.Address, Port: int(h.Host.Port), Options: h.Node.SSHOptions}), ssh.ZeroHopDigest)
		dYAML := ssh.DigestClientConfig(ssh.NewClientConfig(ssh.ClientConfig{NodeID: h.Name, Address: h.Host.Address, Port: int(h.Host.Port), Options: reloadedNode.SSHOptions}), ssh.ZeroHopDigest)
		if !dMem.Equal(dYAML) {
			t.Fatalf("%s: in-memory HopDigest (%s) != YAML reloaded (%s)", h.Name, dMem, dYAML)
		}
	}
}
