package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
	"gopkg.in/yaml.v3"
)

func TestP7W12c_FG12M2_DE12M3_DoctorDiagnosesAndRepairsOpenSSHEndpointAndMultiHopCycles(t *testing.T) {
	t.Parallel()

	makeV2 := func(hosts map[string]models.Host, nodes map[string]NodeV2) *ConfigurationV2 {
		return &ConfigurationV2{
			SchemaVersion: 2,
			Credential:    CredentialConfig{Stores: map[string]StoreConfig{}},
			Hosts:         hosts,
			Identities: map[string]IdentityV2{
				"id-ops":   {User: "ops", AuthType: "auto"},
				"id-alice": {User: "alice", AuthType: "auto"},
			},
			Nodes: nodes,
		}
	}

	cases := []struct {
		name      string
		v2        *ConfigurationV2
		wantJumps map[string]string
	}{
		{
			name: "2hop_saved_to_openssh_ip_backedge",
			v2: makeV2(
				map[string]models.Host{
					"h-a": {Address: "10.0.0.1", Port: 22},
					"h-b": {Address: "10.0.0.2", Port: 22},
				},
				map[string]NodeV2{
					"node-a": {HostRef: "h-a", IdentityRef: "id-ops", ProxyJump: "node-b", SudoMode: models.SudoModeAuto},
					"node-b": {HostRef: "h-b", IdentityRef: "id-ops", ProxyJump: "openssh:10.0.0.1", SudoMode: models.SudoModeAuto},
				},
			),
			wantJumps: map[string]string{
				"node-a": "",
				"node-b": "openssh:10.0.0.1",
			},
		},
		{
			name: "2hop_saved_to_openssh_user_host_port_backedge",
			v2: makeV2(
				map[string]models.Host{
					"h-a": {Address: "10.0.0.1", Port: 22},
					"h-b": {Address: "10.0.0.2", Port: 22},
				},
				map[string]NodeV2{
					"node-a": {HostRef: "h-a", IdentityRef: "id-ops", ProxyJump: "node-b", SudoMode: models.SudoModeAuto},
					"node-b": {HostRef: "h-b", IdentityRef: "id-ops", ProxyJump: "openssh:ops@10.0.0.1:22", SudoMode: models.SudoModeAuto},
				},
			),
			wantJumps: map[string]string{
				"node-a": "",
				"node-b": "openssh:ops@10.0.0.1:22",
			},
		},
		{
			name: "3hop_saved_to_openssh_endpoint_backedge",
			v2: makeV2(
				map[string]models.Host{
					"h-a": {Address: "10.0.0.1", Port: 22},
					"h-b": {Address: "10.0.0.2", Port: 22},
					"h-c": {Address: "10.0.0.3", Port: 22},
				},
				map[string]NodeV2{
					"node-a": {HostRef: "h-a", IdentityRef: "id-ops", ProxyJump: "node-b", SudoMode: models.SudoModeAuto},
					"node-b": {HostRef: "h-b", IdentityRef: "id-ops", ProxyJump: "node-c", SudoMode: models.SudoModeAuto},
					"node-c": {HostRef: "h-c", IdentityRef: "id-ops", ProxyJump: "openssh:10.0.0.1", SudoMode: models.SudoModeAuto},
				},
			),
			wantJumps: map[string]string{
				"node-a": "",
				"node-b": "node-c",
				"node-c": "openssh:10.0.0.1",
			},
		},
		{
			name: "comma_chain_with_openssh_backedge_preserves_valid_hop",
			v2: makeV2(
				map[string]models.Host{
					"h-a":    {Address: "10.0.0.1", Port: 22},
					"h-b":    {Address: "10.0.0.2", Port: 22},
					"h-bast": {Address: "10.0.0.9", Port: 22},
				},
				map[string]NodeV2{
					"bastion": {HostRef: "h-bast", IdentityRef: "id-ops", SudoMode: models.SudoModeAuto},
					"node-a":  {HostRef: "h-a", IdentityRef: "id-ops", ProxyJump: "node-b,bastion", SudoMode: models.SudoModeAuto},
					"node-b":  {HostRef: "h-b", IdentityRef: "id-ops", ProxyJump: "openssh:10.0.0.1", SudoMode: models.SudoModeAuto},
				},
			),
			wantJumps: map[string]string{
				"node-a": "bastion",
				"node-b": "openssh:10.0.0.1",
			},
		},
		{
			name: "downstream_cycle_repaired_without_breaking_upstream_entry",
			v2: makeV2(
				map[string]models.Host{
					"h-entry": {Address: "10.0.0.1", Port: 22},
					"h-a":     {Address: "10.0.0.2", Port: 22},
					"h-b":     {Address: "10.0.0.3", Port: 22},
				},
				map[string]NodeV2{
					"entry":  {HostRef: "h-entry", IdentityRef: "id-ops", ProxyJump: "node-a", SudoMode: models.SudoModeAuto},
					"node-a": {HostRef: "h-a", IdentityRef: "id-ops", ProxyJump: "node-b", SudoMode: models.SudoModeAuto},
					"node-b": {HostRef: "h-b", IdentityRef: "id-ops", ProxyJump: "openssh:10.0.0.2", SudoMode: models.SudoModeAuto},
				},
			),
			wantJumps: map[string]string{
				"entry":  "node-a",
				"node-a": "",
				"node-b": "openssh:10.0.0.2",
			},
		},
		{
			name: "coexisting_invalid_hop_and_openssh_backedge_cycle",
			v2: makeV2(
				map[string]models.Host{
					"h-a": {Address: "10.0.0.1", Port: 22},
					"h-b": {Address: "10.0.0.2", Port: 22},
				},
				map[string]NodeV2{
					"node-a": {HostRef: "h-a", IdentityRef: "id-ops", ProxyJump: "node-b,openssh:openssh:22", SudoMode: models.SudoModeAuto},
					"node-b": {HostRef: "h-b", IdentityRef: "id-ops", ProxyJump: "openssh:10.0.0.1", SudoMode: models.SudoModeAuto},
				},
			),
			wantJumps: map[string]string{
				"node-a": "",
				"node-b": "openssh:10.0.0.1",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertW12cDoctorCycleRepairCase(t, tc.name, tc.v2, tc.wantJumps)
		})
	}

	t.Run("distinct_user_openssh_endpoint_backedge_remains_valid", func(t *testing.T) {
		t.Parallel()
		v2 := makeV2(
			map[string]models.Host{
				"h-a": {Address: "10.0.0.1", Port: 22},
				"h-b": {Address: "10.0.0.2", Port: 22},
			},
			map[string]NodeV2{
				"node-a": {HostRef: "h-a", IdentityRef: "id-alice", ProxyJump: "node-b", SudoMode: models.SudoModeAuto},
				"node-b": {HostRef: "h-b", IdentityRef: "id-ops", ProxyJump: "openssh:bob@10.0.0.1:22", SudoMode: models.SudoModeAuto},
			},
		)
		if err := ValidateGraph(configurationFromV2Unchecked(v2)); err != nil {
			t.Fatalf("ValidateGraph(distinct user endpoint) unexpected error: %v", err)
		}
		if diag := DiagnoseV2(v2); !diag.Healthy() {
			t.Fatalf("DiagnoseV2(distinct user endpoint) = %+v, want healthy", diag.Issues)
		}
	})
}

func assertW12cDoctorCycleRepairCase(t *testing.T, name string, v2 *ConfigurationV2, wantJumps map[string]string) {
	t.Helper()

	var cycleErr *ssh.ProxyCycleError
	err := ValidateGraph(configurationFromV2Unchecked(v2))
	if !errors.Is(err, ErrSchemaValidation) {
		t.Fatalf("ValidateGraph(%s) = %v, want ErrSchemaValidation", name, err)
	}
	if !strings.Contains(name, "coexisting_invalid") && !errors.As(err, &cycleErr) {
		t.Fatalf("ValidateGraph(%s) = %v, want *ssh.ProxyCycleError", name, err)
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "xops_config.yaml")
	keyPath := filepath.Join(dir, "secret.key")
	raw, err := yaml.Marshal(v2)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := NewDefaultStore(cfgPath, keyPath)
	if _, loadErr := store.Load(); loadErr == nil || !strings.Contains(loadErr.Error(), "xops config doctor") {
		t.Fatalf("store.Load() before fix = %v, want fail-closed error with doctor hint", loadErr)
	}

	assertW12cDoctorDiagHasFixableCycle(t, name, cfgPath)

	fixReport, err := FixConfigFile(t.Context(), cfgPath, keyPath)
	if err != nil || !fixReport.Healthy() || len(fixReport.Fixes) == 0 {
		t.Fatalf("FixConfigFile(%s) = (%+v, %v), want healthy repair", name, fixReport, err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load() after fix(%s): %v", name, err)
	}
	if _, err := NewRepositoryWithoutOpenSSH(loaded, store); err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH after fix(%s): %v", name, err)
	}
	for nodeID, wantJump := range wantJumps {
		n, ok := loaded.Nodes.Get(nodeID)
		if !ok || n.ProxyJump != wantJump {
			t.Errorf("repaired node %q ProxyJump = (%q, %v), want %q", nodeID, n.ProxyJump, ok, wantJump)
		}
	}

	recheck, err := DiagnoseConfigFile(cfgPath)
	if err != nil || !recheck.Healthy() {
		t.Fatalf("DiagnoseConfigFile recheck(%s) = (%+v, %v), want healthy", name, recheck, err)
	}
}

func assertW12cDoctorDiagHasFixableCycle(t *testing.T, name, cfgPath string) {
	t.Helper()
	diag, err := DiagnoseConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("DiagnoseConfigFile(%s): %v", name, err)
	}
	if !diag.HasErrors() || !diag.HasFixableIssues() {
		t.Fatalf("DiagnoseConfigFile(%s) = %+v, want fixable errors", name, diag)
	}
	sawCycle := false
	for _, issue := range diag.Issues {
		if issue.Code == "schema_validation" {
			t.Errorf("DiagnoseConfigFile(%s) reported unfixable schema_validation: %+v", name, issue)
		}
		if issue.Code == "proxy_jump_cycle" && issue.Fixable {
			sawCycle = true
		}
	}
	if !sawCycle {
		t.Errorf("DiagnoseConfigFile(%s) missing fixable proxy_jump_cycle issue: %+v", name, diag.Issues)
	}
}

func TestP7W12c_DE12M1_EndpointCycleBetweenSavedNodeAndOpenSSHStanza(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host web
    HostName 10.214.0.1
    Port 22
    User ops

Host web-bob
    HostName 10.214.0.1
    Port 22
    User bob

Host web-2222
    HostName 10.214.0.1
    Port 2222
    User ops

Host mid-to-web
    HostName 10.214.0.9
    Port 22
    User ops
    ProxyJump web
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("h-web", models.Host{Address: "10.214.0.1", Port: 22})
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.214.0.50", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Identities.Set("id-alice", models.Identity{User: "alice", AuthType: "auto"})
	cfg.Nodes.Set("saved-web", models.Node{HostRef: "h-web", IdentityRef: "id-ops"})
	cfg.Nodes.Set("saved-alice", models.Node{HostRef: "h-web", IdentityRef: "id-alice"})
	cfg.Nodes.Set("saved-bastion", models.Node{HostRef: "h-bastion", IdentityRef: "id-ops", ProxyJump: "openssh:web"})
	prov := NewProviderWithOpenSSHParser(cfg, parser)

	// 1-hop and 2-hop cycles between saved-web (ops@10.214.0.1:22) and concrete OpenSSH stanza Host web (ops@10.214.0.1:22).
	for _, jump := range []string{"openssh:web", "openssh:mid-to-web", "saved-bastion"} {
		var cycleErr *ssh.ProxyCycleError
		if _, rErr := ResolveTarget(prov, ConnectionTarget{
			Selector:     "saved-web",
			ProxyJump:    jump,
			HasProxyJump: true,
		}); !errors.As(rErr, &cycleErr) {
			t.Errorf("ResolveTarget(saved-web, jump=%q) = %v, want *ssh.ProxyCycleError", jump, rErr)
		}

		draft := cloneConfiguration(cfg)
		n, _ := draft.Nodes.Get("saved-web")
		n.ProxyJump = jump
		draft.Nodes.Set("saved-web", n)
		if vErr := ValidateSavedNodeJumpCycleWithOpenSSH(draft, parser, "saved-web"); !errors.As(vErr, &cycleErr) {
			t.Errorf("ValidateSavedNodeJumpCycleWithOpenSSH(saved-web, jump=%q) = %v, want *ssh.ProxyCycleError", jump, vErr)
		}
	}

	// Distinct user (alice vs bob) and distinct port (22 vs 2222) on same host remain allowed.
	for _, tc := range []struct {
		selector string
		jump     string
	}{
		{"saved-alice", "openssh:web-bob"},
		{"saved-web", "openssh:web-2222"},
	} {
		res, rErr := ResolveTarget(prov, ConnectionTarget{
			Selector:     tc.selector,
			ProxyJump:    tc.jump,
			HasProxyJump: true,
		})
		if rErr != nil || res.ProxyJump != tc.jump {
			t.Errorf("ResolveTarget(%s, jump=%q) = (%+v, %v), want allowed jump %q", tc.selector, tc.jump, res, rErr, tc.jump)
		}
	}
}

func TestP7W12c_DE12M2_OpenSSHJumpDoesNotMatchCollidingLocalSavedAliases(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host bastion
    HostName 10.0.0.20
    Port 22
    User root

Host *.gw.corp
    HostName 10.0.0.20
    Port 22
    User root

Host *.self.corp
    HostName 10.0.0.99
    Port 22
    User root
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	makeCfg := func(proxyJump string) *Configuration {
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("h-target", models.Host{Address: "10.0.0.99", Port: 22, Alias: []string{"gw-host"}})
		cfg.Identities.Set("id-root", models.Identity{User: "root", AuthType: "auto"})
		cfg.Nodes.Set("root@10.0.0.99:22", models.Node{
			HostRef:     "h-target",
			IdentityRef: "id-root",
			Alias:       []string{"bastion", "east.gw.corp", "loop.self.corp"},
			ProxyJump:   proxyJump,
			SudoMode:    models.SudoModeAuto,
		})
		return cfg
	}

	// 1. ValidateGraph (openSSH == nil) must NOT falsely reject openssh:bastion or openssh:east.gw.corp
	//    against colliding local saved aliases.
	for _, jump := range []string{"openssh:bastion", "openssh:east.gw.corp", "openssh:gw-host"} {
		cfg := makeCfg(jump)
		if gErr := ValidateGraph(cfg); gErr != nil {
			t.Errorf("ValidateGraph(ProxyJump=%q) unexpected error: %v", jump, gErr)
		}
		if _, repoErr := NewRepositoryWithoutOpenSSH(cfg, &repositoryTestStore{}); repoErr != nil {
			t.Errorf("NewRepositoryWithoutOpenSSH(ProxyJump=%q) unexpected error: %v", jump, repoErr)
		}
	}

	// 2. With OpenSSHParser (concrete Host bastion AND wildcard Host *.gw.corp -> 10.0.0.20),
	//    openssh:bastion and openssh:east.gw.corp resolve to 10.0.0.20 != 10.0.0.99 and succeed.
	for _, jump := range []string{"openssh:bastion", "openssh:east.gw.corp"} {
		cfg := makeCfg(jump)
		prov := NewProviderWithOpenSSHParser(cfg, parser)
		if res, rErr := ResolveTarget(prov, ConnectionTarget{Selector: "root@10.0.0.99:22"}); rErr != nil || res.ProxyJump != jump {
			t.Errorf("ResolveTarget(ProxyJump=%q) = (%+v, %v), want jump=%q", jump, res, rErr, jump)
		}
		if vErr := ValidateSavedNodeJumpCycleWithOpenSSH(cfg, parser, "root@10.0.0.99:22"); vErr != nil {
			t.Errorf("ValidateSavedNodeJumpCycleWithOpenSSH(ProxyJump=%q) unexpected error: %v", jump, vErr)
		}
	}

	// 3. Wildcard Host *.self.corp resolving to the SAME endpoint 10.0.0.99:22 MUST fail closed as a cycle.
	cfgSelfWildcard := makeCfg("openssh:loop.self.corp")
	provSelfWildcard := NewProviderWithOpenSSHParser(cfgSelfWildcard, parser)
	var cycleErr *ssh.ProxyCycleError
	if _, rErr := ResolveTarget(provSelfWildcard, ConnectionTarget{Selector: "root@10.0.0.99:22"}); !errors.As(rErr, &cycleErr) {
		t.Errorf("ResolveTarget(wildcard same endpoint) = %v, want *ssh.ProxyCycleError", rErr)
	}
	if vErr := ValidateSavedNodeJumpCycleWithOpenSSH(cfgSelfWildcard, parser, "root@10.0.0.99:22"); !errors.As(vErr, &cycleErr) {
		t.Errorf("ValidateSavedNodeJumpCycleWithOpenSSH(wildcard same endpoint) = %v, want *ssh.ProxyCycleError", vErr)
	}

	// 4. Unprefixed local alias self-jump ("bastion") MUST still fail closed.
	cfgLocalSelf := makeCfg("bastion")
	if gErr := ValidateGraph(cfgLocalSelf); !errors.Is(gErr, ErrSchemaValidation) {
		t.Errorf("ValidateGraph(unprefixed local alias self-jump) = %v, want ErrSchemaValidation", gErr)
	}
}

func TestP7W12c_DE12L1_RawProxyJumpOpenSSHTokensFailClosedBeforeTrim(t *testing.T) {
	t.Parallel()

	parser, err := NewOpenSSHParserFromReader(strings.NewReader("Host web\n  HostName 10.218.0.2\n  User ops\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("h-app", models.Host{Address: "10.218.0.1", Port: 22})
	cfg.Hosts.Set("h-b1", models.Host{Address: "10.218.0.10", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-app", models.Node{HostRef: "h-app", IdentityRef: "id-ops"})
	cfg.Nodes.Set("bastion1", models.Node{HostRef: "h-b1", IdentityRef: "id-ops"})
	prov := NewProviderWithOpenSSHParser(cfg, parser)

	badJumps := []string{
		" openssh:web",
		"\u00a0openssh:web",
		"bastion1, openssh:web",
		"openssh:openssh:web",
		"openssh:web ",
		" OPENSSH:web",
	}

	for _, bad := range badJumps {
		if _, err := ResolveProxyJumpChainWithConfig(cfg, parser, bad); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ResolveProxyJumpChainWithConfig(%q) = %v, want ErrSSHOptionsValidation", bad, err)
		}
		if _, err := ResolveTarget(prov, ConnectionTarget{
			Selector:     "saved-app",
			ProxyJump:    bad,
			HasProxyJump: true,
		}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ResolveTarget(ProxyJump=%q) = %v, want ErrSSHOptionsValidation", bad, err)
		}
		if err := ValidateProxyJumpChainCycle(prov, ProxyJumpTarget{NodeID: "saved-app"}, bad, bad); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ValidateProxyJumpChainCycle(%q) = %v, want ErrSSHOptionsValidation", bad, err)
		}
		if _, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider:     prov,
			Host:         "short",
			CLIProxyJump: bad,
		}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("CanonicalizeHost(CLIProxyJump=%q) = %v, want ErrSSHOptionsValidation", bad, err)
		}
		if _, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider:      prov,
			Host:          "short",
			RawCLIOptions: []string{"ProxyJump=" + bad},
		}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("CanonicalizeHost(RawCLIOptions ProxyJump=%q) = %v, want ErrSSHOptionsValidation", bad, err)
		}
	}

	// Valid unpadded openssh: hop and spaced non-openssh hops must continue to work.
	if got, err := ResolveProxyJumpChainWithConfig(cfg, parser, "bastion1,openssh:web"); err != nil || got != "bastion1,openssh:web" {
		t.Fatalf("ResolveProxyJumpChainWithConfig(valid) = (%q, %v), want bastion1,openssh:web", got, err)
	}
	if got, err := ResolveProxyJumpChainWithConfig(cfg, parser, "bastion1, 10.218.0.20"); err != nil || got != "bastion1,openssh:10.218.0.20" {
		t.Fatalf("ResolveProxyJumpChainWithConfig(spaced non-openssh) = (%q, %v), want bastion1,openssh:10.218.0.20", got, err)
	}
}

func TestP7W12c_DE12L2_WithPendingNodeReadOnlyDefaultUserAndExistingUpdateJump(t *testing.T) {
	t.Parallel()

	localUser, otherUser := w11cDistinctTestUser(t)
	_ = localUser

	const sshCfg = `
Host loop
    HostName 10.220.0.99
    User ops
    ProxyJump loop
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	makeCfg := func() *Configuration {
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("h-saved", models.Host{Address: "10.220.0.1", Port: 22})
		cfg.Hosts.Set("h-loop", models.Host{Address: "10.220.0.2", Port: 22})
		cfg.Hosts.Set("h-bast", models.Host{Address: "10.220.0.10", Port: 22})
		cfg.Identities.Set("id-other", models.Identity{User: otherUser, AuthType: "auto"})
		cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set(otherUser+"@10.220.0.1:22", models.Node{HostRef: "h-saved", IdentityRef: "id-other"})
		cfg.Nodes.Set("saved-loop", models.Node{HostRef: "h-loop", IdentityRef: "id-ops", ProxyJump: "openssh:loop"})
		cfg.Nodes.Set("bastion", models.Node{HostRef: "h-bast", IdentityRef: "id-ops"})
		return cfg
	}

	roProv := NewProviderWithOpenSSHParser(makeCfg(), parser)
	repo, err := NewRepositoryWithOpenSSHParser(makeCfg(), &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	t.Run("default_user_matches_repository_on_adhoc_and_saved_targets", func(t *testing.T) {
		t.Parallel()
		// 1. Saved node match with OpenSSH parser attached: DefaultUser selects saved node otherUser@10.220.0.1:22.
		reqSaved := EnsureNodeOptions{
			Target:      ConnectionTarget{Selector: "10.220.0.1"},
			DefaultUser: otherUser,
		}
		var repoSavedID, roSavedID string
		if err := WithPendingNode(t.Context(), repo, reqSaved, func(l PendingLease) error {
			repoSavedID = l.NodeID()
			return nil
		}); err != nil {
			t.Fatalf("repo WithPendingNode(10.220.0.1): %v", err)
		}
		if err := WithPendingNode(t.Context(), roProv, reqSaved, func(l PendingLease) error {
			roSavedID = l.NodeID()
			return nil
		}); err != nil {
			t.Fatalf("read-only WithPendingNode(10.220.0.1): %v", err)
		}
		wantSavedID := otherUser + "@10.220.0.1:22"
		if repoSavedID != wantSavedID || roSavedID != wantSavedID {
			t.Errorf("saved selector 10.220.0.1: repoID=%q roID=%q, want both %q", repoSavedID, roSavedID, wantSavedID)
		}

		// 2. Ad-hoc creation without OpenSSH config: DefaultUser controls effective node ID on both repo and read-only provider.
		roNoSSH := NewProviderWithoutOpenSSH(makeCfg())
		repoNoSSH, err := NewRepositoryWithoutOpenSSH(makeCfg(), &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}})
		if err != nil {
			t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
		}
		reqAdHoc := EnsureNodeOptions{
			Target:      ConnectionTarget{Selector: "10.220.0.5"},
			DefaultUser: otherUser,
		}
		var repoAdHocID, roAdHocID string
		if err := WithPendingNode(t.Context(), repoNoSSH, reqAdHoc, func(l PendingLease) error {
			repoAdHocID = l.NodeID()
			return nil
		}); err != nil {
			t.Fatalf("repoNoSSH WithPendingNode(10.220.0.5): %v", err)
		}
		if err := WithPendingNode(t.Context(), roNoSSH, reqAdHoc, func(l PendingLease) error {
			roAdHocID = l.NodeID()
			return nil
		}); err != nil {
			t.Fatalf("roNoSSH WithPendingNode(10.220.0.5): %v", err)
		}
		wantAdHocID := otherUser + "@10.220.0.5:22"
		if repoAdHocID != wantAdHocID || roAdHocID != wantAdHocID {
			t.Errorf("ad-hoc selector 10.220.0.5: repoID=%q roID=%q, want both %q", repoAdHocID, roAdHocID, wantAdHocID)
		}
	})

	t.Run("existing_update_jump_overrides_saved_node_base_jump_when_enabled", func(t *testing.T) {
		t.Parallel()
		for _, jump := range []string{"none", "bastion"} {
			req := EnsureNodeOptions{
				Target: ConnectionTarget{Selector: "saved-loop"},
				ExistingUpdate: PendingNodeUpdate{
					Enabled:  true,
					JumpHost: jump,
				},
			}
			var repoID, roID string
			if err := WithPendingNode(t.Context(), repo, req, func(l PendingLease) error {
				repoID = l.NodeID()
				return nil
			}); err != nil {
				t.Fatalf("repo WithPendingNode(saved-loop, jump=%q): %v", jump, err)
			}
			if err := WithPendingNode(t.Context(), roProv, req, func(l PendingLease) error {
				roID = l.NodeID()
				return nil
			}); err != nil {
				t.Fatalf("read-only WithPendingNode(saved-loop, jump=%q): %v", jump, err)
			}
			if repoID != "saved-loop" || roID != "saved-loop" {
				t.Errorf("jump=%q: repoID=%q roID=%q, want saved-loop", jump, repoID, roID)
			}
		}

		// Control: without ExistingUpdate.Enabled, saved-loop's cyclic base ProxyJump fails closed on both.
		var cycleErr *ssh.ProxyCycleError
		if err := WithPendingNode(t.Context(), roProv, EnsureNodeOptions{
			Target: ConnectionTarget{Selector: "saved-loop"},
		}, func(PendingLease) error { return nil }); !errors.As(err, &cycleErr) {
			t.Errorf("read-only WithPendingNode(saved-loop, no update) = %v, want *ssh.ProxyCycleError", err)
		}
	})
}
