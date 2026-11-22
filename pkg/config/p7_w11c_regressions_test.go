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

func w11cDistinctTestUser(t *testing.T) (localUser, otherUser string) {
	t.Helper()
	u, err := getCurrentUser()
	if err != nil || strings.TrimSpace(u) == "" {
		t.Fatalf("getCurrentUser() = (%q, %v)", u, err)
	}
	localUser = strings.TrimSpace(u)
	otherUser = "w11c-bob"
	if localUser == otherUser {
		otherUser = "w11c-alice"
	}
	return localUser, otherUser
}

func TestP7W11c_DE11M1_EnsureAndPendingMatchedTargetFailClosedParity(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host ssh-web
    HostName 10.211.1.1
    User ops

Host ssh-loop
    HostName 10.211.1.2
    User ops
    ProxyJump ssh-loop

Host hop-a
    HostName 10.211.1.3
    User ops
    ProxyJump hop-b

Host hop-b
    HostName 10.211.1.4
    User ops
    ProxyJump hop-a
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	makeBaseCfg := func() *Configuration {
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("h-web", models.Host{Address: "10.211.0.1", Port: 22})
		cfg.Hosts.Set("h-b1", models.Host{Address: "10.211.0.10", Port: 22})
		cfg.Hosts.Set("h-ambig", models.Host{Address: "10.211.0.21", Port: 22})
		cfg.Hosts.Set("h-t1", models.Host{Address: "10.211.0.30", Port: 22})
		cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Identities.Set("id-alice", models.Identity{User: "alice", AuthType: "auto"})
		cfg.Identities.Set("id-bob", models.Identity{User: "bob", AuthType: "auto"})
		cfg.Nodes.Set("saved-web", models.Node{HostRef: "h-web", IdentityRef: "id-ops"})
		cfg.Nodes.Set("bastion", models.Node{HostRef: "h-b1", IdentityRef: "id-ops"})
		cfg.Nodes.Set("jump-1", models.Node{HostRef: "h-ambig", IdentityRef: "id-alice"})
		cfg.Nodes.Set("jump-2", models.Node{HostRef: "h-ambig", IdentityRef: "id-bob"})
		cfg.Nodes.Set("t1-b", models.Node{HostRef: "h-t1", IdentityRef: "id-ops", ProxyJump: "saved-web"})
		return cfg
	}

	t.Run("matched_saved_and_openssh_targets_fail_closed_across_Resolve_Ensure_and_Pending", func(t *testing.T) {
		t.Parallel()
		cfg := makeBaseCfg()
		store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
		repo, err := NewRepositoryWithOpenSSHParser(cfg, store, parser)
		if err != nil {
			t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
		}
		overrideProv := &openSSHOverrideProvider{ConfigProvider: repo, repo: repo}
		roProv := NewProviderWithOpenSSHParser(cfg, parser)

		badTargets := []struct {
			name    string
			target  ConnectionTarget
			wantCyc bool
		}{
			{"saved_tier1_malformed", ConnectionTarget{Selector: "saved-web", ProxyJump: "bastion,,hop2", HasProxyJump: true}, false},
			{"saved_tier1_ambiguous", ConnectionTarget{Selector: "saved-web", ProxyJump: "10.211.0.21", HasProxyJump: true}, false},
			{"saved_tier1_unknown", ConnectionTarget{Selector: "saved-web", ProxyJump: "unknown-single-label", HasProxyJump: true}, false},
			{"saved_tier1_duplicate_hop", ConnectionTarget{Selector: "saved-web", ProxyJump: "bastion,bastion", HasProxyJump: true}, true},
			{"saved_tier1_2hop_cycle", ConnectionTarget{Selector: "saved-web", ProxyJump: "t1-b", HasProxyJump: true}, true},
			{"saved_tier1_openssh_2hop_cycle", ConnectionTarget{Selector: "saved-web", ProxyJump: "openssh:hop-a", HasProxyJump: true}, true},
			{"openssh_tier1_malformed", ConnectionTarget{Selector: "ssh-web", ProxyJump: "bastion,,hop2", HasProxyJump: true}, false},
			{"openssh_tier1_unknown", ConnectionTarget{Selector: "ssh-web", ProxyJump: "unknown-single-label", HasProxyJump: true}, false},
			{"openssh_tier1_self_cycle", ConnectionTarget{Selector: "ssh-web", ProxyJump: "ssh-web", HasProxyJump: true}, true},
			{"openssh_tier4_self_cycle", ConnectionTarget{Selector: "ssh-loop"}, true},
			{"openssh_tier4_2hop_cycle", ConnectionTarget{Selector: "hop-a"}, true},
			{"openssh_prefixed_tier4_2hop_cycle", ConnectionTarget{Selector: OpenSSHNodePrefix + "hop-a"}, true},
		}

		for _, tc := range badTargets {
			t.Run(tc.name, func(t *testing.T) {
				checkErr := func(label string, err error) {
					t.Helper()
					if err == nil {
						t.Errorf("%s(%s) unexpectedly succeeded", label, tc.name)
						return
					}
					if tc.wantCyc {
						var cycleErr *ssh.ProxyCycleError
						if !errors.As(err, &cycleErr) {
							t.Errorf("%s(%s) err = %v, want *ssh.ProxyCycleError", label, tc.name, err)
						}
					}
				}
				_, rErr := ResolveTarget(repo, tc.target)
				checkErr("ResolveTarget", rErr)

				_, eErr := repo.EnsureNodeContext(t.Context(), EnsureNodeOptions{Target: tc.target})
				checkErr("EnsureNodeContext", eErr)

				pErr := repo.WithPendingNode(t.Context(), EnsureNodeOptions{Target: tc.target}, func(PendingLease) error {
					t.Fatalf("Repository.WithPendingNode(%s) invoked callback on invalid ProxyJump", tc.name)
					return nil
				})
				checkErr("Repository.WithPendingNode", pErr)

				ovErr := overrideProv.WithPendingNode(t.Context(), EnsureNodeOptions{Target: tc.target}, func(PendingLease) error {
					t.Fatalf("openSSHOverrideProvider.WithPendingNode(%s) invoked callback on invalid ProxyJump", tc.name)
					return nil
				})
				checkErr("openSSHOverrideProvider.WithPendingNode", ovErr)

				roErr := WithPendingNode(t.Context(), roProv, EnsureNodeOptions{Target: tc.target}, func(PendingLease) error {
					t.Fatalf("WithPendingNode(read-only, %s) invoked callback on invalid ProxyJump", tc.name)
					return nil
				})
				checkErr("WithPendingNode(read-only)", roErr)
			})
		}
	})

	t.Run("createNodeInTransaction_and_prepareExistingNodeLocked_catch_openssh_cycles_and_alias_self_loops", func(t *testing.T) {
		t.Parallel()
		cfg := makeBaseCfg()
		store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
		repo, err := NewRepositoryWithOpenSSHParser(cfg, store, parser)
		if err != nil {
			t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
		}

		// 1. New node with OpenSSH 2-hop cycle in ProxyJump.
		for _, op := range []struct {
			name string
			run  func() error
		}{
			{"EnsureNodeContext_new_node_openssh_cycle", func() error {
				_, err := repo.EnsureNodeContext(t.Context(), EnsureNodeOptions{
					Target: ConnectionTarget{
						Selector:     "10.211.9.1",
						User:         "ops",
						HasUser:      true,
						ProxyJump:    "openssh:hop-a",
						HasProxyJump: true,
					},
				})
				return err
			}},
			{"WithPendingNode_new_node_openssh_cycle", func() error {
				return repo.WithPendingNode(t.Context(), EnsureNodeOptions{
					Target: ConnectionTarget{
						Selector:     "10.211.9.2",
						User:         "ops",
						HasUser:      true,
						ProxyJump:    "openssh:hop-a",
						HasProxyJump: true,
					},
				}, func(PendingLease) error { return nil })
			}},
			{"EnsureNodeContext_new_node_alias_self_loop", func() error {
				_, err := repo.EnsureNodeContext(t.Context(), EnsureNodeOptions{
					Target: ConnectionTarget{
						Selector:     "10.211.9.3",
						User:         "ops",
						HasUser:      true,
						ProxyJump:    "gw.self.example.com",
						HasProxyJump: true,
					},
					Alias: "gw.self.example.com",
				})
				return err
			}},
			{"WithPendingNode_existing_update_openssh_cycle", func() error {
				return repo.WithPendingNode(t.Context(), EnsureNodeOptions{
					Target: ConnectionTarget{Selector: "saved-web"},
					ExistingUpdate: PendingNodeUpdate{
						Enabled:  true,
						JumpHost: "openssh:hop-a",
					},
				}, func(PendingLease) error { return nil })
			}},
			{"WithPendingNode_existing_update_alias_self_loop", func() error {
				return repo.WithPendingNode(t.Context(), EnsureNodeOptions{
					Target: ConnectionTarget{Selector: "saved-web"},
					ExistingUpdate: PendingNodeUpdate{
						Enabled:  true,
						Alias:    "staged-gw.example.com",
						JumpHost: "staged-gw.example.com",
					},
				}, func(PendingLease) error { return nil })
			}},
			{"WithPendingNode_existing_update_disabled_duplicate_jump", func() error {
				return repo.WithPendingNode(t.Context(), EnsureNodeOptions{
					Target: ConnectionTarget{Selector: "saved-web"},
					ExistingUpdate: PendingNodeUpdate{
						Enabled:  false,
						JumpHost: "bastion,bastion",
					},
				}, func(PendingLease) error { return nil })
			}},
		} {
			var cycleErr *ssh.ProxyCycleError
			if err := op.run(); !errors.As(err, &cycleErr) {
				t.Errorf("%s err = %v, want *ssh.ProxyCycleError", op.name, err)
			}
		}
	})
}

func TestP7W11c_DE11M1_ValidateGraphAndDoctorDuplicateAndChainFlatteningCycles(t *testing.T) {
	t.Parallel()

	makeBaseV2 := func() *ConfigurationV2 {
		return &ConfigurationV2{
			SchemaVersion: 2,
			Credential:    CredentialConfig{Stores: map[string]StoreConfig{}},
			Hosts: map[string]models.Host{
				"h-bastion": {Address: "10.102.0.10", Port: 22},
				"h-outer":   {Address: "10.102.0.21", Port: 22},
				"h-mid":     {Address: "10.102.0.22", Port: 22},
				"h-inner":   {Address: "10.102.0.23", Port: 22},
				"h-app":     {Address: "10.102.0.30", Port: 22},
				"h-root":    {Address: "10.102.0.40", Port: 22},
			},
			Identities: map[string]IdentityV2{
				"id-ops": {User: "ops", AuthType: "auto"},
			},
			Nodes: map[string]NodeV2{
				"ops@10.102.0.10:22": {HostRef: "h-bastion", IdentityRef: "id-ops", Alias: []string{"bastion"}, SudoMode: models.SudoModeAuto},
				"root-bastion":       {HostRef: "h-root", IdentityRef: "id-ops", SudoMode: models.SudoModeAuto},
				"chain-inner":        {HostRef: "h-inner", IdentityRef: "id-ops", SudoMode: models.SudoModeAuto},
				"chain-mid":          {HostRef: "h-mid", IdentityRef: "id-ops", ProxyJump: "chain-inner", SudoMode: models.SudoModeAuto},
				"chain-outer":        {HostRef: "h-outer", IdentityRef: "id-ops", ProxyJump: "chain-mid", SudoMode: models.SudoModeAuto},
			},
		}
	}

	rejectCases := []struct {
		name         string
		appJump      string
		wantRepaired string
	}{
		{"duplicate_same_alias", "bastion,bastion", "bastion"},
		{"duplicate_alias_and_id", "bastion,ops@10.102.0.10:22", "bastion"},
		{"duplicate_openssh_case", "openssh:10.102.9.1,OPENSSH:10.102.9.1", "openssh:10.102.9.1"},
		{"chain_flattening_2hop", "chain-mid,chain-inner", "chain-inner"},
		{"chain_flattening_3hop", "chain-outer,chain-inner", "chain-inner"},
	}

	for _, tc := range rejectCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v2 := makeBaseV2()
			v2.Nodes["app"] = NodeV2{HostRef: "h-app", IdentityRef: "id-ops", ProxyJump: tc.appJump, SudoMode: models.SudoModeAuto}

			var cycleErr *ssh.ProxyCycleError
			v2Err := ValidateV2(v2)
			if !errors.Is(v2Err, ErrSchemaValidation) || !errors.As(v2Err, &cycleErr) {
				t.Fatalf("ValidateV2(%s) = %v, want ErrSchemaValidation wrapping *ssh.ProxyCycleError", tc.name, v2Err)
			}
			graphErr := ValidateGraph(configurationFromV2Unchecked(v2))
			if !errors.Is(graphErr, ErrSchemaValidation) || !errors.As(graphErr, &cycleErr) {
				t.Fatalf("ValidateGraph(%s) = %v, want ErrSchemaValidation wrapping *ssh.ProxyCycleError", tc.name, graphErr)
			}
			if _, repoErr := NewRepositoryWithoutOpenSSH(configurationFromV2Unchecked(v2), &repositoryTestStore{}); !errors.Is(repoErr, ErrSchemaValidation) {
				t.Fatalf("NewRepositoryWithoutOpenSSH(%s) = %v, want ErrSchemaValidation", tc.name, repoErr)
			}

			// Verify doctor diagnoses and --fix repairs cleanly.
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

			diag, err := DiagnoseConfigFile(cfgPath)
			if err != nil {
				t.Fatalf("DiagnoseConfigFile(%s): %v", tc.name, err)
			}
			if !diag.HasErrors() || !diag.HasFixableIssues() {
				t.Fatalf("DiagnoseConfigFile(%s) = %+v, want fixable error", tc.name, diag)
			}

			fixReport, err := FixConfigFile(t.Context(), cfgPath, keyPath)
			if err != nil || !fixReport.Healthy() || len(fixReport.Fixes) == 0 {
				t.Fatalf("FixConfigFile(%s) = (%+v, %v), want healthy repair", tc.name, fixReport, err)
			}

			loaded, err := NewDefaultStore(cfgPath, keyPath).Load()
			if err != nil {
				t.Fatalf("Load after fix(%s): %v", tc.name, err)
			}
			appNode, ok := loaded.Nodes.Get("app")
			if !ok || appNode.ProxyJump != tc.wantRepaired {
				t.Fatalf("repaired app.ProxyJump = %q, want %q", appNode.ProxyJump, tc.wantRepaired)
			}
		})
	}

	t.Run("valid_diamond_dag_and_saved_openssh_jump_pass_ValidateGraph_with_nil_openSSH", func(t *testing.T) {
		t.Parallel()
		v2 := makeBaseV2()
		v2.Nodes["d1"] = NodeV2{HostRef: "h-outer", IdentityRef: "id-ops", ProxyJump: "root-bastion", SudoMode: models.SudoModeAuto}
		v2.Nodes["d2"] = NodeV2{HostRef: "h-inner", IdentityRef: "id-ops", ProxyJump: "root-bastion", SudoMode: models.SudoModeAuto}
		v2.Nodes["app-diamond"] = NodeV2{HostRef: "h-app", IdentityRef: "id-ops", ProxyJump: "d1,d2", SudoMode: models.SudoModeAuto}
		v2.Nodes["app-ossh"] = NodeV2{HostRef: "h-app", IdentityRef: "id-ops", ProxyJump: "openssh:corp-gw", SudoMode: models.SudoModeAuto}
		v2.Nodes["bastion-ossh"] = NodeV2{HostRef: "h-mid", IdentityRef: "id-ops", ProxyJump: "openssh:corp-gw", SudoMode: models.SudoModeAuto}
		v2.Nodes["app-via-ossh-bastion"] = NodeV2{HostRef: "h-app", IdentityRef: "id-ops", ProxyJump: "bastion-ossh", SudoMode: models.SudoModeAuto}

		if err := ValidateV2(v2); err != nil {
			t.Fatalf("ValidateV2(valid DAG + saved openssh jump): %v", err)
		}
		if err := ValidateGraph(configurationFromV2Unchecked(v2)); err != nil {
			t.Fatalf("ValidateGraph(valid DAG + saved openssh jump): %v", err)
		}
	})
}

func TestP7W11c_DE11M2_TwoPassCanonicalizedOpenSSHProxyJumpCycles(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host web
    User ops

Host web.corp.example.com
    HostName 10.212.0.1
    ProxyJump ops@web.corp.example.com:22

Host web2
    User ops

Host web2.corp.example.com
    HostName 10.212.0.2
    ProxyJump hop-b

Host hop-b
    HostName 10.212.0.9
    User ops
    ProxyJump ops@web2.corp.example.com:22

Host web3
    User ops

Host web3.corp.example.com
    HostName 10.212.0.3
    ProxyJump hop-c

Host hop-c
    HostName 10.212.0.10
    User ops
    ProxyJump web3

Host web-ok
    User ops

Host web-ok.corp.example.com
    HostName 10.212.0.4
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	cycleTargets := []struct {
		name   string
		target ConnectionTarget
	}{
		{"1hop_canonicalized_qualified_self_loop", ConnectionTarget{Selector: "web.corp.example.com", OriginalHost: "web"}},
		{"1hop_canonicalized_prefixed_self_loop", ConnectionTarget{Selector: OpenSSHNodePrefix + "web.corp.example.com", OriginalHost: "web"}},
		{"2hop_canonicalized_fqdn_cycle", ConnectionTarget{Selector: "web2.corp.example.com", OriginalHost: "web2"}},
		{"2hop_canonicalized_original_alias_cycle", ConnectionTarget{Selector: "web3.corp.example.com", OriginalHost: "web3"}},
		{"1hop_canonicalized_tier1_fqdn_cycle", ConnectionTarget{Selector: "web-ok.corp.example.com", OriginalHost: "web-ok", ProxyJump: "ops@web-ok.corp.example.com:22", HasProxyJump: true}},
		{"1hop_canonicalized_tier1_short_alias_cycle", ConnectionTarget{Selector: "web-ok.corp.example.com", OriginalHost: "web-ok", ProxyJump: "web-ok", HasProxyJump: true}},
	}

	for _, tc := range cycleTargets {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			subStore := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
			subRepo, rErr := NewRepositoryWithOpenSSHParser(nil, subStore, parser)
			if rErr != nil {
				t.Fatalf("NewRepositoryWithOpenSSHParser: %v", rErr)
			}
			var cycleErr *ssh.ProxyCycleError
			if res, err := ResolveTarget(subRepo, tc.target); !errors.As(err, &cycleErr) {
				t.Errorf("ResolveTarget(%s) = (%+v, %v), want *ssh.ProxyCycleError", tc.name, res, err)
			}
			if res, err := subRepo.EnsureNodeContext(t.Context(), EnsureNodeOptions{Target: tc.target}); !errors.As(err, &cycleErr) {
				t.Errorf("EnsureNodeContext(%s) = (%+v, %v), want *ssh.ProxyCycleError", tc.name, res, err)
			}
			if err := subRepo.WithPendingNode(t.Context(), EnsureNodeOptions{Target: tc.target}, func(PendingLease) error { return nil }); !errors.As(err, &cycleErr) {
				t.Errorf("WithPendingNode(%s) = %v, want *ssh.ProxyCycleError", tc.name, err)
			}
		})
	}

	// Distinct user or distinct port on canonicalized target must remain valid.
	for _, valid := range []ConnectionTarget{
		{Selector: "web-ok.corp.example.com", OriginalHost: "web-ok", ProxyJump: "bob@web-ok.corp.example.com:22", HasProxyJump: true},
		{Selector: "web-ok.corp.example.com", OriginalHost: "web-ok", ProxyJump: "ops@web-ok.corp.example.com:2222", HasProxyJump: true},
	} {
		if res, err := ResolveTarget(repo, valid); err != nil {
			t.Errorf("ResolveTarget(%+v) unexpectedly failed: (%+v, %v)", valid, res, err)
		}
	}
}

func TestP7W11c_DE11M3_OpenSSHVirtualDefaultLocalUserDistinctJumpUserParity(t *testing.T) {
	t.Parallel()

	localUser, otherUser := w11cDistinctTestUser(t)

	const sshCfg = `
Host app.example.com
    HostName 10.213.0.1
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	withSSHProv := NewProviderWithOpenSSHParser(nil, parser)
	noSSHProv := NewProviderWithoutOpenSSH(nil)

	distinctJump := otherUser + "@app.example.com"
	for _, tc := range []struct {
		name   string
		prov   ConfigProvider
		target ConnectionTarget
	}{
		{"no_ssh_config", noSSHProv, ConnectionTarget{Selector: "app.example.com", ProxyJump: distinctJump, HasProxyJump: true}},
		{"with_ssh_config_virtual", withSSHProv, ConnectionTarget{Selector: "app.example.com", ProxyJump: distinctJump, HasProxyJump: true}},
		{"with_ssh_config_explicit_openssh", withSSHProv, ConnectionTarget{Selector: OpenSSHNodePrefix + "app.example.com", ProxyJump: distinctJump, HasProxyJump: true}},
	} {
		t.Run("distinct_user_"+tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := ResolveTarget(tc.prov, tc.target)
			if err != nil {
				t.Fatalf("ResolveTarget(%s) failed: %v", tc.name, err)
			}
			if res.User != localUser {
				t.Fatalf("ResolveTarget(%s).User = %q, want %q", tc.name, res.User, localUser)
			}
		})
	}

	// Same effective local user or bare self-jump must still fail closed with *ssh.ProxyCycleError.
	for _, sameJump := range []string{localUser + "@app.example.com", "app.example.com"} {
		var cycleErr *ssh.ProxyCycleError
		if res, err := ResolveTarget(withSSHProv, ConnectionTarget{
			Selector:     "app.example.com",
			ProxyJump:    sameJump,
			HasProxyJump: true,
		}); !errors.As(err, &cycleErr) {
			t.Errorf("ResolveTarget(app.example.com, ProxyJump=%q) = (%+v, %v), want *ssh.ProxyCycleError", sameJump, res, err)
		}
	}
}

func TestP7W11c_DE11L1_ValidateConcreteHostAddressRejectsCommaAndBareOpenSSH(t *testing.T) {
	t.Parallel()

	badHosts := []string{
		",",
		"10.0.0.1,10.0.0.2",
		"web-a,web-b",
		"openssh",
		"OPENSSH",
		"OpenSSH",
		" openssh ",
	}
	for _, bad := range badHosts {
		if err := ValidateConcreteHostAddress(bad); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ValidateConcreteHostAddress(%q) = %v, want ErrSSHOptionsValidation", bad, err)
		}
		v2 := &ConfigurationV2{
			SchemaVersion: 2,
			Credential:    CredentialConfig{Stores: map[string]StoreConfig{}},
			Hosts:         map[string]models.Host{"h-bad": {Address: bad, Port: 22}},
			Identities:    map[string]IdentityV2{"id-ops": {User: "ops", AuthType: "auto"}},
			Nodes:         map[string]NodeV2{"n1": {HostRef: "h-bad", IdentityRef: "id-ops", SudoMode: models.SudoModeAuto}},
		}
		if err := ValidateV2(v2); !errors.Is(err, ErrSchemaValidation) {
			t.Errorf("ValidateV2(host.Address=%q) = %v, want ErrSchemaValidation", bad, err)
		}
		if err := ValidateGraph(configurationFromV2Unchecked(v2)); !errors.Is(err, ErrSchemaValidation) {
			t.Errorf("ValidateGraph(host.Address=%q) = %v, want ErrSchemaValidation", bad, err)
		}
		diag := DiagnoseV2(v2)
		if !diag.HasErrors() {
			t.Errorf("DiagnoseV2(host.Address=%q) reported no errors", bad)
		}
		if res, err := ResolveTarget(NewProviderWithoutOpenSSH(nil), ConnectionTarget{Selector: bad}); err == nil {
			t.Errorf("ResolveTarget(%q) unexpectedly succeeded: %+v", bad, res)
		}
	}
}
