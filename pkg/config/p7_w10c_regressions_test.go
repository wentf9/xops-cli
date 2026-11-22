package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W10c_DE10M1_SavedAndSiblingTier2ProxyJumpFailClosed(t *testing.T) {
	t.Parallel()

	makeBaseCfg := func() *Configuration {
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("h-web", models.Host{Address: "10.101.0.1", Port: 22})
		cfg.Hosts.Set("h-open", models.Host{Address: "10.101.0.10", Port: 2222})
		cfg.Hosts.Set("h-j1", models.Host{Address: "10.101.0.21", Port: 22, Alias: []string{"dup-jump"}})
		cfg.Hosts.Set("h-j2", models.Host{Address: "10.101.0.22", Port: 22, Alias: []string{"dup-jump"}})
		cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("jump-1", models.Node{HostRef: "h-j1", IdentityRef: "id-ops"})
		cfg.Nodes.Set("jump-2", models.Node{HostRef: "h-j2", IdentityRef: "id-ops"})
		return cfg
	}

	t.Run("saved_node_tier2_ambiguous_unknown_and_broken_openssh_jump_fail_closed", func(t *testing.T) {
		t.Parallel()

		// 1. Ambiguous saved jump alias.
		cfgAmbig := makeBaseCfg()
		cfgAmbig.Nodes.Set("saved-ambig", models.Node{HostRef: "h-web", IdentityRef: "id-ops", ProxyJump: "dup-jump"})
		var ambigErr *AmbiguousNodeError
		if res, err := ResolveTarget(NewProviderWithoutOpenSSH(cfgAmbig), ConnectionTarget{Selector: "saved-ambig"}); !errors.As(err, &ambigErr) {
			t.Fatalf("ResolveTarget(saved-ambig, ProxyJump=dup-jump) = (%+v, %v), want *AmbiguousNodeError", res, err)
		}

		// 2. Unknown single-label jump.
		cfgUnknown := makeBaseCfg()
		cfgUnknown.Nodes.Set("saved-unknown", models.Node{HostRef: "h-web", IdentityRef: "id-ops", ProxyJump: "unknown-single-label"})
		if res, err := ResolveTarget(NewProviderWithoutOpenSSH(cfgUnknown), ConnectionTarget{Selector: "saved-unknown"}); err == nil {
			t.Fatalf("ResolveTarget(saved-unknown, ProxyJump=unknown-single-label) = %+v, want fail-closed error", res)
		}

		// 3. Broken OpenSSHParser on saved node with ProxyJump: openssh:bastion.
		cfgBroken := makeBaseCfg()
		cfgBroken.Nodes.Set("saved-ossh", models.Node{HostRef: "h-web", IdentityRef: "id-ops", ProxyJump: "openssh:bastion"})
		brokenProv := NewProviderWithOpenSSHParser(cfgBroken, NewBrokenOpenSSHParser(errors.New("broken ssh_config")))
		if res, err := ResolveTarget(brokenProv, ConnectionTarget{Selector: "saved-ossh"}); err == nil || !strings.Contains(err.Error(), "broken ssh_config") {
			t.Fatalf("ResolveTarget(saved-ossh, broken parser) = (%+v, %v), want broken ssh_config error", res, err)
		}
	})

	t.Run("sibling_inherited_tier2_ambiguous_unknown_and_broken_openssh_jump_fail_closed", func(t *testing.T) {
		t.Parallel()

		parser, err := NewOpenSSHParserFromReader(strings.NewReader("Host saved-open\n  HostName 10.101.0.10\n  Port 2222\n  User ops\n"))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		derivedTarget := ConnectionTarget{Selector: "saved-open", User: "deploy", HasUser: true, Port: 2222, HasPort: true}

		// 1. Sibling has ambiguous ProxyJump.
		cfgAmbig := makeBaseCfg()
		cfgAmbig.Nodes.Set("ops@10.101.0.10:2222", models.Node{HostRef: "h-open", IdentityRef: "id-ops", ProxyJump: "dup-jump"})
		var ambigErr *AmbiguousNodeError
		if res, err := ResolveTarget(NewProviderWithOpenSSHParser(cfgAmbig, parser), derivedTarget); !errors.As(err, &ambigErr) {
			t.Fatalf("ResolveTarget(sibling dup-jump) = (%+v, %v), want *AmbiguousNodeError", res, err)
		}

		// 2. Sibling has unknown single-label ProxyJump.
		cfgUnknown := makeBaseCfg()
		cfgUnknown.Nodes.Set("ops@10.101.0.10:2222", models.Node{HostRef: "h-open", IdentityRef: "id-ops", ProxyJump: "unknown-single-label"})
		if res, err := ResolveTarget(NewProviderWithOpenSSHParser(cfgUnknown, parser), derivedTarget); err == nil {
			t.Fatalf("ResolveTarget(sibling unknown-single-label) = %+v, want fail-closed error", res)
		}

		// 3. Sibling has openssh:bastion jump with broken OpenSSHParser (target by saved IP).
		cfgBroken := makeBaseCfg()
		cfgBroken.Nodes.Set("ops@10.101.0.10:2222", models.Node{HostRef: "h-open", IdentityRef: "id-ops", ProxyJump: "openssh:bastion"})
		brokenProv := NewProviderWithOpenSSHParser(cfgBroken, NewBrokenOpenSSHParser(errors.New("broken sibling ssh_config")))
		if res, err := ResolveTarget(brokenProv, ConnectionTarget{
			Selector: "10.101.0.10",
			User:     "deploy",
			HasUser:  true,
			Port:     2222,
			HasPort:  true,
		}); err == nil || !strings.Contains(err.Error(), "broken sibling ssh_config") {
			t.Fatalf("ResolveTarget(sibling openssh:bastion, broken parser) = (%+v, %v), want broken sibling ssh_config error", res, err)
		}
	})

	t.Run("virtual_openssh_transitive_invalid_hop_stanza_fails_closed", func(t *testing.T) {
		t.Parallel()
		const sshCfg = `
Host app
    HostName 10.101.1.1
    User ops
    ProxyJump bad-bastion

Host bad-bastion
    HostName 10.101.1.2
    Port 99999
`
		parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		prov := NewProviderWithOpenSSHParser(nil, parser)
		if res, err := ResolveTarget(prov, ConnectionTarget{Selector: "app"}); err == nil {
			t.Fatalf("ResolveTarget(app -> bad-bastion Port 99999) = %+v, want fail-closed error", res)
		}
	})
}

func TestP7W10c_DE10M2_TransitiveMultiHopAndEndpointAliasProxyJumpCycles(t *testing.T) {
	t.Parallel()

	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("h-a", models.Host{Address: "10.102.0.1", Port: 22})
	cfg.Hosts.Set("h-b", models.Host{Address: "10.102.0.2", Port: 22})
	cfg.Hosts.Set("h-c", models.Host{Address: "10.102.0.3", Port: 22})
	cfg.Hosts.Set("h-t1", models.Host{Address: "10.102.0.4", Port: 22})
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.102.0.10", Port: 22})
	cfg.Hosts.Set("h-root", models.Host{Address: "10.102.0.20", Port: 22})
	cfg.Hosts.Set("h-d1", models.Host{Address: "10.102.0.21", Port: 22})
	cfg.Hosts.Set("h-d2", models.Host{Address: "10.102.0.22", Port: 22})
	cfg.Hosts.Set("h-shared", models.Host{Address: "10.102.0.30", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Identities.Set("id-alice", models.Identity{User: "alice", AuthType: "auto"})
	cfg.Identities.Set("id-bob", models.Identity{User: "bob", AuthType: "auto"})

	cfg.Nodes.Set("node-a", models.Node{HostRef: "h-a", IdentityRef: "id-ops", ProxyJump: "node-b"})
	cfg.Nodes.Set("node-b", models.Node{HostRef: "h-b", IdentityRef: "id-ops", ProxyJump: "node-a"})
	cfg.Nodes.Set("node-c", models.Node{HostRef: "h-c", IdentityRef: "id-ops", ProxyJump: "node-a"})
	cfg.Nodes.Set("t1-a", models.Node{HostRef: "h-t1", IdentityRef: "id-ops"})
	cfg.Nodes.Set("t1-b", models.Node{HostRef: "h-b", IdentityRef: "id-ops", ProxyJump: "t1-a"})
	cfg.Nodes.Set("ops@10.102.0.10:22", models.Node{HostRef: "h-bastion", IdentityRef: "id-ops", Alias: []string{"bastion"}})
	cfg.Nodes.Set("root-bastion", models.Node{HostRef: "h-root", IdentityRef: "id-ops"})
	cfg.Nodes.Set("diamond-1", models.Node{HostRef: "h-d1", IdentityRef: "id-ops", ProxyJump: "root-bastion"})
	cfg.Nodes.Set("diamond-2", models.Node{HostRef: "h-d2", IdentityRef: "id-ops", ProxyJump: "root-bastion"})
	cfg.Nodes.Set("chain-outer", models.Node{HostRef: "h-d1", IdentityRef: "id-ops", ProxyJump: "chain-inner"})
	cfg.Nodes.Set("chain-inner", models.Node{HostRef: "h-d2", IdentityRef: "id-ops"})
	cfg.Nodes.Set("alice-shared", models.Node{HostRef: "h-shared", IdentityRef: "id-alice", ProxyJump: "bob-shared"})
	cfg.Nodes.Set("bob-shared", models.Node{HostRef: "h-shared", IdentityRef: "id-bob"})

	const sshCfg = `
Host hop-a
    HostName 10.102.1.1
    User ops
    ProxyJump hop-b

Host hop-b
    HostName 10.102.1.2
    User ops
    ProxyJump hop-a

Host loop-qual
    HostName 10.102.1.3
    User ops
    Port 22
    ProxyJump ops@loop-qual:22

Host loop-bare
    HostName 10.102.1.4
    User ops
    Port 22
    ProxyJump loop-bare
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := NewProviderWithOpenSSHParser(cfg, parser)
	noSSHProv := NewProviderWithoutOpenSSH(cfg)

	cycleCases := []struct {
		name   string
		prov   ConfigProvider
		target ConnectionTarget
	}{
		{"saved_2hop_a_b", prov, ConnectionTarget{Selector: "node-a"}},
		{"saved_3hop_c_a_b", prov, ConnectionTarget{Selector: "node-c"}},
		{"tier1_2hop_into_saved_cycle", prov, ConnectionTarget{Selector: "t1-a", ProxyJump: "t1-b", HasProxyJump: true}},
		{"tier4_openssh_2hop_a_b", prov, ConnectionTarget{Selector: "hop-a"}},
		{"tier4_openssh_2hop_prefixed", prov, ConnectionTarget{Selector: OpenSSHNodePrefix + "hop-a"}},
		{"duplicate_comma_hops_same_alias", prov, ConnectionTarget{Selector: "t1-a", ProxyJump: "bastion,bastion", HasProxyJump: true}},
		{"duplicate_comma_hops_alias_and_id", prov, ConnectionTarget{Selector: "t1-a", ProxyJump: "bastion,ops@10.102.0.10:22", HasProxyJump: true}},
		{"duplicate_comma_hops_openssh_case", prov, ConnectionTarget{Selector: "t1-a", ProxyJump: "openssh:10.102.9.1,OPENSSH:10.102.9.1", HasProxyJump: true}},
		{"chain_flattening_outer_jumps_to_inner", prov, ConnectionTarget{Selector: "t1-a", ProxyJump: "chain-outer,chain-inner", HasProxyJump: true}},
		{"openssh_user_port_qualified_self_loop", prov, ConnectionTarget{Selector: "loop-qual"}},
		{"openssh_user_port_qualified_self_loop_prefixed", prov, ConnectionTarget{Selector: OpenSSHNodePrefix + "loop-qual"}},
		{"openssh_deploy_at_loop_bare_self_loop", prov, ConnectionTarget{Selector: "deploy@loop-bare"}},
		{"openssh_prefixed_deploy_at_loop_bare_self_loop", prov, ConnectionTarget{Selector: OpenSSHNodePrefix + "deploy@loop-bare"}},
		{"adhoc_created_self_loop_no_ssh_config", noSSHProv, ConnectionTarget{
			Selector:     "app.example.com",
			User:         "ops",
			HasUser:      true,
			ProxyJump:    "app.example.com",
			HasProxyJump: true,
		}},
		{"adhoc_created_qualified_self_loop_no_ssh_config", noSSHProv, ConnectionTarget{
			Selector:     "app.example.com",
			User:         "ops",
			HasUser:      true,
			ProxyJump:    "ops@app.example.com:22",
			HasProxyJump: true,
		}},
	}

	for _, tc := range cycleCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var cycleErr *ssh.ProxyCycleError
			if res, err := ResolveTarget(tc.prov, tc.target); !errors.As(err, &cycleErr) {
				t.Fatalf("ResolveTarget(%+v) = (%+v, %v), want *ssh.ProxyCycleError", tc.target, res, err)
			}
		})
	}

	validCases := []struct {
		name   string
		prov   ConfigProvider
		target ConnectionTarget
	}{
		{"distinct_user_saved_same_host", prov, ConnectionTarget{Selector: "alice-shared"}},
		{"distinct_user_adhoc_same_host", noSSHProv, ConnectionTarget{
			Selector:     "app.example.com",
			User:         "alice",
			HasUser:      true,
			ProxyJump:    "bob@app.example.com",
			HasProxyJump: true,
		}},
		{"distinct_port_adhoc_same_host", noSSHProv, ConnectionTarget{
			Selector:     "app.example.com",
			User:         "ops",
			HasUser:      true,
			Port:         22,
			HasPort:      true,
			ProxyJump:    "ops@app.example.com:2222",
			HasProxyJump: true,
		}},
		{"diamond_dag_not_a_cycle", prov, ConnectionTarget{
			Selector:     "t1-a",
			ProxyJump:    "diamond-1,diamond-2",
			HasProxyJump: true,
		}},
	}

	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if res, err := ResolveTarget(tc.prov, tc.target); err != nil {
				t.Fatalf("ResolveTarget(%+v) unexpectedly failed: (%+v, %v)", tc.target, res, err)
			}
		})
	}
}

func TestP7W10c_DE10L2_MalformedPlainTargetSelectorsAndConcreteHostAddress(t *testing.T) {
	t.Parallel()

	badHosts := []string{
		"host:99999",
		"[::1",
		"host:0",
		"@host",
		"user@",
		"user@host",
		"host:22",
		"foo:bar:baz",
		"bad host",
		"bad\nhost",
		"host\n",
	}
	for _, bad := range badHosts {
		if err := ValidateConcreteHostAddress(bad); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ValidateConcreteHostAddress(%q) = %v, want ErrSSHOptionsValidation", bad, err)
		}
	}

	for _, good := range []string{"10.0.0.1", "web.example.com", "2001:db8::1", "[2001:db8::1]", "[fe80::1%eth0]", "fe80::1%eth0"} {
		if err := ValidateConcreteHostAddress(good); err != nil {
			t.Errorf("ValidateConcreteHostAddress(%q) failed: %v", good, err)
		}
	}

	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("h-web", models.Host{Address: "10.103.0.1", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("web-01", models.Node{HostRef: "h-web", IdentityRef: "id-ops", Alias: []string{"Prod Web 01"}})
	prov := NewProviderWithoutOpenSSH(cfg)

	malformedSelectors := []string{
		"host:99999",
		"[::1",
		"host:0",
		"@host",
		"user@",
		"bad host",
		"bad\nhost",
		"host\n",
	}
	for _, bad := range malformedSelectors {
		if res, err := ResolveTarget(prov, ConnectionTarget{Selector: bad}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ResolveTarget(bare %q) = (%+v, %v), want ErrSSHOptionsValidation", bad, res, err)
		}
		if res, err := ResolveTarget(prov, ConnectionTarget{Selector: bad, User: "ops", HasUser: true}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ResolveTarget(explicit %q) = (%+v, %v), want ErrSSHOptionsValidation", bad, res, err)
		}
	}

	// Saved spaced alias must remain selectable.
	if res, err := ResolveTarget(prov, ConnectionTarget{Selector: "Prod Web 01"}); err != nil || res.MatchedNodeID != "web-01" {
		t.Fatalf("ResolveTarget(Prod Web 01) = (%+v, %v), want MatchedNodeID=web-01", res, err)
	}
}
