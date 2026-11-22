package adapter

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func w10cTestEnv() ssh.Environment {
	return ssh.Environment{
		HomeDir:   "/home/tester",
		LocalUser: "tester",
		LocalHost: "workstation.local",
		LocalUID:  "1000",
	}
}

func TestP7W10c_DE10M2_TransitiveMultiHopAndAdHocCyclesAcrossControlAndPolicy(t *testing.T) {
	t.Parallel()

	env := w10cTestEnv()
	muxSession, err := ParseSessionOptions([]string{"ControlMaster=auto", "ControlPath=/tmp/cm-w10c-%h-%p-%r-%j-%C"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions: %v", err)
	}

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-a", models.Host{Address: "10.110.0.1", Port: 22})
	cfg.Hosts.Set("h-b", models.Host{Address: "10.110.0.2", Port: 22})
	cfg.Hosts.Set("h-t1", models.Host{Address: "10.110.0.3", Port: 22})
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.110.0.10", Port: 22})
	cfg.Hosts.Set("h-shared", models.Host{Address: "10.110.0.20", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Identities.Set("id-alice", models.Identity{User: "alice", AuthType: "auto"})
	cfg.Identities.Set("id-bob", models.Identity{User: "bob", AuthType: "auto"})

	muxOpts := &ssh.Options{}
	muxOpts.SetControlMaster(ssh.ControlMasterAuto)
	muxOpts.SetControlPath("/tmp/cm-w10c-node-%h-%p-%r-%j-%C")

	cfg.Nodes.Set("node-a", models.Node{HostRef: "h-a", IdentityRef: "id-ops", ProxyJump: "node-b", SSHOptions: muxOpts.Clone()})
	cfg.Nodes.Set("node-b", models.Node{HostRef: "h-b", IdentityRef: "id-ops", ProxyJump: "node-a", SSHOptions: muxOpts.Clone()})
	cfg.Nodes.Set("t1-a", models.Node{HostRef: "h-t1", IdentityRef: "id-ops", SSHOptions: muxOpts.Clone()})
	cfg.Nodes.Set("t1-b", models.Node{HostRef: "h-b", IdentityRef: "id-ops", ProxyJump: "t1-a", SSHOptions: muxOpts.Clone()})
	cfg.Nodes.Set("bastion", models.Node{HostRef: "h-bastion", IdentityRef: "id-ops", SSHOptions: muxOpts.Clone()})
	cfg.Nodes.Set("alice-shared", models.Node{HostRef: "h-shared", IdentityRef: "id-alice", ProxyJump: "bob-shared", SSHOptions: muxOpts.Clone()})
	cfg.Nodes.Set("bob-shared", models.Node{HostRef: "h-shared", IdentityRef: "id-bob", SSHOptions: muxOpts.Clone()})

	const sshCfg = `
Host hop-a
    HostName 10.110.1.1
    User ops
    ProxyJump hop-b
    ControlMaster auto
    ControlPath /tmp/cm-w10c-ssh-%h-%p-%r-%j-%C

Host hop-b
    HostName 10.110.1.2
    User ops
    ProxyJump hop-a

Host loop-qual
    HostName 10.110.1.3
    User ops
    Port 22
    ProxyJump ops@loop-qual:22
    ControlMaster auto
    ControlPath /tmp/cm-w10c-ssh-%h-%p-%r-%j-%C

Host loop-bare
    HostName 10.110.1.4
    User ops
    Port 22
    ProxyJump loop-bare
    ControlMaster auto
    ControlPath /tmp/cm-w10c-ssh-%h-%p-%r-%j-%C
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)
	noSSHProv := config.NewProviderWithoutOpenSSH(cfg)

	cycleReqs := []struct {
		name string
		req  ControlTargetRequest
	}{
		{
			name: "saved_2hop_cycle",
			req:  ControlTargetRequest{Provider: prov, Target: config.ConnectionTarget{Selector: "node-a"}, SessionControl: muxSession, Environment: &env},
		},
		{
			name: "tier1_2hop_into_saved_cycle",
			req:  ControlTargetRequest{Provider: prov, Target: config.ConnectionTarget{Selector: "t1-a", ProxyJump: "t1-b", HasProxyJump: true}, SessionControl: muxSession, Environment: &env},
		},
		{
			name: "tier4_openssh_2hop_cycle",
			req:  ControlTargetRequest{Provider: prov, Target: config.ConnectionTarget{Selector: "hop-a"}, SessionControl: muxSession, Environment: &env},
		},
		{
			name: "duplicate_comma_hops",
			req:  ControlTargetRequest{Provider: prov, Target: config.ConnectionTarget{Selector: "t1-a", ProxyJump: "bastion,bastion", HasProxyJump: true}, SessionControl: muxSession, Environment: &env},
		},
		{
			name: "openssh_qualified_self_loop",
			req:  ControlTargetRequest{Provider: prov, Target: config.ConnectionTarget{Selector: "loop-qual"}, SessionControl: muxSession, Environment: &env},
		},
		{
			name: "openssh_deploy_at_loop_bare",
			req:  ControlTargetRequest{Provider: prov, Target: config.ConnectionTarget{Selector: "deploy@loop-bare"}, SessionControl: muxSession, Environment: &env},
		},
		{
			name: "adhoc_self_loop_under_no_ssh",
			req: ControlTargetRequest{
				Provider: noSSHProv,
				Target: config.ConnectionTarget{
					Selector:     "app.example.com",
					User:         "ops",
					HasUser:      true,
					ProxyJump:    "app.example.com",
					HasProxyJump: true,
				},
				SessionControl: muxSession,
				Environment:    &env,
			},
		},
	}

	for _, tc := range cycleReqs {
		t.Run("control_"+tc.name, func(t *testing.T) {
			t.Parallel()
			var cycleErr *ssh.ProxyCycleError
			if res, err := ResolveControlTarget(tc.req); !errors.As(err, &cycleErr) {
				t.Errorf("ResolveControlTarget(%s) = (%+v, %v), want *ssh.ProxyCycleError", tc.name, res, err)
			}
			if sock, res, err := ResolveControlSocketPath(tc.req); !errors.As(err, &cycleErr) {
				t.Errorf("ResolveControlSocketPath(%s) = (%q, %+v, %v), want *ssh.ProxyCycleError", tc.name, sock, res, err)
			}
		})
	}

	// Verify SSHAdapter.Resolve / GetConfig parity on the same cycle classes.
	policyCases := []struct {
		name   string
		adp    *SSHAdapter
		nodeID string
	}{
		{"saved_2hop_cycle", NewSSHAdapter(prov), "node-a"},
		{"tier1_2hop_cycle", NewSSHAdapter(prov, WithSessionAuthOverride("t1-a", SessionAuth{ProxyJump: "t1-b"})), "t1-a"},
		{"tier4_2hop_cycle", NewSSHAdapter(prov), config.OpenSSHNodePrefix + "hop-a"},
		{"duplicate_hops", NewSSHAdapter(prov, WithSessionAuthOverride("t1-a", SessionAuth{ProxyJump: "bastion,bastion"})), "t1-a"},
		{"openssh_qualified_loop", NewSSHAdapter(prov), config.OpenSSHNodePrefix + "loop-qual"},
		{"openssh_deploy_loop", NewSSHAdapter(prov), config.OpenSSHNodePrefix + "deploy@loop-bare"},
		{"adhoc_self_loop", NewSSHAdapter(noSSHProv, WithSessionAuthOverride("ops@app.example.com:22", SessionAuth{ProxyJump: "app.example.com"})), "ops@app.example.com:22"},
	}
	for _, tc := range policyCases {
		t.Run("policy_"+tc.name, func(t *testing.T) {
			t.Parallel()
			var cycleErr *ssh.ProxyCycleError
			if pol, err := tc.adp.Resolve(t.Context(), ResolveRequest{NodeID: tc.nodeID, ResolveProxy: true}); !errors.As(err, &cycleErr) {
				t.Errorf("Resolve(%s) = (%+v, %v), want *ssh.ProxyCycleError", tc.name, pol, err)
			}
		})
	}

	// Distinct-user jump on same host succeeds across control & policy.
	if sock, res, err := ResolveControlSocketPath(ControlTargetRequest{
		Provider:       prov,
		Target:         config.ConnectionTarget{Selector: "alice-shared"},
		SessionControl: muxSession,
		Environment:    &env,
	}); err != nil || sock == "" || res.Target.JumpHost != "bob-shared" {
		t.Fatalf("ResolveControlSocketPath(alice-shared -> bob-shared) = (%q, %+v, %v), want valid socket", sock, res, err)
	}
	if sock, res, err := ResolveControlSocketPath(ControlTargetRequest{
		Provider: noSSHProv,
		Target: config.ConnectionTarget{
			Selector:     "app.example.com",
			User:         "alice",
			HasUser:      true,
			ProxyJump:    "bob@app.example.com",
			HasProxyJump: true,
		},
		SessionControl: muxSession,
		Environment:    &env,
	}); err != nil || sock == "" || res.Target.JumpHost != "openssh:bob@app.example.com" {
		t.Fatalf("ResolveControlSocketPath(distinct-user ad-hoc) = (%q, %+v, %v), want valid socket", sock, res, err)
	}
}

func TestP7W10c_DE10M3_ControlConfigEmptyLookupAmbiguousSelectorAndPaddedOpenSSH(t *testing.T) {
	t.Parallel()

	env := w10cTestEnv()
	muxSession, err := ParseSessionOptions([]string{"ControlMaster=auto", "ControlPath=/tmp/cm-m3-%h-%p-%r-%j-%C"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions: %v", err)
	}

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-web", models.Host{Address: "10.111.0.1", Port: 2222})
	cfg.Hosts.Set("h-a1", models.Host{Address: "10.111.0.11", Port: 22, Alias: []string{"ambig-web"}})
	cfg.Hosts.Set("h-a2", models.Host{Address: "10.111.0.12", Port: 22, Alias: []string{"ambig-web"}})
	cfg.Hosts.Set("h-c1", models.Host{Address: "10.111.0.21", Port: 22})
	cfg.Hosts.Set("h-c2", models.Host{Address: "10.111.0.22", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})

	savedMux := &ssh.Options{}
	savedMux.SetControlMaster(ssh.ControlMasterAuto)
	savedMux.SetControlPath("/tmp/cm-saved-web-%h-%p-%r")

	cfg.Nodes.Set("saved-web", models.Node{HostRef: "h-web", IdentityRef: "id-ops", SSHOptions: savedMux})
	cfg.Nodes.Set("ambig-1", models.Node{HostRef: "h-a1", IdentityRef: "id-ops"})
	cfg.Nodes.Set("ambig-2", models.Node{HostRef: "h-a2", IdentityRef: "id-ops"})
	cfg.Nodes.Set("cyc-a", models.Node{HostRef: "h-c1", IdentityRef: "id-ops", ProxyJump: "cyc-b"})
	cfg.Nodes.Set("cyc-b", models.Node{HostRef: "h-c2", IdentityRef: "id-ops", ProxyJump: "cyc-a"})

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader("Host web\n  HostName 10.111.1.1\n  User ops\n  ControlMaster auto\n  ControlPath /tmp/cm-ossh-%h\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	t.Run("ResolveControlConfig_validates_session_ProxyJump_even_with_empty_lookupKey", func(t *testing.T) {
		t.Parallel()
		if ctrl, err := ResolveControlConfig(prov, "", "", SessionAuth{ProxyJump: "unknown-single-label"}, muxSession); err == nil {
			t.Errorf("ResolveControlConfig(empty lookupKey, unknown jump) = %+v, want error", ctrl)
		}
		var ambigErr *config.AmbiguousNodeError
		if ctrl, err := ResolveControlConfig(prov, "", "", SessionAuth{ProxyJump: "ambig-web"}, muxSession); !errors.As(err, &ambigErr) {
			t.Errorf("ResolveControlConfig(empty lookupKey, ambiguous jump) = (%+v, %v), want *AmbiguousNodeError", ctrl, err)
		}
		var cycleErr *ssh.ProxyCycleError
		if ctrl, err := ResolveControlConfig(prov, "", "", SessionAuth{ProxyJump: "saved-web,saved-web"}, muxSession); !errors.As(err, &cycleErr) {
			t.Errorf("ResolveControlConfig(empty lookupKey, duplicate hop) = (%+v, %v), want *ssh.ProxyCycleError", ctrl, err)
		}
		if ctrl, err := ResolveControlConfig(prov, "", "", SessionAuth{ProxyJump: "cyc-a"}, muxSession); !errors.As(err, &cycleErr) {
			t.Errorf("ResolveControlConfig(empty lookupKey, 2-hop cycle) = (%+v, %v), want *ssh.ProxyCycleError", ctrl, err)
		}
	})

	t.Run("ResolveControlConfig_empty_lookupKey_with_selector_resolves_saved_address_and_rejects_ambiguity", func(t *testing.T) {
		t.Parallel()
		var ambigErr *config.AmbiguousNodeError
		if ctrl, err := ResolveControlConfig(prov, "", "ambig-web", SessionAuth{}, muxSession); !errors.As(err, &ambigErr) {
			t.Errorf("ResolveControlConfig(selector=ambig-web) = (%+v, %v), want *AmbiguousNodeError", ctrl, err)
		}
		var cycleErr *ssh.ProxyCycleError
		if ctrl, err := ResolveControlConfig(prov, "", "cyc-a", SessionAuth{}, muxSession); !errors.As(err, &cycleErr) {
			t.Errorf("ResolveControlConfig(selector=cyc-a) = (%+v, %v), want *ssh.ProxyCycleError", ctrl, err)
		}
		ctrl, err := ResolveControlConfig(prov, "", "10.111.0.1", SessionAuth{}, SessionControlOptions{})
		if err != nil || ctrl == nil || ctrl.Path != "/tmp/cm-saved-web-%h-%p-%r" {
			t.Fatalf("ResolveControlConfig(selector=10.111.0.1) = (%+v, %v), want saved-web ControlPath", ctrl, err)
		}
	})

	t.Run("SSHAdapter_Resolve_and_ControlTargetRequest_reject_padded_and_control_openssh_selectors", func(t *testing.T) {
		t.Parallel()
		adp := NewSSHAdapter(prov)
		badSelectors := []string{
			" openssh:web",
			"openssh:web ",
			"\u00a0openssh:web",
			"\x00openssh:web",
			"openssh:web\n",
			"openssh:web\u2028",
			" OPENSSH:web",
			"openssh:openssh:web",
		}
		for _, bad := range badSelectors {
			if pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: bad}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("SSHAdapter.Resolve(NodeID=%q) = (%+v, %v), want ErrSSHOptionsValidation", bad, pol, err)
			}
			for _, req := range []ControlTargetRequest{
				{Provider: prov, FallbackHost: bad, Environment: &env},
				{Provider: prov, Target: config.ConnectionTarget{Selector: "saved-web"}, OverrideExpandedHost: bad, ApplyTargetNodeOverrides: true, Environment: &env},
				{Provider: prov, Target: config.ConnectionTarget{Selector: "saved-web", RawSelector: bad}, Environment: &env},
			} {
				if res, err := ResolveControlTarget(req); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
					t.Errorf("ResolveControlTarget(%+v) = (%+v, %v), want ErrSSHOptionsValidation", req, res, err)
				}
				if sock, res, err := ResolveControlSocketPath(req); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
					t.Errorf("ResolveControlSocketPath(%+v) = (%q, %+v, %v), want ErrSSHOptionsValidation", req, sock, res, err)
				}
			}
		}
	})
}

func TestP7W10c_DE10L1_SavedNodeCanonicalOriginGuardAndHostAddressCaseFold(t *testing.T) {
	t.Parallel()

	env := w10cTestEnv()
	readOnlyProv, _ := buildP3EquivalenceFixtures(t, nil)

	cfg := readOnlyProv.Snapshot()
	if h, ok := cfg.Hosts.Get("h-web1"); ok {
		h.Alias = []string{"ProdHostAlias"}
		cfg.Hosts.Set("h-web1", h)
	}
	prov := config.NewProviderWithOpenSSHParser(cfg, readOnlyProv.GetOpenSSHParser())

	savedSelectors := []struct {
		name     string
		selector string
		wantHost string
		wantKey  string
	}{
		{"saved_node_id", "web-01", "10.10.0.1", "web-01"},
		{"saved_node_spaced_alias", "Prod Web 01", "10.10.0.1", "web-01"},
		{"saved_host_address_ipv4", "10.10.0.1", "10.10.0.1", "web-01"},
		{"saved_host_address_ipv6_noncanonical", "2001:0DB8::1", "2001:db8::1", "v6-saved"},
		{"saved_host_alias_case_folded_lower", "prodhostalias", "10.10.0.1", "web-01"},
		{"saved_host_alias_case_folded_upper", "PRODHOSTALIAS", "10.10.0.1", "web-01"},
	}

	for _, tc := range savedSelectors {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := ControlTargetRequest{
				Provider:              prov,
				Target:                config.ConnectionTarget{Selector: tc.selector},
				CanonicalOriginalHost: "short",
				CanonicalHost:         "short.corp.example.com",
				Environment:           &env,
			}
			res, err := ResolveControlTarget(req)
			if err != nil {
				t.Fatalf("ResolveControlTarget(%q): %v", tc.selector, err)
			}
			if res.Target.Host != tc.wantHost || res.LookupKey != tc.wantKey {
				t.Fatalf("ResolveControlTarget(%q) = (host=%q key=%q), want (%q, %q)",
					tc.selector, res.Target.Host, res.LookupKey, tc.wantHost, tc.wantKey)
			}
			if res.SessionAuth.CanonicalHost != "" || res.SessionAuth.OriginalHost == "short" {
				t.Fatalf("ResolveControlTarget(%q) leaked unrelated canonical origin into SessionAuth: %+v",
					tc.selector, res.SessionAuth)
			}
			lk, auth := ResolveControlSessionLookup(req, res.Target)
			if lk != tc.wantKey || auth.CanonicalHost != "" || auth.OriginalHost == "short" {
				t.Fatalf("ResolveControlSessionLookup(%q) = (key=%q auth=%+v), leaked unrelated canonical origin",
					tc.selector, lk, auth)
			}
		})
	}
}
