package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W9c_DE9M1_ResolveTargetAndJumpChainFailClosedAndSelfLoop(t *testing.T) {
	t.Parallel()

	t.Run("hop_syntax_errors_wrap_ErrSSHOptionsValidation_and_fail_closed", func(t *testing.T) {
		t.Parallel()
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("h-web", models.Host{Address: "10.91.0.1", Port: 22})
		cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("saved-web", models.Node{HostRef: "h-web", IdentityRef: "id-ops"})

		parser, err := NewOpenSSHParserFromReader(strings.NewReader("Host ssh-web\n  HostName 10.91.0.2\n  User ops\n"))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		prov := NewProviderWithOpenSSHParser(cfg, parser)

		badHops := []string{
			"openssh:openssh:22",
			"openssh:OPENSSH:22",
			"openssh: web",
			"[::1",
			"host:99999",
			"host:0",
			"@host",
			"user@",
			"host:",
		}
		for _, bad := range badHops {
			if got, err := ResolveProxyJumpChainWithConfig(cfg, parser, bad); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveProxyJumpChainWithConfig(%q) = (%q, %v), want ErrSSHOptionsValidation", bad, got, err)
			}
			// Matched saved node with Tier-1 jump override.
			if res, err := ResolveTarget(prov, ConnectionTarget{
				Selector:     "saved-web",
				ProxyJump:    bad,
				HasProxyJump: true,
			}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveTarget(saved-web, -J %q) = (%+v, %v), want ErrSSHOptionsValidation", bad, res, err)
			}
			// Matched OpenSSH virtual node with Tier-1 jump override.
			if res, err := ResolveTarget(prov, ConnectionTarget{
				Selector:     OpenSSHNodePrefix + "ssh-web",
				ProxyJump:    bad,
				HasProxyJump: true,
			}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveTarget(openssh:ssh-web, -J %q) = (%+v, %v), want ErrSSHOptionsValidation", bad, res, err)
			}
			// Created/ad-hoc node with Tier-1 jump override.
			if res, err := ResolveTarget(prov, ConnectionTarget{
				Selector:     "10.91.0.99",
				User:         "deploy",
				HasUser:      true,
				ProxyJump:    bad,
				HasProxyJump: true,
			}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveTarget(created 10.91.0.99, -J %q) = (%+v, %v), want ErrSSHOptionsValidation", bad, res, err)
			}
			// Saved node baseJump carrying malformed hop syntax.
			badCfg := cloneConfiguration(cfg)
			badCfg.Nodes.Set("bad-saved", models.Node{HostRef: "h-web", IdentityRef: "id-ops", ProxyJump: bad})
			badProv := NewProviderWithoutOpenSSH(badCfg)
			if res, err := ResolveTarget(badProv, ConnectionTarget{Selector: "bad-saved"}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveTarget(bad-saved, baseJump=%q) = (%+v, %v), want ErrSSHOptionsValidation", bad, res, err)
			}
			// Direct normalizeTargetJump without provider also validates hop syntax.
			if got, err := normalizeTargetJump(nil, "", ConnectionTarget{ProxyJump: bad, HasProxyJump: true}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("normalizeTargetJump(nil, -J %q) = (%q, %v), want ErrSSHOptionsValidation", bad, got, err)
			}
		}
	})

	t.Run("unknown_single_label_and_ambiguous_jump_fail_closed", func(t *testing.T) {
		t.Parallel()
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("h-web", models.Host{Address: "10.91.1.1", Port: 22})
		cfg.Hosts.Set("h-j1", models.Host{Address: "10.91.1.10", Port: 22, Alias: []string{"dup-jump"}})
		cfg.Hosts.Set("h-j2", models.Host{Address: "10.91.1.11", Port: 22, Alias: []string{"dup-jump"}})
		cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("saved-web", models.Node{HostRef: "h-web", IdentityRef: "id-ops"})
		cfg.Nodes.Set("jump-1", models.Node{HostRef: "h-j1", IdentityRef: "id-ops"})
		cfg.Nodes.Set("jump-2", models.Node{HostRef: "h-j2", IdentityRef: "id-ops"})

		parser, err := NewOpenSSHParserFromReader(strings.NewReader(
			"Host ssh-web\n  HostName 10.91.1.2\n  User ops\nHost ssh-bad-jump\n  HostName 10.91.1.3\n  User ops\n  ProxyJump unconfigured-hop\n",
		))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		prov := NewProviderWithOpenSSHParser(cfg, parser)

		// Unknown single-label jump must fail closed across matched saved, virtual, and created targets.
		for _, tgt := range []ConnectionTarget{
			{Selector: "saved-web", ProxyJump: "unknown-single-label", HasProxyJump: true},
			{Selector: OpenSSHNodePrefix + "ssh-web", ProxyJump: "unknown-single-label", HasProxyJump: true},
			{Selector: "10.91.1.99", User: "ops", HasUser: true, ProxyJump: "unknown-single-label", HasProxyJump: true},
		} {
			if res, err := ResolveTarget(prov, tgt); err == nil {
				t.Errorf("ResolveTarget(%+v) unexpectedly succeeded (%+v), want unknown-jump error", tgt, res)
			}
		}

		// Derived OpenSSH node inheriting unconfigured single-label ProxyJump fails closed in resolveCreatedTargetJump.
		if res, err := ResolveTarget(prov, ConnectionTarget{
			Selector: "ssh-bad-jump",
			User:     "deploy",
			HasUser:  true,
		}); err == nil {
			t.Errorf("ResolveTarget(deploy@ssh-bad-jump) unexpectedly succeeded (%+v), want fail-closed error", res)
		}

		// Ambiguous jump host propagates *AmbiguousNodeError across matched and created targets.
		for _, tgt := range []ConnectionTarget{
			{Selector: "saved-web", ProxyJump: "dup-jump", HasProxyJump: true},
			{Selector: "10.91.1.99", User: "ops", HasUser: true, ProxyJump: "dup-jump", HasProxyJump: true},
		} {
			var ambig *AmbiguousNodeError
			if res, err := ResolveTarget(prov, tgt); !errors.As(err, &ambig) {
				t.Errorf("ResolveTarget(%+v) = (%+v, %v), want *AmbiguousNodeError", tgt, res, err)
			}
		}
	})

	t.Run("self_referential_proxyjump_returns_ProxyCycleError_across_tiers", func(t *testing.T) {
		t.Parallel()
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("h-self", models.Host{Address: "10.91.2.1", Port: 22})
		cfg.Hosts.Set("h-t1", models.Host{Address: "10.91.2.2", Port: 22})
		cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("ops@10.91.2.1:22", models.Node{
			HostRef:     "h-self",
			IdentityRef: "id-ops",
			Alias:       []string{"self-t2"},
			ProxyJump:   "self-t2",
		})
		cfg.Nodes.Set("ops@10.91.2.2:22", models.Node{
			HostRef:     "h-t1",
			IdentityRef: "id-ops",
			Alias:       []string{"self-t1"},
		})

		parser, err := NewOpenSSHParserFromReader(strings.NewReader(
			"Host loop\n  HostName 10.91.2.3\n  User ops\n  ProxyJump loop\nHost plain-ssh\n  HostName 10.91.2.4\n  User ops\n",
		))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		prov := NewProviderWithOpenSSHParser(cfg, parser)

		cycleCases := []struct {
			name   string
			target ConnectionTarget
		}{
			{
				name:   "tier2_saved_node_self_alias",
				target: ConnectionTarget{Selector: "self-t2"},
			},
			{
				name:   "tier2_saved_node_by_id",
				target: ConnectionTarget{Selector: "ops@10.91.2.1:22"},
			},
			{
				name:   "tier1_override_saved_self_alias",
				target: ConnectionTarget{Selector: "self-t1", ProxyJump: "self-t1", HasProxyJump: true},
			},
			{
				name:   "tier1_override_saved_by_id",
				target: ConnectionTarget{Selector: "ops@10.91.2.2:22", ProxyJump: "ops@10.91.2.2:22", HasProxyJump: true},
			},
			{
				name:   "tier4_openssh_loop_bare",
				target: ConnectionTarget{Selector: "loop"},
			},
			{
				name:   "tier4_openssh_loop_prefixed",
				target: ConnectionTarget{Selector: OpenSSHNodePrefix + "loop"},
			},
			{
				name:   "tier4_openssh_loop_upper_prefixed",
				target: ConnectionTarget{Selector: "OPENSSH:loop"},
			},
			{
				name:   "tier1_override_openssh_self_loop",
				target: ConnectionTarget{Selector: OpenSSHNodePrefix + "plain-ssh", ProxyJump: "plain-ssh", HasProxyJump: true},
			},
		}

		for _, tc := range cycleCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				var cycleErr *ssh.ProxyCycleError
				if res, err := ResolveTarget(prov, tc.target); !errors.As(err, &cycleErr) {
					t.Fatalf("ResolveTarget(%+v) = (%+v, %v), want *ssh.ProxyCycleError", tc.target, res, err)
				}
			})
		}
	})
}

func TestP7W9c_DE9L1_OpenSSHConfigProxyJumpRejectsOpenSSHPrefixAndWhitespace(t *testing.T) {
	t.Parallel()

	badJumps := []struct {
		name string
		raw  string
	}{
		{"lowercase_openssh_prefix", "openssh:bastion"},
		{"uppercase_openssh_prefix", "OPENSSH:bastion"},
		{"mixed_openssh_prefix_in_chain", "bastion,openssh:hop2"},
		{"space_separated_tokens", "jump1 jump2"},
		{"quoted_interior_whitespace", `"jump box"`},
		{"malformed_bracket", "[::1"},
		{"invalid_port", "bastion:99999"},
		{"empty_user", "@bastion"},
	}

	for _, tc := range badJumps {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Direct parseOpenSSHProxyJump rejects with ErrSSHOptionsValidation.
			rawHop := strings.Trim(tc.raw, `"`)
			if got, err := parseOpenSSHProxyJump(rawHop); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("parseOpenSSHProxyJump(%q) = (%q, %v), want ErrSSHOptionsValidation", rawHop, got, err)
			}

			sshCfg := "Host app\n  HostName 10.92.0.1\n  User ops\n  ProxyJump " + tc.raw + "\n"
			parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
			if err != nil {
				// Parse-time rejection also satisfies fail-closed.
				return
			}
			if ps, err := parser.ResolveProxySetting("app"); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveProxySetting(app, %q) = (%q, %v), want ErrSSHOptionsValidation", tc.raw, ps, err)
			}
			if _, _, _, err := parser.GetVirtualNode("app"); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("GetVirtualNode(app, %q) err = %v, want ErrSSHOptionsValidation", tc.raw, err)
			}
			if _, err := parser.GetSSHOptions("app"); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("GetSSHOptions(app, %q) err = %v, want ErrSSHOptionsValidation", tc.raw, err)
			}
			if _, err := ParseOpenSSHHosts(strings.NewReader(sshCfg), "ops"); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ParseOpenSSHHosts(%q) err = %v, want ErrSSHOptionsValidation", tc.raw, err)
			}
			prov := NewProviderWithOpenSSHParser(nil, parser)
			if res, err := ResolveTarget(prov, ConnectionTarget{Selector: "app"}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveTarget(app, %q) = (%+v, %v), want ErrSSHOptionsValidation", tc.raw, res, err)
			}
		})
	}

	t.Run("valid_openssh_proxyjump_and_sibling_normalization", func(t *testing.T) {
		t.Parallel()
		got, err := parseOpenSSHProxyJump("bastion, ops@jump-2:2222, [2001:db8::1]:2200")
		if err != nil {
			t.Fatalf("parseOpenSSHProxyJump(valid): %v", err)
		}
		want := "openssh:bastion,openssh:ops@jump-2:2222,openssh:[2001:db8::1]:2200"
		if got != want {
			t.Fatalf("parseOpenSSHProxyJump(valid) = %q, want %q", got, want)
		}

		// Sibling node inheriting uppercase OPENSSH:10.0.0.1 normalizes to lowercase openssh:10.0.0.1.
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("h-app", models.Host{Address: "10.92.1.5", Port: 22})
		cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("ops@10.92.1.5:22", models.Node{
			HostRef:     "h-app",
			IdentityRef: "id-ops",
			ProxyJump:   "OPENSSH:10.0.0.1",
		})
		prov := NewProviderWithoutOpenSSH(cfg)
		res, err := ResolveTarget(prov, ConnectionTarget{Selector: "10.92.1.5", User: "deploy", HasUser: true})
		if err != nil {
			t.Fatalf("ResolveTarget(sibling OPENSSH:): %v", err)
		}
		if res.ProxyJump != "openssh:10.0.0.1" {
			t.Fatalf("ResolveTarget(sibling OPENSSH:).ProxyJump = %q, want openssh:10.0.0.1", res.ProxyJump)
		}
	})
}
