package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W8c_DE8M2_ResolveTargetFailClosedOnMalformedNodeAndOpenSSHProxyJump(t *testing.T) {
	t.Parallel()

	badJumps := []string{
		"bastion\n",
		"bastion,,hop2",
		"bastion,none",
		"none, ,none",
		",",
		" , ",
		"bastion\u2028",
	}

	t.Run("saved_node_malformed_proxyjump_fails_closed", func(t *testing.T) {
		t.Parallel()
		for _, bad := range badJumps {
			cfg := cloneConfiguration(nil)
			cfg.Hosts.Set("h-web", models.Host{Address: "10.10.0.1", Port: 22})
			cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
			cfg.Nodes.Set("saved-web", models.Node{
				HostRef:     "h-web",
				IdentityRef: "id-ops",
				ProxyJump:   bad,
			})
			prov := NewProviderWithoutOpenSSH(cfg)

			if res, err := ResolveTarget(prov, ConnectionTarget{Selector: "saved-web"}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveTarget(saved-web, jump=%q) = (%+v, %v), want ErrSSHOptionsValidation", bad, res, err)
			}
			// Even with a valid Tier-1 override, malformed saved baseJump fails closed.
			if res, err := ResolveTarget(prov, ConnectionTarget{
				Selector:     "saved-web",
				ProxyJump:    "10.10.0.99",
				HasProxyJump: true,
			}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveTarget(saved-web, override, base=%q) = (%+v, %v), want ErrSSHOptionsValidation", bad, res, err)
			}
			// Sibling derived target inheriting from malformed saved node also fails closed.
			if res, err := ResolveTarget(prov, ConnectionTarget{
				Selector: "10.10.0.1",
				User:     "deploy",
				HasUser:  true,
			}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveTarget(sibling deploy@10.10.0.1, bad=%q) = (%+v, %v), want ErrSSHOptionsValidation", bad, res, err)
			}
			if got, err := normalizeTargetJump(prov, bad, ConnectionTarget{}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("normalizeTargetJump(base=%q) = (%q, %v), want ErrSSHOptionsValidation", bad, got, err)
			}
		}
	})

	t.Run("tier4_openssh_malformed_proxyjump_fails_closed", func(t *testing.T) {
		t.Parallel()
		const sshCfg = `
Host bad-ssh
    HostName 10.20.0.1
    User ops
    ProxyJump bastion,,hop2
`
		parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		prov := NewProviderWithOpenSSHParser(nil, parser)

		for _, tgt := range []ConnectionTarget{
			{Selector: "bad-ssh"},
			{Selector: OpenSSHNodePrefix + "bad-ssh"},
			{Selector: "bad-ssh", User: "deploy", HasUser: true},
		} {
			if res, err := ResolveTarget(prov, tgt); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveTarget(%+v) = (%+v, %v), want ErrSSHOptionsValidation", tgt, res, err)
			}
		}
	})

	t.Run("valid_none_and_none_none_normalize_to_empty", func(t *testing.T) {
		t.Parallel()
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("h-web", models.Host{Address: "10.10.0.1", Port: 22})
		cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("saved-none", models.Node{HostRef: "h-web", IdentityRef: "id-ops", ProxyJump: "none,none"})
		prov := NewProviderWithoutOpenSSH(cfg)

		res, err := ResolveTarget(prov, ConnectionTarget{Selector: "saved-none"})
		if err != nil || res.ProxyJump != "" {
			t.Fatalf("ResolveTarget(saved-none) = (%+v, %v), want empty ProxyJump and nil err", res, err)
		}
	})
}

func TestP7W8c_DE8L2_RejectWhitespacePaddedOpenSSHSelectorsFailClosed(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host web
    HostName 10.90.0.1
    User ops
    Port 2222
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := NewProviderWithOpenSSHParser(nil, parser)

	badSelectors := []string{
		"openssh: web",
		"openssh:\u00a0web",
		"openssh:web ",
		"openssh:web\u00a0",
		" openssh:web",
		"\u00a0openssh:web",
		"openssh:\tweb",
		"openssh:web\n",
		"openssh:web\u2028",
		"OPENSSH: web",
		"OPENSSH:\u00a0web",
		"OPENSSH:web ",
		"openssh:alice@web:2222 ",
		"openssh: alice@web:2222",
		"openssh:alice @web",
		"openssh:alice@ web",
	}

	for _, bad := range badSelectors {
		assertDE8L2RejectedOpenSSHSelector(t, prov, parser, bad)
	}

	// Sanity: clean explicit openssh: selectors remain valid everywhere.
	for _, good := range []string{"openssh:web", "OPENSSH:web", "openssh:alice@web:2222"} {
		assertDE8L2ValidOpenSSHSelector(t, prov, good)
	}
}

func assertDE8L2RejectedOpenSSHSelector(t *testing.T, prov *Provider, parser *OpenSSHParser, bad string) {
	t.Helper()
	if _, _, _, err := prov.Resolve(bad); err == nil {
		t.Errorf("Provider.Resolve(%q) unexpectedly succeeded, want fail-closed error", bad)
	}
	if _, err := prov.ResolveConnection(bad); err == nil {
		t.Errorf("Provider.ResolveConnection(%q) unexpectedly succeeded, want fail-closed error", bad)
	}
	if _, err := prov.ResolveConnectionWithOrigin(bad, "web"); err == nil {
		t.Errorf("Provider.ResolveConnectionWithOrigin(%q) unexpectedly succeeded, want fail-closed error", bad)
	}
	if res, err := ResolveTarget(prov, ConnectionTarget{Selector: bad}); err == nil {
		t.Errorf("ResolveTarget(bare, %q) unexpectedly succeeded (%+v), want fail-closed error", bad, res)
	}
	if res, err := ResolveTarget(prov, ConnectionTarget{Selector: bad, User: "deploy", HasUser: true}); err == nil {
		t.Errorf("ResolveTarget(explicit, %q) unexpectedly succeeded (%+v), want fail-closed error", bad, res)
	}
	if ref, err := ParseTargetRef(bad); err == nil {
		t.Errorf("ParseTargetRef(%q) unexpectedly succeeded (%+v), want fail-closed error", bad, ref)
	}
	if orig, ok := OpenSSHOriginalHost(bad); ok || orig != "" {
		t.Errorf("OpenSSHOriginalHost(%q) = (%q, %v), want (\"\", false)", bad, orig, ok)
	}
	if unwrapped := UnwrapOpenSSHSelector(bad); unwrapped != "" {
		t.Errorf("UnwrapOpenSSHSelector(%q) = %q, want \"\"", bad, unwrapped)
	}
	if parser.HasHost(bad) {
		t.Errorf("OpenSSHParser.HasHost(%q) = true, want false", bad)
	}
	if opts, err := parser.GetSSHOptions(bad); err == nil {
		t.Errorf("OpenSSHParser.GetSSHOptions(%q) unexpectedly succeeded (%+v), want error", bad, opts)
	}
	if ps, err := parser.ResolveProxySetting(bad); err == nil {
		t.Errorf("OpenSSHParser.ResolveProxySetting(%q) unexpectedly succeeded (%q), want error", bad, ps)
	}
}

func assertDE8L2ValidOpenSSHSelector(t *testing.T, prov *Provider, good string) {
	t.Helper()
	if _, h, _, err := prov.Resolve(good); err != nil || h.Address != "10.90.0.1" {
		t.Errorf("Provider.Resolve(%q) = (%+v, %v), want 10.90.0.1", good, h, err)
	}
	if snap, err := prov.ResolveConnectionWithOrigin(good, "web"); err != nil || snap.Host.Address != "10.90.0.1" {
		t.Errorf("Provider.ResolveConnectionWithOrigin(%q) = (%+v, %v), want 10.90.0.1", good, snap.Host, err)
	}
	if res, err := ResolveTarget(prov, ConnectionTarget{Selector: good}); err != nil || res.Host != "10.90.0.1" {
		t.Errorf("ResolveTarget(%q) = (%+v, %v), want 10.90.0.1", good, res, err)
	}
	if ref, err := ParseTargetRef(good); err != nil || !ref.OpenSSH || ref.Host != "web" {
		t.Errorf("ParseTargetRef(%q) = (%+v, %v), want OpenSSH=true Host=web", good, ref, err)
	}
}
