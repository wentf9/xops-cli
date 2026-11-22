package adapter

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func newP7W5cTestConfig() *config.Configuration {
	return config.NewProviderWithoutOpenSSH(nil).Snapshot()
}

func TestP7W5c_D5H1_MalformedProxyJumpFailsClosedNeverDisablesBastion(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host bastion
    HostName 10.0.0.1
    User jumpops

Host virtual-app
    HostName 10.0.0.2
    User appops
    ProxyJump bastion
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	cfg := newP7W5cTestConfig()
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Hosts.Set("h-app", models.Host{Address: "10.0.0.2", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-bastion", models.Node{HostRef: "h-bastion", IdentityRef: "id-ops"})
	cfg.Nodes.Set("saved-app", models.Node{HostRef: "h-app", IdentityRef: "id-ops", ProxyJump: "saved-bastion"})

	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	badJumps := []string{",", " , ", "none,", ",none", "bastion,", ",bastion", "a,,b", "a,none", "none,a", "bastion\n", "bastion\x00"}
	for _, bad := range badJumps {
		if ps, err := proxySettingFromJumpString(bad); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("proxySettingFromJumpString(%q) = (%q, %v), want ErrSSHOptionsValidation", bad, ps, err)
		}

		for _, nodeID := range []string{"saved-app", config.OpenSSHNodePrefix + "virtual-app"} {
			adp := NewSSHAdapter(prov,
				WithOpenSSHParser(parser),
				WithSessionAuthOverride(nodeID, SessionAuth{ProxyJump: bad}),
			)
			if pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: nodeID}); err == nil {
				t.Errorf("Resolve(%s, SessionAuth.ProxyJump=%q) succeeded (proxy=%q), MUST fail closed instead of disabling mandatory bastion",
					nodeID, bad, pol.Proxy())
			}
		}
	}

	// Valid "none" and "none,none" continue to disable lower ProxyJump cleanly.
	for _, validNone := range []string{"none", "NONE", "none,none"} {
		adp := NewSSHAdapter(prov,
			WithOpenSSHParser(parser),
			WithSessionAuthOverride("saved-app", SessionAuth{ProxyJump: validNone}),
		)
		pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "saved-app"})
		if err != nil {
			t.Fatalf("Resolve(saved-app, ProxyJump=%q) unexpected error: %v", validNone, err)
		}
		if !pol.Proxy().IsJumpDisabledOnly() || pol.EffectiveJump() != "" {
			t.Fatalf("Resolve(saved-app, ProxyJump=%q) = (proxy=%q, jump=%q), want ProxyJump=none / empty",
				validNone, pol.Proxy(), pol.EffectiveJump())
		}
	}

	// Malformed persisted node.ProxyJump must also fail closed in Resolve.
	badCfg := newP7W5cTestConfig()
	badCfg.Hosts.Set("h-app", models.Host{Address: "10.0.0.2", Port: 22})
	badCfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	badCfg.Nodes.Set("bad-node", models.Node{HostRef: "h-app", IdentityRef: "id-ops", ProxyJump: "bastion,none"})
	badAdp := NewSSHAdapter(config.NewProviderWithOpenSSHParser(badCfg, nil))
	if _, err := badAdp.Resolve(t.Context(), ResolveRequest{NodeID: "bad-node"}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
		t.Fatalf("Resolve(malformed node.ProxyJump) = %v, want ErrSSHOptionsValidation", err)
	}
}

func TestP7W5c_C5L1_DisableControlResetsImplicitTier4(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host app
    HostName 10.0.0.5
    User ops
    ConnectTimeout 12
    ControlMaster auto
    ControlPath /tmp/cm-%C
    ControlPersist 5m
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := config.NewProviderWithOpenSSHParser(nil, parser)

	adpNoMux := NewSSHAdapter(prov, WithOpenSSHParser(parser), WithControlMultiplexing(false))
	pol, err := adpNoMux.Resolve(t.Context(), ResolveRequest{NodeID: config.OpenSSHNodePrefix + "app"})
	if err != nil {
		t.Fatalf("Resolve(WithControlMultiplexing(false)): %v", err)
	}
	opts := pol.Options()
	if opts == nil || opts.Get(ssh.OptionConnectTimeout) != "12" {
		t.Fatalf("unexpected options: %+v", opts)
	}
	if opts.ImplicitTier4 {
		t.Fatal("WithControlMultiplexing(false) leaked ImplicitTier4=true after stripping OptionClassMux")
	}
}
