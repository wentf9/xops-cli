package adapter

import (
	"errors"
	"os/user"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func w11cDistinctLocalAndOtherUser(t *testing.T) (localUser, otherUser string) {
	t.Helper()
	curr, err := user.Current()
	if err != nil || strings.TrimSpace(curr.Username) == "" {
		t.Fatalf("user.Current() = (%+v, %v)", curr, err)
	}
	localUser = strings.TrimSpace(curr.Username)
	otherUser = "w11c-bob"
	if localUser == otherUser {
		otherUser = "w11c-alice"
	}
	return localUser, otherUser
}

func TestP7W11c_DE11M2_TwoPassCanonicalizedOpenSSHCycleAcrossControlPolicyAndConnector(t *testing.T) {
	t.Parallel()

	env := w10cTestEnv()
	muxSession, err := ParseSessionOptions([]string{"ControlMaster=auto", "ControlPath=/tmp/cm-w11c-%h-%p-%r-%j-%C"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions: %v", err)
	}

	const sshCfg = `
Host web
    User ops

Host web.corp.example.com
    HostName 10.214.0.1
    ProxyJump ops@web.corp.example.com:22

Host web2
    User ops

Host web2.corp.example.com
    HostName 10.214.0.2
    ProxyJump hop-b

Host hop-b
    HostName 10.214.0.9
    User ops
    ProxyJump ops@web2.corp.example.com:22
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := config.NewProviderWithOpenSSHParser(nil, parser)

	cases := []struct {
		name         string
		originalHost string
		canonHost    string
	}{
		{"1hop_canonicalized", "web", "web.corp.example.com"},
		{"2hop_canonicalized", "web2", "web2.corp.example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := ControlTargetRequest{
				Provider:              prov,
				Target:                config.ConnectionTarget{Selector: tc.canonHost, OriginalHost: tc.originalHost},
				CanonicalOriginalHost: tc.originalHost,
				CanonicalHost:         tc.canonHost,
				SessionControl:        muxSession,
				Environment:           &env,
			}
			var cycleErr *ssh.ProxyCycleError
			if res, err := ResolveControlTarget(req); !errors.As(err, &cycleErr) {
				t.Errorf("ResolveControlTarget(%s) = (%+v, %v), want *ssh.ProxyCycleError", tc.name, res, err)
			}
			if sock, res, err := ResolveControlSocketPath(req); !errors.As(err, &cycleErr) {
				t.Errorf("ResolveControlSocketPath(%s) = (%q, %+v, %v), want *ssh.ProxyCycleError", tc.name, sock, res, err)
			}

			nodeID := config.OpenSSHNodePrefix + tc.canonHost
			adp := NewSSHAdapter(prov, WithSessionAuthOverride(nodeID, SessionAuth{
				OriginalHost:  tc.originalHost,
				CanonicalHost: tc.canonHost,
			}))
			if pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: nodeID, ResolveProxy: true}); !errors.As(err, &cycleErr) {
				t.Errorf("SSHAdapter.Resolve(%s) = (%+v, %v), want *ssh.ProxyCycleError", tc.name, pol, err)
			}
			if cfg, err := adp.GetConfig(nodeID); !errors.As(err, &cycleErr) {
				t.Errorf("SSHAdapter.GetConfig(%s) = (%+v, %v), want *ssh.ProxyCycleError", tc.name, cfg, err)
			}

			conn := ssh.NewConnector(adp)
			defer func() { _ = conn.CloseAll() }()
			if cli, err := conn.Connect(t.Context(), nodeID); !errors.As(err, &cycleErr) {
				t.Errorf("Connector.Connect(%s) = (%+v, %v), want *ssh.ProxyCycleError", tc.name, cli, err)
			}
		})
	}
}

func TestP7W11c_DE11M3_OpenSSHVirtualDefaultLocalUserAcrossControlAndPolicy(t *testing.T) {
	t.Parallel()

	localUser, otherUser := w11cDistinctLocalAndOtherUser(t)
	env := w10cTestEnv()
	muxSession, err := ParseSessionOptions([]string{"ControlMaster=auto", "ControlPath=/tmp/cm-w11c-m3-%h-%p-%r-%j-%C"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions: %v", err)
	}

	const sshCfg = `
Host app.example.com
    HostName 10.215.0.1

Host app-explicit.example.com
    HostName 10.215.0.2
    User `
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg + otherUser + "\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	withSSHProv := config.NewProviderWithOpenSSHParser(nil, parser)
	noSSHProv := config.NewProviderWithoutOpenSSH(nil)

	distinctJump := otherUser + "@app.example.com"
	for _, tc := range []struct {
		name string
		prov config.ConfigProvider
	}{
		{"no_ssh_config", noSSHProv},
		{"with_ssh_config", withSSHProv},
	} {
		t.Run("distinct_user_"+tc.name, func(t *testing.T) {
			t.Parallel()
			req := ControlTargetRequest{
				Provider: tc.prov,
				Target: config.ConnectionTarget{
					Selector:     "app.example.com",
					ProxyJump:    distinctJump,
					HasProxyJump: true,
				},
				SessionControl: muxSession,
				Environment:    &env,
			}
			sock, res, err := ResolveControlSocketPath(req)
			if err != nil || sock == "" || res.Target.JumpHost != "openssh:"+distinctJump {
				t.Fatalf("ResolveControlSocketPath(%s) = (%q, %+v, %v), want valid socket and jump %q",
					tc.name, sock, res, err, "openssh:"+distinctJump)
			}
		})
	}

	// Policy layer parity for ProvenanceOpenSSHVirtual with distinct user jump.
	nodeID := config.OpenSSHNodePrefix + "app.example.com"
	adpDistinct := NewSSHAdapter(withSSHProv, WithSessionAuthOverride(nodeID, SessionAuth{ProxyJump: distinctJump}))
	pol, err := adpDistinct.Resolve(t.Context(), ResolveRequest{NodeID: nodeID, ResolveProxy: true})
	if err != nil || pol.EffectiveJump() != "openssh:"+distinctJump {
		t.Fatalf("SSHAdapter.Resolve(distinct user jump) = (%q, %v), want %q", pol.EffectiveJump(), err, "openssh:"+distinctJump)
	}

	// Same effective local user or bare self-jump must fail closed with *ssh.ProxyCycleError.
	for _, sameJump := range []string{localUser + "@app.example.com", "app.example.com"} {
		var cycleErr *ssh.ProxyCycleError
		adpSame := NewSSHAdapter(withSSHProv, WithSessionAuthOverride(nodeID, SessionAuth{ProxyJump: sameJump}))
		if _, err := adpSame.Resolve(t.Context(), ResolveRequest{NodeID: nodeID, ResolveProxy: true}); !errors.As(err, &cycleErr) {
			t.Errorf("SSHAdapter.Resolve(sameJump=%q) = %v, want *ssh.ProxyCycleError", sameJump, err)
		}
		if _, err := ResolveControlTarget(ControlTargetRequest{
			Provider: withSSHProv,
			Target: config.ConnectionTarget{
				Selector:     "app.example.com",
				ProxyJump:    sameJump,
				HasProxyJump: true,
			},
			SessionControl: muxSession,
			Environment:    &env,
		}); !errors.As(err, &cycleErr) {
			t.Errorf("ResolveControlTarget(sameJump=%q) = %v, want *ssh.ProxyCycleError", sameJump, err)
		}
	}

	// OpenSSH virtual host with explicit User <otherUser>: jumping via <localUser> succeeds,
	// while jumping via <otherUser> fails closed across ResolveControlSocketPath.
	sockExplicit, resExplicit, err := ResolveControlSocketPath(ControlTargetRequest{
		Provider: withSSHProv,
		Target: config.ConnectionTarget{
			Selector:     "app-explicit.example.com",
			ProxyJump:    localUser + "@app-explicit.example.com",
			HasProxyJump: true,
		},
		SessionControl: muxSession,
		Environment:    &env,
	})
	if err != nil || sockExplicit == "" || resExplicit.LookupKey != "openssh:app-explicit.example.com" {
		t.Fatalf("ResolveControlSocketPath(explicit User distinct jump) = (%q, %+v, %v), want valid socket", sockExplicit, resExplicit, err)
	}
	var cycleErr *ssh.ProxyCycleError
	if sockSame, resSame, err := ResolveControlSocketPath(ControlTargetRequest{
		Provider: withSSHProv,
		Target: config.ConnectionTarget{
			Selector:     "app-explicit.example.com",
			ProxyJump:    otherUser + "@app-explicit.example.com",
			HasProxyJump: true,
		},
		SessionControl: muxSession,
		Environment:    &env,
	}); !errors.As(err, &cycleErr) {
		t.Errorf("ResolveControlSocketPath(explicit User same jump) = (%q, %+v, %v), want *ssh.ProxyCycleError", sockSame, resSame, err)
	}
}

func TestP7W11c_DE11L2_SessionAuthOpenSSHSelectorsFailClosedBeforeTrim(t *testing.T) {
	t.Parallel()

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-web", models.Host{Address: "10.216.0.1", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-web", models.Node{HostRef: "h-web", IdentityRef: "id-ops"})

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(
		"Host bastion1\n  HostName 10.216.0.10\n  User ops\nHost bastion2\n  HostName 10.216.0.11\n  User ops\nHost web\n  HostName 10.216.0.2\n  User ops\n",
	))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	badValues := []string{
		" openssh:web",
		"openssh:web ",
		"\u00a0openssh:web",
		"\x00openssh:web",
		"openssh:web\n",
		"openssh:web\u2028",
		" OPENSSH:web",
		"openssh:openssh:web",
	}

	for _, bad := range badValues {
		authCases := []struct {
			name string
			auth SessionAuth
		}{
			{"OriginalHost", SessionAuth{OriginalHost: bad}},
			{"CanonicalHost", SessionAuth{CanonicalHost: bad}},
			{"ProxyJump_single", SessionAuth{ProxyJump: bad}},
			{"ProxyJump_second_hop", SessionAuth{ProxyJump: "bastion1," + bad}},
		}
		for _, ac := range authCases {
			adp := NewSSHAdapter(prov, WithSessionAuthOverride("saved-web", ac.auth))
			if pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "saved-web", ResolveProxy: true}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("SSHAdapter.Resolve(%s=%q) = (%+v, %v), want ErrSSHOptionsValidation", ac.name, bad, pol, err)
			}
			if pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "saved-web", ResolveProxy: false}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("SSHAdapter.Resolve(ResolveProxy=false, %s=%q) = (%+v, %v), want ErrSSHOptionsValidation", ac.name, bad, pol, err)
			}
			if _, err := ResolveControlConfig(prov, "saved-web", "saved-web", ac.auth, SessionControlOptions{}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveControlConfig(%s=%q) = %v, want ErrSSHOptionsValidation", ac.name, bad, err)
			}
			clientCfg := &ssh.ClientConfig{NodeID: "saved-web"}
			if err := applySessionOverrideToConfig(clientCfg, ac.auth, ssh.UnsetPathList()); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("applySessionOverrideToConfig(%s=%q) = %v, want ErrSSHOptionsValidation", ac.name, bad, err)
			}
		}
	}

	// Valid multi-hop openssh ProxyJump chain must continue to succeed.
	adpValid := NewSSHAdapter(prov, WithSessionAuthOverride("saved-web", SessionAuth{
		ProxyJump: "openssh:bastion1,openssh:bastion2",
	}))
	pol, err := adpValid.Resolve(t.Context(), ResolveRequest{NodeID: "saved-web", ResolveProxy: true})
	if err != nil || pol.EffectiveJump() != "openssh:bastion1,openssh:bastion2" {
		t.Fatalf("SSHAdapter.Resolve(valid multi-hop openssh) = (%q, %v), want openssh:bastion1,openssh:bastion2", pol.EffectiveJump(), err)
	}
}
