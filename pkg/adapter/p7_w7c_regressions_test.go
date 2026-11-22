package adapter

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W7c_DEF7M1_ResolveControlTargetAndConfigFailClosedOnMalformedProxyJump(t *testing.T) {
	t.Parallel()

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Hosts.Set("h-edge", models.Host{Address: "10.0.0.2", Port: 22})
	cfg.Hosts.Set("h-web", models.Host{Address: "10.0.0.3", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-bastion", models.Node{HostRef: "h-bastion", IdentityRef: "id-ops"})
	cfg.Nodes.Set("edge-jump", models.Node{HostRef: "h-edge", IdentityRef: "id-ops"})
	muxOpts := &ssh.Options{}
	muxOpts.SetControlMaster(ssh.ControlMasterAuto)
	muxOpts.SetControlPath("/tmp/cm-m1-%h-%p-%r-%j-%C")
	cfg.Nodes.Set("saved-web", models.Node{
		HostRef:     "h-web",
		IdentityRef: "id-ops",
		ProxyJump:   "saved-bastion",
		SSHOptions:  muxOpts,
	})
	prov := config.NewProviderWithoutOpenSSH(cfg)

	shadowedSessionOpts, err := ParseSessionOptions([]string{"ProxyJump=edge-jump"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions(ProxyJump=edge-jump): %v", err)
	}

	badJumps := []string{
		"none\n",
		"bastion\n",
		"\n",
		"\t",
		"\r\n",
		"\u0085",
		"\v",
		"\f",
		"\u2028",
		"\u2029",
		"   ",
		",",
		"bastion,none",
	}

	for _, bad := range badJumps {
		// 1. ResolveControlTarget must fail closed and never silently fall back to
		//    Tier-2 "saved-bastion" or shadowed -o ProxyJump.
		if res, err := ResolveControlTarget(ControlTargetRequest{
			Provider:       prov,
			Target:         config.ConnectionTarget{Selector: "saved-web", ProxyJump: bad, HasProxyJump: true},
			SessionControl: shadowedSessionOpts,
		}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ResolveControlTarget(Target.ProxyJump=%q) = (%+v, %v), want ErrSSHOptionsValidation", bad, res, err)
		}
		// Even without HasProxyJump flag set, non-empty malformed ProxyJump must fail closed.
		if res, err := ResolveControlTarget(ControlTargetRequest{
			Provider: prov,
			Target:   config.ConnectionTarget{Selector: "saved-web", ProxyJump: bad},
		}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ResolveControlTarget(ProxyJump=%q, HasProxyJump=false) = (%+v, %v), want ErrSSHOptionsValidation", bad, res, err)
		}
		// Direct resolveControlTier1ProxySetting must never swallow ParseProxyJump errors.
		if ps, err := resolveControlTier1ProxySetting(
			config.ConnectionTarget{ProxyJump: bad, HasProxyJump: true},
			shadowedSessionOpts,
		); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("resolveControlTier1ProxySetting(%q) = (%v, %v), want ErrSSHOptionsValidation", bad, ps, err)
		}

		// 2. ResolveControlConfig must fail closed regardless of provider==nil, empty
		//    sessionOpts, or empty/whitespace lookupKey + selector.
		if ctrl, err := ResolveControlConfig(nil, "", "", SessionAuth{ProxyJump: bad}, SessionControlOptions{}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ResolveControlConfig(nil, empty, ProxyJump=%q) = (%+v, %v), want ErrSSHOptionsValidation", bad, ctrl, err)
		}
		if ctrl, err := ResolveControlConfig(prov, "", "   ", SessionAuth{ProxyJump: bad}, SessionControlOptions{}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ResolveControlConfig(prov, empty lookupKey, ProxyJump=%q) = (%+v, %v), want ErrSSHOptionsValidation", bad, ctrl, err)
		}

		// 3. ResolveControlSocketPath with nil provider / empty selector + FallbackHost must also fail closed.
		if sock, res, err := ResolveControlSocketPath(ControlTargetRequest{
			Provider:     nil,
			Target:       config.ConnectionTarget{Selector: "   ", ProxyJump: bad, HasProxyJump: true},
			FallbackHost: "10.0.0.9",
			FallbackPort: 22,
			FallbackUser: "ops",
		}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ResolveControlSocketPath(nil provider, FallbackHost, ProxyJump=%q) = (%q, %+v, %v), want ErrSSHOptionsValidation", bad, sock, res, err)
		}
	}

	// Explicit HasProxyJump=true with empty ProxyJump="" must also fail closed.
	if res, err := ResolveControlTarget(ControlTargetRequest{
		Provider: prov,
		Target:   config.ConnectionTarget{Selector: "saved-web", ProxyJump: "", HasProxyJump: true},
	}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
		t.Fatalf("ResolveControlTarget(HasProxyJump=true, ProxyJump=\"\") = (%+v, %v), want ErrSSHOptionsValidation", res, err)
	}
	if _, _, err := ResolveControlSocketPath(ControlTargetRequest{
		Provider: prov,
		Target:   config.ConnectionTarget{Selector: "saved-web", ProxyJump: "", HasProxyJump: true},
	}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
		t.Fatalf("ResolveControlSocketPath(HasProxyJump=true, ProxyJump=\"\") err = %v, want ErrSSHOptionsValidation", err)
	}

	// Sanity: unset ProxyJump (HasProxyJump=false, ProxyJump="") succeeds and retains Tier-2 jump.
	okRes, err := ResolveControlTarget(ControlTargetRequest{
		Provider: prov,
		Target:   config.ConnectionTarget{Selector: "saved-web"},
	})
	if err != nil {
		t.Fatalf("ResolveControlTarget(saved-web) unexpected error: %v", err)
	}
	if okRes.Target.JumpHost != "saved-bastion" {
		t.Fatalf("ResolveControlTarget(saved-web).Target.JumpHost = %q, want saved-bastion", okRes.Target.JumpHost)
	}
	if ctrl, err := ResolveControlConfig(nil, "", "", SessionAuth{}, SessionControlOptions{}); err != nil || ctrl != nil {
		t.Fatalf("ResolveControlConfig(nil, empty) = (%+v, %v), want (nil, nil)", ctrl, err)
	}
}

func TestP7W7c_DEF7M2_TwoPassCanonicalizedControlLookupPreservesCanonicalHost(t *testing.T) {
	t.Parallel()

	env := ssh.Environment{
		HomeDir:   "/home/tester",
		LocalUser: "tester",
		LocalHost: "workstation.local",
		LocalUID:  "1000",
	}

	readOnlyProv, repo := buildP3EquivalenceFixtures(t, nil)

	for _, tc := range []struct {
		name   string
		target config.ConnectionTarget
	}{
		{
			name: "bare_canonicalized_selector_without_req_canonical_host",
			target: config.ConnectionTarget{
				Selector:     "short.corp.example.com",
				OriginalHost: "short",
			},
		},
		{
			name: "explicit_openssh_canonicalized_selector_without_req_canonical_host",
			target: config.ConnectionTarget{
				Selector:     config.OpenSSHNodePrefix + "short.corp.example.com",
				OriginalHost: "short",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Intentionally leave CanonicalHost and CanonicalOriginalHost unset on the request.
			req := ControlTargetRequest{
				Provider:    readOnlyProv,
				Target:      tc.target,
				Environment: &env,
			}
			ctrlRes, err := ResolveControlTarget(req)
			if err != nil {
				t.Fatalf("ResolveControlTarget: %v", err)
			}
			if ctrlRes.Target.OriginalHost != "short" || ctrlRes.Target.CanonicalHost != "short.corp.example.com" {
				t.Fatalf("ResolveControlTarget.Target = %+v, want OriginalHost=short CanonicalHost=short.corp.example.com", ctrlRes.Target)
			}
			if ctrlRes.LookupKey != "openssh:short.corp.example.com" {
				t.Fatalf("ResolveControlTarget.LookupKey = %q, want openssh:short.corp.example.com", ctrlRes.LookupKey)
			}
			if ctrlRes.SessionAuth.OriginalHost != "short" || ctrlRes.SessionAuth.CanonicalHost != "short.corp.example.com" {
				t.Fatalf("ResolveControlTarget.SessionAuth = %+v, want OriginalHost=short CanonicalHost=short.corp.example.com", ctrlRes.SessionAuth)
			}

			ctrlSock, sockRes, err := ResolveControlSocketPath(req)
			if err != nil {
				t.Fatalf("ResolveControlSocketPath: %v", err)
			}
			if ctrlSock == "" {
				t.Fatalf("ResolveControlSocketPath returned empty socket (Pass-2 ControlMaster/ControlPath lost); res=%+v", sockRes)
			}

			// Compare byte-for-byte against dial plane.
			var dialTarget ssh.TargetContext
			var dialSock string
			if err := repo.WithPendingNode(t.Context(), config.EnsureNodeOptions{
				Target:      tc.target,
				DefaultUser: env.LocalUser,
			}, func(lease config.PendingLease) error {
				nodeID := lease.NodeID()
				adp := NewSSHAdapter(repo, WithSessionAuthOverride(nodeID, SessionAuth{
					OriginalHost:  "short",
					CanonicalHost: "short.corp.example.com",
				}))
				clientCfg, err := adp.GetConfig(nodeID)
				if err != nil {
					return err
				}
				dialCtrl, err := adp.GetControlConfig(nodeID)
				if err != nil {
					return err
				}
				dialTarget = ssh.BuildClientTargetContext(nodeID, clientCfg, env, nil)
				dialSock, err = dialCtrl.ResolvePath(env, dialTarget)
				return err
			}); err != nil {
				t.Fatalf("dial plane WithPendingNode: %v", err)
			}

			if sockRes.Target != dialTarget {
				t.Fatalf("TargetContext mismatch:\n  control = %+v\n  dial    = %+v", sockRes.Target, dialTarget)
			}
			if ctrlSock != dialSock {
				t.Fatalf("ControlPath mismatch:\n  control = %q\n  dial    = %q", ctrlSock, dialSock)
			}
		})
	}
}

type strippingProxyJumpProvider struct {
	config.ConfigProvider
	parser *config.OpenSSHParser
}

func (p *strippingProxyJumpProvider) GetOpenSSHParser() *config.OpenSSHParser {
	return p.parser
}

func (p *strippingProxyJumpProvider) ResolveConnection(nodeID string) (config.ConnectionSnapshot, error) {
	snap, err := p.ConfigProvider.ResolveConnection(nodeID)
	if err != nil {
		return snap, err
	}
	if snap.Provenance.IsUnpersistedOpenSSH() {
		// Simulate unpersisted OpenSSH snapshot with empty Node.ProxyJump so
		// t4ParserProxy (from OpenSSHParser.ResolveProxySettingWithCanonical) supplies hops.
		snap.Node.ProxyJump = ""
	}
	return snap, nil
}

func TestP7W7c_DEF7M3_Tier4ParserProxyJumpHopsPrefixedWithOpenSSH(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host jump-box",
		"  HostName 10.60.0.1",
		"  User juser",
		"  Port 2201",
		"",
		"Host hop2",
		"  HostName 10.60.0.2",
		"  User h2user",
		"  Port 2202",
		"",
		"Host app-single",
		"  HostName 10.60.0.10",
		"  User appuser",
		"  ProxyJump jump-box",
		"  ControlMaster auto",
		"  ControlPath /tmp/cm-m3-%h-%p-%r-%n-%j-%C",
		"",
		"Host app-multi",
		"  HostName 10.60.0.20",
		"  User appuser",
		"  ProxyJump jump-box,alice@hop2:2222",
		"  ControlMaster auto",
		"  ControlPath /tmp/cm-m3-%h-%p-%r-%n-%j-%C",
	}, "\n") + "\n"

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	dir := t.TempDir()
	store := config.NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	strippedProv := &strippingProxyJumpProvider{ConfigProvider: repo, parser: parser}
	adp := NewSSHAdapter(strippedProv)

	env := ssh.Environment{
		HomeDir:   "/home/tester",
		LocalUser: "tester",
		LocalHost: "workstation.local",
		LocalUID:  "1000",
	}

	for _, tc := range []struct {
		name     string
		alias    string
		wantJump string
		wantHops []string
	}{
		{
			name:     "single_t4_parser_hop",
			alias:    "app-single",
			wantJump: "openssh:jump-box",
			wantHops: []string{"openssh:jump-box", "openssh:app-single"},
		},
		{
			name:     "multi_t4_parser_hops",
			alias:    "app-multi",
			wantJump: "openssh:jump-box,openssh:alice@hop2:2222",
			wantHops: []string{"openssh:jump-box", "openssh:alice@hop2:2222", "openssh:app-multi"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			nodeID := config.OpenSSHNodePrefix + tc.alias

			// Both ResolveProxy=false and ResolveProxy=true must prefix Tier-4 parser hops.
			for _, resolveProxy := range []bool{false, true} {
				pol, err := adp.Resolve(t.Context(), ResolveRequest{
					NodeID:       nodeID,
					ResolveProxy: resolveProxy,
				})
				if err != nil {
					t.Fatalf("Resolve(%q, ResolveProxy=%v): %v", nodeID, resolveProxy, err)
				}
				if got := pol.EffectiveJump(); got != tc.wantJump {
					t.Fatalf("Resolve(%q, ResolveProxy=%v).EffectiveJump() = %q, want %q", nodeID, resolveProxy, got, tc.wantJump)
				}
			}

			clientCfg, err := adp.GetConfig(nodeID)
			if err != nil {
				t.Fatalf("GetConfig(%q): %v", nodeID, err)
			}
			if clientCfg.ProxyJump != tc.wantJump {
				t.Fatalf("GetConfig(%q).ProxyJump = %q, want %q", nodeID, clientCfg.ProxyJump, tc.wantJump)
			}

			// CapturePlan must resolve every hop cleanly without ErrNodeNotFound.
			plan, err := ssh.CapturePlan(t.Context(), adp, nodeID, "p7-w7c-m3")
			if err != nil {
				t.Fatalf("CapturePlan(%q): %v", nodeID, err)
			}
			if len(plan.Hops) != len(tc.wantHops) {
				t.Fatalf("CapturePlan(%q) hop count = %d (%+v), want %d (%v)", nodeID, len(plan.Hops), plan.Hops, len(tc.wantHops), tc.wantHops)
			}
			for i, wantID := range tc.wantHops {
				if plan.Hops[i].NodeID != wantID {
					t.Fatalf("CapturePlan(%q).Hops[%d].NodeID = %q, want %q", nodeID, i, plan.Hops[i].NodeID, wantID)
				}
			}

			// Control plane and dial plane must produce identical %j and %C ControlPath.
			ctrlSock, ctrlRes, err := ResolveControlSocketPath(ControlTargetRequest{
				Provider:    repo,
				Target:      config.ConnectionTarget{Selector: nodeID},
				Environment: &env,
			})
			if err != nil {
				t.Fatalf("ResolveControlSocketPath(%q): %v", nodeID, err)
			}
			dialCtrl, err := adp.GetControlConfig(nodeID)
			if err != nil {
				t.Fatalf("GetControlConfig(%q): %v", nodeID, err)
			}
			dialTarget := ssh.BuildClientTargetContext(nodeID, clientCfg, env, nil)
			dialSock, err := dialCtrl.ResolvePath(env, dialTarget)
			if err != nil {
				t.Fatalf("dial ResolvePath(%q): %v", nodeID, err)
			}
			if ctrlRes.Target.JumpHost != tc.wantJump || dialTarget.JumpHost != tc.wantJump {
				t.Fatalf("JumpHost mismatch: control=%q dial=%q want=%q", ctrlRes.Target.JumpHost, dialTarget.JumpHost, tc.wantJump)
			}
			if ctrlSock != dialSock {
				t.Fatalf("ControlPath mismatch:\n  control = %q\n  dial    = %q", ctrlSock, dialSock)
			}
		})
	}
}

func TestP7W7c_DEF7M4_ProviderRejectsDoubleOpenSSHPrefix(t *testing.T) {
	t.Parallel()

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader("Host openssh\n  HostName 10.99.0.1\n  User ops\n  Port 22\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := config.NewProviderWithOpenSSHParser(nil, parser)

	badIDs := []string{
		"openssh:",
		"OPENSSH:",
		"openssh:openssh:22",
		"openssh:OPENSSH:22",
		"openssh:openssh:0022",
		"OPENSSH:openssh:22",
		"openssh:openssh:web",
		"openssh: openssh:22",
	}
	for _, id := range badIDs {
		if _, _, _, err := prov.Resolve(id); err == nil {
			t.Errorf("Provider.Resolve(%q) unexpectedly succeeded, want fail-closed error", id)
		}
		if _, err := prov.ResolveConnection(id); err == nil {
			t.Errorf("Provider.ResolveConnection(%q) unexpectedly succeeded, want fail-closed error", id)
		}
		if _, err := prov.ResolveConnectionWithOrigin(id, "openssh"); err == nil {
			t.Errorf("Provider.ResolveConnectionWithOrigin(%q) unexpectedly succeeded, want fail-closed error", id)
		}
	}

	// Single-prefixed host named "openssh" (without port collision) and user@openssh:port remain valid.
	if _, h, _, err := prov.Resolve("openssh:openssh"); err != nil || h.Address != "10.99.0.1" {
		t.Fatalf("Provider.Resolve(openssh:openssh) = (%+v, %v), want 10.99.0.1", h, err)
	}
	if _, h, id, err := prov.Resolve("openssh:alice@openssh:2222"); err != nil || h.Address != "10.99.0.1" || h.Port != 2222 || id.User != "alice" {
		t.Fatalf("Provider.Resolve(openssh:alice@openssh:2222) = (%+v, %+v, %v), want alice@10.99.0.1:2222", h, id, err)
	}
}
