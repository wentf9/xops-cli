package adapter

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func setupW18cTier4ScopingFixture(t *testing.T, setRuntimeOrigin bool) (*config.Provider, *config.Repository) {
	t.Helper()
	sshCfg := strings.Join([]string{
		"Host app.example.com",
		"  HostName 192.0.2.99",
		"  Port 9999",
		"  ProxyCommand /bin/evil-mismatched",
		"  SendEnv LEAK_MISMATCH",
		"  ConnectTimeout 77",
		"  ControlMaster auto",
		"  ControlPath /tmp/leaked-w18c-%C",
		"",
		"Host app-endpoint-match",
		"  HostName 10.10.0.1",
		"  Port 2222",
		"  ProxyCommand /bin/evil-matched",
		"  SendEnv LEAK_MATCH",
		"  ConnectTimeout 42",
		"  ControlMaster auto",
		"  ControlPath /tmp/scoped-w18c-%C",
		"",
		"Host 10.10.*",
		"  Port 22",
		"  ConnectTimeout 66",
		"",
		"Host short.openssh-only.example.com",
		"  HostName 10.88.0.5",
		"  Port 2205",
		"  ProxyCommand /bin/legit-openssh-proxy",
		"  SendEnv ALLOW_OPENSSH",
		"  ControlMaster auto",
		"  ControlPath /tmp/openssh-only-w18c-%C",
		"",
		"Host *",
		"  ServerAliveInterval 33",
	}, "\n") + "\n"

	makePair := func() (*config.Configuration, *config.OpenSSHParser) {
		parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfg.Hosts.Set("h-app", models.Host{Address: "10.10.0.1", Port: 2222})
		cfg.Identities.Set("id-app", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("app.example.com", models.Node{
			HostRef:     "h-app",
			IdentityRef: "id-app",
			Alias:       []string{"app-saved"},
		})
		return cfg, parser
	}

	roCfg, roParser := makePair()
	roProv := config.NewProviderWithOpenSSHParser(roCfg, roParser)
	repoCfg, repoParser := makePair()
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "xops_config.yaml"), filepath.Join(t.TempDir(), "xops.key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(repoCfg, store, repoParser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	if setRuntimeOrigin {
		origin := config.OpenSSHOrigin{Alias: "app", CanonicalHost: "app.example.com"}
		roProv.SetNodeOpenSSHOrigin("app.example.com", origin)
		repo.SetNodeOpenSSHOrigin("app.example.com", origin)
	}
	return roProv, repo
}

func assertW18cNoUnsafeOrMismatchedTier4(t *testing.T, pol EffectivePolicy, desc string) {
	t.Helper()
	opts := pol.Options()
	if opts == nil {
		return
	}
	if got := opts.ActiveProxyCommand(); got != "" {
		t.Fatalf("%s: leaked Tier-4 ProxyCommand=%q", desc, got)
	}
	if pol.Proxy().Kind() == ssh.ProxyCommand {
		t.Fatalf("%s: leaked Tier-4 ProxyCommand via Proxy()", desc)
	}
	if envVal := opts.Get(ssh.OptionSendEnv); envVal != "" {
		t.Fatalf("%s: leaked Tier-4 SendEnv=%q", desc, envVal)
	}
	if got := opts.Get(ssh.OptionConnectTimeout); got == "77" || got == "66" {
		t.Fatalf("%s: leaked mismatched Tier-4 ConnectTimeout=%q", desc, got)
	}
	if got := opts.ControlPath(); strings.Contains(got, "leaked-w18c") {
		t.Fatalf("%s: leaked mismatched Tier-4 ControlPath=%q", desc, got)
	}
}

func TestP7W18c_L3_18_H1_AdHocPendingAndControlTargetTier4Scoping(t *testing.T) {
	t.Parallel()
	t.Run("dial_saved_node_canonicalized_and_runtime_origin_stays_scoped_and_filtered", assertW18cDialSavedDerivedScoping)
	t.Run("control_plane_never_rewrites_saved_derived_lookupKey_to_openssh", assertW18cControlSavedDerivedScoping)
	t.Run("genuine_openssh_canonical_target_still_uses_openssh_lookupKey", assertW18cGenuineOpenSSHControlLookup)
}

func assertW18cDialSavedDerivedScoping(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name             string
		setRuntimeOrigin bool
		target           config.ConnectionTarget
		sessionAuth      SessionAuth
		wantTimeout      string
		wantScopedCtrl   bool
	}{
		{
			name: "canonicalized_user_override_blocks_mismatched_and_filters_matched",
			target: config.ConnectionTarget{
				Selector:     "app.example.com",
				OriginalHost: "app",
				User:         "altuser",
				HasUser:      true,
			},
			sessionAuth:    SessionAuth{OriginalHost: "app", CanonicalHost: "app.example.com", User: "altuser"},
			wantTimeout:    "42",
			wantScopedCtrl: true,
		},
		{
			name:             "runtime_origin_user_override_blocks_mismatched_and_filters_matched",
			setRuntimeOrigin: true,
			target:           config.ConnectionTarget{Selector: "app-saved", User: "altuser", HasUser: true},
			sessionAuth:      SessionAuth{User: "altuser"},
			wantTimeout:      "42",
			wantScopedCtrl:   true,
		},
		{
			name: "canonicalized_port_2223_override_blocks_both_9999_and_2222",
			target: config.ConnectionTarget{
				Selector:     "app.example.com",
				OriginalHost: "app",
				Port:         2223,
				HasPort:      true,
			},
			sessionAuth:    SessionAuth{OriginalHost: "app", CanonicalHost: "app.example.com", Port: 2223},
			wantTimeout:    "",
			wantScopedCtrl: false,
		},
		{
			name: "hostname_override_scopes_away_from_10_10_0_1",
			target: config.ConnectionTarget{
				Selector:     "app.example.com",
				OriginalHost: "app",
				User:         "altuser",
				HasUser:      true,
			},
			sessionAuth:    SessionAuth{HostName: "10.10.0.99", OriginalHost: "app", CanonicalHost: "app.example.com", User: "altuser"},
			wantTimeout:    "",
			wantScopedCtrl: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, repo := setupW18cTier4ScopingFixture(t, tc.setRuntimeOrigin)
			if err := repo.WithPendingNode(t.Context(), config.EnsureNodeOptions{Target: tc.target}, func(lease config.PendingLease) error {
				snap, err := repo.ResolveConnection(lease.NodeID())
				if err != nil {
					t.Fatalf("ResolveConnection: %v", err)
				}
				if snap.Provenance != config.ProvenanceAdHocPending {
					t.Fatalf("Provenance = %s, want adhoc_pending", snap.Provenance)
				}
				adp := NewSSHAdapter(repo, WithLocalExecution(true), WithSessionAuthOverride(lease.NodeID(), tc.sessionAuth))
				pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: lease.NodeID(), ResolveProxy: true})
				if err != nil {
					t.Fatalf("Resolve: %v", err)
				}
				assertW18cNoUnsafeOrMismatchedTier4(t, pol, tc.name)
				gotTimeout := ""
				if opts := pol.Options(); opts != nil {
					gotTimeout = opts.Get(ssh.OptionConnectTimeout)
				}
				if gotTimeout != tc.wantTimeout {
					t.Fatalf("ConnectTimeout = %q, want %q", gotTimeout, tc.wantTimeout)
				}
				if tc.wantScopedCtrl {
					if ctrl := pol.Control(); ctrl == nil || !strings.Contains(ctrl.Path, "scoped-w18c") {
						t.Fatalf("Control = %+v, want scoped-w18c for matching 10.10.0.1:2222 endpoint", ctrl)
					}
				} else if ctrl := pol.Control(); ctrl != nil {
					t.Fatalf("Control = %+v, want nil for non-matching endpoint", ctrl)
				}
				return nil
			}); err != nil {
				t.Fatalf("WithPendingNode: %v", err)
			}
		})
	}
}

func assertW18cControlSavedDerivedScoping(t *testing.T) {
	t.Parallel()
	env := ssh.Environment{HomeDir: t.TempDir(), LocalUser: "localuser", LocalHost: "localhost"}
	for _, tc := range []struct {
		name             string
		setRuntimeOrigin bool
		req              ControlTargetRequest
		wantLookupKey    string
		wantCtrlNil      bool
	}{
		{
			name: "canonicalized_user_override",
			req: ControlTargetRequest{
				Target:                config.ConnectionTarget{Selector: "app.example.com", OriginalHost: "app", User: "altuser", HasUser: true},
				CanonicalOriginalHost: "app",
				CanonicalHost:         "app.example.com",
				Environment:           &env,
			},
			wantLookupKey: "altuser@10.10.0.1:2222",
			wantCtrlNil:   false,
		},
		{
			name: "canonicalized_port_2223_override",
			req: ControlTargetRequest{
				Target:                config.ConnectionTarget{Selector: "app.example.com", OriginalHost: "app", Port: 2223, HasPort: true},
				CanonicalOriginalHost: "app",
				CanonicalHost:         "app.example.com",
				Environment:           &env,
			},
			wantLookupKey: "ops@10.10.0.1:2223",
			wantCtrlNil:   true,
		},
		{
			name:             "runtime_origin_user_override",
			setRuntimeOrigin: true,
			req: ControlTargetRequest{
				Target:      config.ConnectionTarget{Selector: "app-saved", User: "altuser", HasUser: true},
				Environment: &env,
			},
			wantLookupKey: "altuser@10.10.0.1:2222",
			wantCtrlNil:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			roProv, _ := setupW18cTier4ScopingFixture(t, tc.setRuntimeOrigin)
			req := tc.req
			req.Provider = roProv
			sockPath, res, err := ResolveControlSocketPath(req)
			if err != nil {
				t.Fatalf("ResolveControlSocketPath: %v", err)
			}
			if res.LookupKey != tc.wantLookupKey || config.IsOpenSSHNodeID(res.LookupKey) {
				t.Fatalf("LookupKey = %q, want non-OpenSSH %q", res.LookupKey, tc.wantLookupKey)
			}
			if strings.Contains(sockPath, "leaked-w18c") {
				t.Fatalf("ControlPath leaked mismatched Host app.example.com: %q", sockPath)
			}
			if tc.wantCtrlNil {
				if sockPath != "" {
					t.Fatalf("sockPath = %q, want empty for port 2223", sockPath)
				}
			} else if !strings.Contains(sockPath, "scoped-w18c") {
				t.Fatalf("sockPath = %q, want endpoint-matched scoped-w18c", sockPath)
			}
			adp := NewSSHAdapter(roProv, WithLocalExecution(true), WithControlProxyMode(true), WithSessionAuthOverride(res.LookupKey, res.SessionAuth))
			pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: res.LookupKey, ResolveProxy: true})
			if err != nil {
				t.Fatalf("Resolve(%q): %v", res.LookupKey, err)
			}
			assertW18cNoUnsafeOrMismatchedTier4(t, pol, tc.name)
		})
	}
}

func assertW18cGenuineOpenSSHControlLookup(t *testing.T) {
	t.Parallel()
	roProv, _ := setupW18cTier4ScopingFixture(t, false)
	env := ssh.Environment{HomeDir: t.TempDir(), LocalUser: "localuser", LocalHost: "localhost"}
	sockPath, res, err := ResolveControlSocketPath(ControlTargetRequest{
		Provider:              roProv,
		Target:                config.ConnectionTarget{Selector: "short.openssh-only.example.com", OriginalHost: "short", User: "alt", HasUser: true},
		CanonicalOriginalHost: "short",
		CanonicalHost:         "short.openssh-only.example.com",
		Environment:           &env,
	})
	if err != nil {
		t.Fatalf("ResolveControlSocketPath(openssh-only): %v", err)
	}
	if res.LookupKey != "openssh:short.openssh-only.example.com" {
		t.Fatalf("LookupKey = %q, want openssh:short.openssh-only.example.com", res.LookupKey)
	}
	if !strings.Contains(sockPath, "openssh-only-w18c") {
		t.Fatalf("sockPath = %q, want openssh-only-w18c", sockPath)
	}
}
