package adapter

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func buildW16bM1Fixtures(t *testing.T, globalOpts *ssh.Options) (*config.Provider, *config.Repository) {
	t.Helper()

	sshCfg := strings.Join([]string{
		"Host jump-box",
		"  HostName 10.30.0.1",
		"  User juser",
		"  Port 2201",
		"",
		"Host app-virtual",
		"  HostName 10.30.0.20",
		"  User vuser",
		"  Port 2220",
		"  ProxyJump jump-box",
		"  ControlMaster auto",
		"  ControlPath /tmp/cm-app-%h-%p-%r-%n-%j-%C",
		"  ControlPersist 60s",
		"  RemoteCommand uptime",
		"  SessionType none",
		"",
		"Host short",
		"  User ops",
		"",
		"Host *.corp.example.com",
		"  HostName 10.40.0.5",
		"  Port 2222",
		"  ControlMaster auto",
		"  ControlPath /tmp/cm-canon-%n-%h-%p-%r-%j-%C",
		"  RemoteCommand date",
		"",
		"Host *",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains corp.example.com",
	}, "\n") + "\n"

	makeCfg := func() (*config.Configuration, *config.OpenSSHParser) {
		parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfg.SSHOptions = globalOpts.Clone()

		cfg.Hosts.Set("h-bastion", models.Host{Address: "10.10.0.254", Port: 22})
		cfg.Identities.Set("id-bastion", models.Identity{User: "jump", AuthType: "auto"})
		cfg.Nodes.Set("bastion", models.Node{HostRef: "h-bastion", IdentityRef: "id-bastion"})

		webOpts := ssh.MustOptions(
			ssh.OptionControlMaster, "auto",
			ssh.OptionControlPath, "/tmp/cm-web01-%h-%p-%r-%n-%j-%C",
			ssh.OptionRemoteCommand, "echo web01",
			ssh.OptionSessionType, "none",
		)
		cfg.Hosts.Set("h-web1", models.Host{Address: "10.10.0.1", Port: 2222})
		cfg.Identities.Set("id-web1", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("web-01", models.Node{
			HostRef:     "h-web1",
			IdentityRef: "id-web1",
			Alias:       []string{"Prod Web 01"},
			ProxyJump:   "bastion",
			SSHOptions:  webOpts,
		})
		return cfg, parser
	}

	roCfg, roParser := makeCfg()
	readOnlyProv := config.NewProviderWithOpenSSHParser(roCfg, roParser)

	repoCfg, repoParser := makeCfg()
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(repoCfg, store, repoParser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	return readOnlyProv, repo
}

func resolveW16bDialBaseline(
	t *testing.T,
	repo *config.Repository,
	env ssh.Environment,
	target config.ConnectionTarget,
	overrideOrig, overrideHost, canonHost string,
) (ssh.TargetContext, string, *ssh.ControlConfig, *ssh.Options) {
	t.Helper()

	var (
		dialTarget ssh.TargetContext
		dialSock   string
		dialCtrl   *ssh.ControlConfig
		dialOpts   *ssh.Options
	)
	if err := repo.WithPendingNode(t.Context(), config.EnsureNodeOptions{
		Target:      target,
		DefaultUser: env.LocalUser,
	}, func(lease config.PendingLease) error {
		nodeID := lease.NodeID()
		adp := NewSSHAdapter(repo,
			WithLocalExecution(true),
			WithSessionAuthOverride(nodeID, SessionAuth{
				HostName:      overrideHost,
				OriginalHost:  overrideOrig,
				CanonicalHost: canonHost,
				ProxyJump:     target.ProxyJump,
			}),
		)
		pol, err := adp.Resolve(t.Context(), ResolveRequest{
			NodeID:          nodeID,
			RequireSnapshot: true,
			ResolveProxy:    true,
		})
		if err != nil {
			t.Fatalf("dial Resolve(%q): %v", nodeID, err)
		}
		clientCfg, err := pol.ClientConfig()
		if err != nil {
			t.Fatalf("dial ClientConfig(%q): %v", nodeID, err)
		}
		dialCtrl = pol.Control()
		dialOpts = pol.Options()
		dialTarget = ssh.BuildClientTargetContext(nodeID, clientCfg, env, nil)
		if dialCtrl.IsEnabled() {
			var pathErr error
			dialSock, pathErr = dialCtrl.ResolvePath(env, dialTarget)
			if pathErr != nil {
				t.Fatalf("dial ResolvePath(%q): %v", nodeID, pathErr)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPendingNode: %v", err)
	}
	return dialTarget, dialSock, dialCtrl, dialOpts
}

type w16bOpenSSHOverrideCase struct {
	name          string
	target        config.ConnectionTarget
	overrideOrig  string
	overrideHost  string
	canonOrig     string
	canonHost     string
	wantLookupKey string
	wantRemoteCmd string
	wantPathPref  string
}

func assertW16bOpenSSHAliasOverrideCase(t *testing.T, env ssh.Environment, tc w16bOpenSSHOverrideCase) {
	t.Helper()
	roProv, repo := buildW16bM1Fixtures(t, nil)

	req := ControlTargetRequest{
		Provider:                 roProv,
		Target:                   tc.target,
		ApplyTargetNodeOverrides: true,
		OverrideOriginalHost:     tc.overrideOrig,
		OverrideExpandedHost:     tc.overrideHost,
		CanonicalOriginalHost:    tc.canonOrig,
		CanonicalHost:            tc.canonHost,
		Environment:              &env,
	}
	ctrlSock, ctrlRes, err := ResolveControlSocketPath(req)
	if err != nil {
		t.Fatalf("ResolveControlSocketPath: %v", err)
	}
	if ctrlRes.LookupKey != tc.wantLookupKey {
		t.Fatalf("LookupKey = %q, want %q", ctrlRes.LookupKey, tc.wantLookupKey)
	}
	if !strings.HasPrefix(ctrlSock, tc.wantPathPref) {
		t.Fatalf("control socket = %q, want prefix %q", ctrlSock, tc.wantPathPref)
	}

	dialTarget, dialSock, _, dialOpts := resolveW16bDialBaseline(t, repo, env, tc.target, tc.overrideOrig, tc.overrideHost, tc.canonHost)
	if ctrlRes.Target != dialTarget || ctrlSock != dialSock {
		t.Fatalf("control vs dial mismatch:\n  target: %+v vs %+v\n  sock:   %q vs %q", ctrlRes.Target, dialTarget, ctrlSock, dialSock)
	}

	roPol, err := NewSSHAdapter(roProv, WithSessionAuthOverride(ctrlRes.LookupKey, ctrlRes.SessionAuth)).Resolve(t.Context(), ResolveRequest{
		NodeID:       ctrlRes.LookupKey,
		ResolveProxy: true,
	})
	if err != nil {
		t.Fatalf("ro Resolve(%q): %v", ctrlRes.LookupKey, err)
	}
	if got := roPol.Options().Get(ssh.OptionRemoteCommand); got != tc.wantRemoteCmd {
		t.Fatalf("ro Resolve(%q) RemoteCommand = %q, want %q (dial=%q)", ctrlRes.LookupKey, got, tc.wantRemoteCmd, dialOpts.Get(ssh.OptionRemoteCommand))
	}
	if gotTarget := roPol.controlTargetContextWithEnv(roPol.nodeID, env); gotTarget != dialTarget {
		t.Fatalf("ro Policy TargetContext mismatch:\n  ro   = %+v\n  dial = %+v", gotTarget, dialTarget)
	}
	if roCfg, err := roPol.ClientConfig(); err != nil || roCfg.Port != dialTarget.Port || roCfg.User != dialTarget.User || roCfg.Address != dialTarget.Host {
		t.Fatalf("ro ClientConfig = (%+v, %v), want host=%q port=%d user=%q", roCfg, err, dialTarget.Host, dialTarget.Port, dialTarget.User)
	}

	directCtrl, err := ResolveControlConfig(roProv, "", tc.target.Selector, SessionAuth{
		HostName:      tc.overrideHost,
		User:          tc.target.User,
		Port:          tc.target.Port,
		OriginalHost:  tc.overrideOrig,
		CanonicalHost: tc.canonHost,
	}, SessionControlOptions{})
	if err != nil || !directCtrl.IsEnabled() {
		t.Fatalf("ResolveControlConfig(empty lookupKey, %s) = (%+v, %v), want enabled ControlConfig", tc.name, directCtrl, err)
	}
}

func assertW16bNoSnapshotOpenSSHOverride(t *testing.T, env ssh.Environment) {
	t.Helper()
	roProv, _ := buildW16bM1Fixtures(t, nil)
	noSnapProv := w13cNoSnapshotProvider{ConfigProvider: roProv}

	adp := NewSSHAdapter(noSnapProv, WithSessionAuthOverride("openssh:app-virtual", SessionAuth{
		Port:         2299,
		User:         "altuser",
		OriginalHost: "app-virtual",
	}))
	pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "openssh:app-virtual", ResolveProxy: true})
	if err != nil {
		t.Fatalf("Resolve(noSnap, openssh:app-virtual): %v", err)
	}
	if pol.hasSnapshot {
		t.Fatal("expected !hasSnapshot for w13cNoSnapshotProvider")
	}
	if ctrl := pol.Control(); ctrl == nil || ctrl.Path != "/tmp/cm-app-%h-%p-%r-%n-%j-%C" || ctrl.Persist != "60s" {
		t.Fatalf("noSnap Control() = %+v, want Host app-virtual ControlConfig", ctrl)
	}
	if opts := pol.Options(); opts == nil || opts.Get(ssh.OptionRemoteCommand) != "uptime" || opts.SessionType() != ssh.SessionTypeNone {
		t.Fatalf("noSnap Options() = %v, want RemoteCommand=uptime and SessionType=none", opts)
	}
	if pol.EffectiveJump() != "openssh:jump-box" {
		t.Fatalf("noSnap EffectiveJump() = %q, want openssh:jump-box", pol.EffectiveJump())
	}
	gotTarget := pol.controlTargetContextWithEnv(pol.nodeID, env)
	if gotTarget.Host != "10.30.0.20" || gotTarget.Port != 2299 || gotTarget.User != "altuser" || gotTarget.OriginalHost != "app-virtual" || gotTarget.JumpHost != "openssh:jump-box" {
		t.Fatalf("noSnap TargetContext = %+v", gotTarget)
	}

	adpCanon := NewSSHAdapter(noSnapProv, WithSessionAuthOverride("openssh:short.corp.example.com", SessionAuth{
		Port:          2299,
		OriginalHost:  "short",
		CanonicalHost: "short.corp.example.com",
	}))
	polCanon, err := adpCanon.Resolve(t.Context(), ResolveRequest{NodeID: "openssh:short.corp.example.com"})
	if err != nil {
		t.Fatalf("Resolve(noSnap, canonical): %v", err)
	}
	if ctrl := polCanon.Control(); ctrl == nil || ctrl.Path != "/tmp/cm-canon-%n-%h-%p-%r-%j-%C" {
		t.Fatalf("noSnap canonical Control() = %+v, want Pass-2 ControlPath", ctrl)
	}
	if opts := polCanon.Options(); opts == nil || opts.Get(ssh.OptionRemoteCommand) != "date" {
		t.Fatalf("noSnap canonical Options() = %v, want RemoteCommand=date", opts)
	}
}

func TestP7W16b_L3_16_M1_OverriddenOpenSSHAliasControlAndPreDialParity(t *testing.T) {
	t.Parallel()

	env := w10cTestEnv()
	cases := []w16bOpenSSHOverrideCase{
		{
			name: "openssh_alias_port_override_no_global_mux",
			target: config.ConnectionTarget{
				Selector: "app-virtual",
				Port:     2299,
				HasPort:  true,
			},
			overrideOrig:  "app-virtual",
			wantLookupKey: "openssh:app-virtual",
			wantRemoteCmd: "uptime",
			wantPathPref:  "/tmp/cm-app-10.30.0.20-2299-vuser-app-virtual-openssh:jump-box-",
		},
		{
			name: "openssh_alias_user_override_no_global_mux",
			target: config.ConnectionTarget{
				Selector: "app-virtual",
				User:     "altuser",
				HasUser:  true,
			},
			overrideOrig:  "app-virtual",
			wantLookupKey: "openssh:app-virtual",
			wantRemoteCmd: "uptime",
			wantPathPref:  "/tmp/cm-app-10.30.0.20-2220-altuser-app-virtual-openssh:jump-box-",
		},
		{
			name: "openssh_alias_user_port_hostname_override_no_global_mux",
			target: config.ConnectionTarget{
				Selector: "app-virtual",
				User:     "altuser",
				HasUser:  true,
				Port:     2299,
				HasPort:  true,
			},
			overrideOrig:  "app-virtual",
			overrideHost:  "10.30.0.99",
			wantLookupKey: "openssh:app-virtual",
			wantRemoteCmd: "uptime",
			wantPathPref:  "/tmp/cm-app-10.30.0.99-2299-altuser-app-virtual-openssh:jump-box-",
		},
		{
			name: "openssh_twopass_canonical_port_override_no_global_mux",
			target: config.ConnectionTarget{
				Selector:     "short.corp.example.com",
				OriginalHost: "short",
				Port:         2299,
				HasPort:      true,
			},
			overrideOrig:  "short",
			canonOrig:     "short",
			canonHost:     "short.corp.example.com",
			wantLookupKey: "openssh:short.corp.example.com",
			wantRemoteCmd: "date",
			wantPathPref:  "/tmp/cm-canon-short-10.40.0.5-2299-ops--",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertW16bOpenSSHAliasOverrideCase(t, env, tc)
		})
	}
	t.Run("no_snapshot_provider_openssh_override_matches_derived_provenance", func(t *testing.T) {
		t.Parallel()
		assertW16bNoSnapshotOpenSSHOverride(t, env)
	})
}

func TestP7W16b_L3_16_M1_OverriddenSavedNodeDoesNotLeakTier2Options(t *testing.T) {
	t.Parallel()

	env := w10cTestEnv()

	t.Run("no_global_mux_saved_node_port_and_user_overrides_do_not_leak_tier2", func(t *testing.T) {
		t.Parallel()
		roProv, repo := buildW16bM1Fixtures(t, nil)

		for _, tc := range []struct {
			name         string
			selector     string
			auth         SessionAuth
			target       config.ConnectionTarget
			overrideOrig string
			wantKey      string
		}{
			{
				name:         "port_override_by_id_with_override_orig",
				selector:     "web-01",
				auth:         SessionAuth{Port: 2299},
				target:       config.ConnectionTarget{Selector: "web-01", Port: 2299, HasPort: true},
				overrideOrig: "web-01",
				wantKey:      "ops@10.10.0.1:2299",
			},
			{
				name:         "user_override_by_id_with_override_orig",
				selector:     "web-01",
				auth:         SessionAuth{User: "altuser"},
				target:       config.ConnectionTarget{Selector: "web-01", User: "altuser", HasUser: true},
				overrideOrig: "web-01",
				wantKey:      "altuser@10.10.0.1:2222",
			},
			{
				name:         "port_override_by_alias_with_override_orig",
				selector:     "Prod Web 01",
				auth:         SessionAuth{Port: 2299},
				target:       config.ConnectionTarget{Selector: "Prod Web 01", Port: 2299, HasPort: true},
				overrideOrig: "Prod Web 01",
				wantKey:      "ops@10.10.0.1:2299",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				ctrl, err := ResolveControlConfig(roProv, "", tc.selector, tc.auth, SessionControlOptions{})
				if err != nil {
					t.Fatalf("ResolveControlConfig(%s): %v", tc.name, err)
				}
				if ctrl != nil {
					t.Fatalf("ResolveControlConfig(%s) leaked saved web-01 ControlConfig: %+v", tc.name, ctrl)
				}

				sock, res, err := ResolveControlSocketPath(ControlTargetRequest{
					Provider:                 roProv,
					Target:                   tc.target,
					ApplyTargetNodeOverrides: true,
					OverrideOriginalHost:     tc.overrideOrig,
					Environment:              &env,
				})
				if err != nil {
					t.Fatalf("ResolveControlSocketPath(%s): %v", tc.name, err)
				}
				if sock != "" {
					t.Fatalf("ResolveControlSocketPath(%s) leaked saved web-01 ControlPath: %q", tc.name, sock)
				}
				if res.LookupKey != tc.wantKey {
					t.Fatalf("ResolveControlSocketPath(%s).LookupKey = %q, want %q (must not revert to %q)", tc.name, res.LookupKey, tc.wantKey, tc.overrideOrig)
				}

				pol, err := NewSSHAdapter(roProv, WithSessionAuthOverride(res.LookupKey, res.SessionAuth)).Resolve(t.Context(), ResolveRequest{
					NodeID: res.LookupKey,
				})
				if err != nil {
					t.Fatalf("Resolve(%q): %v", res.LookupKey, err)
				}
				if opts := pol.Options(); opts != nil && (opts.Get(ssh.OptionRemoteCommand) != "" || opts.SessionType() == ssh.SessionTypeNone) {
					t.Fatalf("Resolve(%q) leaked saved web-01 RemoteCommand/SessionType: %v", res.LookupKey, opts)
				}

				// Confirm dial plane also has no ControlConfig and no RemoteCommand.
				_, dialSock, dialCtrl, dialOpts := resolveW16bDialBaseline(t, repo, env, tc.target, "", "", "")
				if dialSock != "" || dialCtrl != nil {
					t.Fatalf("dial plane unexpectedly had ControlConfig %+v (sock=%q)", dialCtrl, dialSock)
				}
				if dialOpts != nil && dialOpts.Get(ssh.OptionRemoteCommand) != "" {
					t.Fatalf("dial plane unexpectedly leaked RemoteCommand: %v", dialOpts)
				}
			})
		}
	})

	t.Run("global_mux_used_instead_of_saved_node_tier2_on_port_override", func(t *testing.T) {
		t.Parallel()
		globalMux := ssh.MustOptions(
			ssh.OptionControlMaster, "auto",
			ssh.OptionControlPath, "/tmp/cm-global-%h-%p-%r-%n-%j-%C",
		)
		roProv, repo := buildW16bM1Fixtures(t, globalMux)
		target := config.ConnectionTarget{Selector: "web-01", Port: 2299, HasPort: true}

		ctrlSock, ctrlRes, err := ResolveControlSocketPath(ControlTargetRequest{
			Provider:    roProv,
			Target:      target,
			Environment: &env,
		})
		if err != nil {
			t.Fatalf("ResolveControlSocketPath: %v", err)
		}
		if !strings.HasPrefix(ctrlSock, "/tmp/cm-global-10.10.0.1-2299-ops-") {
			t.Fatalf("control socket = %q, want Tier-3 global prefix /tmp/cm-global-10.10.0.1-2299-ops- (not web-01 Tier-2)", ctrlSock)
		}
		dialTarget, dialSock, _, _ := resolveW16bDialBaseline(t, repo, env, target, "", "", "")
		if ctrlRes.Target != dialTarget || ctrlSock != dialSock {
			t.Fatalf("control vs dial mismatch:\n  target: %+v vs %+v\n  sock:   %q vs %q", ctrlRes.Target, dialTarget, ctrlSock, dialSock)
		}
	})
}

func newW16bM2HostAliasRepo(t *testing.T) *config.Repository {
	t.Helper()
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-web", models.Host{
		Address: "10.236.0.10",
		Port:    2200,
		Alias:   []string{"bastion-host"},
	})
	cfg.Identities.Set("id-web", models.Identity{
		User:     "ops",
		AuthType: "password",
		Password: "initial-web-pw",
	})
	cfg.Nodes.Set("web-node", models.Node{
		HostRef:     "h-web",
		IdentityRef: "id-web",
		Alias:       nil,
	})

	// Shared host referenced by two nodes (hostRefCount == 2): Host.Alias must NOT cross-leak.
	cfg.Hosts.Set("h-shared", models.Host{
		Address: "10.236.0.20",
		Port:    22,
		Alias:   []string{"shared-host"},
	})
	cfg.Identities.Set("id-a", models.Identity{User: "usera", AuthType: "password", Password: "pw-a"})
	cfg.Identities.Set("id-b", models.Identity{User: "userb", AuthType: "password", Password: "pw-b"})
	cfg.Nodes.Set("shared-a", models.Node{HostRef: "h-shared", IdentityRef: "id-a"})
	cfg.Nodes.Set("shared-b", models.Node{HostRef: "h-shared", IdentityRef: "id-b"})

	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	return repo
}

func assertW16bM2SingleNodeHostAliasOverrides(t *testing.T, repo *config.Repository) {
	t.Helper()

	override := SessionAuth{
		HostName: "10.236.0.99",
		Port:     2299,
		User:     "alice",
		Password: "host-alias-pw",
		OTP:      "654321",
		Remember: false,
	}
	adp := NewSSHAdapter(repo, WithSessionAuthOverride("bastion-host", override))

	for _, id := range []string{"bastion-host", "web-node"} {
		cfg, err := adp.GetConfig(id)
		if err != nil {
			t.Fatalf("GetConfig(%q): %v", id, err)
		}
		if cfg.NodeID != "web-node" || cfg.Address != "10.236.0.99" || cfg.Port != 2299 || cfg.User != "alice" || cfg.Password != "host-alias-pw" {
			t.Fatalf("GetConfig(%q) = %+v, want web-node alice@10.236.0.99:2299 pw=host-alias-pw", id, cfg)
		}

		pwSec, err := adp.ResolveSecret(t.Context(), ssh.SecretRequest{
			NodeID:   id,
			Kind:     ssh.SecretKindLoginPassword,
			Host:     cfg.Address,
			BaseHost: cfg.BaseHost,
			Port:     cfg.Port,
			User:     cfg.User,
		})
		if err != nil || string(pwSec) != "host-alias-pw" {
			t.Fatalf("ResolveSecret(login, %q) = (%q, %v), want host-alias-pw", id, string(pwSec), err)
		}

		otpSec, err := adp.ResolveSecret(t.Context(), ssh.SecretRequest{
			NodeID:   id,
			Kind:     ssh.SecretKindOTP,
			Host:     cfg.Address,
			BaseHost: cfg.BaseHost,
			Port:     cfg.Port,
			User:     cfg.User,
		})
		if err != nil || string(otpSec) != "654321" {
			t.Fatalf("ResolveSecret(otp, %q) = (%q, %v), want 654321", id, string(otpSec), err)
		}
	}

	// Verify exact-key precedence when both Host.Alias and canonical NodeID are registered.
	adpBoth := NewSSHAdapter(repo,
		WithSessionAuthOverride("bastion-host", SessionAuth{Port: 2244}),
		WithSessionAuthOverride("web-node", SessionAuth{Port: 2255}),
	)
	if c, err := adpBoth.GetConfig("bastion-host"); err != nil || c.Port != 2244 {
		t.Fatalf("GetConfig(bastion-host) with both = (port=%d, err=%v), want 2244", c.Port, err)
	}
	if c, err := adpBoth.GetConfig("web-node"); err != nil || c.Port != 2255 {
		t.Fatalf("GetConfig(web-node) with both = (port=%d, err=%v), want 2255", c.Port, err)
	}
}

func assertW16bM2HostAliasWritebackGuards(t *testing.T, repo *config.Repository) {
	t.Helper()

	adpNoRem := NewSSHAdapter(repo, WithSessionAuthOverride("bastion-host", SessionAuth{
		Password: "session-pw",
		Remember: false,
	}))
	cfg, err := adpNoRem.GetConfig("bastion-host")
	if err != nil || cfg.NodeID != "web-node" {
		t.Fatalf("GetConfig(bastion-host) = (%+v, %v), want NodeID=web-node", cfg, err)
	}
	if tok, err := adpNoRem.UpdateAuth(t.Context(), "web-node", cfg.AuthUpdateToken, "leaked-pw", "", ""); err != nil || tok != cfg.AuthUpdateToken {
		t.Fatalf("UpdateAuth(web-node with Remember:false on bastion-host) = (%q, %v), want unchanged token", tok, err)
	}
	if tok, err := adpNoRem.UpdateSudo(t.Context(), "web-node", cfg.SudoUpdateToken, ssh.SudoModeSu, "leaked-su"); err != nil || tok != cfg.SudoUpdateToken {
		t.Fatalf("UpdateSudo(web-node with Remember:false on bastion-host) = (%q, %v), want unchanged token", tok, err)
	}
	snap, err := repo.ResolveConnection("web-node")
	if err != nil || snap.Identity.Password != "initial-web-pw" || snap.Node.SuPwd != "" {
		t.Fatalf("Remember:false on Host.Alias leaked writeback: ident=%+v node=%+v err=%v", snap.Identity, snap.Node, err)
	}

	batchOpts, err := ParseSessionOptions([]string{"BatchMode=yes"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions(BatchMode=yes): %v", err)
	}
	globalOpts, err := ParseSessionOptions([]string{"ConnectTimeout=5"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions(ConnectTimeout=5): %v", err)
	}
	adpBatch := NewSSHAdapter(repo,
		WithSessionControlOverride("bastion-host", batchOpts),
		WithGlobalSessionControl(globalOpts),
		WithSessionAuthOverride("bastion-host", SessionAuth{Remember: true}),
	)
	if !adpBatch.interactiveDecisionForNode("web-node").Denied() {
		t.Fatal("interactiveDecisionForNode(web-node) missed BatchMode=yes on Host.Alias bastion-host")
	}
	if tok, err := adpBatch.UpdateAuth(t.Context(), "web-node", cfg.AuthUpdateToken, "batch-leaked", "", ""); err != nil || tok != cfg.AuthUpdateToken {
		t.Fatalf("UpdateAuth(web-node under BatchMode=yes on bastion-host) = (%q, %v), want unchanged token", tok, err)
	}
}

func assertW16bM2HostAliasSuppressAndDisableMux(t *testing.T, repo *config.Repository) {
	t.Helper()

	confirmCalled := false
	lease := w16bStubPendingLease{
		nodeID: "web-node",
		onConfirm: func() error {
			confirmCalled = true
			return nil
		},
	}
	adpSuppress := NewSSHAdapter(repo, WithSessionAuthOverride("bastion-host", SessionAuth{
		SuppressNodeConfirmation: true,
	}))
	if err := adpSuppress.FinalizePendingConnection(t.Context(), lease, nil); err != nil {
		t.Fatalf("FinalizePendingConnection(web-node with SuppressNodeConfirmation on bastion-host): %v", err)
	}
	if confirmCalled {
		t.Fatal("FinalizePendingConnection confirmed web-node despite SuppressNodeConfirmation on Host.Alias bastion-host")
	}

	muxOpts, err := ParseSessionOptions([]string{"ControlMaster=yes", "ControlPath=/tmp/cm-%C", "ConnectTimeout=9"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions(mux): %v", err)
	}
	adpMux := NewSSHAdapter(repo, WithSessionControlOverride("bastion-host", muxOpts))
	adpMux.DisableSessionControlSharing("web-node")
	for _, id := range []string{"web-node", "bastion-host"} {
		pol, err := adpMux.Resolve(t.Context(), ResolveRequest{NodeID: id})
		if err != nil {
			t.Fatalf("Resolve(%q) after DisableSessionControlSharing: %v", id, err)
		}
		if ctrl := pol.Control(); ctrl == nil || ctrl.Path != "none" || ctrl.Master != ssh.ControlMasterNo {
			t.Fatalf("Resolve(%q).Control() = %+v, want disabled none", id, ctrl)
		}
		if opts := pol.Options(); opts == nil || opts.Get(ssh.OptionConnectTimeout) != "9" {
			t.Fatalf("Resolve(%q) dropped ConnectTimeout=9: %v", id, opts)
		}
	}
}

func assertW16bM2HostAliasDirectWriteback(t *testing.T, repo *config.Repository) {
	t.Helper()

	adpWrite := NewSSHAdapter(repo, WithSessionAuthOverride("bastion-host", SessionAuth{Remember: true}))
	cfgW, err := adpWrite.GetConfig("bastion-host")
	if err != nil {
		t.Fatalf("GetConfig(bastion-host): %v", err)
	}
	if nextTok, err := adpWrite.UpdateAuth(t.Context(), "bastion-host", cfgW.AuthUpdateToken, "saved-via-host-alias", "", ""); err != nil || nextTok == cfgW.AuthUpdateToken {
		t.Fatalf("UpdateAuth(bastion-host) = (%q, %v), want updated token", nextTok, err)
	}
	if nextSudo, err := adpWrite.UpdateSudo(t.Context(), "bastion-host", cfgW.SudoUpdateToken, ssh.SudoModeSu, "su-via-host-alias"); err != nil || nextSudo == cfgW.SudoUpdateToken {
		t.Fatalf("UpdateSudo(bastion-host) = (%q, %v), want updated token", nextSudo, err)
	}
	snapAfter, err := repo.ResolveConnection("web-node")
	if err != nil || snapAfter.Identity.Password != "saved-via-host-alias" || snapAfter.Node.SuPwd != "su-via-host-alias" {
		t.Fatalf("direct Host.Alias writeback failed: ident=%+v node=%+v err=%v", snapAfter.Identity, snapAfter.Node, err)
	}
}

func assertW16bM2HostAliasCallbacksAndDisableMux(t *testing.T) {
	t.Helper()
	repo := newW16bM2HostAliasRepo(t)
	assertW16bM2HostAliasWritebackGuards(t, repo)
	assertW16bM2HostAliasSuppressAndDisableMux(t, repo)
	assertW16bM2HostAliasDirectWriteback(t, repo)
}

type w16bStubPendingLease struct {
	nodeID    string
	onConfirm func() error
}

func (l w16bStubPendingLease) NodeID() string { return l.nodeID }
func (l w16bStubPendingLease) Confirm(context.Context) error {
	if l.onConfirm != nil {
		return l.onConfirm()
	}
	return nil
}

func assertW16bM2SharedMultiNodeHostAliasDoesNotCrossLeak(t *testing.T, repo *config.Repository) {
	t.Helper()

	if got := repo.FindAlias("shared-host"); got != "" {
		t.Fatalf("expected shared multi-node Host.Alias shared-host to be ambiguous (FindAlias==\"\"), got %q", got)
	}

	batchMuxOpts, err := ParseSessionOptions([]string{"BatchMode=yes", "ControlMaster=yes", "ControlPath=/tmp/cm-shared-%C", "ConnectTimeout=44"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions: %v", err)
	}
	adp := NewSSHAdapter(repo,
		WithSessionAuthOverride("shared-host", SessionAuth{
			HostName:                 "10.236.0.250",
			Port:                     2288,
			User:                     "intruder",
			Password:                 "leaked-shared-pw",
			OTP:                      "999999",
			Remember:                 false,
			SuppressNodeConfirmation: true,
		}),
		WithSessionControlOverride("shared-host", batchMuxOpts),
	)

	for _, tc := range []struct {
		nodeID   string
		wantUser string
		wantPW   string
	}{
		{"shared-a", "usera", "pw-a"},
		{"shared-b", "userb", "pw-b"},
	} {
		cfg, err := adp.GetConfig(tc.nodeID)
		if err != nil {
			t.Fatalf("GetConfig(%q): %v", tc.nodeID, err)
		}
		if cfg.Address != "10.236.0.20" || cfg.Port != 22 || cfg.User != tc.wantUser || cfg.Password != tc.wantPW {
			t.Fatalf("shared-host override leaked onto %s: %+v", tc.nodeID, cfg)
		}
		if adp.interactiveDecisionForNode(tc.nodeID).Denied() {
			t.Fatalf("shared-host BatchMode=yes leaked onto %s", tc.nodeID)
		}
		pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: tc.nodeID})
		if err != nil {
			t.Fatalf("Resolve(%q): %v", tc.nodeID, err)
		}
		if pol.Control() != nil || (pol.Options() != nil && pol.Options().Get(ssh.OptionConnectTimeout) == "44") {
			t.Fatalf("shared-host control override leaked onto %s: ctrl=%+v opts=%v", tc.nodeID, pol.Control(), pol.Options())
		}
		pwSec, err := adp.ResolveSecret(t.Context(), ssh.SecretRequest{
			NodeID: tc.nodeID,
			Kind:   ssh.SecretKindLoginPassword,
			Host:   cfg.Address,
			Port:   cfg.Port,
			User:   cfg.User,
		})
		if err != nil || string(pwSec) != tc.wantPW {
			t.Fatalf("ResolveSecret(%q) = (%q, %v), want %q", tc.nodeID, string(pwSec), err, tc.wantPW)
		}
	}

	// DisableSessionControlSharing on shared-a must NOT mutate the unrelated "shared-host" key.
	adp.DisableSessionControlSharing("shared-a")
	if sharedEntry, ok := adp.sessionControlOverrides["shared-host"]; !ok || sharedEntry.Path == nil || *sharedEntry.Path != "/tmp/cm-shared-%C" {
		t.Fatalf("DisableSessionControlSharing(shared-a) mutated ambiguous shared-host override: %+v", sharedEntry)
	}
}

func TestP7W16b_L3_16_M2_HostAliasForwardAndReverseCallbacks(t *testing.T) {
	t.Parallel()

	repo := newW16bM2HostAliasRepo(t)

	t.Run("single_node_host_alias_honors_session_auth_and_secret_overrides", func(t *testing.T) {
		t.Parallel()
		assertW16bM2SingleNodeHostAliasOverrides(t, repo)
	})
	t.Run("single_node_host_alias_honors_batchmode_remember_suppress_and_disable_mux", func(t *testing.T) {
		t.Parallel()
		assertW16bM2HostAliasCallbacksAndDisableMux(t)
	})
	t.Run("shared_multi_node_host_alias_does_not_cross_leak", func(t *testing.T) {
		t.Parallel()
		assertW16bM2SharedMultiNodeHostAliasDoesNotCrossLeak(t, repo)
	})
}
