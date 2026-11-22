package adapter

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

func newW13cAdapterDeferredAuthFixture(t *testing.T) (*config.Repository, config.Store, *credential.Registry, *SSHAdapter) {
	t.Helper()
	dir := t.TempDir()
	store := config.NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.key"))
	baseCfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	baseCfg.SchemaVersion = 2
	baseCfg.Credential = &config.CredentialConfig{
		DefaultStore:     "mem-store",
		RememberPrompted: "always",
		Stores: map[string]config.StoreConfig{
			"mem-store": {Type: config.StoreTypeEncryptedFile, Path: filepath.Join(dir, "vault"), Unlock: "prompt"},
		},
	}
	if err := store.Save(baseCfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	repo, err := config.NewRepositoryWithoutOpenSSH(baseCfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	for _, n := range []struct{ id, hostRef, addr string }{
		{"saved-bastion", "h-bastion", "10.233.0.1"},
		{"saved-app", "h-app", "10.233.0.2"},
	} {
		if _, err := repo.CreateNodeContext(t.Context(), n.id,
			models.Node{HostRef: n.hostRef, IdentityRef: "id-shared"},
			models.Host{Address: n.addr, Port: 22},
			models.Identity{User: "ops", AuthType: "auto"},
		); err != nil {
			t.Fatalf("CreateNodeContext(%s): %v", n.id, err)
		}
	}
	reg := credential.NewRegistry()
	if err := reg.Register("mem-store", &adapterCredentialStore{data: map[string]credential.Secret{}}); err != nil {
		t.Fatalf("registry.Register: %v", err)
	}
	journal, err := credential.NewJournalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewJournalStore: %v", err)
	}
	credSvc, err := credential.NewService(reg, journal, repo.AsConfigUpdater(), nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	adp := NewSSHAdapter(repo,
		WithCredentialSource(reg),
		WithCredentialService(credSvc),
		WithCredentialRecording(true),
		WithGlobalSessionAuth(SessionAuth{Remember: true}),
	)
	return repo, store, reg, adp
}

func TestP7W13c_L4_13_M1_AdapterDeferredAuthSurvivesBastionSecretBind(t *testing.T) {
	t.Parallel()

	repo, store, reg, adp := newW13cAdapterDeferredAuthFixture(t)
	err := repo.WithPendingNode(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "saved-app"},
		ExistingUpdate: config.PendingNodeUpdate{
			Enabled:  true,
			JumpHost: "saved-bastion",
			Tags:     []string{"prod"},
		},
	}, func(appLease config.PendingLease) error {
		bastionCfg, bErr := adp.GetConfig("saved-bastion")
		if bErr != nil {
			t.Fatalf("GetConfig(saved-bastion): %v", bErr)
		}
		appCfg, aErr := adp.GetConfig("saved-app")
		if aErr != nil {
			t.Fatalf("GetConfig(saved-app): %v", aErr)
		}

		if _, uErr := adp.UpdateAuth(t.Context(), "saved-bastion", bastionCfg.AuthUpdateToken, "bastion-secret", "", ""); uErr != nil {
			t.Fatalf("UpdateAuth(saved-bastion): %v", uErr)
		}
		if !repo.IsPendingNode("saved-app") {
			t.Fatal("saved-bastion commit cleared saved-app isUpdate pending state")
		}
		if _, uErr := adp.UpdateAuth(t.Context(), "saved-app", appCfg.AuthUpdateToken, "app-secret", "", ""); uErr != nil {
			t.Fatalf("UpdateAuth(saved-app): %v", uErr)
		}
		diskBefore, dErr := store.Load()
		if dErr != nil {
			t.Fatalf("store.Load(before): %v", dErr)
		}
		if n, _ := diskBefore.Nodes.Get("saved-app"); n.ProxyJump != "" {
			t.Fatalf("staged saved-app leaked to disk before FinalizePendingConnection: %+v", n)
		}
		return adp.FinalizePendingConnection(t.Context(), appLease, nil)
	})
	if err != nil {
		t.Fatalf("WithPendingNode + FinalizePendingConnection: %v", err)
	}

	diskAfter, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load(after): %v", err)
	}
	appNode, _ := diskAfter.Nodes.Get("saved-app")
	appIdent, _ := diskAfter.Identities.Get(appNode.IdentityRef)
	if appNode.ProxyJump != "saved-bastion" || appIdent.LoginPasswordRef == nil {
		t.Fatalf("persisted saved-app = (node=%+v ident=%+v), want ProxyJump=saved-bastion and LoginPasswordRef", appNode, appIdent)
	}
	sec, sErr := reg.Resolve(t.Context(), *appIdent.LoginPasswordRef)
	if sErr != nil || string(sec.Value) != "app-secret" {
		t.Fatalf("resolved saved-app secret = (%q, %v), want app-secret", string(sec.Value), sErr)
	}
}

func TestP7W13c_L3_13_M1_Tier3ProxyCommandParityInControlAndPolicy(t *testing.T) {
	t.Parallel()

	env := w10cTestEnv()
	const sshCfg = `
Host loop
    HostName 10.234.0.1
    Port 22
    User ops
    ProxyJump loop

Host ssh-app
    HostName 10.234.0.2
    Port 22
    User ops
    ProxyJump ssh-bastion

Host ssh-bastion
    HostName 10.234.0.10
    Port 22
    User ops
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	muxOpts, err := ParseSessionOptions([]string{"ControlMaster=auto", "ControlPath=/tmp/cm-w13c-%h-%p-%r-%j-%C"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions: %v", err)
	}

	for _, tc := range []struct {
		name     string
		proxyCmd string
	}{
		{"Tier3_active_ProxyCommand", "nc %h %p"},
		{"Tier3_ProxyCommand_none", "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertW13cTier3ProxyCommandControlCase(t, parser, muxOpts, &env, tc.proxyCmd)
		})
	}
}

func assertW13cTier3ProxyCommandControlCase(
	t *testing.T,
	parser *config.OpenSSHParser,
	muxOpts SessionControlOptions,
	env *ssh.Environment,
	proxyCmd string,
) {
	t.Helper()
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	t3Opts := &ssh.Options{}
	if err := t3Opts.Set(ssh.OptionProxyCommand, proxyCmd); err != nil {
		t.Fatalf("Set ProxyCommand: %v", err)
	}
	cfg.SSHOptions = t3Opts
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.234.0.30", Port: 22})
	cfg.Hosts.Set("h-saved-loop", models.Host{Address: "10.234.0.20", Port: 22})
	cfg.Hosts.Set("h-saved-valid", models.Host{Address: "10.234.0.21", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("bastion", models.Node{HostRef: "h-bastion", IdentityRef: "id-ops"})
	cfg.Nodes.Set("saved-loop", models.Node{HostRef: "h-saved-loop", IdentityRef: "id-ops", ProxyJump: "openssh:loop"})
	cfg.Nodes.Set("saved-valid", models.Node{HostRef: "h-saved-valid", IdentityRef: "id-ops", ProxyJump: "bastion"})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	for _, tgt := range []config.ConnectionTarget{
		{Selector: "loop"},
		{Selector: "openssh:loop"},
		{Selector: "loop", User: "alice", HasUser: true},
		{Selector: "loop", Port: 2222, HasPort: true},
		{Selector: "ssh-app"},
	} {
		req := ControlTargetRequest{
			Provider:       prov,
			Target:         tgt,
			SessionControl: muxOpts,
			Environment:    env,
		}
		res, rErr := ResolveControlTarget(req)
		if rErr != nil || res.Target.JumpHost != "" {
			t.Fatalf("ResolveControlTarget(%+v) = (jump=%q, err=%v), want empty JumpHost", tgt, res.Target.JumpHost, rErr)
		}
		sock, sockRes, sErr := ResolveControlSocketPath(req)
		if sErr != nil || sock == "" || sockRes.Target.JumpHost != "" {
			t.Fatalf("ResolveControlSocketPath(%+v) = (%q, jump=%q, err=%v), want valid socket without jump", tgt, sock, sockRes.Target.JumpHost, sErr)
		}
		ctrl, cErr := ResolveControlConfig(prov, "", tgt.Selector, res.SessionAuth, muxOpts)
		if cErr != nil || !ctrl.IsEnabled() {
			t.Fatalf("ResolveControlConfig(empty lookupKey, %q) = (%+v, %v), want enabled control", tgt.Selector, ctrl, cErr)
		}
		adp := NewSSHAdapter(prov, WithLocalExecution(true), WithSessionControlOverride(res.LookupKey, muxOpts))
		pol, pErr := adp.Resolve(t.Context(), ResolveRequest{NodeID: res.LookupKey, ResolveProxy: true})
		if pErr != nil || pol.EffectiveJump() != "" {
			t.Fatalf("SSHAdapter.Resolve(%q) = (jump=%q, err=%v), want empty EffectiveJump", res.LookupKey, pol.EffectiveJump(), pErr)
		}
	}

	assertW13cTier2SavedNodesNotShadowedByTier3(t, prov, muxOpts, env)
}

func assertW13cTier2SavedNodesNotShadowedByTier3(
	t *testing.T,
	prov config.ConfigProvider,
	muxOpts SessionControlOptions,
	env *ssh.Environment,
) {
	t.Helper()
	validReq := ControlTargetRequest{
		Provider:       prov,
		Target:         config.ConnectionTarget{Selector: "saved-valid"},
		SessionControl: muxOpts,
		Environment:    env,
	}
	validSock, validRes, vErr := ResolveControlSocketPath(validReq)
	if vErr != nil || validSock == "" || validRes.Target.JumpHost != "bastion" {
		t.Fatalf("ResolveControlSocketPath(saved-valid) = (%q, jump=%q, err=%v), want JumpHost=bastion",
			validSock, validRes.Target.JumpHost, vErr)
	}

	var cycleErr *ssh.ProxyCycleError
	loopReq := ControlTargetRequest{
		Provider:       prov,
		Target:         config.ConnectionTarget{Selector: "saved-loop"},
		SessionControl: muxOpts,
		Environment:    env,
	}
	if _, err := ResolveControlTarget(loopReq); !errors.As(err, &cycleErr) {
		t.Errorf("ResolveControlTarget(saved-loop under Tier-3 ProxyCommand) = %v, want *ssh.ProxyCycleError", err)
	}
	if _, _, err := ResolveControlSocketPath(loopReq); !errors.As(err, &cycleErr) {
		t.Errorf("ResolveControlSocketPath(saved-loop under Tier-3 ProxyCommand) = %v, want *ssh.ProxyCycleError", err)
	}
	if _, err := ResolveControlConfig(prov, "saved-loop", "saved-loop", SessionAuth{}, muxOpts); !errors.As(err, &cycleErr) {
		t.Errorf("ResolveControlConfig(saved-loop under Tier-3 ProxyCommand) = %v, want *ssh.ProxyCycleError", err)
	}
}

func TestP7W13c_L3_13_M2_PortAndUserOverridesPropagateThroughControlSocketPathAndPolicy(t *testing.T) {
	t.Parallel()

	env := w10cTestEnv()
	const sshCfg = `
Host web
    HostName 10.235.0.1
    Port 22
    User ops

Host short
    User ops

Host short.corp.example.com
    HostName 10.235.0.1
    Port 22
    User ops
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-web", models.Host{Address: "10.235.0.1", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-web", models.Node{HostRef: "h-web", IdentityRef: "id-ops"})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	muxOpts, err := ParseSessionOptions([]string{"ControlMaster=auto", "ControlPath=/tmp/cm-w13c-%r@%h:%p-%j"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions: %v", err)
	}

	allowedCases := []struct {
		name     string
		req      ControlTargetRequest
		wantPort int
		wantUser string
	}{
		{
			name: "saved_node_port_override_with_empty_NodeID",
			req: ControlTargetRequest{
				Provider: prov,
				Target: config.ConnectionTarget{
					Selector: "saved-web", Port: 2222, HasPort: true,
					ProxyJump: "saved-web", HasProxyJump: true,
				},
				SessionControl: muxOpts,
				Environment:    &env,
			},
			wantPort: 2222,
			wantUser: "ops",
		},
		{
			name: "saved_node_port_override_with_base_NodeID",
			req: ControlTargetRequest{
				Provider: prov,
				NodeID:   "saved-web",
				Target: config.ConnectionTarget{
					Selector: "saved-web", Port: 2222, HasPort: true,
					ProxyJump: "saved-web", HasProxyJump: true,
				},
				SessionControl: muxOpts,
				Environment:    &env,
			},
			wantPort: 2222,
			wantUser: "ops",
		},
		{
			name: "saved_node_user_override_with_base_NodeID",
			req: ControlTargetRequest{
				Provider: prov,
				NodeID:   "saved-web",
				Target: config.ConnectionTarget{
					Selector: "saved-web", User: "alice", HasUser: true,
					ProxyJump: "saved-web", HasProxyJump: true,
				},
				SessionControl: muxOpts,
				Environment:    &env,
			},
			wantPort: 22,
			wantUser: "alice",
		},
		{
			name: "openssh_bare_alias_port_override",
			req: ControlTargetRequest{
				Provider: prov,
				Target: config.ConnectionTarget{
					Selector: "web", Port: 2222, HasPort: true,
					ProxyJump: "openssh:web", HasProxyJump: true,
				},
				SessionControl: muxOpts,
				Environment:    &env,
			},
			wantPort: 2222,
			wantUser: "ops",
		},
		{
			name: "openssh_bare_alias_user_override",
			req: ControlTargetRequest{
				Provider: prov,
				Target: config.ConnectionTarget{
					Selector: "web", User: "alice", HasUser: true,
					ProxyJump: "openssh:web", HasProxyJump: true,
				},
				SessionControl: muxOpts,
				Environment:    &env,
			},
			wantPort: 22,
			wantUser: "alice",
		},
		{
			name: "openssh_prefixed_with_base_NodeID_and_port_override",
			req: ControlTargetRequest{
				Provider: prov,
				NodeID:   "openssh:web",
				Target: config.ConnectionTarget{
					Selector: "openssh:web", Port: 2222, HasPort: true,
					ProxyJump: "openssh:web", HasProxyJump: true,
				},
				SessionControl: muxOpts,
				Environment:    &env,
			},
			wantPort: 2222,
			wantUser: "ops",
		},
		{
			name: "openssh_inline_user_port_selector",
			req: ControlTargetRequest{
				Provider: prov,
				Target: config.ConnectionTarget{
					Selector:  "alice@web:2222",
					ProxyJump: "openssh:web", HasProxyJump: true,
				},
				SessionControl: muxOpts,
				Environment:    &env,
			},
			wantPort: 2222,
			wantUser: "alice",
		},
		{
			name: "canonicalized_openssh_port_override",
			req: ControlTargetRequest{
				Provider: prov,
				Target: config.ConnectionTarget{
					Selector: "short", Port: 2222, HasPort: true,
					ProxyJump: "openssh:short", HasProxyJump: true,
				},
				CanonicalOriginalHost: "short",
				CanonicalHost:         "short.corp.example.com",
				SessionControl:        muxOpts,
				Environment:           &env,
			},
			wantPort: 2222,
			wantUser: "ops",
		},
	}

	for _, tc := range allowedCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sock, res, err := ResolveControlSocketPath(tc.req)
			if err != nil {
				t.Fatalf("ResolveControlSocketPath(%s) unexpected error: %v", tc.name, err)
			}
			if sock == "" || res.Target.Port != tc.wantPort || res.Target.User != tc.wantUser || res.Target.JumpHost == "" {
				t.Fatalf("ResolveControlSocketPath(%s) = (sock=%q, target=%+v), want port=%d user=%q non-empty JumpHost",
					tc.name, sock, res.Target, tc.wantPort, tc.wantUser)
			}
		})
	}

	t.Run("no_snapshot_explicit_port_in_NodeID_not_clobbered_by_openssh_default", func(t *testing.T) {
		t.Parallel()
		adp := NewSSHAdapter(prov, WithSessionAuthOverride("ops@10.235.0.1:2222", SessionAuth{
			OriginalHost: "web",
			ProxyJump:    "openssh:web",
		}))
		pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "ops@10.235.0.1:2222", ResolveProxy: true})
		if err != nil || pol.EffectiveJump() != "openssh:web" {
			t.Fatalf("SSHAdapter.Resolve(!hasSnapshot ops@10.235.0.1:2222 -> openssh:web) = (%q, %v), want openssh:web",
				pol.EffectiveJump(), err)
		}
	})

	t.Run("composite_and_ipv6_openssh_NodeID_with_session_overrides", func(t *testing.T) {
		t.Parallel()
		assertW13cCompositeAndNoSnapshotOpenSSHOverrides(t, prov, muxOpts, &env)
	})

	t.Run("genuine_cycles_on_overridden_port_or_user_still_fail_closed", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name string
			req  ControlTargetRequest
		}{
			{
				name: "same_overridden_port_2222",
				req: ControlTargetRequest{
					Provider: prov,
					NodeID:   "saved-web",
					Target: config.ConnectionTarget{
						Selector: "saved-web", Port: 2222, HasPort: true,
						ProxyJump: "openssh:ops@10.235.0.1:2222", HasProxyJump: true,
					},
					SessionControl: muxOpts,
					Environment:    &env,
				},
			},
			{
				name: "same_overridden_user_alice",
				req: ControlTargetRequest{
					Provider: prov,
					NodeID:   "openssh:web",
					Target: config.ConnectionTarget{
						Selector: "openssh:web", User: "alice", HasUser: true,
						ProxyJump: "openssh:alice@web", HasProxyJump: true,
					},
					SessionControl: muxOpts,
					Environment:    &env,
				},
			},
			{
				name: "no_override_self_loop_with_custom_env_local_user",
				req: ControlTargetRequest{
					Provider: prov,
					NodeID:   "saved-web",
					Target: config.ConnectionTarget{
						Selector: "saved-web", ProxyJump: "saved-web", HasProxyJump: true,
					},
					SessionControl: muxOpts,
					Environment:    &ssh.Environment{LocalUser: "different-local-user"},
				},
			},
		} {
			var cycleErr *ssh.ProxyCycleError
			if _, _, err := ResolveControlSocketPath(tc.req); !errors.As(err, &cycleErr) {
				t.Errorf("ResolveControlSocketPath(%s) = %v, want *ssh.ProxyCycleError", tc.name, err)
			}
		}
	})
}

type w13cNoSnapshotProvider struct {
	config.ConfigProvider
}

func (p w13cNoSnapshotProvider) ResolveConnection(string) (config.ConnectionSnapshot, error) {
	return config.ConnectionSnapshot{}, config.ErrNodeNotFound
}

func (p w13cNoSnapshotProvider) GetOpenSSHParser() *config.OpenSSHParser {
	if src, ok := p.ConfigProvider.(interface{ GetOpenSSHParser() *config.OpenSSHParser }); ok {
		return src.GetOpenSSHParser()
	}
	return nil
}

func assertW13cCompositeAndNoSnapshotOpenSSHOverrides(
	t *testing.T,
	prov config.ConfigProvider,
	muxOpts SessionControlOptions,
	env *ssh.Environment,
) {
	t.Helper()

	// 1. hasSnapshot composite OpenSSH NodeIDs ("openssh:alice@web" + Port 2222, "openssh:web:22" + User alice, "openssh:[::1]:22" + Port 2222).
	for _, tc := range []struct {
		name   string
		nodeID string
		auth   SessionAuth
		want   string
	}{
		{
			name:   "openssh_inline_user_with_port_override",
			nodeID: "openssh:alice@web",
			auth:   SessionAuth{Port: 2222, ProxyJump: "openssh:alice@web"},
			want:   "openssh:alice@web",
		},
		{
			name:   "openssh_inline_port_with_user_override",
			nodeID: "openssh:web:22",
			auth:   SessionAuth{User: "alice", ProxyJump: "openssh:web:22"},
			want:   "openssh:web:22",
		},
		{
			name:   "openssh_ipv6_with_port_override",
			nodeID: "openssh:[::1]:22",
			auth:   SessionAuth{Port: 2222, ProxyJump: "openssh:[::1]:22"},
			want:   "openssh:[::1]:22",
		},
	} {
		adp := NewSSHAdapter(prov, WithSessionAuthOverride(tc.nodeID, tc.auth))
		pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: tc.nodeID, ResolveProxy: true})
		if err != nil || pol.EffectiveJump() != tc.want {
			t.Errorf("SSHAdapter.Resolve(%s, nodeID=%q) = (%q, %v), want %q", tc.name, tc.nodeID, pol.EffectiveJump(), err, tc.want)
		}
		sock, _, sErr := ResolveControlSocketPath(ControlTargetRequest{
			Provider: prov,
			NodeID:   tc.nodeID,
			Target: config.ConnectionTarget{
				Selector:     tc.nodeID,
				User:         tc.auth.User,
				HasUser:      tc.auth.User != "",
				Port:         tc.auth.Port,
				HasPort:      tc.auth.Port > 0,
				ProxyJump:    tc.auth.ProxyJump,
				HasProxyJump: true,
			},
			SessionControl: muxOpts,
			Environment:    env,
		})
		if sErr != nil || sock == "" {
			t.Errorf("ResolveControlSocketPath(%s) = (%q, %v), want valid socket", tc.name, sock, sErr)
		}
	}

	// 2. !hasSnapshot openssh: NodeID + SessionAuth{Port: 2222} / {User: "bob"} must not falsely self-loop
	//    (both without OpenSSH config and with OpenSSH config via w13cNoSnapshotProvider),
	//    while matching the overridden port/user MUST still fail closed with *ssh.ProxyCycleError.
	noOpenSSHProv := config.NewProviderWithoutOpenSSH(nil)
	noSnapWithOpenSSH := w13cNoSnapshotProvider{ConfigProvider: prov}
	for _, tc := range []struct {
		name     string
		provider config.ConfigProvider
		nodeID   string
		auth     SessionAuth
	}{
		{"nosnap_no_openssh_user_port_override", noOpenSSHProv, "openssh:alice@web", SessionAuth{Port: 2222, ProxyJump: "openssh:alice@web"}},
		{"nosnap_no_openssh_fqdn_port_override", noOpenSSHProv, "openssh:web.example.com", SessionAuth{Port: 2222, ProxyJump: "openssh:web.example.com"}},
		{"nosnap_no_openssh_ipv6_port_override", noOpenSSHProv, "openssh:[::1]:22", SessionAuth{Port: 2222, ProxyJump: "openssh:[::1]:22"}},
		{"nosnap_with_openssh_bare_port_override", noSnapWithOpenSSH, "openssh:web", SessionAuth{Port: 2222, ProxyJump: "openssh:web"}},
		{"nosnap_with_openssh_user_port_override", noSnapWithOpenSSH, "openssh:alice@web", SessionAuth{Port: 2222, ProxyJump: "openssh:alice@web"}},
		{"nosnap_with_openssh_bare_user_override", noSnapWithOpenSSH, "openssh:web", SessionAuth{User: "alice", ProxyJump: "openssh:web"}},
	} {
		adp := NewSSHAdapter(tc.provider, WithSessionAuthOverride(tc.nodeID, tc.auth))
		pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: tc.nodeID, ResolveProxy: true})
		if err != nil || pol.EffectiveJump() != tc.auth.ProxyJump {
			t.Errorf("SSHAdapter.Resolve(%s) = (%q, %v), want %q", tc.name, pol.EffectiveJump(), err, tc.auth.ProxyJump)
		}
	}

	for _, tc := range []struct {
		name     string
		provider config.ConfigProvider
		nodeID   string
		auth     SessionAuth
	}{
		{"nosnap_true_cycle_overridden_port_2222", noOpenSSHProv, "openssh:alice@web", SessionAuth{Port: 2222, ProxyJump: "openssh:alice@web:2222"}},
		{"nosnap_true_cycle_same_port_22", noSnapWithOpenSSH, "openssh:web", SessionAuth{Port: 22, ProxyJump: "openssh:web"}},
		{"nosnap_true_cycle_same_overridden_user", noSnapWithOpenSSH, "openssh:web", SessionAuth{User: "alice", ProxyJump: "openssh:alice@web"}},
	} {
		var cycleErr *ssh.ProxyCycleError
		adp := NewSSHAdapter(tc.provider, WithSessionAuthOverride(tc.nodeID, tc.auth))
		if _, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: tc.nodeID, ResolveProxy: true}); !errors.As(err, &cycleErr) {
			t.Errorf("SSHAdapter.Resolve(%s) = %v, want *ssh.ProxyCycleError", tc.name, err)
		}
	}
}
