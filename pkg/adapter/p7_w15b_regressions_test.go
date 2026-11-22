package adapter

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W15bAnswerCommandHelperProcess(t *testing.T) {
	if !slices.Contains(os.Args, "w15b-echo-env") {
		return
	}
	fmt.Printf("%s|%s|%s\n", os.Getenv("XOPS_HOST"), os.Getenv("XOPS_USER"), os.Getenv("XOPS_IDENTITY"))
	os.Exit(0)
}

func buildW15bM1Fixture(t *testing.T) (config.ConfigProvider, config.ConfigProvider) {
	t.Helper()
	const sshCfg = `
Host old-22
    HostName 10.0.0.1
    Port 22
    BatchMode yes
    ControlMaster auto
    ControlPath /tmp/mux-22-%C
    ConnectTimeout 22

Host saved-web
    HostName 10.0.0.1
    Port 22
    BatchMode yes
    ControlMaster auto
    ControlPath /tmp/mux-saved-22-%C
    ConnectTimeout 77

Host old-no-hostname
    BatchMode yes
    ConnectTimeout 88

Host app-2222
    HostName 10.0.0.1
    Port 2222
    ControlMaster auto
    ControlPath /tmp/mux-2222-%C
    ConnectTimeout 42

Host target-99
    HostName 10.0.0.99
    Port 22
    ControlMaster auto
    ControlPath /tmp/mux-99-%C
    ConnectTimeout 55

Host target-99-2222
    HostName 10.0.0.99
    Port 2222
    ControlMaster auto
    ControlPath /tmp/mux-99-2222-%C
    ConnectTimeout 66

Host short
    ConnectTimeout 11

Host short.corp.example
    ServerAliveInterval 44

Host *
    ServerAliveInterval 25
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-web", models.Host{
		Address: "10.0.0.1",
		Port:    22,
		Alias:   []string{"short.corp.example"},
	})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-web", models.Node{
		HostRef:      "h-web",
		IdentityRef:  "id-ops",
		Alias:        []string{"old-22", "old-no-hostname"},
		OpenSSHAlias: "old-22",
	})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)
	return prov, w13cNoSnapshotProvider{ConfigProvider: prov}
}

func assertW15bM1ResolvedPolicy(t *testing.T, pol EffectivePolicy, wantTimeout, wantPath string) {
	t.Helper()
	opts := pol.Options()
	if opts == nil || opts.Get(ssh.OptionConnectTimeout) != wantTimeout || opts.BatchMode() {
		t.Fatalf("opts = %v, want ConnectTimeout=%s and BatchMode=false", opts, wantTimeout)
	}
	ctrl := pol.Control()
	if ctrl == nil || ctrl.Path != wantPath {
		t.Fatalf("ctrl = %+v, want %q", ctrl, wantPath)
	}
}

func assertW15bM1HostNamePass2Blocked(t *testing.T, prov config.ConfigProvider) {
	t.Helper()
	adp := NewSSHAdapter(prov, WithSessionAuthOverride("saved-web", SessionAuth{
		HostName:      "10.0.0.250",
		OriginalHost:  "short",
		CanonicalHost: "short.corp.example",
	}))
	pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "saved-web"})
	if err != nil {
		t.Fatalf("Resolve(HostName:10.0.0.250): %v", err)
	}
	if pol.CanonicalHost() != "" {
		t.Fatalf("CanonicalHost leaked onto overridden host: got %q, want empty", pol.CanonicalHost())
	}
	if ctrl := pol.Control(); ctrl != nil {
		t.Fatalf("unexpected ControlConfig leaked onto 10.0.0.250: %+v", ctrl)
	}
	opts := pol.Options()
	if opts == nil || opts.Get(ssh.OptionServerAliveInterval) != "25" || opts.Get(ssh.OptionConnectTimeout) != "" || opts.BatchMode() {
		t.Fatalf("HostName:10.0.0.250 opts = %v, want only Host * ServerAliveInterval=25", opts)
	}
}

func TestP7W15b_L3_15_M1_Tier4ScopingHonorsSessionHostNameAndPort(t *testing.T) {
	t.Parallel()

	env := w10cTestEnv()
	prov, noSnapProv := buildW15bM1Fixture(t)

	t.Run("saved_node_port_override_2222_matches_control_socket", func(t *testing.T) {
		t.Parallel()
		adp := NewSSHAdapter(prov, WithSessionAuthOverride("saved-web", SessionAuth{Port: 2222}))
		pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "saved-web"})
		if err != nil {
			t.Fatalf("Resolve(saved-web, Port:2222): %v", err)
		}
		assertW15bM1ResolvedPolicy(t, pol, "42", "/tmp/mux-2222-%C")
		wantSock, err := ssh.ExpandControlPath(pol.Control().Path, env, pol.controlTargetContextWithEnv("saved-web", env))
		if err != nil {
			t.Fatalf("ExpandControlPath: %v", err)
		}
		gotSock, _, err := ResolveControlSocketPath(ControlTargetRequest{
			Provider:    prov,
			NodeID:      "saved-web",
			Target:      config.ConnectionTarget{Selector: "saved-web", Port: 2222, HasPort: true},
			Environment: &env,
		})
		if err != nil || gotSock != wantSock {
			t.Fatalf("ResolveControlSocketPath(Port:2222) = (%q, %v), want %q", gotSock, err, wantSock)
		}
	})

	t.Run("saved_node_hostname_override_matches_control_socket", func(t *testing.T) {
		t.Parallel()
		adp := NewSSHAdapter(prov, WithSessionAuthOverride("saved-web", SessionAuth{HostName: "10.0.0.99"}))
		pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "saved-web"})
		if err != nil {
			t.Fatalf("Resolve(saved-web, HostName:10.0.0.99): %v", err)
		}
		assertW15bM1ResolvedPolicy(t, pol, "55", "/tmp/mux-99-%C")
		wantSock, err := ssh.ExpandControlPath(pol.Control().Path, env, pol.controlTargetContextWithEnv("saved-web", env))
		if err != nil {
			t.Fatalf("ExpandControlPath: %v", err)
		}
		gotSock, _, err := ResolveControlSocketPath(ControlTargetRequest{
			Provider:                 prov,
			NodeID:                   "saved-web",
			Target:                   config.ConnectionTarget{Selector: "saved-web"},
			ApplyTargetNodeOverrides: true,
			OverrideExpandedHost:     "10.0.0.99",
			Environment:              &env,
		})
		if err != nil || gotSock != wantSock {
			t.Fatalf("ResolveControlSocketPath(HostName:10.0.0.99) = (%q, %v), want %q", gotSock, err, wantSock)
		}
	})

	t.Run("saved_node_combined_hostname_and_port_override", func(t *testing.T) {
		t.Parallel()
		adp := NewSSHAdapter(prov, WithSessionAuthOverride("saved-web", SessionAuth{HostName: "10.0.0.99", Port: 2222}))
		pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "saved-web"})
		if err != nil {
			t.Fatalf("Resolve(HostName+Port): %v", err)
		}
		assertW15bM1ResolvedPolicy(t, pol, "66", "/tmp/mux-99-2222-%C")
	})

	t.Run("hostname_override_blocks_pass2_alias_and_no_hostname_stanza", func(t *testing.T) {
		t.Parallel()
		assertW15bM1HostNamePass2Blocked(t, prov)
	})

	t.Run("port_override_blocks_pass2_alias_on_port_22", func(t *testing.T) {
		t.Parallel()
		adp := NewSSHAdapter(prov, WithSessionAuthOverride("saved-web", SessionAuth{
			Port:          2222,
			OriginalHost:  "short",
			CanonicalHost: "short.corp.example",
		}))
		pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "saved-web"})
		if err != nil {
			t.Fatalf("Resolve(Port:2222 + Pass-2): %v", err)
		}
		assertW15bM1ResolvedPolicy(t, pol, "42", "/tmp/mux-2222-%C")
		if got := pol.Options().Get(ssh.OptionServerAliveInterval); got != "25" {
			t.Fatalf("ServerAliveInterval = %q, want 25 (must not leak Pass-2 44)", got)
		}
	})

	t.Run("no_snapshot_fallback_honors_port_and_hostname_overrides", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name        string
			provider    config.ConfigProvider
			nodeID      string
			auth        SessionAuth
			wantTimeout string
			wantPath    string
		}{
			{"saved_nosnap_port_2222", noSnapProv, "saved-web", SessionAuth{Port: 2222}, "42", "/tmp/mux-2222-%C"},
			{"saved_nosnap_host_99", noSnapProv, "saved-web", SessionAuth{HostName: "10.0.0.99"}, "55", "/tmp/mux-99-%C"},
			{"adhoc_nodeid_port_2222", prov, "alice@10.0.0.1:22", SessionAuth{Port: 2222}, "42", "/tmp/mux-2222-%C"},
			{"adhoc_nodeid_host_99", prov, "alice@10.0.0.1:22", SessionAuth{HostName: "10.0.0.99"}, "55", "/tmp/mux-99-%C"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				adp := NewSSHAdapter(tc.provider, WithSessionAuthOverride(tc.nodeID, tc.auth))
				pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: tc.nodeID})
				if err != nil {
					t.Fatalf("Resolve(%s): %v", tc.name, err)
				}
				assertW15bM1ResolvedPolicy(t, pol, tc.wantTimeout, tc.wantPath)
			})
		}
	})
}

func buildW15bM2Fixture(t *testing.T) (config.ConfigProvider, config.ConfigProvider, config.ConfigProvider) {
	t.Helper()
	const sshCfg = `
Host web
    HostName 10.235.0.5
    Port 2200
    User webops
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.235.0.2", Port: 22})
	cfg.Hosts.Set("h-web", models.Host{Address: "10.235.0.10", Port: 2200})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "password", Password: "saved-pw"})
	cfg.Nodes.Set("bastion", models.Node{HostRef: "h-bastion", IdentityRef: "id-ops"})
	cfg.Nodes.Set("node-1", models.Node{
		HostRef:     "h-web",
		IdentityRef: "id-ops",
		Alias:       []string{"web-alias"},
		ProxyJump:   "bastion",
		SSHOptions:  ssh.MustOptions(ssh.OptionConnectTimeout, "17", ssh.OptionControlMaster, "auto", ssh.OptionControlPath, "/tmp/cm-%n-%h-%p-%r-%j"),
	})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)
	return prov, w13cNoSnapshotProvider{ConfigProvider: prov}, config.NewProviderWithoutOpenSSH(cfg)
}

func assertW15bM2NoSnapshotTargetContexts(t *testing.T, prov, noSnapProv, noOpenSSHProv config.ConfigProvider, env ssh.Environment) {
	t.Helper()
	cases := []struct {
		name      string
		provider  config.ConfigProvider
		nodeID    string
		auth      *SessionAuth
		wantHost  string
		wantPort  int
		wantUser  string
		wantOrig  string
		wantCanon string
	}{
		{
			name:     "adhoc_user_host_port",
			provider: prov,
			nodeID:   "alice@10.235.0.1:2222",
			wantHost: "10.235.0.1", wantPort: 2222, wantUser: "alice", wantOrig: "alice@10.235.0.1:2222",
		},
		{
			name:     "adhoc_collision_suffix",
			provider: prov,
			nodeID:   "ops@10.235.0.1:22-2",
			wantHost: "10.235.0.1", wantPort: 22, wantUser: "ops", wantOrig: "ops@10.235.0.1:22-2",
		},
		{
			name:     "adhoc_ipv6_user_port",
			provider: prov,
			nodeID:   "alice@[2001:db8::1]:2222",
			wantHost: "2001:db8::1", wantPort: 2222, wantUser: "alice", wantOrig: "alice@[2001:db8::1]:2222",
		},
		{
			name:     "openssh_without_snapshot",
			provider: noSnapProv,
			nodeID:   "openssh:web",
			wantHost: "10.235.0.5", wantPort: 2200, wantUser: "webops", wantOrig: "web",
		},
		{
			name:     "openssh_without_snapshot_and_tier1_overrides",
			provider: noSnapProv,
			nodeID:   "openssh:web",
			auth:     &SessionAuth{HostName: "10.235.0.99", Port: 2299, User: "bob"},
			wantHost: "10.235.0.99", wantPort: 2299, wantUser: "bob", wantOrig: "web",
		},
		{
			name:     "unlisted_fqdn",
			provider: prov,
			nodeID:   "unlisted.example.com",
			wantHost: "unlisted.example.com", wantPort: 22, wantUser: env.LocalUser, wantOrig: "unlisted.example.com",
		},
		{
			name:      "dns_canonicalized_unlisted",
			provider:  noOpenSSHProv,
			nodeID:    "short-dns",
			auth:      &SessionAuth{OriginalHost: "short-dns", CanonicalHost: "short-dns.corp.example.com"},
			wantHost:  "short-dns.corp.example.com",
			wantPort:  22,
			wantUser:  env.LocalUser,
			wantOrig:  "short-dns",
			wantCanon: "short-dns.corp.example.com",
		},
		{
			name:     "saved_node_under_no_snapshot_provider",
			provider: noSnapProv,
			nodeID:   "node-1",
			wantHost: "10.235.0.10", wantPort: 2200, wantUser: "ops", wantOrig: "node-1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var adpOpts []Option
			if tc.auth != nil {
				adpOpts = append(adpOpts, WithSessionAuthOverride(tc.nodeID, *tc.auth))
			}
			adp := NewSSHAdapter(tc.provider, adpOpts...)
			pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: tc.nodeID})
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tc.nodeID, err)
			}
			if pol.hasSnapshot {
				t.Fatalf("expected !hasSnapshot for %s", tc.name)
			}
			got := pol.controlTargetContextWithEnv(pol.nodeID, env)
			if got.Host != tc.wantHost || got.Port != tc.wantPort || got.User != tc.wantUser ||
				got.OriginalHost != tc.wantOrig || got.CanonicalHost != tc.wantCanon {
				t.Fatalf("TargetContext(%s) = %+v, want Host=%q Port=%d User=%q Orig=%q Canon=%q",
					tc.name, got, tc.wantHost, tc.wantPort, tc.wantUser, tc.wantOrig, tc.wantCanon)
			}
			if pol.TargetContext().CanonicalTargetIdentity() == "" {
				t.Fatalf("TargetContext(%s).CanonicalTargetIdentity() is empty", tc.name)
			}
			expanded, err := ssh.ExpandControlPath("/tmp/cm-%r@%h:%p-%C", env, got)
			wantPrefix := fmt.Sprintf("/tmp/cm-%s@%s:%d-", tc.wantUser, tc.wantHost, tc.wantPort)
			if err != nil || !strings.HasPrefix(expanded, wantPrefix) {
				t.Fatalf("ExpandControlPath(%s) = (%q, %v), want prefix %q", tc.name, expanded, err, wantPrefix)
			}
		})
	}
}

func assertW15bM2SavedAliasResolution(t *testing.T, prov config.ConfigProvider, env ssh.Environment) {
	t.Helper()
	adp := NewSSHAdapter(prov)

	pol, err := adp.Resolve(t.Context(), ResolveRequest{
		NodeID:          "web-alias",
		RequireSnapshot: true,
		ResolveProxy:    true,
	})
	if err != nil {
		t.Fatalf("Resolve(web-alias): %v", err)
	}
	if pol.EffectiveJump() != "bastion" || pol.Options().Get(ssh.OptionConnectTimeout) != "17" {
		t.Fatalf("Resolve(web-alias) = (jump=%q timeout=%q), want (bastion, 17)",
			pol.EffectiveJump(), pol.Options().Get(ssh.OptionConnectTimeout))
	}
	clientCfg, err := pol.ClientConfig()
	if err != nil {
		t.Fatalf("pol.ClientConfig(): %v", err)
	}
	if clientCfg.NodeID != "node-1" || clientCfg.Address != "10.235.0.10" || clientCfg.Port != 2200 || clientCfg.User != "ops" {
		t.Fatalf("ClientConfig(web-alias) = %+v, want node-1 ops@10.235.0.10:2200", clientCfg)
	}

	aliasPath, err := adp.ExpandControlPath("web-alias", "/tmp/cm-%n-%h-%p-%r-%j")
	if err != nil {
		t.Fatalf("ExpandControlPath(web-alias): %v", err)
	}
	nodePath, err := adp.ExpandControlPath("node-1", "/tmp/cm-%n-%h-%p-%r-%j")
	if err != nil {
		t.Fatalf("ExpandControlPath(node-1): %v", err)
	}
	if aliasPath != nodePath || aliasPath != "/tmp/cm-node-1-10.235.0.10-2200-ops-bastion" {
		t.Fatalf("ExpandControlPath mismatch: alias=%q node=%q", aliasPath, nodePath)
	}

	ctrlRes, err := ResolveControlTarget(ControlTargetRequest{
		Provider:    prov,
		Target:      config.ConnectionTarget{Selector: "web-alias"},
		Environment: &env,
	})
	if err != nil {
		t.Fatalf("ResolveControlTarget(web-alias): %v", err)
	}
	if gotTarget := pol.controlTargetContextWithEnv(pol.nodeID, env); gotTarget != ctrlRes.Target {
		t.Fatalf("TargetContext mismatch between Resolve(web-alias) and ResolveControlTarget:\n  pol  = %+v\n  ctrl = %+v",
			gotTarget, ctrlRes.Target)
	}
}

func assertW15bM2SavedAliasOverrideLookup(t *testing.T, prov config.ConfigProvider) {
	t.Helper()

	adpByAlias := NewSSHAdapter(prov, WithSessionAuthOverride("web-alias", SessionAuth{
		Port:     2222,
		User:     "alice",
		Password: "alias-override-pw",
	}))
	cfgByAlias, err := adpByAlias.GetConfig("web-alias")
	if err != nil {
		t.Fatalf("GetConfig(web-alias): %v", err)
	}
	if cfgByAlias.NodeID != "node-1" || cfgByAlias.Port != 2222 || cfgByAlias.User != "alice" {
		t.Fatalf("GetConfig(web-alias) = (id=%q port=%d user=%q), want (node-1, 2222, alice)",
			cfgByAlias.NodeID, cfgByAlias.Port, cfgByAlias.User)
	}
	sec, err := adpByAlias.ResolveSecret(t.Context(), ssh.SecretRequest{
		NodeID: cfgByAlias.NodeID,
		Kind:   ssh.SecretKindLoginPassword,
		Host:   cfgByAlias.Address,
		Port:   cfgByAlias.Port,
		User:   cfgByAlias.User,
	})
	if err != nil || string(sec) != "alias-override-pw" {
		t.Fatalf("ResolveSecret(node-1 with alias-keyed override) = (%q, %v), want alias-override-pw", string(sec), err)
	}

	ctrlOpts, err := ParseSessionOptions([]string{"ConnectTimeout=31"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions: %v", err)
	}
	adpByNode := NewSSHAdapter(prov,
		WithSessionAuthOverride("node-1", SessionAuth{Port: 2233}),
		WithSessionControlOverride("node-1", ctrlOpts),
	)
	polByNode, err := adpByNode.Resolve(t.Context(), ResolveRequest{NodeID: "web-alias", RequireSnapshot: true})
	if err != nil {
		t.Fatalf("Resolve(web-alias with node-1 override): %v", err)
	}
	if polByNode.Options().Get(ssh.OptionConnectTimeout) != "31" {
		t.Fatalf("node-1 control override did not apply to web-alias: %v", polByNode.Options())
	}
	if gotCfg, err := polByNode.ClientConfig(); err != nil || gotCfg.Port != 2233 {
		t.Fatalf("node-1 auth override did not apply to web-alias: cfg=%+v err=%v", gotCfg, err)
	}

	adpBoth := NewSSHAdapter(prov,
		WithSessionAuthOverride("web-alias", SessionAuth{Port: 2244}),
		WithSessionAuthOverride("node-1", SessionAuth{Port: 2255}),
	)
	if c, err := adpBoth.GetConfig("web-alias"); err != nil || c.Port != 2244 {
		t.Fatalf("GetConfig(web-alias) with both overrides = (port=%d, err=%v), want 2244", c.Port, err)
	}
	if c, err := adpBoth.GetConfig("node-1"); err != nil || c.Port != 2255 {
		t.Fatalf("GetConfig(node-1) with both overrides = (port=%d, err=%v), want 2255", c.Port, err)
	}
}

func newW15bM2LegacyAliasRepo(t *testing.T) *config.Repository {
	t.Helper()
	baseCfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	baseCfg.Hosts.Set("h-1", models.Host{Address: "10.235.0.10", Port: 2200})
	baseCfg.Identities.Set("id-1", models.Identity{User: "ops", AuthType: "password", Password: "initial-pw"})
	baseCfg.Nodes.Set("node-1", models.Node{HostRef: "h-1", IdentityRef: "id-1", Alias: []string{"web-alias"}})
	repo, err := config.NewRepositoryWithoutOpenSSH(baseCfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	return repo
}

func assertW15bM2AliasCallbackGuards(t *testing.T) {
	t.Helper()
	repo := newW15bM2LegacyAliasRepo(t)

	// 1. Session-only Remember:false registered on "web-alias" must prevent UpdateAuth/UpdateSudo
	//    when Connector calls back using canonical ClientConfig.NodeID ("node-1").
	adpNoRemember := NewSSHAdapter(repo, WithSessionAuthOverride("web-alias", SessionAuth{
		Password: "session-only-pw",
		Remember: false,
	}))
	cfgNoRem, err := adpNoRemember.GetConfig("web-alias")
	if err != nil || cfgNoRem.NodeID != "node-1" {
		t.Fatalf("GetConfig(web-alias) = (%+v, %v), want NodeID=node-1", cfgNoRem, err)
	}
	if tok, err := adpNoRemember.UpdateAuth(t.Context(), cfgNoRem.NodeID, cfgNoRem.AuthUpdateToken, "leaked-pw", "", ""); err != nil || tok != cfgNoRem.AuthUpdateToken {
		t.Fatalf("UpdateAuth(node-1 with Remember:false on web-alias) = (%q, %v), want unchanged token", tok, err)
	}
	if tok, err := adpNoRemember.UpdateSudo(t.Context(), cfgNoRem.NodeID, cfgNoRem.SudoUpdateToken, ssh.SudoModeSu, "leaked-su"); err != nil || tok != cfgNoRem.SudoUpdateToken {
		t.Fatalf("UpdateSudo(node-1 with Remember:false on web-alias) = (%q, %v), want unchanged token", tok, err)
	}
	snap, err := repo.ResolveConnection("node-1")
	if err != nil || snap.Identity.Password != "initial-pw" || snap.Node.SuPwd != "" {
		t.Fatalf("session-only alias override persisted secrets onto node-1: ident=%+v node=%+v err=%v", snap.Identity, snap.Node, err)
	}

	// 2. Alias-keyed BatchMode=yes must still deny interactiveDecisionForNode("node-1")
	//    even when a globalSessionControl override (e.g. ConnectTimeout=5) is also set.
	batchOpts, err := ParseSessionOptions([]string{"BatchMode=yes"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions(BatchMode=yes): %v", err)
	}
	globalOpts, err := ParseSessionOptions([]string{"ConnectTimeout=5"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions(ConnectTimeout=5): %v", err)
	}
	adpBatch := NewSSHAdapter(repo,
		WithSessionControlOverride("web-alias", batchOpts),
		WithGlobalSessionControl(globalOpts),
		WithSessionAuthOverride("web-alias", SessionAuth{Remember: true}),
	)
	if !adpBatch.interactiveDecisionForNode("node-1").Denied() {
		t.Fatal("interactiveDecisionForNode(node-1) bypassed BatchMode=yes registered on web-alias under globalSessionControl")
	}
	if tok, err := adpBatch.UpdateAuth(t.Context(), "node-1", cfgNoRem.AuthUpdateToken, "batch-leaked-pw", "", ""); err != nil || tok != cfgNoRem.AuthUpdateToken {
		t.Fatalf("UpdateAuth(node-1 under BatchMode=yes on web-alias) = (%q, %v), want unchanged token", tok, err)
	}
}

func assertW15bM2DirectAliasWritebackAndDisableMux(t *testing.T) {
	t.Helper()
	repo := newW15bM2LegacyAliasRepo(t)

	// 1. Direct UpdateAuth("web-alias", ...) & UpdateSudo("web-alias", ...) on legacy provider
	//    must persist against canonical "node-1".
	adpWrite := NewSSHAdapter(repo, WithSessionAuthOverride("web-alias", SessionAuth{Remember: true}))
	cfgWrite, err := adpWrite.GetConfig("web-alias")
	if err != nil {
		t.Fatalf("GetConfig(web-alias): %v", err)
	}
	nextAuthTok, err := adpWrite.UpdateAuth(t.Context(), "web-alias", cfgWrite.AuthUpdateToken, "updated-pw", "", "")
	if err != nil || nextAuthTok == cfgWrite.AuthUpdateToken {
		t.Fatalf("UpdateAuth(web-alias) = (%q, %v), want updated version token", nextAuthTok, err)
	}
	nextSudoTok, err := adpWrite.UpdateSudo(t.Context(), "web-alias", cfgWrite.SudoUpdateToken, ssh.SudoModeSu, "updated-su")
	if err != nil || nextSudoTok == cfgWrite.SudoUpdateToken {
		t.Fatalf("UpdateSudo(web-alias) = (%q, %v), want updated version token", nextSudoTok, err)
	}
	snap, err := repo.ResolveConnection("node-1")
	if err != nil || snap.Identity.Password != "updated-pw" || snap.Node.SuPwd != "updated-su" || snap.Node.SudoMode != models.SudoModeSu {
		t.Fatalf("direct alias writeback failed to update node-1: ident=%+v node=%+v err=%v", snap.Identity, snap.Node, err)
	}

	// 2. DisableSessionControlSharing("node-1") must disable an alias-keyed mux override on
	//    "web-alias" (and preserve non-mux options like ConnectTimeout=9).
	muxOpts, err := ParseSessionOptions([]string{"ControlMaster=yes", "ControlPath=/tmp/cm-%C", "ConnectTimeout=9"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions(mux): %v", err)
	}
	adpMux := NewSSHAdapter(repo, WithSessionControlOverride("web-alias", muxOpts))
	adpMux.DisableSessionControlSharing("node-1")
	for _, id := range []string{"node-1", "web-alias"} {
		pol, err := adpMux.Resolve(t.Context(), ResolveRequest{NodeID: id})
		if err != nil {
			t.Fatalf("Resolve(%q) after DisableSessionControlSharing: %v", id, err)
		}
		if ctrl := pol.Control(); ctrl == nil || ctrl.Path != "none" || ctrl.Master != ssh.ControlMasterNo {
			t.Fatalf("Resolve(%q).Control() = %+v, want disabled none", id, ctrl)
		}
		if opts := pol.Options(); opts == nil || opts.Get(ssh.OptionConnectTimeout) != "9" {
			t.Fatalf("Resolve(%q) dropped ConnectTimeout=9 after DisableSessionControlSharing: %v", id, opts)
		}
	}
}

func TestP7W15b_L3_15_M2_NoSnapshotTargetContextAndSavedAliasResolution(t *testing.T) {
	t.Parallel()

	env := w10cTestEnv()
	prov, noSnapProv, noOpenSSHProv := buildW15bM2Fixture(t)

	t.Run("no_snapshot_target_context_populates_host_port_user_and_identity", func(t *testing.T) {
		t.Parallel()
		assertW15bM2NoSnapshotTargetContexts(t, prov, noSnapProv, noOpenSSHProv, env)
	})
	t.Run("saved_node_alias_resolves_snapshot_options_proxyjump_and_control_path", func(t *testing.T) {
		t.Parallel()
		assertW15bM2SavedAliasResolution(t, prov, env)
	})
	t.Run("saved_node_alias_honors_overrides_keyed_by_alias_or_canonical_node_id", func(t *testing.T) {
		t.Parallel()
		assertW15bM2SavedAliasOverrideLookup(t, prov)
	})
	t.Run("saved_node_alias_callback_guards_for_writeback_and_batchmode", func(t *testing.T) {
		t.Parallel()
		assertW15bM2AliasCallbackGuards(t)
	})
	t.Run("saved_node_alias_direct_writeback_and_disable_control_sharing", func(t *testing.T) {
		t.Parallel()
		assertW15bM2DirectAliasWritebackAndDisableMux(t)
	})
}

func buildW15bM3Fixtures(t *testing.T) (config.ConfigProvider, config.ConfigProvider) {
	t.Helper()
	const sshCfg = `
Host old-22
    HostName 10.235.0.1
    Port 22
    ControlMaster auto
    ControlPath /tmp/mux-22-%C

Host app-2222
    HostName 10.235.0.1
    Port 2222
    ControlMaster auto
    ControlPath /tmp/mux-2222-%C

Host ssh-2222
    HostName 10.235.0.2
    Port 2222
    User deploy
    ControlMaster auto
    ControlPath /tmp/mux-ssh-2222-%C
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-2222", models.Host{Address: "10.235.0.1", Port: 2222})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-2222", models.Node{HostRef: "h-2222", IdentityRef: "id-ops"})
	return config.NewProviderWithOpenSSHParser(cfg, parser), config.NewProviderWithoutOpenSSH(cfg)
}

func assertW15bM3ResolvedIgnoresFallback(t *testing.T, req ControlTargetRequest, wantPort int, wantUser, wantSockPrefix string) {
	t.Helper()
	sock, res, err := ResolveControlSocketPath(req)
	if err != nil {
		t.Fatalf("ResolveControlSocketPath: %v", err)
	}
	if res.Target.Port != wantPort || res.Target.User != wantUser {
		t.Fatalf("Target = %+v, want Port=%d User=%q", res.Target, wantPort, wantUser)
	}
	if res.SessionAuth.Port != 0 || res.SessionAuth.User != "" {
		t.Fatalf("SessionAuth polluted by FallbackPort/FallbackUser: %+v", res.SessionAuth)
	}
	if !strings.HasPrefix(sock, wantSockPrefix) {
		t.Fatalf("socket = %q, want prefix %q", sock, wantSockPrefix)
	}
	_, directAuth := ResolveControlSessionLookup(req, res.Target)
	if directAuth.Port != 0 || directAuth.User != "" {
		t.Fatalf("ResolveControlSessionLookup polluted by fallback: %+v", directAuth)
	}
}

func assertW15bM3UnresolvedAppliesFallback(t *testing.T, req ControlTargetRequest, wantPort uint16, wantUser string) {
	t.Helper()
	res, err := ResolveControlTarget(req)
	if err != nil {
		t.Fatalf("ResolveControlTarget: %v", err)
	}
	if res.Target.Port != int(wantPort) || res.Target.User != wantUser {
		t.Fatalf("Target = %+v, want Port=%d User=%q", res.Target, wantPort, wantUser)
	}
	if res.SessionAuth.Port != wantPort || res.SessionAuth.User != wantUser {
		t.Fatalf("SessionAuth = %+v, want Port=%d User=%q", res.SessionAuth, wantPort, wantUser)
	}
	_, directAuth := ResolveControlSessionLookup(req, res.Target)
	if directAuth.Port != wantPort || directAuth.User != wantUser {
		t.Fatalf("ResolveControlSessionLookup = %+v, want Port=%d User=%q", directAuth, wantPort, wantUser)
	}
}

func TestP7W15b_L3_15_M3_FallbackUserPortOnlyAppliedWhenUnresolved(t *testing.T) {
	t.Parallel()

	env := w10cTestEnv()
	prov, noOpenSSHProv := buildW15bM3Fixtures(t)

	t.Run("resolved_saved_node_ignores_fallback_port_and_user", func(t *testing.T) {
		t.Parallel()
		assertW15bM3ResolvedIgnoresFallback(t, ControlTargetRequest{
			Provider:     prov,
			NodeID:       "saved-2222",
			Target:       config.ConnectionTarget{Selector: "saved-2222"},
			FallbackHost: "saved-2222",
			FallbackPort: 22,
			FallbackUser: "localuser",
			Environment:  &env,
		}, 2222, "ops", "/tmp/mux-2222-")
	})

	t.Run("resolved_openssh_virtual_node_ignores_fallback_port_and_user", func(t *testing.T) {
		t.Parallel()
		assertW15bM3ResolvedIgnoresFallback(t, ControlTargetRequest{
			Provider:     prov,
			Target:       config.ConnectionTarget{Selector: "ssh-2222"},
			FallbackHost: "ssh-2222",
			FallbackPort: 22,
			FallbackUser: "localuser",
			Environment:  &env,
		}, 2222, "deploy", "/tmp/mux-ssh-2222-")
	})

	t.Run("resolved_node_still_honors_explicit_target_port_and_user", func(t *testing.T) {
		t.Parallel()
		res, err := ResolveControlTarget(ControlTargetRequest{
			Provider: prov,
			NodeID:   "saved-2222",
			Target: config.ConnectionTarget{
				Selector: "saved-2222",
				Port:     2299,
				HasPort:  true,
				User:     "alice",
				HasUser:  true,
			},
			FallbackPort: 22,
			FallbackUser: "localuser",
			Environment:  &env,
		})
		if err != nil {
			t.Fatalf("ResolveControlTarget(explicit port/user): %v", err)
		}
		if res.SessionAuth.Port != 2299 || res.SessionAuth.User != "alice" {
			t.Fatalf("SessionAuth = %+v, want Port=2299 User=alice", res.SessionAuth)
		}
	})

	t.Run("unresolved_empty_selector_applies_fallback", func(t *testing.T) {
		t.Parallel()
		assertW15bM3UnresolvedAppliesFallback(t, ControlTargetRequest{
			Provider:     prov,
			FallbackHost: "10.235.0.50",
			FallbackPort: 2222,
			FallbackUser: "fallback-u",
			Environment:  &env,
		}, 2222, "fallback-u")
	})

	t.Run("unresolved_empty_selector_nil_provider_applies_fallback", func(t *testing.T) {
		t.Parallel()
		assertW15bM3UnresolvedAppliesFallback(t, ControlTargetRequest{
			Provider:     nil,
			FallbackHost: "10.235.0.50",
			FallbackPort: 2222,
			FallbackUser: "fallback-u",
			Environment:  &env,
		}, 2222, "fallback-u")
	})

	t.Run("resolved_adhoc_selector_ignores_fallback_port_and_user", func(t *testing.T) {
		t.Parallel()
		req := ControlTargetRequest{
			Provider:     noOpenSSHProv,
			Target:       config.ConnectionTarget{Selector: "adhoc.example.com"},
			FallbackHost: "10.235.0.50",
			FallbackPort: 2222,
			FallbackUser: "fallback-u",
			Environment:  &env,
		}
		res, err := ResolveControlTarget(req)
		if err != nil {
			t.Fatalf("ResolveControlTarget(adhoc): %v", err)
		}
		if res.Target.Port != 22 || res.SessionAuth.Port != 0 || res.SessionAuth.User != "" {
			t.Fatalf("resolved ad-hoc selector polluted by fallback: target=%+v auth=%+v", res.Target, res.SessionAuth)
		}
		_, directAuth := ResolveControlSessionLookup(req, res.Target)
		if directAuth.Port != 0 || directAuth.User != "" {
			t.Fatalf("ResolveControlSessionLookup(adhoc) polluted by fallback: %+v", directAuth)
		}
	})
}

func TestP7W15b_L3_15_M4_OTPAndChallengeCommandHonorSessionHostNameAndUser(t *testing.T) {
	t.Parallel()

	helperArgs := []string{"-test.run=^TestP7W15bAnswerCommandHelperProcess$", "--", "w15b-echo-env"}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-cmd", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{
		User:     "ops",
		AuthType: "keyboard-interactive",
		OTP: &models.OTPConfig{
			Command: os.Args[0],
			Args:    helperArgs,
			Timeout: 5 * time.Second,
		},
		KeyboardInteractive: &models.KeyboardInteractiveConfig{
			Rules: []models.ChallengeRule{
				{
					Name:          "env-check-rule",
					PromptPattern: "^Enter Token:",
					Source:        models.ChallengeSourceCommand,
					Command:       os.Args[0],
					Args:          helperArgs,
					Timeout:       5 * time.Second,
				},
			},
		},
	})
	cfg.Nodes.Set("cmd-node", models.Node{HostRef: "h-cmd", IdentityRef: "id-ops"})
	prov := config.NewProviderWithoutOpenSSH(cfg)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	// 1. With SessionAuth.{HostName, User, Port} override, both OTP and ChallengeRule commands
	//    must receive the effective overridden XOPS_HOST and XOPS_USER matching SecretRequest.
	adpOverride := NewSSHAdapter(prov, WithSessionAuthOverride("cmd-node", SessionAuth{
		HostName: "[2001:db8::99]",
		User:     "alice",
		Port:     2222,
	}))
	clientCfg, err := adpOverride.GetConfig("cmd-node")
	if err != nil {
		t.Fatalf("GetConfig(cmd-node): %v", err)
	}
	otpAns, err := adpOverride.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:     ssh.SecretKindOTP,
		NodeID:   clientCfg.NodeID,
		Host:     clientCfg.Address,
		BaseHost: clientCfg.BaseHost,
		Port:     clientCfg.Port,
		User:     clientCfg.User,
		Prompt:   "OTP:",
		Attempt:  1,
	})
	if err != nil || string(otpAns) != "2001:db8::99|alice|id-ops" {
		t.Fatalf("OTP helper env = (%q, %v), want 2001:db8::99|alice|id-ops", string(otpAns), err)
	}

	kiAns, err := adpOverride.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:     ssh.SecretKindKeyboardInteractive,
		NodeID:   clientCfg.NodeID,
		Host:     clientCfg.Address,
		BaseHost: clientCfg.BaseHost,
		Port:     clientCfg.Port,
		User:     clientCfg.User,
		Prompt:   "Enter Token:",
		Attempt:  1,
	})
	if err != nil || string(kiAns) != "2001:db8::99|alice|id-ops" {
		t.Fatalf("ChallengeRule helper env = (%q, %v), want 2001:db8::99|alice|id-ops", string(kiAns), err)
	}

	// 2. Without override, both commands receive the base snapshot host and user.
	adpBase := NewSSHAdapter(prov)
	baseOTP, err := adpBase.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:    ssh.SecretKindOTP,
		NodeID:  "cmd-node",
		Host:    "10.0.0.1",
		Port:    22,
		User:    "ops",
		Prompt:  "OTP:",
		Attempt: 1,
	})
	if err != nil || string(baseOTP) != "10.0.0.1|ops|id-ops" {
		t.Fatalf("ResolveSecret(OTP base) = (%q, %v), want 10.0.0.1|ops|id-ops", string(baseOTP), err)
	}
	baseKI, err := adpBase.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:    ssh.SecretKindKeyboardInteractive,
		NodeID:  "cmd-node",
		Host:    "10.0.0.1",
		Port:    22,
		User:    "ops",
		Prompt:  "Enter Token:",
		Attempt: 1,
	})
	if err != nil || string(baseKI) != "10.0.0.1|ops|id-ops" {
		t.Fatalf("ResolveSecret(ChallengeRule base) = (%q, %v), want 10.0.0.1|ops|id-ops", string(baseKI), err)
	}
}
