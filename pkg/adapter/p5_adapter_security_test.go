package adapter

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

type spyWriteBackProvider struct {
	config.ConfigProvider
	authWrites atomic.Int32
	sudoWrites atomic.Int32
}

func (s *spyWriteBackProvider) UpdateAuthAtVersionContext(_ context.Context, _, authVersion, _, _, _ string) (string, error) {
	s.authWrites.Add(1)
	return authVersion + "-mutated", nil
}

func (s *spyWriteBackProvider) UpdateSudoAtVersionContext(_ context.Context, _, sudoVersion string, _ models.SudoMode, _ string) (string, error) {
	s.sudoWrites.Add(1)
	return sudoVersion + "-mutated", nil
}

func (s *spyWriteBackProvider) GetOpenSSHParser() *config.OpenSSHParser {
	if p, ok := s.ConfigProvider.(interface{ GetOpenSSHParser() *config.OpenSSHParser }); ok {
		return p.GetOpenSSHParser()
	}
	return nil
}

type interactionCaptureResolver struct {
	interactionDisabled atomic.Bool
}

func (r *interactionCaptureResolver) Resolve(ctx context.Context, _ credential.Ref) (credential.Secret, error) {
	r.interactionDisabled.Store(credential.InteractionDisabled(ctx))
	return credential.Secret{Value: []byte("resolved-secret")}, nil
}

func TestP5_IsNonInteractiveForNodeFailClosed(t *testing.T) {
	t.Parallel()
	t.Run("nil_adapter_and_nil_provider_fail_closed", testP5IsNonInteractiveNilAdapterAndProvider)
	t.Run("unlatched_node_with_broken_ssh_config_fails_closed_and_blocks_writeback", testP5IsNonInteractiveUnlatchedBrokenConfig)
	t.Run("saved_node_with_invalid_tier4_option_disables_interaction_in_ResolveSecret", testP5IsNonInteractiveSavedInvalidTier4)
}

func testP5IsNonInteractiveNilAdapterAndProvider(t *testing.T) {
	var nilAdp *SSHAdapter
	if !nilAdp.isNonInteractiveForNode("any-node") {
		t.Fatal("(*SSHAdapter)(nil).isNonInteractiveForNode must return true (fail closed)")
	}
	if tok, err := nilAdp.UpdateAuth(t.Context(), "any-node", "v1", "pw", "", ""); err != nil || tok != "v1" {
		t.Fatalf("nil adapter UpdateAuth = (%q, %v), want (v1, nil)", tok, err)
	}
	noProvAdp := NewSSHAdapter(nil)
	if !noProvAdp.isNonInteractiveForNode("any-node") {
		t.Fatal("SSHAdapter with nil cfgProvider must fail closed (return true)")
	}
}

func testP5IsNonInteractiveUnlatchedBrokenConfig(t *testing.T) {
	brokenProv := config.NewProviderWithOpenSSHParser(nil, config.NewBrokenOpenSSHParser(errors.New("broken ssh_config")))
	spy := &spyWriteBackProvider{ConfigProvider: brokenProv}

	confirmCalled := false
	adp := NewSSHAdapter(
		spy,
		WithCredentialRecording(true),
		WithRememberConfirmation(func(context.Context, string) (bool, error) {
			confirmCalled = true
			return true, nil
		}),
	)

	if !adp.isNonInteractiveForNode("unlatched-node") {
		t.Fatal("isNonInteractiveForNode must fail closed (true) for unlatched node when Resolve fails")
	}
	tok, err := adp.UpdateAuth(t.Context(), "unlatched-node", "auth-v1", "discovered-secret", "", "")
	if err != nil || tok != "auth-v1" {
		t.Fatalf("UpdateAuth on fail-closed node = (%q, %v), want (auth-v1, nil)", tok, err)
	}
	sudoTok, err := adp.UpdateSudo(t.Context(), "unlatched-node", "sudo-v1", ssh.SudoModeSudo, "sudo-secret")
	if err != nil || sudoTok != "sudo-v1" {
		t.Fatalf("UpdateSudo on fail-closed node = (%q, %v), want (sudo-v1, nil)", sudoTok, err)
	}
	if spy.authWrites.Load() != 0 || spy.sudoWrites.Load() != 0 || confirmCalled {
		t.Fatalf("fail-closed node attempted credential write-back: authWrites=%d sudoWrites=%d confirmCalled=%v",
			spy.authWrites.Load(), spy.sudoWrites.Load(), confirmCalled)
	}
}

func testP5IsNonInteractiveSavedInvalidTier4(t *testing.T) {
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader("Host edge\n  HostName 10.40.0.1\n  ControlMaster bogus\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: "10.40.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{
		User:             "ops",
		AuthType:         "password",
		LoginPasswordRef: &credential.Ref{StoreID: "file", ItemID: "pw1"},
	})
	cfg.Nodes.Set("edge", models.Node{HostRef: "h1", IdentityRef: "id1"})

	resolver := &interactionCaptureResolver{}
	adp := NewSSHAdapter(config.NewProviderWithOpenSSHParser(cfg, parser), WithCredentialSource(resolver))
	if !adp.isNonInteractiveForNode("edge") {
		t.Fatal("expected isNonInteractiveForNode(edge)=true when Resolve fails on invalid ControlMaster")
	}
	sec, err := adp.ResolveSecret(t.Context(), ssh.SecretRequest{
		NodeID: "edge",
		Host:   "10.40.0.1",
		Port:   22,
		User:   "ops",
		Kind:   ssh.SecretKindLoginPassword,
	})
	if err != nil || string(sec) != "resolved-secret" {
		t.Fatalf("ResolveSecret = (%q, %v), want (resolved-secret, nil)", string(sec), err)
	}
	if !resolver.interactionDisabled.Load() {
		t.Fatal("ResolveSecret did not disable interaction via credential.WithoutInteraction when Resolve failed")
	}
}

func TestP5_Tier4SavedManagedAddressScopingBypassesClosed(t *testing.T) {
	t.Parallel()
	t.Run("bypass1_concrete_host_without_explicit_HostName_requires_address_match", testP5Bypass1ConcreteWithoutHostName)
	t.Run("bypass2_wildcard_with_conflicting_HostName_or_mismatched_name_blocked_while_Host_star_kept", testP5Bypass2WildcardIsolation)
	t.Run("bypass3_stale_snapOrigin_reverified_when_saved_node_Host_Address_changes", testP5Bypass3StaleSnapOrigin)
}

func testP5Bypass1ConcreteWithoutHostName(t *testing.T) {
	const sshCfg = `
Host prod
    ControlMaster auto
    ControlPath /tmp/evil-prod-%C
    ConnectTimeout 99

Host *
    ServerAliveInterval 25
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Hosts.Set("h-ip", models.Host{Address: "10.99.99.99", Port: 22})
	cfg.Nodes.Set("prod", models.Node{HostRef: "h-ip", IdentityRef: "id1"})
	cfg.Hosts.Set("h-dns", models.Host{Address: "prod", Port: 22})
	cfg.Nodes.Set("dns-prod", models.Node{HostRef: "h-dns", IdentityRef: "id1"})

	adp := NewSSHAdapter(config.NewProviderWithOpenSSHParser(cfg, parser))

	pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "prod"})
	if err != nil || pol.Control() != nil {
		t.Fatalf("Bypass 1: Host prod (without HostName) leaked ControlConfig onto 10.99.99.99: (%+v, %v)", pol.Control(), err)
	}
	opts := pol.Options()
	if opts == nil || opts.Get(ssh.OptionServerAliveInterval) != "25" {
		t.Fatalf("expected Host * ServerAliveInterval=25 fallback, got (%+v, %v)", opts, err)
	}
	if opts.Get(ssh.OptionConnectTimeout) != "" || opts.ControlPath() != "" {
		t.Fatalf("Bypass 1: Host prod leaked ConnectTimeout=%q ControlPath=%q", opts.Get(ssh.OptionConnectTimeout), opts.ControlPath())
	}

	polDNS, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "dns-prod"})
	if err != nil || polDNS.Options() == nil || polDNS.Options().Get(ssh.OptionConnectTimeout) != "99" {
		t.Fatalf("dns-prod (Host.Address=prod) opts = (%+v, %v), want ConnectTimeout=99", polDNS.Options(), err)
	}
}

func testP5Bypass2WildcardIsolation(t *testing.T) {
	const sshCfg = `
Host prod-*
    HostName 10.20.30.40
    ControlMaster auto
    ControlPath /tmp/evil-wild-explicit-%C
    ConnectTimeout 88

Host stage-*
    ControlMaster auto
    ControlPath /tmp/evil-wild-implicit-%C
    ConnectTimeout 77

Host 192.168.1.*
    TCPKeepAlive no

Host *
    ServerAliveInterval 25
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Hosts.Set("h1", models.Host{Address: "192.168.1.50", Port: 22})
	cfg.Nodes.Set("prod-web", models.Node{HostRef: "h1", IdentityRef: "id1", Alias: []string{"stage-web"}})

	adp := NewSSHAdapter(config.NewProviderWithOpenSSHParser(cfg, parser))

	pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "prod-web"})
	if err != nil || pol.Control() != nil {
		t.Fatalf("Bypass 2: wildcard Host prod-*/stage-* leaked ControlConfig onto 192.168.1.50: (%+v, %v)", pol.Control(), err)
	}
	opts := pol.Options()
	if opts == nil {
		t.Fatalf("Resolve(prod-web) = (%+v, %v), want Host * fallback", opts, err)
	}
	if got := opts.Get(ssh.OptionConnectTimeout); got != "" {
		t.Fatalf("Bypass 2: wildcard leaked ConnectTimeout=%q onto prod-web (192.168.1.50)", got)
	}
	if got := opts.Get(ssh.OptionServerAliveInterval); got != "25" {
		t.Fatalf("expected Host * ServerAliveInterval=25, got %q", got)
	}
	if keepAlive, set := opts.TCPKeepAlive(); !set || keepAlive {
		t.Fatalf("expected Host 192.168.1.* TCPKeepAlive=no via Host.Address, got (%v, %v)", keepAlive, set)
	}
}

func testP5Bypass3StaleSnapOrigin(t *testing.T) {
	const sshCfg = `
Host app-old
    HostName 10.0.0.1
    ControlMaster auto
    ControlPath /tmp/old-app-%C
    ConnectTimeout 66

Host *
    ServerAliveInterval 25
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatal(err)
	}
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateNodeContext(t.Context(), "saved-app",
		models.Node{HostRef: "h1", IdentityRef: "id1"},
		models.Host{Address: "10.0.0.1", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatal(err)
	}
	repo.SetNodeOpenSSHOrigin("saved-app", config.OpenSSHOrigin{Alias: "app-old"})

	adp := NewSSHAdapter(repo)
	if polBefore, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "saved-app"}); err != nil || polBefore.Options() == nil || polBefore.Options().Get(ssh.OptionConnectTimeout) != "66" {
		t.Fatalf("before address change opts = (%+v, %v), want ConnectTimeout=66", polBefore.Options(), err)
	}

	snap := repo.Snapshot()
	ref := repo.View().NodeRefs["saved-app"]
	n, _ := snap.Nodes.Get("saved-app")
	id, _ := snap.Identities.Get(n.IdentityRef)
	if err := repo.ReplaceNodeAtRefContext(t.Context(), ref, "saved-app", n, models.Host{Address: "10.0.0.2", Port: 22}, id); err != nil {
		t.Fatal(err)
	}
	repo.SetNodeOpenSSHOrigin("saved-app", config.OpenSSHOrigin{Alias: "app-old"})

	assertP5StaleOriginRejected(t, "no_tier1_origin", NewSSHAdapter(repo))
	assertP5StaleOriginRejected(t, "echoed_tier1_origin", NewSSHAdapter(repo, WithSessionAuthOverride("saved-app", SessionAuth{OriginalHost: "app-old"})))
}

func assertP5StaleOriginRejected(t *testing.T, label string, adp *SSHAdapter) {
	t.Helper()
	pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "saved-app"})
	if err != nil {
		t.Fatalf("Resolve(%s): %v", label, err)
	}
	if ctrl := pol.Control(); ctrl != nil {
		t.Fatalf("Bypass 3 (%s): stale snapOrigin leaked ControlConfig after Host.Address changed: %+v", label, ctrl)
	}
	opts := pol.Options()
	if opts != nil && opts.Get(ssh.OptionConnectTimeout) != "" {
		t.Fatalf("Bypass 3 (%s): stale snapOrigin leaked ConnectTimeout=%q", label, opts.Get(ssh.OptionConnectTimeout))
	}
	if opts == nil || opts.Get(ssh.OptionServerAliveInterval) != "25" {
		t.Fatalf("expected Host * ServerAliveInterval=25 fallback (%s), got %+v", label, opts)
	}
}

func setupP5ManagedKeyProvider() config.ConfigProvider {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: "10.91.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "key", KeyPath: "/tmp/saved_managed_key"})
	cfg.Nodes.Set("saved", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
		SSHOptions:  ssh.MustOptions(ssh.OptionIdentityFile, "/tmp/tier2_key"),
	})
	return config.NewProviderWithoutOpenSSH(cfg)
}

func TestP5_IdentityFileNoneTruncationAndKeyPathClear(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		authOverride *SessionAuth
		cliOptions   []string
		wantKeyPath  string
		wantKeyPaths []string
	}{
		{
			name:         "cli_option_IdentityFile_none_clears_managed_KeyPath",
			cliOptions:   []string{"IdentityFile=none"},
			wantKeyPath:  "",
			wantKeyPaths: []string{"none"},
		},
		{
			name:         "cli_option_concrete_then_none_then_extra",
			cliOptions:   []string{"IdentityFile=/tmp/cli_first", "IdentityFile=NONE", "IdentityFile=/tmp/cli_after_none"},
			wantKeyPath:  "/tmp/cli_first",
			wantKeyPaths: []string{"/tmp/cli_first"},
		},
		{
			name:         "cli_flag_i_none_then_extra_clears_managed_KeyPath",
			authOverride: &SessionAuth{KeyPaths: []string{"none", "/tmp/after_none"}},
			wantKeyPath:  "",
			wantKeyPaths: []string{"none"},
		},
		{
			name:         "cli_flag_k1_plus_option_IdentityFile_none",
			authOverride: &SessionAuth{KeyPaths: []string{"/tmp/flag_k1"}},
			cliOptions:   []string{"IdentityFile=none"},
			wantKeyPath:  "/tmp/flag_k1",
			wantKeyPaths: []string{"/tmp/flag_k1"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prov := setupP5ManagedKeyProvider()
			var opts []Option
			if tc.authOverride != nil {
				opts = append(opts, WithSessionAuthOverride("saved", *tc.authOverride))
			}
			if len(tc.cliOptions) > 0 {
				sc, err := ParseSessionOptions(tc.cliOptions, "")
				if err != nil {
					t.Fatal(err)
				}
				opts = append(opts, WithSessionControlOverride("saved", sc))
			}
			cfg, err := NewSSHAdapter(prov, opts...).GetConfig("saved")
			if err != nil {
				t.Fatal(err)
			}
			if cfg.KeyPath != tc.wantKeyPath || !slices.Equal(cfg.KeyPaths, tc.wantKeyPaths) {
				t.Fatalf("got (KeyPath=%q, KeyPaths=%v), want (%q, %v)", cfg.KeyPath, cfg.KeyPaths, tc.wantKeyPath, tc.wantKeyPaths)
			}
		})
	}

	t.Run("virtual_openssh_node_IdentityFile_none_clears_cfg_KeyPath", func(t *testing.T) {
		parser, err := config.NewOpenSSHParserFromReader(strings.NewReader("Host vapp\n  HostName 10.91.0.2\n  User ops\n  IdentityFile /tmp/ssh_cfg_key\n"))
		if err != nil {
			t.Fatal(err)
		}
		prov := config.NewProviderWithOpenSSHParser(&config.Configuration{}, parser)
		sc, err := ParseSessionOptions([]string{"IdentityFile=none"}, "")
		if err != nil {
			t.Fatal(err)
		}
		nodeID := config.OpenSSHNodePrefix + "vapp"
		cfg, err := NewSSHAdapter(prov, WithSessionControlOverride(nodeID, sc)).GetConfig(nodeID)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.KeyPath != "" || !slices.Equal(cfg.KeyPaths, []string{"none"}) {
			t.Fatalf("virtual node with -o IdentityFile=none got (KeyPath=%q, KeyPaths=%v), want (\"\", [none])", cfg.KeyPath, cfg.KeyPaths)
		}
	})
}

func TestP5_LayeredSessionControlOverridesAndDisableSharing(t *testing.T) {
	t.Parallel()

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.92.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "key", KeyPath: "/tmp/saved_key"})
	cfg.Nodes.Set("app", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
		SSHOptions:  ssh.MustOptions(ssh.OptionIdentityFile, "/tmp/tier2_key"),
	})
	prov := config.NewProviderWithoutOpenSSH(cfg)

	globalCtrl, err := ParseSessionOptions([]string{
		"BatchMode=yes",
		"StrictHostKeyChecking=yes",
		"ConnectTimeout=15",
		"ControlMaster=auto",
		"ControlPath=/tmp/global-%C",
		"ControlPersist=5m",
		"SendEnv=LANG",
		"IdentityFile=/tmp/global_cli_key",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	nodeCtrl, err := ParseSessionOptions([]string{
		"ConnectTimeout=3",
		"ServerAliveInterval=10",
		"ControlPath=/tmp/app-%C",
		"IdentityFile=/tmp/node_cli_key",
		"IdentityFile=none",
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	adp := NewSSHAdapter(prov, WithGlobalSessionControl(globalCtrl), WithSessionControlOverride("app", nodeCtrl))
	assertP5LayeredSessionOptionsBeforeDisable(t, adp)
	adp.DisableSessionControlSharing("app")
	assertP5LayeredSessionOptionsAfterDisable(t, adp)
}

func assertP5LayeredSessionOptionsBeforeDisable(t *testing.T, adp *SSHAdapter) {
	t.Helper()
	if !adp.isNonInteractiveForNode("app") {
		t.Fatal("node override must inherit global BatchMode=yes instead of shadowing globalSessionControl")
	}
	ctrl, err := adp.GetControlConfig("app")
	if err != nil || ctrl == nil {
		t.Fatalf("GetControlConfig(app) = (%+v, %v)", ctrl, err)
	}
	if ctrl.Path != "/tmp/app-%C" || ctrl.Master != ssh.ControlMasterAuto || ctrl.Persist != "5m" {
		t.Fatalf("layered ControlConfig = %+v, want Path=/tmp/app-%%C Master=auto Persist=5m", ctrl)
	}
	clientCfg, err := adp.GetConfig("app")
	if err != nil || clientCfg.Options == nil {
		t.Fatalf("GetConfig(app) = (%+v, %v)", clientCfg, err)
	}
	assertP5CommonLayeredNonMuxOptions(t, clientCfg.Options)
	if clientCfg.KeyPath != "/tmp/node_cli_key" || !slices.Equal(clientCfg.KeyPaths, []string{"/tmp/node_cli_key"}) {
		t.Fatalf("layered IdentityFile=none leak: KeyPath=%q KeyPaths=%v", clientCfg.KeyPath, clientCfg.KeyPaths)
	}
	if got := clientCfg.Options.IdentityFiles(); !slices.Equal(got, []string{"/tmp/node_cli_key"}) {
		t.Fatalf("clientCfg.Options.IdentityFiles() = %v, want [/tmp/node_cli_key]", got)
	}
}

func assertP5LayeredSessionOptionsAfterDisable(t *testing.T, adp *SSHAdapter) {
	t.Helper()
	ctrlAfter, err := adp.GetControlConfig("app")
	if err != nil || ctrlAfter == nil || ctrlAfter.Path != "none" || ctrlAfter.Master != ssh.ControlMasterNo || ctrlAfter.Persist != "" {
		t.Fatalf("GetControlConfig after DisableSessionControlSharing = (%+v, %v), want disabled none", ctrlAfter, err)
	}
	cfgAfter, err := adp.GetConfig("app")
	if err != nil || cfgAfter.Options == nil {
		t.Fatalf("GetConfig after DisableSessionControlSharing = (%+v, %v)", cfgAfter, err)
	}
	assertP5CommonLayeredNonMuxOptions(t, cfgAfter.Options)
	if cfgAfter.Options.ControlPath() != "none" || cfgAfter.Options.ControlPersist() != "" {
		t.Fatalf("expected mux disabled cleanly, got path=%q persist=%q", cfgAfter.Options.ControlPath(), cfgAfter.Options.ControlPersist())
	}
}

func assertP5CommonLayeredNonMuxOptions(t *testing.T, opts *ssh.Options) {
	t.Helper()
	if !opts.BatchMode() {
		t.Fatal("lost global BatchMode=yes")
	}
	if opts.StrictHostKeyChecking() != ssh.StrictHostKeyCheckingYes {
		t.Fatalf("StrictHostKeyChecking = %q, want yes", opts.StrictHostKeyChecking())
	}
	if opts.ConnectTimeout() != 3*time.Second {
		t.Fatalf("ConnectTimeout = %v, want 3s", opts.ConnectTimeout())
	}
	if opts.Get(ssh.OptionServerAliveInterval) != "10" {
		t.Fatalf("ServerAliveInterval = %q, want 10", opts.Get(ssh.OptionServerAliveInterval))
	}
	if got := opts.SendEnvPatterns(); !slices.Equal(got, []string{"LANG"}) {
		t.Fatalf("SendEnvPatterns = %v, want [LANG]", got)
	}
}
