package adapter

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP0_SavedNodeTier4AddressScopingIsolation(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host web
    HostName 192.168.99.99
    ControlMaster auto
    ControlPath /tmp/evil-web-%C
    ConnectTimeout 99

Host web-alias
    HostName 192.168.99.98
    ControlMaster yes
    ControlPath /tmp/evil-alias-%C
    ConnectTimeout 88

Host host-alias
    HostName 192.168.99.97
    ControlMaster yes
    ControlPath /tmp/evil-host-%C
    ConnectTimeout 77

Host 192.168.99.96
    ControlMaster yes
    ControlPath /tmp/evil-ip-%C
    ConnectTimeout 66

Host *
    ServerAliveInterval 25
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{
		Address: "10.0.0.1",
		Port:    22,
		Alias:   []string{"host-alias"},
	})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("web", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
		Alias:       []string{"web-alias", "192.168.99.96"},
	})

	adp := NewSSHAdapter(config.NewProviderWithOpenSSHParser(cfg, parser))

	pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "web"})
	if err != nil {
		t.Fatalf("Resolve(web): %v", err)
	}
	if ctrl := pol.Control(); ctrl != nil {
		t.Fatalf("unrelated concrete Host web/alias leaked ControlConfig onto saved node web (10.0.0.1): %+v", ctrl)
	}

	opts := pol.Options()
	if opts == nil {
		t.Fatal("expected wildcard Host * ServerAliveInterval=25")
	}
	if got := opts.Get(ssh.OptionConnectTimeout); got != "" {
		t.Fatalf("unrelated concrete Host leaked ConnectTimeout=%q onto saved node web (10.0.0.1)", got)
	}
	if got := opts.ControlPath(); got != "" {
		t.Fatalf("unrelated concrete Host leaked ControlPath=%q onto saved node web (10.0.0.1)", got)
	}
	if got := opts.Get(ssh.OptionServerAliveInterval); got != "25" {
		t.Fatalf("expected Host * ServerAliveInterval=25, got %q", got)
	}
}

func TestP0_SavedNodeTier4AllowsMatchingExplicitHostNameAndIPv6(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host web
    HostName 10.0.0.1
    ControlMaster auto
    ControlPath /tmp/good-web-%C
    ConnectTimeout 14

Host v6node
    HostName 2001:0db8::1
    ConnectTimeout 19

Host v6mismatch
    HostName 2001:db8::99
    ConnectTimeout 99

Host 10.0.0.5
    HostName 192.168.99.5
    ConnectTimeout 55
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Hosts.Set("h-web", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Nodes.Set("web", models.Node{HostRef: "h-web", IdentityRef: "id1"})

	cfg.Hosts.Set("h-v6", models.Host{Address: "2001:db8::1", Port: 22})
	cfg.Nodes.Set("v6node", models.Node{HostRef: "h-v6", IdentityRef: "id1", Alias: []string{"v6mismatch"}})

	cfg.Hosts.Set("h-redir", models.Host{Address: "10.0.0.5", Port: 22})
	cfg.Nodes.Set("redir-target", models.Node{HostRef: "h-redir", IdentityRef: "id1"})

	adp := NewSSHAdapter(config.NewProviderWithOpenSSHParser(cfg, parser))

	// Matching explicit HostName applies cleanly.
	polWeb, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "web"})
	if err != nil || polWeb.Control() == nil || polWeb.Control().Path != "/tmp/good-web-%C" {
		t.Fatalf("matching Host web control = (%+v, %v), want /tmp/good-web-%%C", polWeb.Control(), err)
	}
	if optsWeb := polWeb.Options(); optsWeb == nil || optsWeb.Get(ssh.OptionConnectTimeout) != "14" {
		t.Fatalf("matching Host web opts = (%+v, %v), want ConnectTimeout=14", optsWeb, err)
	}

	// Canonical IPv6 matches v6node while rejecting mismatched alias v6mismatch.
	polV6, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "v6node"})
	if err != nil || polV6.Options() == nil || polV6.Options().Get(ssh.OptionConnectTimeout) != "19" {
		t.Fatalf("matching IPv6 v6node opts = (%+v, %v), want ConnectTimeout=19", polV6.Options(), err)
	}

	// Concrete Host 10.0.0.5 redirected to 192.168.99.5 must NOT leak onto saved node at 10.0.0.5.
	polRedir, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "redir-target"})
	if err != nil {
		t.Fatalf("Resolve(redir-target): %v", err)
	}
	if optsRedir := polRedir.Options(); optsRedir != nil && optsRedir.Get(ssh.OptionConnectTimeout) != "" {
		t.Fatalf("redirected Host 10.0.0.5 leaked ConnectTimeout=%q", optsRedir.Get(ssh.OptionConnectTimeout))
	}
}

func TestP0_DisableSessionControlSharingPreservesGlobalOptions(t *testing.T) {
	t.Parallel()

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.10.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("app", models.Node{HostRef: "h1", IdentityRef: "id1"})

	globalCtrl, err := ParseSessionOptions([]string{
		"BatchMode=yes",
		"StrictHostKeyChecking=yes",
		"ConnectTimeout=9",
		"ControlMaster=auto",
		"ControlPath=/tmp/cm-%C",
		"ControlPersist=5m",
	}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions: %v", err)
	}

	adp := NewSSHAdapter(
		config.NewProviderWithoutOpenSSH(cfg),
		WithGlobalSessionControl(globalCtrl),
	)

	// "app" has no entry in sessionControlOverrides yet; disabling control sharing must seed from globalSessionControl.
	adp.DisableSessionControlSharing("app")

	ctrl, err := adp.GetControlConfig("app")
	if err != nil {
		t.Fatalf("GetControlConfig(app): %v", err)
	}
	if ctrl == nil || ctrl.Path != "none" || ctrl.Master != ssh.ControlMasterNo {
		t.Fatalf("expected disabled control config on app, got %+v", ctrl)
	}

	clientCfg, err := adp.GetConfig("app")
	if err != nil {
		t.Fatalf("GetConfig(app): %v", err)
	}
	if clientCfg.Options == nil {
		t.Fatal("expected non-nil clientCfg.Options")
	}
	if !clientCfg.Options.BatchMode() {
		t.Fatal("DisableSessionControlSharing dropped global BatchMode=yes on nodeID")
	}
	if clientCfg.Options.StrictHostKeyChecking() != ssh.StrictHostKeyCheckingYes {
		t.Fatalf("DisableSessionControlSharing dropped global StrictHostKeyChecking=yes, got %q", clientCfg.Options.StrictHostKeyChecking())
	}
	if clientCfg.Options.ConnectTimeout() != 9*time.Second {
		t.Fatalf("DisableSessionControlSharing dropped global ConnectTimeout=9s, got %v", clientCfg.Options.ConnectTimeout())
	}
	if clientCfg.Options.ControlPath() != "none" || clientCfg.Options.ControlPersist() != "" {
		t.Fatalf("expected mux disabled cleanly, got path=%q persist=%q", clientCfg.Options.ControlPath(), clientCfg.Options.ControlPersist())
	}
}

func TestP0_IsNonInteractiveForNodeFailClosedAndValidateSecretMissingBaseHost(t *testing.T) {
	t.Parallel()

	t.Run("interactiveDecisionForNode honors Tier-1 BatchMode and latch even when Resolve fails", func(t *testing.T) {
		brokenProv := config.NewProviderWithOpenSSHParser(nil, config.NewBrokenOpenSSHParser(errors.New("broken ssh_config")))
		batchOpts, err := ParseSessionOptions([]string{"BatchMode=yes"}, "")
		if err != nil {
			t.Fatal(err)
		}

		// 1. Tier-1 BatchMode=yes denies interactivity even when Resolve fails on broken ssh_config.
		adpTier1 := NewSSHAdapter(brokenProv, WithSessionControlOverride("unsaved-node", batchOpts))
		if !adpTier1.interactiveDecisionForNode("unsaved-node").Denied() {
			t.Fatal("expected interactiveDecisionForNode=Deny with Tier-1 BatchMode=yes despite broken parser")
		}

		// 2. Latched BatchMode denies interactivity even when Resolve fails on broken ssh_config.
		adpLatched := NewSSHAdapter(brokenProv)
		adpLatched.latchBatchMode("unsaved-node")
		if !adpLatched.interactiveDecisionForNode("unsaved-node").Denied() {
			t.Fatal("expected interactiveDecisionForNode=Deny with latched BatchMode despite broken parser")
		}

		// 3. Explicit Tier-1 BatchMode=no still overrides latched BatchMode.
		batchNoOpts, err := ParseSessionOptions([]string{"BatchMode=no"}, "")
		if err != nil {
			t.Fatal(err)
		}
		adpNo := NewSSHAdapter(brokenProv, WithSessionControlOverride("unsaved-node", batchNoOpts))
		adpNo.latchBatchMode("unsaved-node")
		if adpNo.interactiveDecisionForNode("unsaved-node").Denied() {
			t.Fatal("expected explicit Tier-1 BatchMode=no to override latch")
		}

		// 4. Nil cfgProvider with Tier-1 BatchMode=yes or latch still denies interactivity.
		adpNil := NewSSHAdapter(nil, WithSessionControlOverride("n1", batchOpts))
		if !adpNil.interactiveDecisionForNode("n1").Denied() {
			t.Fatal("expected interactiveDecisionForNode=Deny with nil cfgProvider and Tier-1 BatchMode=yes")
		}
	})

	t.Run("validateSecretRequestSnapshotWithState fails closed when BaseHost omitted under HostName override", func(t *testing.T) {
		store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
		repo, err := config.NewRepositoryWithoutOpenSSH(nil, store)
		if err != nil {
			t.Fatal(err)
		}
		creds := round7StubCredentialResolver{secrets: map[string]string{"file/p": "secret-pw"}}
		if _, err := repo.CreateNodeContext(t.Context(), "ov-node",
			models.Node{HostRef: "h1", IdentityRef: "id1"},
			models.Host{Address: "10.99.0.1", Port: 22},
			models.Identity{User: "ops", AuthType: "password", LoginPasswordRef: &credential.Ref{StoreID: "file", ItemID: "p"}},
		); err != nil {
			t.Fatal(err)
		}

		adp := NewSSHAdapter(repo,
			WithCredentialSource(creds),
			WithSessionAuthOverride("ov-node", SessionAuth{HostName: "override.example.internal"}),
		)
		cfg, err := adp.GetConfig("ov-node")
		if err != nil {
			t.Fatalf("GetConfig: %v", err)
		}

		// Omitting BaseHost under HostName override must fail closed with ErrSnapshotMismatch.
		_, err = adp.ResolveSecret(t.Context(), ssh.SecretRequest{
			NodeID:       "ov-node",
			Host:         cfg.Address,
			BaseHost:     "",
			Port:         cfg.Port,
			User:         cfg.User,
			Kind:         ssh.SecretKindLoginPassword,
			VersionToken: cfg.AuthUpdateToken,
		})
		if !errors.Is(err, ssh.ErrSnapshotMismatch) {
			t.Fatalf("ResolveSecret without BaseHost under HostName override = %v, want ErrSnapshotMismatch", err)
		}

		// Providing matching BaseHost succeeds.
		sec, err := adp.ResolveSecret(t.Context(), ssh.SecretRequest{
			NodeID:       "ov-node",
			Host:         cfg.Address,
			BaseHost:     cfg.BaseHost,
			Port:         cfg.Port,
			User:         cfg.User,
			Kind:         ssh.SecretKindLoginPassword,
			VersionToken: cfg.AuthUpdateToken,
		})
		if err != nil || string(sec) != "secret-pw" {
			t.Fatalf("ResolveSecret with matching BaseHost = (%q, %v), want (secret-pw, nil)", string(sec), err)
		}
	})
}
