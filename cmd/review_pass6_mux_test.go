package cmd

import (
	"context"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func buildPass6Repo(t *testing.T, sshConfigText string) *config.Repository {
	t.Helper()
	repo := setupTestRepository(t)
	cfg := repo.Snapshot()

	cfg.Hosts.Set("web-host", models.Host{
		Address: "10.238.221.181",
		Port:    22,
	})
	cfg.Identities.Set("web-id", models.Identity{
		User:     "ops",
		AuthType: "auto",
	})
	cfg.Nodes.Set("web-01", models.Node{
		HostRef:     "web-host",
		IdentityRef: "web-id",
	})

	store := config.NewDefaultStore(
		filepath.Join(t.TempDir(), "config.yaml"),
		filepath.Join(t.TempDir(), "key"),
	)
	if strings.TrimSpace(sshConfigText) == "" {
		r, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
		if err != nil {
			t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
		}
		return r
	}
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshConfigText))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	r, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	return r
}

func newPass6SessionControl(t *testing.T, sockPath string, kvPairs ...string) adapter.SessionControlOptions {
	t.Helper()
	var ctrl adapter.SessionControlOptions
	ctrl.SetMaster(ssh.ControlMasterYes)
	ctrl.SetPath(sockPath)
	ctrl.SetPersist("5m")
	if len(kvPairs)%2 != 0 {
		t.Fatalf("expected even key-value pairs, got %d", len(kvPairs))
	}
	if len(kvPairs) > 0 {
		ctrl.Options = &ssh.Options{}
		for i := 0; i < len(kvPairs); i += 2 {
			if err := ctrl.Options.Set(kvPairs[i], kvPairs[i+1]); err != nil {
				t.Fatalf("Options.Set(%q, %q): %v", kvPairs[i], kvPairs[i+1], err)
			}
		}
	}
	return ctrl
}

func newPass6Connector(adp *adapter.SSHAdapter) *ssh.Connector {
	connector := ssh.NewConnector(adp, ssh.WithHostKeyVerifier(staticHostKeyTrust{}))
	connector.AcceptNewHostKey.Store(true)
	return connector
}

func dialPass6FixtureRaw(t *testing.T, addr string) *cryptoSSH.Client {
	t.Helper()
	rawClient, err := cryptoSSH.Dial("tcp", addr, &cryptoSSH.ClientConfig{
		User:            "fixture",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("cryptoSSH.Dial(%s): %v", addr, err)
	}
	t.Cleanup(func() { _ = rawClient.Close() })
	return rawClient
}

func parsePass6MuxDaemonChild(
	t *testing.T,
	ctx context.Context,
	repo *config.Repository,
	spec MuxDaemonSpec,
) (string, *ssh.ClientConfig, *ssh.Options) {
	t.Helper()
	decoded := roundTripMuxDaemonSpecThroughPipe(t, spec)

	childOpts := NewSshOptions()
	if err := childOpts.applyMuxDaemonSpec(decoded); err != nil {
		t.Fatalf("applyMuxDaemonSpec(child %+v): %v", decoded, err)
	}
	if err := childOpts.Validate(); err != nil {
		t.Fatalf("Validate(child): %v", err)
	}
	childNodeID, _, err := childOpts.resolveNode(ctx, repo)
	if err != nil {
		t.Fatalf("resolveNode(child): %v", err)
	}
	childAdpOpts, err := childOpts.buildAdapterOptions(childNodeID, repo.Snapshot(), repo)
	if err != nil {
		t.Fatalf("buildAdapterOptions(child): %v", err)
	}
	adp := adapter.NewSSHAdapter(repo, childAdpOpts...)
	childCfg, err := adp.GetConfig(childNodeID)
	if err != nil {
		t.Fatalf("GetConfig(child %q): %v", childNodeID, err)
	}
	sessionCtrl, err := childOpts.toSessionControlOptions()
	if err != nil {
		t.Fatalf("toSessionControlOptions(child): %v", err)
	}
	effSSHOpts, err := adp.ResolveSSHOptions(childNodeID, sessionCtrl)
	if err != nil {
		t.Fatalf("ResolveSSHOptions(child %q): %v", childNodeID, err)
	}
	return childNodeID, childCfg, effSSHOpts
}

func TestPass6_M5_MuxDaemonArgsPreservesHostNameAndEscapesPercent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New: %v", err)
	}
	defer func() { _ = fix.Close() }()
	rawClient := dialPass6FixtureRaw(t, fix.Address)

	sshCfg := strings.Join([]string{
		"Host app-alias",
		"  HostName 10.0.0.5",
		"  User ops",
		"  Port 22",
		"  ServerAliveCountMax 7",
	}, "\n")

	t.Run("alias_cli_hostname_override_and_child_parity", func(t *testing.T) {
		verifyPass6M5AliasHostNameOverride(t, ctx, rawClient, sshCfg)
	})
	t.Run("ipv6_zone_percent_escaping_on_alias_and_saved_node", func(t *testing.T) {
		verifyPass6M5IPv6ZoneEscaping(t, ctx, rawClient, sshCfg)
	})
	t.Run("no_redundant_hostname_and_jump_isolation", func(t *testing.T) {
		verifyPass6M5NoRedundantAndJumpIsolation(t, ctx, rawClient)
	})
}

func verifyPass6M5AliasHostNameOverride(
	t *testing.T,
	ctx context.Context,
	rawClient *cryptoSSH.Client,
	sshCfg string,
) {
	t.Helper()
	tmpDir := shortControlTempDir(t)
	sockPath := filepath.Join(tmpDir, "m5-alias.sock")

	master, err := ssh.StartMuxServer(ctx, rawClient, ssh.MuxMasterOptions{
		Path: sockPath,
		Target: ssh.TargetContext{
			Host:         "10.0.0.99",
			Port:         2222,
			User:         "ops",
			OriginalHost: "app-alias",
			Control:      &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: sockPath, Persist: "5m"},
		},
	})
	if err != nil {
		t.Fatalf("StartMuxServer: %v", err)
	}
	defer func() { _ = master.Shutdown() }()

	parentOpts := NewSshOptions()
	parentOpts.Host = "app-alias"
	parentOpts.targetNodeIDs = []string{"openssh:app-alias"}
	parentOpts.control.Options = []string{"HostName=%h.ignored.internal", "ServerAliveInterval=15"}

	spec := parentOpts.buildMuxDaemonSpec("openssh:app-alias", sockPath, master)
	joinedOpts := strings.Join(spec.Options, " ")
	if strings.Contains(joinedOpts, "ignored.internal") {
		t.Fatalf("expected raw CLI HostName option to be stripped in favor of DialHost, got %q", joinedOpts)
	}
	if spec.TargetHost != "app-alias" || !spec.OpenSSHNamespace || spec.DialHost != "10.0.0.99" {
		t.Fatalf("expected TargetHost=app-alias, OpenSSHNamespace=true, DialHost=10.0.0.99, got %+v", spec)
	}
	if !slices.Contains(spec.Options, "ServerAliveInterval=15") {
		t.Fatalf("expected connection-wide ServerAliveInterval=15 to survive, got %v", spec.Options)
	}

	childRepo := buildPass6Repo(t, sshCfg)
	_, childCfg, effOpts := parsePass6MuxDaemonChild(t, ctx, childRepo, spec)
	if childCfg.Address != "10.0.0.99" || childCfg.Port != 2222 || childCfg.OriginalHost != "app-alias" {
		t.Fatalf("childCfg = (Address=%q, Port=%d, OriginalHost=%q), want (10.0.0.99, 2222, app-alias)",
			childCfg.Address, childCfg.Port, childCfg.OriginalHost)
	}
	if effOpts == nil || effOpts.ServerAliveCountMax() != 7 {
		t.Fatalf("expected Tier 4 ServerAliveCountMax=7 in daemon child, got %v", effOpts)
	}
}

func verifyPass6M5IPv6ZoneEscaping(
	t *testing.T,
	ctx context.Context,
	rawClient *cryptoSSH.Client,
	sshCfg string,
) {
	t.Helper()
	tmpDir := shortControlTempDir(t)

	cases := []struct {
		name         string
		nodeID       string
		origHost     string
		masterHost   string
		wantDialAddr string
	}{
		{
			name:         "alias_eth0_zone",
			nodeID:       "openssh:app-alias",
			origHost:     "app-alias",
			masterHost:   "fe80::1%eth0",
			wantDialAddr: "fe80::1%eth0",
		},
		{
			name:         "saved_node_percent_h_zone",
			nodeID:       "web-01",
			origHost:     "",
			masterHost:   "[fe80::1%h0]",
			wantDialAddr: "fe80::1%h0",
		},
	}

	for i, tc := range cases {
		sockPath := filepath.Join(tmpDir, "z"+strconv.Itoa(i)+".sock")
		master, err := ssh.StartMuxServer(ctx, rawClient, ssh.MuxMasterOptions{
			Path: sockPath,
			Target: ssh.TargetContext{
				Host:         tc.masterHost,
				Port:         22,
				User:         "ops",
				OriginalHost: tc.origHost,
				Control:      &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: sockPath, Persist: "5m"},
			},
		})
		if err != nil {
			t.Fatalf("%s: StartMuxServer: %v", tc.name, err)
		}
		defer func() { _ = master.Shutdown() }()

		parentOpts := NewSshOptions()
		parentOpts.targetNodeIDs = []string{tc.nodeID}
		spec := parentOpts.buildMuxDaemonSpec(tc.nodeID, sockPath, master)
		if spec.DialHost != tc.wantDialAddr {
			t.Fatalf("%s: spec.DialHost = %q, want verbatim %q", tc.name, spec.DialHost, tc.wantDialAddr)
		}

		childRepo := buildPass6Repo(t, sshCfg)
		_, childCfg, _ := parsePass6MuxDaemonChild(t, ctx, childRepo, spec)
		if childCfg.Address != tc.wantDialAddr {
			t.Fatalf("%s: childCfg.Address = %q, want %q", tc.name, childCfg.Address, tc.wantDialAddr)
		}
	}
}

func verifyPass6M5NoRedundantAndJumpIsolation(
	t *testing.T,
	ctx context.Context,
	rawClient *cryptoSSH.Client,
) {
	t.Helper()
	tmpDir := shortControlTempDir(t)

	directSock := filepath.Join(tmpDir, "direct.sock")
	directMaster, err := ssh.StartMuxServer(ctx, rawClient, ssh.MuxMasterOptions{
		Path: directSock,
		Target: ssh.TargetContext{
			Host:    "2001:db8::1",
			Port:    22,
			User:    "ops",
			Control: &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: directSock, Persist: "5m"},
		},
	})
	if err != nil {
		t.Fatalf("StartMuxServer(direct): %v", err)
	}
	defer func() { _ = directMaster.Shutdown() }()

	directOpts := NewSshOptions()
	directSpec := directOpts.buildMuxDaemonSpec("[2001:db8::1]", directSock, directMaster)
	if directSpec.DialHost != "" {
		t.Fatalf("expected no redundant DialHost when dialHost equals cleanMuxHost(targetHost), got %+v", directSpec)
	}

	jumpSameSock := filepath.Join(tmpDir, "jsame.sock")
	jumpSameMaster, err := ssh.StartMuxServer(ctx, rawClient, ssh.MuxMasterOptions{
		Path: jumpSameSock,
		Target: ssh.TargetContext{
			Host:         "bastion.internal",
			Port:         22,
			User:         "jump",
			OriginalHost: "bastion.internal",
			Control:      &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: jumpSameSock, Persist: "5m"},
		},
	})
	if err != nil {
		t.Fatalf("StartMuxServer(jumpSame): %v", err)
	}
	defer func() { _ = jumpSameMaster.Shutdown() }()

	jumpAliasSock := filepath.Join(tmpDir, "jalias.sock")
	jumpAliasMaster, err := ssh.StartMuxServer(ctx, rawClient, ssh.MuxMasterOptions{
		Path: jumpAliasSock,
		Target: ssh.TargetContext{
			Host:         "10.0.0.1",
			Port:         22,
			User:         "jump",
			OriginalHost: "bastion-alias",
			Control:      &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: jumpAliasSock, Persist: "5m"},
		},
	})
	if err != nil {
		t.Fatalf("StartMuxServer(jumpAlias): %v", err)
	}
	defer func() { _ = jumpAliasMaster.Shutdown() }()

	targetOpts := NewSshOptions()
	targetOpts.Host = "app"
	targetOpts.JumpHost = "bastion.internal,bastion-alias"
	targetOpts.targetNodeIDs = []string{"openssh:app"}
	targetOpts.control.Options = []string{"HostName=10.0.0.99"}

	sameSpec := targetOpts.buildMuxDaemonSpec("openssh:bastion.internal", jumpSameSock, jumpSameMaster)
	if sameSpec.DialHost != "" || strings.Contains(strings.Join(sameSpec.Options, " "), "HostName=") {
		t.Fatalf("expected target HostName override not to leak onto jumpSameMaster, got %+v", sameSpec)
	}
	aliasSpec := targetOpts.buildMuxDaemonSpec("openssh:bastion-alias", jumpAliasSock, jumpAliasMaster)
	if strings.Contains(strings.Join(aliasSpec.Options, " "), "10.0.0.99") || aliasSpec.DialHost != "10.0.0.1" {
		t.Fatalf("expected jumpAliasMaster to set DialHost=10.0.0.1 without target leak, got %+v", aliasSpec)
	}
}

func TestPass6_M6_ResolveOwnedMasterNodeIDAndCanonicalizedConnectorMaster(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New: %v", err)
	}
	defer func() { _ = fix.Close() }()
	fixHost, portStr, _ := net.SplitHostPort(fix.Address)
	fixPort, _ := strconv.Atoi(portStr)

	sshCfg := strings.Join([]string{
		"Host web",
		"  ServerAliveCountMax 3",
		"",
		"Host web.corp.example.com",
		"  HostName " + fixHost,
		"  Port " + strconv.Itoa(fixPort),
		"  User fixture",
		"  ServerAliveCountMax 13",
		"  ServerAliveInterval 17",
		"",
		"Host proxy.corp.example.com",
		"  HostName " + fixHost,
		"  Port " + strconv.Itoa(fixPort),
		"  User fixture",
		"  ProxyCommand sh -c 'exit 1'",
	}, "\n")
	repo := buildPass6Repo(t, sshCfg)

	verifyPass6M6CanonicalizedConnectorMaster(t, ctx, repo, sshCfg, fixHost, fixPort)
	verifyPass6M6ProxyCommandCheckUsesMasterNodeID(t, ctx, repo, fix.Address, fixHost, fixPort)
}

func verifyPass6M6CanonicalizedConnectorMaster(
	t *testing.T,
	ctx context.Context,
	repo *config.Repository,
	sshCfg string,
	fixHost string,
	fixPort int,
) {
	t.Helper()
	tmpDir := shortControlTempDir(t)
	sockPath := filepath.Join(tmpDir, "canon-owned.sock")

	const canonNodeID = "openssh:web.corp.example.com"
	adp := adapter.NewSSHAdapter(
		repo,
		adapter.WithNonInteractive(true),
		adapter.WithSessionAuthOverride(canonNodeID, adapter.SessionAuth{
			Password:     sshfixture.Password,
			OriginalHost: "web",
		}),
		adapter.WithSessionControlOverride(canonNodeID, newPass6SessionControl(t, sockPath)),
	)
	connector := newPass6Connector(adp)
	defer func() { _ = connector.CloseAll() }()

	client, err := connector.Connect(ctx, canonNodeID)
	if err != nil {
		t.Fatalf("connector.Connect(%s): %v", canonNodeID, err)
	}
	defer func() { _ = client.Close() }()

	masters := connector.Masters()
	if len(masters) != 1 {
		t.Fatalf("expected 1 owned master, got %d", len(masters))
	}
	m := masters[0]
	if got := connector.MasterNodeID(m); got != canonNodeID {
		t.Fatalf("connector.MasterNodeID = %q, want %q", got, canonNodeID)
	}
	if got := resolveOwnedMasterNodeID(repo, connector, m); got != canonNodeID {
		t.Fatalf("resolveOwnedMasterNodeID = %q, want %q", got, canonNodeID)
	}
	if got := resolvePersistentHandoffNodeID(repo, connector, m, canonNodeID); got != canonNodeID {
		t.Fatalf("resolvePersistentHandoffNodeID(owned) = %q, want %q", got, canonNodeID)
	}
	if got := resolvePersistentHandoffNodeID(repo, nil, m, canonNodeID); got != canonNodeID {
		t.Fatalf("resolvePersistentHandoffNodeID(unowned canonicalized) = %q, want %q", got, canonNodeID)
	}
	if found := findOwnedMasterForNode(connector, canonNodeID); found != m {
		t.Fatalf("findOwnedMasterForNode(%q) = %v, want %v", canonNodeID, found, m)
	}

	opts := NewSshOptions()
	opts.targetNodeIDs = []string{canonNodeID}
	spec := opts.buildMuxDaemonSpec(canonNodeID, sockPath, m)
	if spec.TargetHost != "web.corp.example.com" || !spec.OpenSSHNamespace || spec.DialHost != fixHost || spec.OriginalHost != "web" {
		t.Fatalf("expected canonicalized TargetHost=web.corp.example.com, OpenSSHNamespace=true, DialHost=%s, OriginalHost=web, got %+v", fixHost, spec)
	}

	childRepo := buildPass6Repo(t, sshCfg)
	_, childCfg, effOpts := parsePass6MuxDaemonChild(t, ctx, childRepo, spec)
	if childCfg.Address != fixHost || childCfg.Port != fixPort || childCfg.OriginalHost != "web" {
		t.Fatalf("childCfg = (Address=%q, Port=%d, OriginalHost=%q), want (%s, %d, web)",
			childCfg.Address, childCfg.Port, childCfg.OriginalHost, fixHost, fixPort)
	}
	// OpenSSH two-pass semantics apply Pass 1 (Host web -> ServerAliveCountMax=3)
	// before Pass 2 (Host web.corp.example.com -> ServerAliveInterval=17).
	if effOpts == nil || effOpts.ServerAliveCountMax() != 3 || effOpts.ServerAliveInterval() != 17*time.Second {
		t.Fatalf("expected canonicalized ServerAliveCountMax=3 and ServerAliveInterval=17s, got %v", effOpts)
	}
}

func verifyPass6M6ProxyCommandCheckUsesMasterNodeID(
	t *testing.T,
	ctx context.Context,
	repo *config.Repository,
	fixAddr string,
	fixHost string,
	fixPort int,
) {
	t.Helper()
	tmpDir := shortControlTempDir(t)
	sockPath := filepath.Join(tmpDir, "proxy-owned.sock")

	const proxyNodeID = "openssh:proxy.corp.example.com"
	// Override ProxyCommand=none during setup so the fixture TCP server can accept the
	// connection, then verify hasActiveProxyCommandInPath detects Tier 4 ProxyCommand
	// via connector.MasterNodeID(m) even when OriginalHost is "proxy" (absent in ssh_config)
	// and nodeID passed to the checker is unrelated.
	adp := adapter.NewSSHAdapter(
		repo,
		adapter.WithNonInteractive(true),
		adapter.WithSessionAuthOverride(proxyNodeID, adapter.SessionAuth{
			Password:     sshfixture.Password,
			OriginalHost: "proxy",
			ProxyJump:    "none",
		}),
		adapter.WithSessionControlOverride(
			proxyNodeID,
			newPass6SessionControl(t, sockPath, ssh.OptionProxyCommand, "none"),
		),
	)
	connector := newPass6Connector(adp)
	defer func() { _ = connector.CloseAll() }()

	client, err := connector.Connect(ctx, proxyNodeID)
	if err != nil {
		t.Fatalf("connector.Connect(%s) against %s (%s:%d): %v", proxyNodeID, fixAddr, fixHost, fixPort, err)
	}
	defer func() { _ = client.Close() }()

	checkOpts := NewSshOptions()
	if !checkOpts.hasActiveProxyCommandInPath(repo, "web-01", connector) {
		t.Fatal("expected hasActiveProxyCommandInPath to detect ProxyCommand via connector.MasterNodeID(m)")
	}
}

func TestPass6_M6_PendingOpenSSHAliasSavedJumpAndRace(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New: %v", err)
	}
	defer func() { _ = fix.Close() }()
	fixHost, portStr, _ := net.SplitHostPort(fix.Address)
	fixPort, _ := strconv.Atoi(portStr)

	sshCfg := strings.Join([]string{
		"Host app-alias",
		"  HostName " + fixHost,
		"  User ops",
		"  Port 22",
		"  ServerAliveCountMax 9",
		"",
		"Host app-alias-2",
		"  HostName " + fixHost,
		"  User ops",
		"  Port 22",
		"  ServerAliveCountMax 11",
	}, "\n")

	t.Run("pending_openssh_alias_and_collision_alt_id", func(t *testing.T) {
		verifyPass6M6PendingAliasResolution(t, ctx, sshCfg, fixHost, fixPort)
	})
	t.Run("saved_node_and_saved_jump_chain_handoff", func(t *testing.T) {
		verifyPass6M6SavedJumpChainAndRace(t, ctx, sshCfg, fixHost, fixPort)
	})
}

func verifyPass6M6PendingAliasResolution(
	t *testing.T,
	ctx context.Context,
	sshCfg string,
	fixHost string,
	fixPort int,
) {
	t.Helper()
	repo := buildPass6Repo(t, sshCfg)
	tmpDir := shortControlTempDir(t)

	// Prepare first pending connection for app-alias with user+port overrides.
	res1, err := repo.PrepareNodeContext(ctx, config.EnsureNodeOptions{
		Target: config.ConnectionTarget{
			Selector: "app-alias",
			User:     "fixture",
			HasUser:  true,
			Port:     uint16(fixPort),
			HasPort:  true,
		},
		Password: sshfixture.Password,
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(app-alias): %v", err)
	}
	if _, isSaved := repo.GetNode(res1.NodeID); isSaved {
		t.Fatalf("expected %q to remain pending (unsaved)", res1.NodeID)
	}

	// Prepare colliding pending connection on app-alias-2 sharing (fixture, 10.0.0.5, fixPort)
	// with a distinct IdentityFile to exercise disambiguated altID ("openssh:fixture@app-alias-2:<port>").
	res2, err := repo.PrepareNodeContext(ctx, config.EnsureNodeOptions{
		Target: config.ConnectionTarget{
			Selector: "app-alias-2",
			User:     "fixture",
			HasUser:  true,
			Port:     uint16(fixPort),
			HasPort:  true,
		},
		Password:     sshfixture.Password,
		IdentityFile: "/tmp/alt-key",
		Tags:         []string{"alt"},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(app-alias-2): %v", err)
	}
	if !strings.HasPrefix(res2.NodeID, config.OpenSSHNodePrefix) {
		t.Fatalf("expected colliding pending alias to allocate openssh: altID, got %q", res2.NodeID)
	}

	sock1 := filepath.Join(tmpDir, "p1.sock")
	sock2 := filepath.Join(tmpDir, "p2.sock")
	adp := adapter.NewSSHAdapter(
		repo,
		adapter.WithNonInteractive(true),
		adapter.WithCredentialRecording(false),
		adapter.WithSuppressNodeConfirmation(true),
		adapter.WithSessionAuthOverride(res1.NodeID, adapter.SessionAuth{
			Password:                 sshfixture.Password,
			HostName:                 fixHost,
			OriginalHost:             "app-alias",
			SuppressNodeConfirmation: true,
		}),
		adapter.WithSessionControlOverride(res1.NodeID, newPass6SessionControl(t, sock1)),
		adapter.WithSessionAuthOverride(res2.NodeID, adapter.SessionAuth{
			Password:                 sshfixture.Password,
			HostName:                 fixHost,
			OriginalHost:             "app-alias-2",
			SuppressNodeConfirmation: true,
		}),
		adapter.WithSessionControlOverride(res2.NodeID, newPass6SessionControl(t, sock2)),
	)
	connector := newPass6Connector(adp)
	defer func() { _ = connector.CloseAll() }()

	c1, err := connector.Connect(ctx, res1.NodeID)
	if err != nil {
		t.Fatalf("Connect(res1 %q): %v", res1.NodeID, err)
	}
	defer func() { _ = c1.Close() }()

	c2, err := connector.Connect(ctx, res2.NodeID)
	if err != nil {
		t.Fatalf("Connect(res2 %q): %v", res2.NodeID, err)
	}
	defer func() { _ = c2.Close() }()

	m1 := findOwnedMasterForNode(connector, res1.NodeID)
	m2 := findOwnedMasterForNode(connector, res2.NodeID)
	if m1 == nil || m2 == nil {
		t.Fatalf("expected owned masters for res1 (%v) and res2 (%v)", m1, m2)
	}

	if got := resolveOwnedMasterNodeID(repo, connector, m1); got != "openssh:app-alias" {
		t.Fatalf("resolveOwnedMasterNodeID(m1) = %q, want openssh:app-alias", got)
	}
	if got := resolveOwnedMasterNodeID(repo, nil, m1); got != "openssh:app-alias" {
		t.Fatalf("resolveOwnedMasterNodeID(nil connector, m1) = %q, want openssh:app-alias", got)
	}
	if got := resolveOwnedMasterNodeID(repo, connector, m2); got != "openssh:app-alias-2" {
		t.Fatalf("resolveOwnedMasterNodeID(m2) = %q, want openssh:app-alias-2", got)
	}

	// Verify targetNodeIDs tracking + daemon child re-resolution in a fresh OS-like Repository
	// where r.pending is empty.
	verifyPass6M6FreshChildRecovery(t, ctx, sshCfg, fixHost, fixPort, res1.NodeID, sock1, m1, resolveOwnedMasterNodeID(repo, connector, m1))
	verifyPass6M6PendingRewrittenHostNameFallback(t, ctx, tmpDir, fixHost, fixPort)
}

func verifyPass6M6FreshChildRecovery(
	t *testing.T,
	ctx context.Context,
	sshCfg string,
	fixHost string,
	fixPort int,
	resNodeID string,
	sock1 string,
	m1 *ssh.MuxServer,
	handoffID string,
) {
	t.Helper()
	opts := NewSshOptions()
	opts.IdentityFile = "/tmp/cli-target-key"
	opts.targetNodeIDs = []string{resNodeID}
	opts.recordTargetHandoffNodeID(resNodeID, handoffID)

	spec := opts.buildMuxDaemonSpec(handoffID, sock1, m1)
	if spec.TargetHost != "app-alias" || !spec.OpenSSHNamespace || !slices.Equal(spec.IdentityFiles, []string{"/tmp/cli-target-key"}) || spec.DialHost != fixHost {
		t.Fatalf("expected TargetHost=app-alias, OpenSSHNamespace=true, IdentityFiles=[/tmp/cli-target-key], DialHost=%s, got %+v", fixHost, spec)
	}

	freshChildRepo := buildPass6Repo(t, sshCfg)
	_, childCfg, effOpts := parsePass6MuxDaemonChild(t, ctx, freshChildRepo, spec)
	if childCfg.Address != fixHost || childCfg.Port != fixPort || childCfg.User != "fixture" {
		t.Fatalf("fresh childCfg = (Address=%q, Port=%d, User=%q), want (%s, %d, fixture)",
			childCfg.Address, childCfg.Port, childCfg.User, fixHost, fixPort)
	}
	if effOpts == nil || effOpts.ServerAliveCountMax() != 9 {
		t.Fatalf("expected fresh daemon child to recover ServerAliveCountMax=9, got %v", effOpts)
	}
}

func verifyPass6M6PendingRewrittenHostNameFallback(
	t *testing.T,
	ctx context.Context,
	tmpDir string,
	fixHost string,
	fixPort int,
) {
	t.Helper()
	// Also verify fallback pending OpenSSHAlias lookup when CLI -o HostName overrode
	// master.Target().Host away from ssh_config's HostName (10.0.0.5 -> fixHost).
	overrideCfg := strings.Join([]string{
		"Host override-alias",
		"  HostName 10.0.0.5",
		"  User ops",
		"  Port 22",
	}, "\n")
	overrideRepo := buildPass6Repo(t, overrideCfg)
	if _, prepErr := overrideRepo.PrepareNodeContext(ctx, config.EnsureNodeOptions{
		Target: config.ConnectionTarget{
			Selector: "override-alias",
			User:     "fixture",
			HasUser:  true,
			Port:     uint16(fixPort),
			HasPort:  true,
		},
	}); prepErr != nil {
		t.Fatalf("PrepareNodeContext(override-alias): %v", prepErr)
	}
	rawClient := dialPass6FixtureRaw(t, net.JoinHostPort(fixHost, strconv.Itoa(fixPort)))
	overrideSock := filepath.Join(tmpDir, "p-override.sock")
	overrideMaster, err := ssh.StartMuxServer(ctx, rawClient, ssh.MuxMasterOptions{
		Path: overrideSock,
		Target: ssh.TargetContext{
			Host:         fixHost,
			Port:         fixPort,
			User:         "fixture",
			OriginalHost: "override-alias",
			Control:      &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: overrideSock, Persist: "5m"},
		},
	})
	if err != nil {
		t.Fatalf("StartMuxServer(overrideMaster): %v", err)
	}
	defer func() { _ = overrideMaster.Shutdown() }()

	if got := resolveOwnedMasterNodeID(overrideRepo, nil, overrideMaster); got != "openssh:override-alias" {
		t.Fatalf("resolveOwnedMasterNodeID(override-alias with rewritten HostName) = %q, want openssh:override-alias", got)
	}
}

func verifyPass6M6SavedJumpChainAndRace(
	t *testing.T,
	ctx context.Context,
	sshCfg string,
	fixHost string,
	fixPort int,
) {
	t.Helper()
	repo := buildPass6Repo(t, sshCfg)
	cfg := repo.Snapshot()
	cfg.Hosts.Set("jump-host", models.Host{Address: fixHost, Port: uint16(fixPort)})
	cfg.Hosts.Set("target-host", models.Host{Address: fixHost, Port: uint16(fixPort)})
	cfg.Identities.Set("fix-id", models.Identity{User: "fixture", AuthType: "auto"})
	cfg.Nodes.Set("jump-01", models.Node{HostRef: "jump-host", IdentityRef: "fix-id"})
	cfg.Nodes.Set("target-01", models.Node{HostRef: "target-host", IdentityRef: "fix-id", ProxyJump: "jump-01"})

	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "k"))
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader(savedRepo): %v", err)
	}
	savedRepo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser(savedRepo): %v", err)
	}
	// Simulate an earlier session alias annotation on target-01; direct saved-node
	// connection (OriginalHost == "") must still preserve saved node ID "target-01".
	savedRepo.SetNodeOpenSSHAlias("target-01", "app-alias")

	tmpDir := shortControlTempDir(t)
	jumpSock := filepath.Join(tmpDir, "j-saved.sock")
	targetSock := filepath.Join(tmpDir, "t-saved.sock")

	adp := adapter.NewSSHAdapter(
		savedRepo,
		adapter.WithNonInteractive(true),
		adapter.WithGlobalSessionAuth(adapter.SessionAuth{Password: sshfixture.Password}),
		adapter.WithSessionControlOverride("jump-01", newPass6SessionControl(t, jumpSock)),
		adapter.WithSessionControlOverride("target-01", newPass6SessionControl(t, targetSock)),
	)
	connector := newPass6Connector(adp)
	defer func() { _ = connector.CloseAll() }()

	cli, err := connector.Connect(ctx, "target-01")
	if err != nil {
		t.Fatalf("connector.Connect(target-01): %v", err)
	}
	defer func() { _ = cli.Close() }()

	jumpMaster := findOwnedMasterForNode(connector, "jump-01")
	targetMaster := findOwnedMasterForNode(connector, "target-01")
	if jumpMaster == nil || targetMaster == nil {
		t.Fatalf("expected both jumpMaster (%v) and targetMaster (%v)", jumpMaster, targetMaster)
	}
	if got := resolveOwnedMasterNodeID(savedRepo, connector, jumpMaster); got != "jump-01" {
		t.Fatalf("resolveOwnedMasterNodeID(jumpMaster) = %q, want jump-01", got)
	}
	if got := resolveOwnedMasterNodeID(savedRepo, connector, targetMaster); got != "target-01" {
		t.Fatalf("resolveOwnedMasterNodeID(targetMaster) = %q, want target-01", got)
	}

	jumps := persistentJumpHops(connector.Masters())
	if !isSuppressedJumpMaster(jumps, connector.MasterNodeID(jumpMaster), "jump-01") {
		t.Fatal("expected saved jump-01 master to be suppressed when target-01 master is persistent")
	}
	chain := jumpChainMasters(connector, targetMaster, connector.Masters())
	if len(chain) != 1 || chain[0] != jumpMaster {
		t.Fatalf("jumpChainMasters = %v, want [%v]", chain, jumpMaster)
	}

	// Concurrent -race stress across connector/provider readers and pending resolution.
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for range 25 {
				if got := resolveOwnedMasterNodeID(savedRepo, connector, targetMaster); got != "target-01" {
					t.Errorf("worker %d: resolveOwnedMasterNodeID = %q, want target-01", id, got)
					return
				}
				if got := findOwnedMasterForNode(connector, "jump-01"); got != jumpMaster {
					t.Errorf("worker %d: findOwnedMasterForNode = %v, want %v", id, got, jumpMaster)
					return
				}
				opts := NewSshOptions()
				_ = opts.hasActiveProxyCommandInPath(savedRepo, "target-01", connector)
				_, _ = savedRepo.PrepareNodeContext(ctx, config.EnsureNodeOptions{
					Target: config.ConnectionTarget{
						Selector: "app-alias",
						User:     "raceuser" + strconv.Itoa(id),
						HasUser:  true,
						Port:     uint16(fixPort),
						HasPort:  true,
					},
				})
			}
		}(g)
	}
	wg.Wait()
}
