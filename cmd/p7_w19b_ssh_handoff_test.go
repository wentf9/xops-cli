package cmd

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func buildW19bHandoffRepo(t *testing.T, sshCfg, fixHost string, fixPort int, savedUser string) *config.Repository {
	t.Helper()
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-app", models.Host{Address: fixHost, Port: uint16(fixPort)})
	cfg.Identities.Set("id-app", models.Identity{
		User:     savedUser,
		AuthType: "password",
		Password: sshfixture.Password,
		KeyPath:  "/tmp/w19b_saved_key",
	})
	tier2Opts := &ssh.Options{}
	if err := tier2Opts.Set(ssh.OptionServerAliveInterval, "33"); err != nil {
		t.Fatal(err)
	}
	if err := tier2Opts.Set(ssh.OptionServerAliveCountMax, "6"); err != nil {
		t.Fatal(err)
	}
	cfg.Nodes.Set("app.example.com", models.Node{
		HostRef:     "h-app",
		IdentityRef: "id-app",
		Alias:       []string{"app-saved"},
		SSHOptions:  tier2Opts,
	})
	store := config.NewDefaultStore(
		filepath.Join(t.TempDir(), "xops_config.yaml"),
		filepath.Join(t.TempDir(), "xops.key"),
	)
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	return repo
}

func assertW19bHostileTier4Blocked(t *testing.T, opts *ssh.Options, desc string) {
	t.Helper()
	if opts == nil {
		return
	}
	if got := opts.ActiveProxyCommand(); got != "" {
		t.Fatalf("%s: leaked Tier-4 ProxyCommand=%q", desc, got)
	}
	if got := opts.Get(ssh.OptionStrictHostKeyChecking); got != "" {
		t.Fatalf("%s: leaked hostile StrictHostKeyChecking=%q", desc, got)
	}
	if got := opts.Get(ssh.OptionUserKnownHostsFile); got != "" {
		t.Fatalf("%s: leaked hostile UserKnownHostsFile=%q", desc, got)
	}
	if got := opts.Get(ssh.OptionSendEnv); got != "" {
		t.Fatalf("%s: leaked Tier-4 SendEnv=%q", desc, got)
	}
	if got := opts.Get(ssh.OptionConnectTimeout); got == "77" {
		t.Fatalf("%s: leaked mismatched Host app.example.com ConnectTimeout=77", desc)
	}
}

func TestP7W19b_L3_19_H1_ControlPersistHandoffEnforcesProvenance(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New: %v", err)
	}
	defer func() { _ = fix.Close() }()
	fixHost, portStr, err := net.SplitHostPort(fix.Address)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", fix.Address, err)
	}
	fixPort, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", portStr, err)
	}

	sshCfg := strings.Join([]string{
		"Host app",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains example.com",
		"",
		"Host app.example.com",
		"  HostName 192.0.2.99",
		"  Port 9999",
		"  StrictHostKeyChecking no",
		"  UserKnownHostsFile /dev/null",
		"  ProxyCommand /bin/evil-proxy",
		"  SendEnv LEAK_W19B",
		"  ConnectTimeout 77",
		"",
		"Host app-real",
		"  HostName " + fixHost,
		"  Port " + portStr,
		"  ProxyCommand /bin/evil-real",
		"  SendEnv LEAK_REAL",
		"  ConnectTimeout 41",
		"",
		"Host ossh-box",
		"  HostName " + fixHost,
		"  Port " + portStr,
		"  User ops",
		"  ServerAliveCountMax 9",
		"  ConnectTimeout 29",
	}, "\n") + "\n"

	t.Run("PathA_overridden_saved_node_adhoc_pending_preserves_non_openssh_handoff", func(t *testing.T) {
		assertW19bH1PathAAdHocPending(t, ctx, sshCfg, fixHost, fixPort)
	})
	t.Run("PathB_saved_managed_canonicalized_node_preserves_saved_identity_and_tier2", func(t *testing.T) {
		assertW19bH1PathBSavedManaged(t, ctx, sshCfg, fixHost, fixPort)
	})
	t.Run("Genuine_openssh_derived_still_normalizes_to_openssh_namespace", func(t *testing.T) {
		assertW19bH1GenuineOpenSSHDerived(t, ctx, sshCfg, fixHost, fixPort)
	})
}

func assertW19bNonOpenSSHMasterNodeIDs(
	t *testing.T,
	repo *config.Repository,
	connector *ssh.Connector,
	m *ssh.MuxServer,
	wantID string,
	label string,
) {
	t.Helper()
	if got := normalizeOwnedMasterNodeID(repo, wantID, m); got != wantID {
		t.Fatalf("normalizeOwnedMasterNodeID(%s) = %q, want %q", label, got, wantID)
	}
	if got := resolveOwnedMasterNodeID(repo, connector, m); got != wantID {
		t.Fatalf("resolveOwnedMasterNodeID(%s) = %q, want %q", label, got, wantID)
	}
	if got := resolveOwnedMasterNodeID(repo, nil, m); got != wantID {
		t.Fatalf("resolveMasterNodeID(%s) = %q, want %q", label, got, wantID)
	}
	if got := resolvePersistentHandoffNodeID(repo, connector, m, wantID); got != wantID {
		t.Fatalf("resolvePersistentHandoffNodeID(%s, owned) = %q, want %q", label, got, wantID)
	}
	if got := resolvePersistentHandoffNodeID(repo, nil, m, wantID); got != wantID {
		t.Fatalf("resolvePersistentHandoffNodeID(%s, unowned) = %q, want %q", label, got, wantID)
	}
	if got := resolvePendingOpenSSHAlias(repo, wantID); got != "" {
		t.Fatalf("resolvePendingOpenSSHAlias(%s) = %q, want empty", label, got)
	}
	if got := resolvePendingCanonicalHost(repo, wantID); got != "" {
		t.Fatalf("resolvePendingCanonicalHost(%s) = %q, want empty", label, got)
	}
}

func assertW19bH1PathAPortOverride(t *testing.T, ctx context.Context, repo *config.Repository, sshCfg, tmpDir, fixHost string, fixPort int) error {
	t.Helper()
	altPort := uint16(2223)
	if int(altPort) == fixPort {
		altPort = 2224
	}
	portOpts := NewSshOptions()
	portOpts.Remember = "never"
	portOpts.Port = altPort
	portOpts.Host = "app.example.com"
	portOpts.originalHost = "app"
	portOpts.canonicalized = true
	portOpts.Target = config.ConnectionTarget{
		Selector:     "app.example.com",
		OriginalHost: "app",
		Port:         altPort,
		HasPort:      true,
	}
	return repo.WithPendingNode(ctx, config.EnsureNodeOptions{Target: portOpts.Target}, func(portLease config.PendingLease) error {
		portOwnedID := portLease.NodeID()
		portOpts.targetNodeIDs = []string{portOwnedID}
		portSpec := portOpts.buildMuxDaemonSpecWithRawNode(repo, portOwnedID, portOwnedID, filepath.Join(tmpDir, "w19b-port.sock"), nil)
		if portSpec.OpenSSHNamespace || portSpec.TargetHost != "app.example.com" || !portSpec.PreserveSelector || portSpec.Port != altPort {
			t.Fatalf("Path A -p MuxDaemonSpec mismatch: %+v", portSpec)
		}
		childRepoPort := buildW19bHandoffRepo(t, sshCfg, fixHost, fixPort, "ops")
		_, portChildCfg, portChildOpts := parsePass6MuxDaemonChildWithProvenanceCheck(t, ctx, childRepoPort, portSpec, config.ProvenanceAdHocPending)
		if portChildCfg.Address != fixHost || portChildCfg.Port != int(altPort) || portChildCfg.User != "ops" {
			t.Fatalf("Path A -p childCfg = (%q, %d, %q), want (%s, %d, ops)", portChildCfg.Address, portChildCfg.Port, portChildCfg.User, fixHost, altPort)
		}
		assertW19bHostileTier4Blocked(t, portChildOpts, "Path A -p detached daemon")
		if portChildOpts != nil && portChildOpts.Get(ssh.OptionConnectTimeout) == "41" {
			t.Fatalf("Path A -p detached daemon leaked port-%d ConnectTimeout=41 onto port %d", fixPort, altPort)
		}
		return nil
	})
}

func assertW19bH1PathADetachedChild(
	t *testing.T,
	ctx context.Context,
	sshCfg, fixHost string,
	fixPort int,
	ownedID string,
	spec MuxDaemonSpec,
) {
	t.Helper()
	if spec.OpenSSHNamespace || spec.TargetHost != "app.example.com" || !spec.PreserveSelector || spec.User != "fixture" || int(spec.Port) != fixPort || !spec.Canonicalized || spec.OriginalHost != "app" {
		t.Fatalf("Path A MuxDaemonSpec mismatch: %+v", spec)
	}
	childRepo := buildW19bHandoffRepo(t, sshCfg, fixHost, fixPort, "ops")
	childNodeID, childCfg, childOpts := parsePass6MuxDaemonChildWithProvenanceCheck(t, ctx, childRepo, spec, config.ProvenanceAdHocPending)
	if childNodeID != ownedID || config.IsOpenSSHNodeID(childNodeID) {
		t.Fatalf("Path A child nodeID = %q, want non-OpenSSH %q", childNodeID, ownedID)
	}
	if childCfg.Address != fixHost || childCfg.Port != fixPort || childCfg.User != "fixture" || childCfg.OriginalHost != "app" {
		t.Fatalf("Path A childCfg = (Addr=%q Port=%d User=%q Orig=%q), want (%s %d fixture app)",
			childCfg.Address, childCfg.Port, childCfg.User, childCfg.OriginalHost, fixHost, fixPort)
	}
	assertW19bHostileTier4Blocked(t, childOpts, "Path A detached daemon")
	if childOpts == nil || childOpts.Get(ssh.OptionConnectTimeout) != "41" {
		t.Fatalf("Path A detached daemon lost endpoint-matched safe ConnectTimeout=41: %v", childOpts)
	}
}

func assertW19bH1PathAAdHocPending(t *testing.T, ctx context.Context, sshCfg, fixHost string, fixPort int) {
	t.Helper()
	repo := buildW19bHandoffRepo(t, sshCfg, fixHost, fixPort, "ops")
	tmpDir := shortControlTempDir(t)
	sockPath := filepath.Join(tmpDir, "w19b-path-a.sock")

	opts := NewSshOptions()
	opts.Remember = "never"
	opts.User = "fixture"
	opts.Host = "app.example.com"
	opts.originalHost = "app"
	opts.canonicalized = true
	opts.Target = config.ConnectionTarget{
		Selector:     "app.example.com",
		OriginalHost: "app",
		User:         "fixture",
		HasUser:      true,
	}

	if err := repo.WithPendingNode(ctx, config.EnsureNodeOptions{Target: opts.Target}, func(lease config.PendingLease) error {
		ownedID := lease.NodeID()
		snap, err := repo.ResolveConnection(ownedID)
		if err != nil || snap.Provenance != config.ProvenanceAdHocPending {
			t.Fatalf("foreground ResolveConnection(%q) = (%s, %v), want adhoc_pending", ownedID, snap.Provenance, err)
		}

		adp := adapter.NewSSHAdapter(
			repo,
			adapter.WithNonInteractive(true),
			adapter.WithCredentialRecording(false),
			adapter.WithSuppressNodeConfirmation(true),
			adapter.WithSessionAuthOverride(ownedID, adapter.SessionAuth{
				Password:                 sshfixture.Password,
				OriginalHost:             "app",
				CanonicalHost:            "app.example.com",
				SuppressNodeConfirmation: true,
			}),
			adapter.WithSessionControlOverride(ownedID, newPass6SessionControl(t, sockPath)),
		)
		connector := newPass6Connector(adp)
		defer func() { _ = connector.CloseAll() }()

		client, err := connector.Connect(ctx, ownedID)
		if err != nil {
			t.Fatalf("connector.Connect(%q): %v", ownedID, err)
		}
		defer func() { _ = client.Close() }()

		m := findOwnedMasterForNode(connector, ownedID)
		if m == nil {
			t.Fatalf("expected owned master for %q", ownedID)
		}

		assertW19bNonOpenSSHMasterNodeIDs(t, repo, connector, m, ownedID, "Path A")
		if got := resolveMasterNodeIDViaUserPending(repo, "app", fixHost, "fixture", uint16(fixPort)); got != "" {
			t.Fatalf("resolveMasterNodeIDViaUserPending(adhoc_pending) = %q, want empty", got)
		}
		if got := resolveMasterVirtualOpenSSHNodeID(repo, "app", fixHost, "fixture", uint16(fixPort)); got != "" {
			t.Fatalf("resolveMasterVirtualOpenSSHNodeID(adhoc_pending) = %q, want empty", got)
		}

		opts.targetNodeIDs = []string{ownedID}
		spec := opts.buildMuxDaemonSpecWithRawNode(repo, ownedID, ownedID, sockPath, m)
		assertW19bH1PathADetachedChild(t, ctx, sshCfg, fixHost, fixPort, ownedID, spec)
		return assertW19bH1PathAPortOverride(t, ctx, repo, sshCfg, tmpDir, fixHost, fixPort)
	}); err != nil {
		t.Fatalf("WithPendingNode(Path A): %v", err)
	}
}

func assertW19bH1PathBSavedManaged(t *testing.T, ctx context.Context, sshCfg, fixHost string, fixPort int) {
	t.Helper()
	repo := buildW19bHandoffRepo(t, sshCfg, fixHost, fixPort, "fixture")
	repo.SetNodeOpenSSHOrigin("app.example.com", config.OpenSSHOrigin{
		Alias:         "app",
		CanonicalHost: "app.example.com",
	})
	tmpDir := shortControlTempDir(t)
	sockPath := filepath.Join(tmpDir, "w19b-path-b.sock")

	opts := NewSshOptions()
	opts.Host = "app.example.com"
	opts.originalHost = "app"
	opts.canonicalized = true
	opts.Target = config.ConnectionTarget{
		Selector:     "app.example.com",
		OriginalHost: "app",
	}
	opts.targetNodeIDs = []string{"app.example.com"}

	adp := adapter.NewSSHAdapter(
		repo,
		adapter.WithNonInteractive(true),
		adapter.WithSessionAuthOverride("app.example.com", adapter.SessionAuth{
			OriginalHost:  "app",
			CanonicalHost: "app.example.com",
		}),
		adapter.WithSessionControlOverride("app.example.com", newPass6SessionControl(t, sockPath)),
	)
	connector := newPass6Connector(adp)
	defer func() { _ = connector.CloseAll() }()

	client, err := connector.Connect(ctx, "app.example.com")
	if err != nil {
		t.Fatalf("connector.Connect(app.example.com): %v", err)
	}
	defer func() { _ = client.Close() }()

	m := findOwnedMasterForNode(connector, "app.example.com")
	if m == nil {
		t.Fatal("expected owned master for app.example.com")
	}

	assertW19bNonOpenSSHMasterNodeIDs(t, repo, connector, m, "app.example.com", "Path B")

	spec := opts.buildMuxDaemonSpecWithRawNode(repo, "app.example.com", "app.example.com", sockPath, m)
	if spec.OpenSSHNamespace || spec.TargetHost != "app.example.com" || !spec.PreserveSelector || spec.OriginalHost != "app" || !spec.Canonicalized {
		t.Fatalf("Path B MuxDaemonSpec mismatch: %+v", spec)
	}

	childRepo := buildW19bHandoffRepo(t, sshCfg, fixHost, fixPort, "fixture")
	childNodeID, childCfg, childOpts := parsePass6MuxDaemonChildWithProvenanceCheck(t, ctx, childRepo, spec, config.ProvenanceSavedManaged)
	if childNodeID != "app.example.com" {
		t.Fatalf("Path B child nodeID = %q, want app.example.com", childNodeID)
	}
	if childCfg.Address != fixHost || childCfg.Port != fixPort || childCfg.User != "fixture" || childCfg.Password != sshfixture.Password {
		t.Fatalf("Path B childCfg lost saved address/credentials: %+v", childCfg)
	}
	if childOpts == nil || childOpts.ServerAliveInterval() != 33*time.Second || childOpts.ServerAliveCountMax() != 6 {
		t.Fatalf("Path B child daemon lost saved Tier-2 SSHOptions: %v", childOpts)
	}
	assertW19bHostileTier4Blocked(t, childOpts, "Path B detached daemon")
	if childOpts.Get(ssh.OptionConnectTimeout) != "41" {
		t.Fatalf("Path B child daemon lost endpoint-matched safe ConnectTimeout=41: %v", childOpts)
	}
}

func assertW19bH1GenuineOpenSSHDerived(t *testing.T, ctx context.Context, sshCfg, fixHost string, fixPort int) {
	t.Helper()
	repo := buildW19bHandoffRepo(t, sshCfg, fixHost, fixPort, "ops")
	tmpDir := shortControlTempDir(t)
	sockPath := filepath.Join(tmpDir, "w19b-ossh-derived.sock")

	opts := NewSshOptions()
	opts.Remember = "never"
	opts.User = "fixture"
	opts.Host = "ossh-box"
	opts.Target = config.ConnectionTarget{
		Selector: "ossh-box",
		User:     "fixture",
		HasUser:  true,
	}

	if err := repo.WithPendingNode(ctx, config.EnsureNodeOptions{Target: opts.Target}, func(lease config.PendingLease) error {
		rawID := lease.NodeID()
		snap, err := repo.ResolveConnection(rawID)
		if err != nil {
			t.Fatalf("ResolveConnection(%q): %v", rawID, err)
		}
		if snap.Provenance != config.ProvenanceOpenSSHDerived {
			t.Fatalf("ossh-box -l fixture Provenance = %s, want openssh_derived", snap.Provenance)
		}

		adp := adapter.NewSSHAdapter(
			repo,
			adapter.WithNonInteractive(true),
			adapter.WithCredentialRecording(false),
			adapter.WithSuppressNodeConfirmation(true),
			adapter.WithSessionAuthOverride(rawID, adapter.SessionAuth{
				Password:                 sshfixture.Password,
				OriginalHost:             "ossh-box",
				SuppressNodeConfirmation: true,
			}),
			adapter.WithSessionControlOverride(rawID, newPass6SessionControl(t, sockPath)),
		)
		connector := newPass6Connector(adp)
		defer func() { _ = connector.CloseAll() }()

		client, err := connector.Connect(ctx, rawID)
		if err != nil {
			t.Fatalf("connector.Connect(%q): %v", rawID, err)
		}
		defer func() { _ = client.Close() }()

		m := findOwnedMasterForNode(connector, rawID)
		if m == nil {
			t.Fatalf("expected owned master for %q", rawID)
		}

		const wantHandoffID = config.OpenSSHNodePrefix + "ossh-box"
		if got := normalizeOwnedMasterNodeID(repo, rawID, m); got != wantHandoffID {
			t.Fatalf("normalizeOwnedMasterNodeID(openssh_derived) = %q, want %q", got, wantHandoffID)
		}
		if got := resolveOwnedMasterNodeID(repo, connector, m); got != wantHandoffID {
			t.Fatalf("resolveOwnedMasterNodeID(openssh_derived) = %q, want %q", got, wantHandoffID)
		}
		if got := resolveOwnedMasterNodeID(repo, nil, m); got != wantHandoffID {
			t.Fatalf("resolveMasterNodeID(openssh_derived) = %q, want %q", got, wantHandoffID)
		}
		if got := resolvePendingOpenSSHAlias(repo, rawID); got != "ossh-box" {
			t.Fatalf("resolvePendingOpenSSHAlias(openssh_derived) = %q, want ossh-box", got)
		}

		opts.targetNodeIDs = []string{rawID}
		opts.recordTargetHandoffNodeID(rawID, wantHandoffID)
		spec := opts.buildMuxDaemonSpecWithRawNode(repo, wantHandoffID, rawID, sockPath, m)
		if !spec.OpenSSHNamespace || spec.TargetHost != "ossh-box" || spec.User != "fixture" {
			t.Fatalf("genuine OpenSSH derived MuxDaemonSpec mismatch: %+v", spec)
		}

		childRepo := buildW19bHandoffRepo(t, sshCfg, fixHost, fixPort, "ops")
		childNodeID, childCfg, childOpts := parsePass6MuxDaemonChildWithProvenanceCheck(t, ctx, childRepo, spec, config.ProvenanceOpenSSHVirtual)
		if !config.IsOpenSSHNodeID(childNodeID) {
			t.Fatalf("genuine OpenSSH child nodeID = %q, want openssh: namespace", childNodeID)
		}
		if childCfg.Address != fixHost || childCfg.Port != fixPort || childCfg.User != "fixture" {
			t.Fatalf("genuine OpenSSH childCfg = (%q, %d, %q), want (%s, %d, fixture)",
				childCfg.Address, childCfg.Port, childCfg.User, fixHost, fixPort)
		}
		if childOpts == nil || childOpts.ServerAliveCountMax() != 9 || childOpts.Get(ssh.OptionConnectTimeout) != "29" {
			t.Fatalf("genuine OpenSSH child lost Tier-4 virtual options: %v", childOpts)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPendingNode(ossh-box): %v", err)
	}
}

func parsePass6MuxDaemonChildWithProvenanceCheck(
	t *testing.T,
	ctx context.Context,
	repo *config.Repository,
	spec MuxDaemonSpec,
	wantProv config.NodeProvenance,
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
	var (
		childNodeID string
		childCfg    *ssh.ClientConfig
		effSSHOpts  *ssh.Options
	)
	if err := childOpts.withTestPendingNode(ctx, repo, func(lease config.PendingLease) error {
		childNodeID = lease.NodeID()
		snap, err := repo.ResolveConnection(childNodeID)
		if err != nil {
			t.Fatalf("child ResolveConnection(%q): %v", childNodeID, err)
		}
		if snap.Provenance != wantProv {
			t.Fatalf("child ResolveConnection(%q).Provenance = %s, want %s", childNodeID, snap.Provenance, wantProv)
		}
		childAdpOpts, err := childOpts.buildAdapterOptions(childNodeID, repo.Snapshot(), repo)
		if err != nil {
			t.Fatalf("buildAdapterOptions(child): %v", err)
		}
		adp := adapter.NewSSHAdapter(repo, childAdpOpts...)
		childCfg, err = adp.GetConfig(childNodeID)
		if err != nil {
			t.Fatalf("GetConfig(child %q): %v", childNodeID, err)
		}
		sessionCtrl, err := childOpts.toSessionControlOptions()
		if err != nil {
			t.Fatalf("toSessionControlOptions(child): %v", err)
		}
		pol, err := adp.Resolve(ctx, adapter.ResolveRequest{NodeID: childNodeID, SessionControl: &sessionCtrl})
		if err != nil {
			t.Fatalf("Resolve(child %q): %v", childNodeID, err)
		}
		effSSHOpts = pol.Options()
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingNode(child): %v", err)
	}
	return childNodeID, childCfg, effSSHOpts
}

func TestP7W19b_L3_19_M1_CheckOwnedMasterDoesNotFallThroughToOpenSSH(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New: %v", err)
	}
	defer func() { _ = fix.Close() }()
	fixHost, portStr, err := net.SplitHostPort(fix.Address)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", fix.Address, err)
	}
	fixPort, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", portStr, err)
	}

	sshCfg := strings.Join([]string{
		"Host clean-node",
		"  ProxyCommand /bin/evil-clean-node",
		"",
		"Host clean-alias",
		"  ProxyCommand /bin/evil-clean-alias",
		"",
		"Host proxied-ossh",
		"  HostName " + fixHost,
		"  Port " + portStr,
		"  User ops",
		"  ProxyCommand /bin/real-ossh-proxy",
		"",
		"Host *",
		"  ProxyCommand /bin/evil-wildcard",
	}, "\n") + "\n"

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-clean", models.Host{Address: fixHost, Port: uint16(fixPort)})
	cfg.Identities.Set("id-clean", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	cfg.Nodes.Set("clean-node", models.Node{
		HostRef:     "h-clean",
		IdentityRef: "id-clean",
		Alias:       []string{"clean-alias"},
	})
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "k"))
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	t.Run("saved_owned_master_not_falsely_blocked_by_openssh_Host_or_wildcard_ProxyCommand", func(t *testing.T) {
		tmpDir := shortControlTempDir(t)
		sockPath := filepath.Join(tmpDir, "clean-owned.sock")

		adp := adapter.NewSSHAdapter(
			repo,
			adapter.WithNonInteractive(true),
			adapter.WithSessionAuthOverride("clean-node", adapter.SessionAuth{
				OriginalHost: "clean-alias",
			}),
			adapter.WithSessionControlOverride("clean-node", newPass6SessionControl(t, sockPath)),
		)
		connector := newPass6Connector(adp)
		defer func() { _ = connector.CloseAll() }()

		client, err := connector.Connect(ctx, "clean-node")
		if err != nil {
			t.Fatalf("connector.Connect(clean-node): %v", err)
		}
		defer func() { _ = client.Close() }()

		opts := NewSshOptions()
		opts.Host = "clean-alias"
		opts.Target = config.ConnectionTarget{Selector: "clean-alias"}
		opts.targetNodeIDs = []string{"clean-node"}

		skip, skipErr := opts.shouldSkipMasterHandoff(ctx, connector, repo, "clean-node")
		if skipErr != nil || skip {
			t.Fatalf("shouldSkipMasterHandoff(clean-node with owned master) = (%v, %v), want (false, nil)", skip, skipErr)
		}
	})

	t.Run("derived_openssh_target_preserves_isTarget_ProxyCommand_none_override_and_detects_active_proxy", func(t *testing.T) {
		tmpDir := shortControlTempDir(t)
		sockPath := filepath.Join(tmpDir, "ossh-proxy-owned.sock")

		osshParser, pErr := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
		if pErr != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", pErr)
		}
		osshStore := config.NewDefaultStore(filepath.Join(t.TempDir(), "ossh.yaml"), filepath.Join(t.TempDir(), "ossh.key"))
		osshRepo, rErr := config.NewRepositoryWithOpenSSHParser(config.NewProviderWithoutOpenSSH(nil).Snapshot(), osshStore, osshParser)
		if rErr != nil {
			t.Fatalf("NewRepositoryWithOpenSSHParser: %v", rErr)
		}

		if err := osshRepo.WithPendingNode(ctx, config.EnsureNodeOptions{
			Target: config.ConnectionTarget{
				Selector: "proxied-ossh",
				User:     "fixture",
				HasUser:  true,
			},
		}, func(lease config.PendingLease) error {
			derivedID := lease.NodeID()
			snap, snapErr := osshRepo.ResolveConnection(derivedID)
			if snapErr != nil || snap.Provenance != config.ProvenanceOpenSSHDerived {
				t.Fatalf("ResolveConnection(%q) = (%s, %v), want openssh_derived", derivedID, snap.Provenance, snapErr)
			}
			adp := adapter.NewSSHAdapter(
				osshRepo,
				adapter.WithNonInteractive(true),
				adapter.WithCredentialRecording(false),
				adapter.WithSuppressNodeConfirmation(true),
				adapter.WithSessionAuthOverride(derivedID, adapter.SessionAuth{
					Password:                 sshfixture.Password,
					OriginalHost:             "proxied-ossh",
					ProxyJump:                "none",
					SuppressNodeConfirmation: true,
				}),
				adapter.WithSessionControlOverride(derivedID, newPass6SessionControl(t, sockPath, ssh.OptionProxyCommand, "none")),
			)
			connector := newPass6Connector(adp)
			defer func() { _ = connector.CloseAll() }()

			client, err := connector.Connect(ctx, derivedID)
			if err != nil {
				t.Fatalf("connector.Connect(%q): %v", derivedID, err)
			}
			defer func() { _ = client.Close() }()

			// Without -o ProxyCommand=none: must detect proxied-ossh's ProxyCommand and skip handoff.
			optsNoOverride := NewSshOptions()
			optsNoOverride.Host = "proxied-ossh"
			optsNoOverride.User = "fixture"
			optsNoOverride.Target = config.ConnectionTarget{Selector: "proxied-ossh", User: "fixture", HasUser: true}
			optsNoOverride.targetNodeIDs = []string{derivedID}
			if skip, err := optsNoOverride.shouldSkipMasterHandoff(ctx, connector, osshRepo, derivedID); err != nil || !skip {
				t.Fatalf("shouldSkipMasterHandoff(proxied-ossh without override) = (%v, %v), want (true, nil)", skip, err)
			}

			// With -o ProxyCommand=none on target: isTarget must remain true for owned master so handoff is allowed.
			optsOverride := NewSshOptions()
			optsOverride.Host = "proxied-ossh"
			optsOverride.User = "fixture"
			optsOverride.control.Options = []string{"ProxyCommand=none"}
			optsOverride.Target = config.ConnectionTarget{Selector: "proxied-ossh", User: "fixture", HasUser: true}
			optsOverride.targetNodeIDs = []string{derivedID}
			if skip, err := optsOverride.shouldSkipMasterHandoff(ctx, connector, osshRepo, derivedID); err != nil || skip {
				t.Fatalf("shouldSkipMasterHandoff(proxied-ossh with -o ProxyCommand=none) = (%v, %v), want (false, nil)", skip, err)
			}
			return nil
		}); err != nil {
			t.Fatalf("WithPendingNode(proxied-ossh): %v", err)
		}
	})
}

func TestP7W19b_L3_19_M2_CanonicalizeCLIHostNameInPlaceDialAndControl(t *testing.T) {
	t.Parallel()

	openSSH := strings.Join([]string{
		"Host prod-nocli",
		"  User pass1-ops",
		"",
		"Host prod-nocli.corp.example.com",
		"  HostName 10.20.30.40",
		"",
		"Host web.corp.example.com",
		"  HostName 10.20.30.40",
		"  User corp-ops",
		"  Port 2222",
		"  ControlPath /tmp/w19b-cm-%n-%h-%p-%r",
		"  ServerAliveInterval 23",
		"",
		"Host prod-web.corp.example.com",
		"  User token-ops",
		"  Port 2202",
		"  ControlPath /tmp/w19b-tok-%n-%h-%p-%r",
		"",
		"Host *",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains corp.example.com",
	}, "\n") + "\n"

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSH))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := config.NewProviderWithOpenSSHParser(nil, parser)
	resolver := &phase4FakeResolver{
		hosts: map[string][]string{
			"prod-nocli.corp.example.com": {"10.20.30.40"},
			"web.corp.example.com":        {"10.20.30.40"},
			"prod-web.corp.example.com":   {"10.20.30.41"},
		},
	}

	t.Run("cli_HostName_canonicalized_in_place_across_dial_and_control_check", func(t *testing.T) {
		t.Parallel()
		dialSock := assertW19bM2DialCanonicalCLIHostName(t, prov, resolver)
		ctlSock := assertW19bM2ControlCanonicalCLIHostName(t, prov, resolver)
		const wantSock = "/tmp/w19b-cm-prod-web.corp.example.com-2222-corp-ops"
		if ctlSock != wantSock || dialSock != wantSock {
			t.Fatalf("socket mismatch: dial=%q control=%q want=%q", dialSock, ctlSock, wantSock)
		}
	})

	t.Run("cli_HostName_with_percent_h_token_canonicalized_without_reexpanding_to_unqualified", func(t *testing.T) {
		t.Parallel()
		opts := NewSshOptions()
		opts.Host = "prod"
		opts.Target = config.ConnectionTarget{Selector: "prod", RawSelector: "prod"}
		opts.control.Options = []string{"HostName=%h-web"}
		if err := opts.ensureGeneralOptionsApplied(); err != nil {
			t.Fatalf("ensureGeneralOptionsApplied: %v", err)
		}
		if err := opts.applyHostnameCanonicalization(t.Context(), prov, resolver); err != nil {
			t.Fatalf("applyHostnameCanonicalization: %v", err)
		}
		got, err := opts.effectiveHostName()
		if err != nil || got != "prod-web.corp.example.com" {
			t.Fatalf("effectiveHostName(%q) = (%q, %v), want (prod-web.corp.example.com, nil)", "%h-web", got, err)
		}
	})

	t.Run("no_cli_HostName_keeps_cliHostName_empty_so_pass2_HostName_wins", func(t *testing.T) {
		t.Parallel()
		assertW19bM2NoCLIHostNamePreservesPass2(t, prov, resolver)
	})
}

func assertW19bM2DialCanonicalCLIHostName(t *testing.T, prov *config.Provider, resolver config.CanonicalResolver) string {
	t.Helper()
	dialOpts := NewSshOptions()
	dialOpts.Host = "prod"
	dialOpts.Target = config.ConnectionTarget{Selector: "prod", RawSelector: "prod"}
	dialOpts.control.Options = []string{"HostName=web"}
	dialOpts.canonicalResolver = resolver
	if err := dialOpts.ensureGeneralOptionsApplied(); err != nil {
		t.Fatalf("ensureGeneralOptionsApplied(dial): %v", err)
	}
	if err := dialOpts.applyHostnameCanonicalization(t.Context(), prov, resolver); err != nil {
		t.Fatalf("applyHostnameCanonicalization(dial): %v", err)
	}
	if dialOpts.cliHostName != "web.corp.example.com" || dialOpts.HostName != "web.corp.example.com" {
		t.Fatalf("dial CLI HostName not canonicalized in place: cliHostName=%q HostName=%q", dialOpts.cliHostName, dialOpts.HostName)
	}
	effHost, err := dialOpts.effectiveHostName()
	if err != nil || effHost != "web.corp.example.com" {
		t.Fatalf("dial effectiveHostName() = (%q, %v), want (web.corp.example.com, nil)", effHost, err)
	}

	dialNodeID := config.OpenSSHNodePrefix + "web.corp.example.com"
	adpOpts, err := dialOpts.buildAdapterOptions(dialNodeID, prov.Snapshot(), prov)
	if err != nil {
		t.Fatalf("buildAdapterOptions(dial): %v", err)
	}
	dialCfg, err := adapter.NewSSHAdapter(prov, adpOpts...).GetConfig(dialNodeID)
	if err != nil {
		t.Fatalf("adp.GetConfig(dial): %v", err)
	}
	if dialCfg.Address != "web.corp.example.com" || dialCfg.OriginalHost != "prod" || dialCfg.CanonicalHost != "web.corp.example.com" {
		t.Fatalf("dialCfg = (Addr=%q Orig=%q Canon=%q), want (web.corp.example.com, prod, web.corp.example.com)",
			dialCfg.Address, dialCfg.OriginalHost, dialCfg.CanonicalHost)
	}
	if dialCfg.User != "corp-ops" || dialCfg.Port != 2222 || dialCfg.Options == nil || dialCfg.Options.ServerAliveInterval() != 23*time.Second {
		t.Fatalf("dialCfg lost Pass-2 User/Port/Options: user=%q port=%d opts=%v", dialCfg.User, dialCfg.Port, dialCfg.Options)
	}
	dialSock, err := controlSocketPath(dialOpts, prov, dialNodeID)
	if err != nil {
		t.Fatalf("controlSocketPath(dial): %v", err)
	}
	return dialSock
}

func assertW19bM2ControlCanonicalCLIHostName(t *testing.T, prov *config.Provider, resolver config.CanonicalResolver) string {
	t.Helper()
	ctlOpts := NewSshOptions()
	ctlOpts.control.CtlCmd = "check"
	ctlOpts.Host = "prod"
	ctlOpts.Target = config.ConnectionTarget{Selector: "prod", RawSelector: "prod"}
	ctlOpts.control.Options = []string{"HostName=web"}
	ctlOpts.canonicalResolver = resolver
	if err := ctlOpts.ensureGeneralOptionsApplied(); err != nil {
		t.Fatalf("ensureGeneralOptionsApplied(control): %v", err)
	}
	if err := prepareControlOptionsForContext(t.Context(), ctlOpts, prov, io.Discard); err != nil {
		t.Fatalf("prepareControlOptionsForContext(-O check): %v", err)
	}
	if ctlOpts.cliHostName != "web.corp.example.com" || ctlOpts.HostName != "web.corp.example.com" {
		t.Fatalf("control CLI HostName not canonicalized in place: cliHostName=%q HostName=%q", ctlOpts.cliHostName, ctlOpts.HostName)
	}
	ctlNodeID, err := resolveControlNodeID(prov, effectiveConnectionTarget(ctlOpts, ""))
	if err != nil {
		t.Fatalf("resolveControlNodeID: %v", err)
	}
	target, err := controlTarget(ctlOpts, prov, ctlNodeID)
	if err != nil {
		t.Fatalf("controlTarget: %v", err)
	}
	if target.Host != "web.corp.example.com" || target.OriginalHost != "prod" || target.User != "corp-ops" || target.Port != 2222 {
		t.Fatalf("control target = %+v, want Host=web.corp.example.com OriginalHost=prod User=corp-ops Port=2222", target)
	}
	ctlSock, err := expandControlSocketPath(ctlOpts, prov, ctlNodeID, target, io.Discard)
	if err != nil {
		t.Fatalf("expandControlSocketPath(-O check): %v", err)
	}
	return ctlSock
}

func assertW19bM2NoCLIHostNamePreservesPass2(t *testing.T, prov *config.Provider, resolver config.CanonicalResolver) {
	t.Helper()
	opts := NewSshOptions()
	opts.Host = "prod-nocli"
	opts.Target = config.ConnectionTarget{Selector: "prod-nocli", RawSelector: "prod-nocli"}
	if err := opts.applyHostnameCanonicalization(t.Context(), prov, resolver); err != nil {
		t.Fatalf("applyHostnameCanonicalization: %v", err)
	}
	if opts.cliHostName != "" || opts.HostName != "" {
		t.Fatalf("expected empty cliHostName/HostName when CLI -o HostName unset, got cliHostName=%q HostName=%q", opts.cliHostName, opts.HostName)
	}
	if opts.Host != "prod-nocli.corp.example.com" || opts.Target.Selector != "prod-nocli.corp.example.com" {
		t.Fatalf("unexpected canonical host/selector: Host=%q Selector=%q", opts.Host, opts.Target.Selector)
	}
	nodeID, err := resolveControlNodeID(prov, effectiveConnectionTarget(opts, ""))
	if err != nil {
		t.Fatalf("resolveControlNodeID: %v", err)
	}
	target, err := controlTarget(opts, prov, nodeID)
	if err != nil {
		t.Fatalf("controlTarget: %v", err)
	}
	if target.Host != "10.20.30.40" {
		t.Fatalf("Pass-2 HostName was clobbered: target.Host = %q, want 10.20.30.40", target.Host)
	}
}
