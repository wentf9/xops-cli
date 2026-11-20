package adapter

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func newTestProviderWithNode(t *testing.T, parser *config.OpenSSHParser, nodeID string, node models.Node, host models.Host, ident models.Identity) config.ConfigProvider {
	t.Helper()
	repo, err := config.NewRepositoryWithOpenSSHParser(nil, adapterTestStore{}, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	if _, err := repo.CreateNodeContext(t.Context(), nodeID, node, host, ident); err != nil {
		t.Fatalf("CreateNodeContext(%q): %v", nodeID, err)
	}
	return repo
}

func TestRound4_P1_9a_And_P2_23_ConcurrentVirtualCanonIsolationAndCanonicalHost(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host edge-a",
		"  HostName app.corp.example.com",
		"  User user-a",
		"  ConnectTimeout 11",
		"  ServerAliveInterval 21",
		"",
		"Host edge-b",
		"  HostName app.corp.example.com",
		"  User user-b",
		"  ConnectTimeout 33",
		"  ServerAliveInterval 44",
		"",
		"Host app.corp.example.com",
		"  User canon-direct",
		"  ConnectTimeout 55",
	}, "\n") + "\n"

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	dir := t.TempDir()
	store := config.NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	// Simulate an existing virtual canonicalized entry for edge-a on app.corp.example.com.
	prepA, err := repo.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{
			Selector:     config.OpenSSHNodePrefix + "app.corp.example.com",
			OriginalHost: "edge-a",
		},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(edge-a): %v", err)
	}

	adpA := NewSSHAdapter(repo, WithSessionAuthOverride(prepA.NodeID, SessionAuth{OriginalHost: "edge-a"}))
	adpB := NewSSHAdapter(repo, WithSessionAuthOverride(prepA.NodeID, SessionAuth{OriginalHost: "edge-b"}))

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 4 {
		wg.Go(func() {
			cfgA, err := adpA.GetConfig(prepA.NodeID)
			if err != nil {
				errs <- err
				return
			}
			if cfgA.User != "user-a" || cfgA.OriginalHost != "edge-a" || cfgA.CanonicalHost != "app.corp.example.com" || cfgA.Options.Get(ssh.OptionConnectTimeout) != "11" {
				errs <- errors.New("adpA observed leaked edge-b / canon-direct config: user=" + cfgA.User + " canon=" + cfgA.CanonicalHost)
			}
		})
		wg.Go(func() {
			cfgB, err := adpB.GetConfig(prepA.NodeID)
			if err != nil {
				errs <- err
				return
			}
			if cfgB.User != "user-b" || cfgB.OriginalHost != "edge-b" || cfgB.CanonicalHost != "app.corp.example.com" || cfgB.Options.Get(ssh.OptionConnectTimeout) != "33" {
				errs <- errors.New("adpB observed leaked edge-a / canon-direct config: user=" + cfgB.User + " canon=" + cfgB.CanonicalHost)
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

func TestRound4_P2_17_TwoPassTier4SkipsUnrelatedConcreteHostByAddress(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host unrelated-same-ip",
		"  HostName 10.77.0.5",
		"  Port 22",
		"  ConnectTimeout 99",
		"  ServerAliveInterval 88",
		"",
		"Host app-short",
		"  User ops",
		"  ConnectTimeout 12",
		"",
		"Host *.corp.example.com",
		"  ServerAliveInterval 18",
	}, "\n") + "\n"

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	provider := newTestProviderWithNode(t, parser, "ops@10.77.0.5:22", models.Node{
		HostRef:       "h1",
		IdentityRef:   "id1",
		OpenSSHAlias:  "app-short",
		CanonicalHost: "app-short.corp.example.com",
	}, models.Host{Address: "10.77.0.5", Port: 22}, models.Identity{User: "ops"})
	adp := NewSSHAdapter(provider)

	opts, err := adp.ResolveSSHOptions("ops@10.77.0.5:22", SessionControlOptions{})
	if err != nil {
		t.Fatalf("ResolveSSHOptions: %v", err)
	}
	if got := opts.Get(ssh.OptionConnectTimeout); got != "12" {
		t.Fatalf("ConnectTimeout = %q, want 12 from Pass 1 app-short (not 99 from unrelated same IP)", got)
	}
	if got := opts.Get(ssh.OptionServerAliveInterval); got != "18" {
		t.Fatalf("ServerAliveInterval = %q, want 18 from Pass 2 *.corp.example.com (not 88)", got)
	}
}

func TestRound4_P2_18_BatchModeLatchedAcrossConfirmConnection(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host batch-node",
		"  HostName 10.88.0.5",
		"  User ops",
		"  BatchMode yes",
	}, "\n") + "\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	dir := t.TempDir()
	store := config.NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	prep, err := repo.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "batch-node"},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext: %v", err)
	}

	adp := NewSSHAdapter(
		repo,
		WithSessionAuthOverride(prep.NodeID, SessionAuth{Password: "pw", Remember: true}),
	)

	// ConfirmConnection commits ProvenanceOpenSSHDerived -> ProvenanceSavedManaged,
	// where Tier-4 BatchMode is filtered out unless latched in the session.
	if err := adp.ConfirmConnection(t.Context(), prep.NodeID); err != nil {
		t.Fatalf("ConfirmConnection: %v", err)
	}

	if !adp.isNonInteractiveForNode(prep.NodeID) {
		t.Fatal("expected BatchMode=yes latch to keep node non-interactive after ConfirmConnection")
	}
	clientCfg, err := adp.GetConfig(prep.NodeID)
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if clientCfg.Options == nil || !clientCfg.Options.BatchMode() {
		t.Fatalf("expected latched BatchMode=yes in GetConfig options, got %+v", clientCfg.Options)
	}
	if tok, err := adp.UpdateAuth(t.Context(), prep.NodeID, "tok", "new-pw", "", ""); err != nil || tok != "tok" {
		t.Fatalf("expected UpdateAuth no-op under latched BatchMode=yes, got tok=%q err=%v", tok, err)
	}

	// Explicit Tier-1 BatchMode=no overrides the latch.
	overrideOpts, err := ParseOptionStrings([]string{"BatchMode=no"})
	if err != nil {
		t.Fatalf("ParseOptionStrings: %v", err)
	}
	if adp.sessionControlOverrides == nil {
		adp.sessionControlOverrides = make(map[string]SessionControlOptions)
	}
	adp.sessionControlOverrides[prep.NodeID] = overrideOpts
	if adp.isNonInteractiveForNode(prep.NodeID) {
		t.Fatal("explicit Tier-1 BatchMode=no must override latched BatchMode=yes")
	}
}

func TestRound4_P2_19_ProxyJumpMultiNoneNormalizedToDisabled(t *testing.T) {
	t.Parallel()

	provider := newTestProviderWithNode(t, nil, "ops@10.99.0.5:22", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
		ProxyJump:   "none,none",
	}, models.Host{Address: "10.99.0.5", Port: 22}, models.Identity{User: "ops"})

	adp := NewSSHAdapter(provider)
	clientCfg, err := adp.GetConfig("ops@10.99.0.5:22")
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if clientCfg.ProxyJump != "" {
		t.Fatalf("GetConfig ProxyJump = %q, want empty when normalized from none,none", clientCfg.ProxyJump)
	}

	opts, err := ParseOptionStringsWithJump([]string{"proxy_jump=none,none", "ProxyCommand=echo proxy"}, "none,none")
	if err != nil {
		t.Fatalf("ParseOptionStringsWithJump: %v", err)
	}
	if opts.ToSSHOptions().ActiveProxyCommand() == "" {
		t.Fatal("disabled proxy_jump=none,none must allow ProxyCommand to remain active")
	}

	adp2 := NewSSHAdapter(provider, WithSessionAuthOverride("ops@10.99.0.5:22", SessionAuth{ProxyJump: "none,none"}))
	clientCfg2, err := adp2.GetConfig("ops@10.99.0.5:22")
	if err != nil {
		t.Fatalf("GetConfig(override none,none): %v", err)
	}
	if clientCfg2.ProxyJump != "" || !clientCfg2.HasOriginalProxyJump {
		t.Fatalf("override none,none ProxyJump = (%q, %v), want (\"\", true)", clientCfg2.ProxyJump, clientCfg2.HasOriginalProxyJump)
	}
}
