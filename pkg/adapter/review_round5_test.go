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

func TestRound5_P1_2_ConcurrentDistinctOriginalsResolveSecretZeroMismatch(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host edge-a",
		"  HostName shared.corp.example.com",
		"  User user-a",
		"  Port 2201",
		"  ConnectTimeout 11",
		"",
		"Host edge-b",
		"  HostName shared.corp.example.com",
		"  User user-b",
		"  Port 2202",
		"  ConnectTimeout 22",
	}, "\n") + "\n"

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	sharedNodeID := config.OpenSSHNodePrefix + "shared.corp.example.com"
	adpA := NewSSHAdapter(repo, WithSessionAuthOverride(sharedNodeID, SessionAuth{
		OriginalHost:  "edge-a",
		CanonicalHost: "shared.corp.example.com",
		Password:      "secret-a",
	}))
	adpB := NewSSHAdapter(repo, WithSessionAuthOverride(sharedNodeID, SessionAuth{
		OriginalHost:  "edge-b",
		CanonicalHost: "shared.corp.example.com",
		Password:      "secret-b",
	}))

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 8 {
		wg.Go(func() {
			cfgA, err := adpA.GetConfig(sharedNodeID)
			if err != nil {
				errs <- err
				return
			}
			if cfgA.User != "user-a" || cfgA.Port != 2201 || cfgA.Options.Get(ssh.OptionConnectTimeout) != "11" {
				errs <- errors.New("edge-a GetConfig options/identity mismatch")
				return
			}
			secA, err := adpA.ResolveSecret(t.Context(), ssh.SecretRequest{
				NodeID:       sharedNodeID,
				Host:         cfgA.Address,
				Port:         cfgA.Port,
				User:         cfgA.User,
				Kind:         ssh.SecretKindLoginPassword,
				VersionToken: cfgA.AuthUpdateToken,
			})
			if err != nil || string(secA) != "secret-a" {
				errs <- errors.New("edge-a ResolveSecret mismatch or error")
			}
		})
		wg.Go(func() {
			cfgB, err := adpB.GetConfig(sharedNodeID)
			if err != nil {
				errs <- err
				return
			}
			if cfgB.User != "user-b" || cfgB.Port != 2202 || cfgB.Options.Get(ssh.OptionConnectTimeout) != "22" {
				errs <- errors.New("edge-b GetConfig options/identity mismatch")
				return
			}
			secB, err := adpB.ResolveSecret(t.Context(), ssh.SecretRequest{
				NodeID:       sharedNodeID,
				Host:         cfgB.Address,
				Port:         cfgB.Port,
				User:         cfgB.User,
				Kind:         ssh.SecretKindLoginPassword,
				VersionToken: cfgB.AuthUpdateToken,
			})
			if err != nil || string(secB) != "secret-b" {
				errs <- errors.New("edge-b ResolveSecret mismatch or error")
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestRound5_P2_7_SavedSameNameOpenSSHAliasIsolationAndPrecedence(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host short-app",
		"  ConnectTimeout 15",
		"  User ssh-cfg-user",
		"",
		"Host shared-app",
		"  HostName 2001:db8:0::10",
		"  ConnectTimeout 15",
		"  User ssh-cfg-user",
		"",
		"Host unrelated-same-ip",
		"  HostName [2001:0DB8::10]",
		"  ConnectTimeout 99",
		"  ServerAliveCountMax 7",
		"",
		"Host *.corp.example.com",
		"  HostName 2001:db8::10",
		"  ServerAliveInterval 23",
	}, "\n") + "\n"

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "2001:0db8::10", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops"})
	cfg.Nodes.Set("shared-app", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
	})
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	// Simulate an unrelated stale entry in provider side-map; explicit tier1OriginalHost
	// takes precedence over the shared side-map, and clearing the side-map exercises
	// the same-name saved node IPv6-equivalent isolation path without leaking options
	// from unrelated-same-ip.
	repo.SetNodeOpenSSHAlias("shared-app", "unrelated-same-ip")
	adpTier1 := NewSSHAdapter(repo, WithSessionAuthOverride("shared-app", SessionAuth{
		OriginalHost:  "short-app",
		CanonicalHost: "short-app.corp.example.com",
	}))
	pol1, err := adpTier1.Resolve(t.Context(), ResolveRequest{NodeID: "shared-app"})
	if err != nil {
		t.Fatalf("Resolve(tier1): %v", err)
	}
	opts1 := pol1.Options()
	if opts1.Get(ssh.OptionConnectTimeout) != "15" || opts1.Get(ssh.OptionServerAliveInterval) != "23" || opts1.Get(ssh.OptionServerAliveCountMax) != "" {
		t.Fatalf("expected Tier 1 Pass-1 (15) + Pass-2 (23) with no leak, got ConnectTimeout=%q ServerAliveInterval=%q ServerAliveCountMax=%q",
			opts1.Get(ssh.OptionConnectTimeout), opts1.Get(ssh.OptionServerAliveInterval), opts1.Get(ssh.OptionServerAliveCountMax))
	}

	repo.SetNodeOpenSSHAlias("shared-app", "")
	if got := repo.NodeOpenSSHAlias("shared-app"); got != "" {
		t.Fatalf("SetNodeOpenSSHAlias(empty) did not clear side-map: got %q", got)
	}
	adpDefault := NewSSHAdapter(repo)
	pol2, err := adpDefault.Resolve(t.Context(), ResolveRequest{NodeID: "shared-app"})
	if err != nil {
		t.Fatalf("Resolve(same-name saved node): %v", err)
	}
	opts2 := pol2.Options()
	if opts2.Get(ssh.OptionConnectTimeout) != "15" || opts2.Get(ssh.OptionServerAliveCountMax) != "" {
		t.Fatalf("same-name saved node with IPv6 equivalence expected ConnectTimeout=15 and no ServerAliveCountMax leak, got ConnectTimeout=%q ServerAliveCountMax=%q",
			opts2.Get(ssh.OptionConnectTimeout), opts2.Get(ssh.OptionServerAliveCountMax))
	}
}

func TestRound5_P2_9_ResolveDoesNotLatchBatchMode(t *testing.T) {
	t.Parallel()

	sshCfg := "Host batchbox\n  HostName 10.1.2.3\n  User ops\n  BatchMode yes\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	if err := repo.WithPendingNode(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "batchbox", User: "otheruser", HasUser: true},
	}, func(lease config.PendingLease) error {
		nodeID := lease.NodeID()
		if !repo.IsPendingNode(nodeID) {
			t.Fatalf("expected Prepared OpenSSHDerived node, got %q", nodeID)
		}
		adp := NewSSHAdapter(repo)

		pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: nodeID})
		if err != nil {
			t.Fatalf("Resolve failed: %v", err)
		}
		opts := pol.Options()
		if !opts.BatchMode() {
			t.Fatal("expected Resolve to report BatchMode=yes from Tier 4")
		}
		if adp.isBatchModeLatched(nodeID) {
			t.Fatal("read-only Resolve must NOT latch BatchMode onto SSHAdapter")
		}

		if _, err := adp.GetConfig(nodeID); err != nil {
			t.Fatalf("GetConfig failed: %v", err)
		}
		if !adp.isBatchModeLatched(nodeID) {
			t.Fatal("GetConfig for ProvenanceOpenSSHDerived must latch BatchMode")
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPendingNode: %v", err)
	}
}

func TestRound5_P2_10_ProxyJumpCommaPreservesProxyCommand(t *testing.T) {
	t.Parallel()

	sshCfg := "Host target-box\n  HostName 10.2.3.4\n  User ops\n  ProxyCommand nc %h %p\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := config.NewProviderWithOpenSSHParser(nil, parser)

	if ps := proxySettingFromJumpString(" , "); ps.Kind() == ssh.ProxyJump {
		t.Fatalf("proxySettingFromJumpString(\" , \") = %v, must not be ProxyJump", ps)
	}

	adp := NewSSHAdapter(prov, WithLocalExecution(true), WithSessionAuthOverride(config.OpenSSHNodePrefix+"target-box", SessionAuth{
		ProxyJump: " , ",
	}))
	cfg, err := adp.GetConfig(config.OpenSSHNodePrefix + "target-box")
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if got := cfg.Options.ActiveProxyCommand(); got != "nc %h %p" {
		t.Fatalf("ProxyJump=\" , \" masked ProxyCommand: got %q, want \"nc %%h %%p\"", got)
	}
}

func TestRound5_P2_12_ParseSessionOptionsSupportsSnakeCaseIdentityFileAndProxyJump(t *testing.T) {
	t.Parallel()

	parsed, err := ParseSessionOptions([]string{
		"identity_file=/tmp/r5_id",
		"proxy_jump=bastion-r5",
	}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions failed: %v", err)
	}
	if files := parsed.Options.IdentityFiles(); len(files) != 1 || files[0] != "/tmp/r5_id" {
		t.Fatalf("identity_file not parsed cleanly: %v", files)
	}
	suppressed, err := ParseSessionOptions([]string{
		"proxy_jump=bastion-r5",
		"ProxyCommand=nc %h %p",
	}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions(proxy_jump + ProxyCommand) failed: %v", err)
	}
	if sshOpts := suppressed.ToSSHOptions(); sshOpts != nil && sshOpts.Get(ssh.OptionProxyCommand) != "" {
		t.Fatalf("proxy_jump did not activate ProxyJump suppression: ProxyCommand=%q", sshOpts.Get(ssh.OptionProxyCommand))
	}
	if _, err := ParseSessionOptions([]string{"proxy_jump="}, ""); err == nil {
		t.Fatal("expected empty proxy_jump value to be rejected")
	}
}
