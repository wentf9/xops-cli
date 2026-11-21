package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func newP6PendingTestRepo(t *testing.T, openSSHCfg string) (*config.Repository, *config.Configuration) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "xops_config.yaml")
	keyPath := filepath.Join(dir, "xops_config.key")
	store := config.NewDefaultStore(cfgPath, keyPath)
	var (
		parser *config.OpenSSHParser
		err    error
	)
	if openSSHCfg != "" {
		parser, err = config.NewOpenSSHParserFromReader(strings.NewReader(openSSHCfg))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
	}
	repo, err := config.NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	return repo, repo.Snapshot()
}

func closedLoopbackPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	if err := ln.Close(); err != nil {
		t.Fatalf("ln.Close: %v", err)
	}
	return port
}

// startSilentLoopbackServer listens on loopback and accepts one TCP connection
// without writing an SSH banner so callers can cancel mid-handshake cleanly.
func startSilentLoopbackServer(t *testing.T) (uint16, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	accepted := make(chan struct{})
	done := make(chan struct{})
	t.Cleanup(func() {
		close(done)
		_ = ln.Close()
	})
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		close(accepted)
		defer func() { _ = conn.Close() }()
		<-done
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port), accepted
}

func assertPendingReleasedAndRepreparable(t *testing.T, provider config.ConfigProvider, nodeID string, target config.ConnectionTarget, newAlias string) {
	t.Helper()
	if _, err := provider.ResolveConnection(nodeID); !errors.Is(err, config.ErrNodeNotFound) {
		t.Fatalf("ResolveConnection(%q) after failed connect = %v, want ErrNodeNotFound (pending entry leaked)", nodeID, err)
	}
	preparer, ok := provider.(interface {
		PrepareNodeContext(context.Context, config.EnsureNodeOptions) (config.EnsureNodeResult, error)
	})
	if !ok {
		t.Fatalf("provider %T does not implement PrepareNodeContext", provider)
	}
	res, err := preparer.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{
		Target: target,
		Alias:  newAlias,
	})
	if err != nil {
		t.Fatalf("subsequent PrepareNodeContext(%+v, alias=%q) failed (expected clean re-prepare without ErrConfigConflict): %v", target, newAlias, err)
	}
	if res.NodeID != nodeID {
		t.Fatalf("re-prepared NodeID = %q, want %q", res.NodeID, nodeID)
	}
	discardPendingNode(provider, res.NodeID)
}

func TestP6_SSHPendingNodeDiscardedOnFailedAndCanceledConnect(t *testing.T) {
	t.Setenv("XOPS_CLI_SSH_FROM_TUI", "")
	port := closedLoopbackPort(t)
	nodeID := config.FormatNodeID("ops", "127.0.0.1", port)
	target := config.ConnectionTarget{
		Selector: "127.0.0.1",
		User:     "ops",
		HasUser:  true,
		Port:     port,
		HasPort:  true,
	}

	t.Run("failed_dial_releases_repository_pending", func(t *testing.T) {
		repo, cfg := newP6PendingTestRepo(t, "")
		opts := NewSshOptions()
		opts.Host = "127.0.0.1"
		opts.User = "ops"
		opts.Port = port
		opts.Alias = "ssh-first-alias"
		opts.Command = "true"
		opts.Target = target
		opts.parsedArgs = true

		if err := opts.runConnectionWithProvider(t.Context(), cfg, repo, false); err == nil {
			t.Fatal("expected runConnectionWithProvider against closed loopback port to fail")
		}
		assertPendingReleasedAndRepreparable(t, repo, nodeID, target, "ssh-second-alias")
	})

	t.Run("canceled_handshake_releases_repository_pending", func(t *testing.T) {
		silentPort, accepted := startSilentLoopbackServer(t)
		silentNodeID := config.FormatNodeID("ops", "127.0.0.1", silentPort)
		silentTarget := config.ConnectionTarget{
			Selector: "127.0.0.1",
			User:     "ops",
			HasUser:  true,
			Port:     silentPort,
			HasPort:  true,
		}
		repo, cfg := newP6PendingTestRepo(t, "")
		opts := NewSshOptions()
		opts.Host = "127.0.0.1"
		opts.User = "ops"
		opts.Port = silentPort
		opts.Alias = "ssh-cancel-first"
		opts.Command = "true"
		opts.Target = silentTarget
		opts.parsedArgs = true

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go func() {
			select {
			case <-accepted:
				cancel()
			case <-time.After(3 * time.Second):
				cancel()
			}
		}()

		if err := opts.runConnectionWithProvider(ctx, cfg, repo, false); err == nil {
			t.Fatal("expected runConnectionWithProvider canceled mid-handshake to fail")
		}
		assertPendingReleasedAndRepreparable(t, repo, silentNodeID, silentTarget, "ssh-cancel-second")
	})

	t.Run("pre_connect_validation_error_releases_pending", func(t *testing.T) {
		repo, _ := newP6PendingTestRepo(t, "")
		opts := NewSshOptions()
		opts.Host = "127.0.0.1"
		opts.User = "ops"
		opts.Port = port
		opts.Alias = "ssh-invalid-session"
		opts.NoCmd = true
		opts.Command = "echo conflict"
		opts.Target = target
		opts.parsedArgs = true

		if _, _, err := opts.prepareValidatedConnectionNode(t.Context(), repo); err == nil {
			t.Fatal("expected prepareValidatedConnectionNode with -N + command to fail")
		}
		assertPendingReleasedAndRepreparable(t, repo, nodeID, target, "ssh-after-invalid")
	})

	t.Run("background_parent_failed_connect_releases_pending", func(t *testing.T) {
		repo, cfg := newP6PendingTestRepo(t, "")
		opts := NewSshOptions()
		opts.Host = "127.0.0.1"
		opts.User = "ops"
		opts.Port = port
		opts.Alias = "ssh-bg-first"
		opts.BgRun = true
		opts.NoCmd = true
		opts.Target = target
		opts.parsedArgs = true

		if err := opts.runParentDaemonWithProvider(t.Context(), cfg, repo); err == nil {
			t.Fatal("expected runParentDaemonWithProvider against closed loopback port to fail")
		}
		assertPendingReleasedAndRepreparable(t, repo, nodeID, target, "ssh-bg-second")
	})

	t.Run("openssh_override_provider_releases_pending", func(t *testing.T) {
		repo, cfg := newP6PendingTestRepo(t, "")
		sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
		content := fmt.Sprintf("Host app-override\n  HostName 127.0.0.1\n  User ops\n  Port %d\n  ConnectTimeout 1\n", port)
		if err := os.WriteFile(sshCfgPath, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		overrideProv, err := config.WithOpenSSHConfigOverride(repo, sshCfgPath)
		if err != nil {
			t.Fatalf("WithOpenSSHConfigOverride: %v", err)
		}

		opts := NewSshOptions()
		opts.Host = "127.0.0.1"
		opts.User = "ops"
		opts.Port = port
		opts.Alias = "ssh-ov-first"
		opts.Command = "true"
		opts.Target = target
		opts.parsedArgs = true

		if err := opts.runConnectionWithProvider(t.Context(), cfg, overrideProv, false); err == nil {
			t.Fatal("expected runConnectionWithProvider on override provider against closed port to fail")
		}
		assertPendingReleasedAndRepreparable(t, overrideProv, nodeID, target, "ssh-ov-second")
	})
}

func TestP6_ExecPendingNodeDiscardedOnFailedAndCanceledConnect(t *testing.T) {
	port := closedLoopbackPort(t)
	nodeID := config.FormatNodeID("ops", "127.0.0.1", port)
	target := config.ConnectionTarget{
		Selector: "127.0.0.1",
		User:     "ops",
		HasUser:  true,
		Port:     port,
		HasPort:  true,
	}

	t.Run("batch_exec_failed_connect_releases_pending", func(t *testing.T) {
		repo, cfg := newP6PendingTestRepo(t, "")
		opts := NewExecOptions()
		opts.Host = fmt.Sprintf("ops@127.0.0.1:%d", port)
		opts.Alias = "exec-batch-first"
		opts.Command = "uptime"
		opts.TaskCount = 1

		if err := opts.runWithProvider(t.Context(), cfg, repo); err == nil {
			t.Fatal("expected ExecOptions.runWithProvider against closed loopback port to fail")
		}
		assertPendingReleasedAndRepreparable(t, repo, nodeID, target, "exec-batch-second")
	})

	t.Run("interactive_exec_canceled_handshake_releases_pending", func(t *testing.T) {
		silentPort, accepted := startSilentLoopbackServer(t)
		silentNodeID := config.FormatNodeID("ops", "127.0.0.1", silentPort)
		silentTarget := config.ConnectionTarget{
			Selector: "127.0.0.1",
			User:     "ops",
			HasUser:  true,
			Port:     silentPort,
			HasPort:  true,
		}
		repo, cfg := newP6PendingTestRepo(t, "")
		opts := NewExecOptions()
		opts.Host = fmt.Sprintf("ops@127.0.0.1:%d", silentPort)
		opts.Alias = "exec-inter-first"
		opts.Command = "uptime"
		opts.Interactive = true
		opts.TaskCount = 1

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go func() {
			select {
			case <-accepted:
				cancel()
			case <-time.After(3 * time.Second):
				cancel()
			}
		}()

		if err := opts.runWithProvider(ctx, cfg, repo); err == nil {
			t.Fatal("expected interactive ExecOptions.runWithProvider canceled mid-handshake to fail")
		}
		assertPendingReleasedAndRepreparable(t, repo, silentNodeID, silentTarget, "exec-inter-second")
	})

	t.Run("materialize_tagged_mid_batch_error_rolls_back_earlier_pending", func(t *testing.T) {
		repo, _ := newP6PendingTestRepo(t, "")
		if _, err := repo.CreateNodeContext(
			t.Context(),
			"tagged-a",
			models.Node{HostRef: "h-a", IdentityRef: "id-a", Tags: []string{"web"}},
			models.Host{Address: "127.0.0.1", Port: port},
			models.Identity{User: "alice", AuthType: "auto"},
		); err != nil {
			t.Fatalf("CreateNodeContext(tagged-a): %v", err)
		}
		firstTarget := target
		firstAddr := utils.HostInfo{Host: "127.0.0.1", User: "ops", Port: port, Alias: "tagged-pending-a"}
		badTarget := config.ConnectionTarget{Selector: ""}
		badAddr := utils.HostInfo{Host: ""}

		opts := NewExecOptions()
		tasks := []execHostTask{
			{
				rawHost:       "tagged-a",
				host:          "127.0.0.1",
				pendingTarget: &firstTarget,
				pendingAddr:   &firstAddr,
				isTaggedTask:  true,
			},
			{
				rawHost:       "tagged-b",
				host:          "",
				pendingTarget: &badTarget,
				pendingAddr:   &badAddr,
				isTaggedTask:  true,
			},
		}
		if _, _, err := opts.materializeExecTasks(t.Context(), repo, tasks); err == nil {
			t.Fatal("expected materializeExecTasks to fail on second tagged task")
		}
		assertPendingReleasedAndRepreparable(t, repo, nodeID, target, "tagged-pending-retry")
	})
}

func TestP6_ScpPendingNodeDiscardedOnFailedAndCanceledConnect(t *testing.T) {
	port := closedLoopbackPort(t)
	nodeID := config.FormatNodeID("ops", "127.0.0.1", port)
	target := config.ConnectionTarget{
		Selector: "127.0.0.1",
		User:     "ops",
		HasUser:  true,
		Port:     port,
		HasPort:  true,
	}

	t.Run("connectSftpForPath_failed_connect_releases_repository_pending", func(t *testing.T) {
		repo, cfg := newP6PendingTestRepo(t, "")
		opts := NewScpOptions()
		opts.Port = port
		opts.Alias = "scp-first-alias"
		opts.Source = filepath.Join(t.TempDir(), "local.txt")
		opts.Dest = "ops@127.0.0.1:/tmp/remote.txt"

		connector, err := opts.credentialConnector(repo, cfg)
		if err != nil {
			t.Fatalf("credentialConnector: %v", err)
		}
		defer func() { _ = connector.CloseAll() }()

		_, _, err = opts.connectSftpForPath(t.Context(), PathInfo{
			IsRemote: true,
			Host:     "127.0.0.1",
			User:     "ops",
			Port:     port,
			Path:     "/tmp/remote.txt",
		}, "", repo, connector)
		if err == nil {
			t.Fatal("expected connectSftpForPath against closed loopback port to fail")
		}
		assertPendingReleasedAndRepreparable(t, repo, nodeID, target, "scp-second-alias")
	})

	t.Run("connectSftpForPath_canceled_handshake_releases_pending", func(t *testing.T) {
		silentPort, accepted := startSilentLoopbackServer(t)
		silentNodeID := config.FormatNodeID("ops", "127.0.0.1", silentPort)
		silentTarget := config.ConnectionTarget{
			Selector: "127.0.0.1",
			User:     "ops",
			HasUser:  true,
			Port:     silentPort,
			HasPort:  true,
		}
		repo, cfg := newP6PendingTestRepo(t, "")
		opts := NewScpOptions()
		opts.Port = silentPort
		opts.Alias = "scp-cancel-first"
		opts.Source = filepath.Join(t.TempDir(), "local.txt")
		opts.Dest = "ops@127.0.0.1:/tmp/remote.txt"

		connector, err := opts.credentialConnector(repo, cfg)
		if err != nil {
			t.Fatalf("credentialConnector: %v", err)
		}
		defer func() { _ = connector.CloseAll() }()

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go func() {
			select {
			case <-accepted:
				cancel()
			case <-time.After(3 * time.Second):
				cancel()
			}
		}()

		_, _, err = opts.connectSftpForPath(ctx, PathInfo{
			IsRemote: true,
			Host:     "127.0.0.1",
			User:     "ops",
			Port:     silentPort,
			Path:     "/tmp/remote.txt",
		}, "", repo, connector)
		if err == nil {
			t.Fatal("expected connectSftpForPath canceled mid-handshake to fail")
		}
		assertPendingReleasedAndRepreparable(t, repo, silentNodeID, silentTarget, "scp-cancel-second")
	})

	t.Run("connectSftpForPath_openssh_override_releases_pending", func(t *testing.T) {
		repo, cfg := newP6PendingTestRepo(t, "")
		sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
		content := fmt.Sprintf("Host scp-ov\n  HostName 127.0.0.1\n  User ops\n  Port %d\n", port)
		if err := os.WriteFile(sshCfgPath, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		overrideProv, err := config.WithOpenSSHConfigOverride(repo, sshCfgPath)
		if err != nil {
			t.Fatalf("WithOpenSSHConfigOverride: %v", err)
		}

		opts := NewScpOptions()
		opts.Port = port
		opts.Alias = "scp-ov-first"
		opts.Source = filepath.Join(t.TempDir(), "local.txt")
		opts.Dest = "ops@127.0.0.1:/tmp/remote.txt"

		connector, err := opts.credentialConnector(overrideProv, cfg)
		if err != nil {
			t.Fatalf("credentialConnector: %v", err)
		}
		defer func() { _ = connector.CloseAll() }()

		_, _, err = opts.connectSftpForPath(t.Context(), PathInfo{
			IsRemote: true,
			Host:     "127.0.0.1",
			User:     "ops",
			Port:     port,
			Path:     "/tmp/remote.txt",
		}, "", overrideProv, connector)
		if err == nil {
			t.Fatal("expected connectSftpForPath on override provider against closed port to fail")
		}
		assertPendingReleasedAndRepreparable(t, overrideProv, nodeID, target, "scp-ov-second")
	})

	t.Run("batch_scp_invalid_jump_releases_pending", func(t *testing.T) {
		repo, _ := newP6PendingTestRepo(t, "")
		opts := NewScpOptions()
		opts.Host = fmt.Sprintf("ops@127.0.0.1:%d", port)
		opts.JumpHost = "a,,b" // rejected by ResolveProxyJumpChain
		opts.Alias = "scp-badjump-first"

		_, _, err := opts.getOrCreateNodeForPath(t.Context(), repo, PathInfo{
			IsRemote: true,
			Host:     "127.0.0.1",
			User:     "ops",
			Port:     port,
		}, "")
		if err == nil {
			t.Fatal("expected batch getOrCreateNodeForPath with invalid JumpHost to fail")
		}
		assertPendingReleasedAndRepreparable(t, repo, nodeID, target, "scp-badjump-second")
	})
}

func TestP6_PendingDiscardPreservesConcurrentSharedCaller(t *testing.T) {
	t.Setenv("XOPS_CLI_SSH_FROM_TUI", "")
	port := closedLoopbackPort(t)
	repo, cfg := newP6PendingTestRepo(t, "")
	target := config.ConnectionTarget{
		Selector: "127.0.0.1",
		User:     "ops",
		HasUser:  true,
		Port:     port,
		HasPort:  true,
	}

	// Caller 1 registers pending node (refs = 1).
	first, err := repo.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{
		Target: target,
		Alias:  "shared-alias",
	})
	if err != nil || !first.Created {
		t.Fatalf("caller 1 PrepareNodeContext = (%+v, %v), want Created=true", first, err)
	}

	// Caller 2 prepares the same target (refs = 2) and fails on connect -> discards only its own ref (refs = 1).
	opts := NewSshOptions()
	opts.Host = "127.0.0.1"
	opts.User = "ops"
	opts.Port = port
	opts.Alias = "shared-alias"
	opts.Command = "true"
	opts.Target = target
	opts.parsedArgs = true

	if err := opts.runConnectionWithProvider(t.Context(), cfg, repo, false); err == nil {
		t.Fatal("expected caller 2 runConnectionWithProvider against closed port to fail")
	}

	// Caller 1's pending entry must remain resolvable until Caller 1 finishes or discards.
	if _, err := repo.ResolveConnection(first.NodeID); err != nil {
		t.Fatalf("caller 2 discard clobbered concurrent caller 1 pending entry: %v", err)
	}

	// Once Caller 1 discards its reference, the pending entry is removed and re-preparable with different params.
	repo.DiscardPendingNode(first.NodeID)
	assertPendingReleasedAndRepreparable(t, repo, first.NodeID, target, "different-alias-after-both-released")

	// Sanity check: confirm helper ignores nil / non-discarder providers without panicking.
	discardPendingNode(nil, first.NodeID)
	discardPendingNode(struct{}{}, first.NodeID)
	discardPendingNode(repo, "")
}
