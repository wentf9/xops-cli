package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/config"
)

// TestP7Repro_MED2_SftpRunContextDiscardsPendingNodeOnFailure verifies MED-2
// behaviorally: (*SftpOptions).runWithProvider scopes pending node creation via
// config.WithPendingNode so failed dials and mid-handshake cancellations always
// discard the pending registration without persisting it or poisoning retries,
// while attaching via an existing ControlMaster confirms the node cleanly.
func TestP7Repro_MED2_SftpRunContextDiscardsPendingNodeOnFailure(t *testing.T) {
	t.Setenv("XOPS_CLI_SSH_FROM_TUI", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XOPS_CONFIG_DIR", home)

	t.Run("failed_dial_discards_pending_node", func(t *testing.T) {
		port := closedLoopbackPort(t)
		nodeID := config.FormatNodeID("ops", "127.0.0.1", port)
		target := config.ConnectionTarget{
			Selector: "127.0.0.1",
			User:     "ops",
			HasUser:  true,
			Port:     port,
			HasPort:  true,
		}
		repo, cfg := newP6PendingTestRepo(t, "")
		opts := NewSftpOptions()
		opts.Host = "127.0.0.1"
		opts.User = "ops"
		opts.Port = port
		opts.Alias = "sftp-fail-first"
		opts.Remember = "always"
		opts.Target = target
		opts.parsedArgs = true

		if err := opts.runWithProvider(t.Context(), cfg, repo, false); err == nil {
			t.Fatal("expected SftpOptions.runWithProvider against closed loopback port to fail")
		}
		if _, saved := repo.Snapshot().Nodes.Get(nodeID); saved {
			t.Fatalf("failed sftp connect persisted node %q", nodeID)
		}
		assertPendingReleasedAndRepreparable(t, repo, nodeID, target, "sftp-fail-second")
	})

	t.Run("canceled_handshake_discards_pending_node", func(t *testing.T) {
		silentPort, accepted := startSilentLoopbackServer(t)
		nodeID := config.FormatNodeID("ops", "127.0.0.1", silentPort)
		target := config.ConnectionTarget{
			Selector: "127.0.0.1",
			User:     "ops",
			HasUser:  true,
			Port:     silentPort,
			HasPort:  true,
		}
		repo, cfg := newP6PendingTestRepo(t, "")
		opts := NewSftpOptions()
		opts.Host = "127.0.0.1"
		opts.User = "ops"
		opts.Port = silentPort
		opts.Alias = "sftp-cancel-first"
		opts.Remember = "always"
		opts.Target = target
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

		if err := opts.runWithProvider(ctx, cfg, repo, false); err == nil {
			t.Fatal("expected SftpOptions.runWithProvider canceled mid-handshake to fail")
		}
		if _, saved := repo.Snapshot().Nodes.Get(nodeID); saved {
			t.Fatalf("canceled sftp connect persisted node %q", nodeID)
		}
		assertPendingReleasedAndRepreparable(t, repo, nodeID, target, "sftp-cancel-second")
	})

	t.Run("controlmaster_attach_confirms_pending_node", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()

		fix, port, sockPath := startP7ReproControlMaster(t, ctx)
		nodeID := config.FormatNodeID("ops", "127.0.0.1", port)
		target := config.ConnectionTarget{
			Selector: "127.0.0.1",
			User:     "ops",
			HasUser:  true,
			Port:     port,
			HasPort:  true,
		}
		repo, cfg := newP6PendingTestRepo(t, "")
		opts := NewSftpOptions()
		opts.Host = "127.0.0.1"
		opts.User = "ops"
		opts.Port = port
		opts.Alias = "sftp-mux-confirm"
		opts.Remember = "always"
		opts.Target = target
		opts.parsedArgs = true
		opts.control.Options = []string{"ControlMaster=auto", "ControlPath=" + sockPath}

		authBefore := fix.Authenticated.Load()
		// The SSH fixture does not serve an SFTP subsystem, so sftp.NewClient
		// fails after Connect + FinalizePendingConnection; confirmation already
		// happened right after attaching via the existing ControlMaster.
		_ = opts.runWithProvider(ctx, cfg, repo, false)
		if fix.Authenticated.Load() != authBefore {
			t.Fatalf("expected sftp to attach via existing ControlMaster without new auth handshake (before=%d after=%d)",
				authBefore, fix.Authenticated.Load())
		}
		assertP7ReproNodeConfirmedNotOrphaned(t, "sftp", repo, nodeID)
	})
}
