//go:build p7repro

package cmd

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/config"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func startP7ReproControlMaster(t *testing.T, ctx context.Context) (*sshfixture.Server, uint16, string) {
	t.Helper()
	fix, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(_ string, ch cryptoSSH.Channel) {
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})
	if err != nil {
		t.Fatalf("sshfixture.NewWithOptions: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := fix.Close(); closeErr != nil {
			t.Errorf("close sshfixture: %v", closeErr)
		}
	})

	_, portText, err := net.SplitHostPort(fix.Address)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", fix.Address, err)
	}
	portNum, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse port %q: %v", portText, err)
	}
	port := uint16(portNum)

	rawClient, err := cryptoSSH.Dial("tcp", fix.Address, &cryptoSSH.ClientConfig{
		User:            "ops",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.FixedHostKey(fix.HostKey),
		Timeout:         3 * time.Second,
	})
	if err != nil {
		t.Fatalf("cryptoSSH.Dial(%s): %v", fix.Address, err)
	}
	t.Cleanup(func() { _ = rawClient.Close() })

	sockPath := filepath.Join(shortControlTempDir(t), "med3.sock")
	master, err := ssh.StartMuxServer(ctx, rawClient, ssh.MuxMasterOptions{
		Path: sockPath,
		Target: ssh.TargetContext{
			Host:         "127.0.0.1",
			Port:         int(port),
			User:         "ops",
			OriginalHost: "127.0.0.1",
			Control: &ssh.ControlConfig{
				Master:  ssh.ControlMasterAuto,
				Path:    sockPath,
				Persist: "5m",
			},
		},
	})
	if err != nil {
		t.Fatalf("ssh.StartMuxServer: %v", err)
	}
	t.Cleanup(func() { _ = master.Shutdown() })

	return fix, port, sockPath
}

func assertP7ReproNodeConfirmedNotOrphaned(t *testing.T, label string, repo *config.Repository, nodeID string) {
	t.Helper()
	_, saved := repo.Snapshot().Nodes.Get(nodeID)
	_, stillPending := repo.PendingNodeExecution(nodeID)
	if !saved || stillPending {
		t.Fatalf("%s: after attaching via existing ControlMaster, node %q has saved=%v, stillPending=%v (want saved=true, stillPending=false; ConfirmNodeContext was skipped while caller marked confirmed=true, leaving pending node orphaned)",
			label, nodeID, saved, stillPending)
	}
}

// TestP7Repro_MED3_ControlMasterAttachSkipsConfirmAndOrphansPending reproduces MED-3:
// When Connector.Connect attaches via an existing ControlMaster socket, it returns
// before calling ConfirmConnection/ConfirmNodeContext. Meanwhile cmd ssh, scp, and
// interactive exec unconditionally mark confirmed=true, so the pending node is
// neither confirmed into Repository.Snapshot() nor discarded, leaving it orphaned.
func TestP7Repro_MED3_ControlMasterAttachSkipsConfirmAndOrphansPending(t *testing.T) {
	t.Setenv("XOPS_CLI_SSH_FROM_TUI", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XOPS_CONFIG_DIR", home)

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

	t.Run("ssh_attach_orphans_pending", func(t *testing.T) {
		repo, cfg := newP6PendingTestRepo(t, "")
		opts := NewSshOptions()
		opts.Host = "127.0.0.1"
		opts.User = "ops"
		opts.Port = port
		opts.Alias = "med3-ssh"
		opts.Remember = "always"
		opts.Command = "true"
		opts.Target = target
		opts.parsedArgs = true
		opts.control.Options = []string{"ControlMaster=auto", "ControlPath=" + sockPath}

		authBefore := fix.Authenticated.Load()
		if err := opts.runConnectionWithProvider(ctx, cfg, repo, false); err != nil {
			t.Fatalf("ssh runConnectionWithProvider via ControlMaster failed: %v", err)
		}
		if fix.Authenticated.Load() != authBefore {
			t.Fatalf("expected ssh to attach via existing ControlMaster without new auth handshake (before=%d after=%d)",
				authBefore, fix.Authenticated.Load())
		}
		assertP7ReproNodeConfirmedNotOrphaned(t, "ssh", repo, nodeID)
	})

	t.Run("scp_attach_orphans_pending", func(t *testing.T) {
		repo, cfg := newP6PendingTestRepo(t, "")
		opts := NewScpOptions()
		opts.Port = port
		opts.Alias = "med3-scp"
		opts.Remember = "always"
		opts.Source = filepath.Join(t.TempDir(), "local.txt")
		opts.Dest = "ops@127.0.0.1:/tmp/remote.txt"
		opts.control.Options = []string{"ControlMaster=auto", "ControlPath=" + sockPath}

		connector, err := opts.credentialConnector(repo, cfg)
		if err != nil {
			t.Fatalf("credentialConnector: %v", err)
		}
		defer func() { _ = connector.CloseAll() }()

		authBefore := fix.Authenticated.Load()
		gotNodeID, sftpCli, err := opts.connectSftpForPath(ctx, PathInfo{
			IsRemote: true,
			Host:     "127.0.0.1",
			User:     "ops",
			Port:     port,
			Path:     "/tmp/remote.txt",
		}, "", repo, connector)
		if err != nil {
			t.Fatalf("scp connectSftpForPath via ControlMaster failed: %v", err)
		}
		_ = sftpCli.Close()
		if fix.Authenticated.Load() != authBefore {
			t.Fatalf("expected scp to attach via existing ControlMaster without new auth handshake (before=%d after=%d)",
				authBefore, fix.Authenticated.Load())
		}
		assertP7ReproNodeConfirmedNotOrphaned(t, "scp", repo, gotNodeID)
	})

	t.Run("exec_interactive_attach_orphans_pending", func(t *testing.T) {
		repo, cfg := newP6PendingTestRepo(t, "")
		opts := NewExecOptions()
		opts.Host = fmt.Sprintf("ops@127.0.0.1:%d", port)
		opts.Alias = "med3-exec"
		opts.Remember = "always"
		opts.Command = "true"
		opts.Interactive = true
		opts.TaskCount = 1
		opts.control.Options = []string{"ControlMaster=auto", "ControlPath=" + sockPath}

		authBefore := fix.Authenticated.Load()
		// Even if non-TTY terminal setup returns an error after Connect,
		// runInteractiveWithConfirm already fired onConnected() and set
		// confirmedTasks[0]=true before starting the interactive command.
		_ = opts.runWithProvider(ctx, cfg, repo)
		if fix.Authenticated.Load() != authBefore {
			t.Fatalf("expected exec to attach via existing ControlMaster without new auth handshake (before=%d after=%d)",
				authBefore, fix.Authenticated.Load())
		}
		assertP7ReproNodeConfirmedNotOrphaned(t, "exec", repo, nodeID)
	})
}
