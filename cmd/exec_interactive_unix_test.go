//go:build !windows

package cmd

import (
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/internal/testpty"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestExecInteractiveRegularFileOutputCompatible(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	var executedCmd string
	var execMu sync.Mutex
	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(command string, channel cryptoSSH.Channel) {
			execMu.Lock()
			executedCmd = command
			execMu.Unlock()
			_, _ = io.WriteString(channel, "interactive-output\n")
			_, _ = channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	address, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	master, slave, err := testpty.Open()
	if err != nil {
		t.Skipf("PTY allocation unavailable in test environment: %v", err)
	}
	t.Cleanup(func() {
		_ = slave.Close()
		_ = master.Close()
	})
	logFile, err := os.CreateTemp(t.TempDir(), "stderr-*.log")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	connector := ssh.NewConnector(tunnelTestProvider{cfg: &ssh.ClientConfig{
		NodeID: "fixture", Address: address, Port: port, User: "test", AuthType: "password", Password: sshfixture.Password,
	}}, ssh.WithHostKeyVerifier(execFixtureVerifier{server.HostKey}), ssh.WithEnvironment(ssh.Environment{
		InteractiveIO: ssh.InteractiveIO{Stdin: slave, Stdout: slave, Stderr: logFile},
	}))
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	})

	o := NewExecOptions()
	command := newCmdExecWithOptions(o)
	if err := command.Flags().Parse([]string{"--host", "fixture", "-x", "-c", "uptime"}); err != nil {
		t.Fatal(err)
	}
	if err := o.Complete(command, nil); err != nil {
		t.Fatal(err)
	}
	task := execHostTask{nodeID: "fixture", host: "fixture"}
	// On unconfigured node, runInteractive executes raw "uptime" (server default)
	err = o.runInteractive(ctx, connector, task, "uptime")
	if err != nil {
		t.Fatalf("expected successful interactive execution, got: %v", err)
	}
	execMu.Lock()
	gotCmd := executedCmd
	execMu.Unlock()
	if gotCmd != "uptime" {
		t.Fatalf("expected server default command payload %q, got %q", "uptime", gotCmd)
	}
}
