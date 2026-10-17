//go:build !windows

package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/internal/testpty"
	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func TestExecInteractiveExplicitSudo(t *testing.T) {
	for _, test := range []struct {
		name, interpreter string
		login             bool
	}{
		{"bash non-login", "bash", false},
		{"bash login", "bash", true},
		{"sh", "sh", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			payloads := make(chan string, 1)
			server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{ExecHandler: func(command string, channel cryptoSSH.Channel) {
				payloads <- command
				_, _ = io.WriteString(channel, "interactive-output\n")
				_, _ = channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{7}))
			}})
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
				t.Skipf("PTY allocation unavailable: %v", err)
			}
			t.Cleanup(func() { _ = slave.Close(); _ = master.Close() })
			before, err := term.GetState(int(slave.Fd()))
			if err != nil {
				t.Fatal(err)
			}
			var output, stderr bytes.Buffer
			connector := ssh.NewConnector(tunnelTestProvider{cfg: &ssh.ClientConfig{
				NodeID: "fixture", Address: address, Port: port, User: "test", AuthType: "password", Password: sshfixture.Password,
				SudoMode: ssh.SudoModeRoot,
			}}, ssh.WithHostKeyVerifier(execFixtureVerifier{server.HostKey}), ssh.WithEnvironment(ssh.Environment{
				InteractiveIO: ssh.InteractiveIO{Stdin: slave, Stdout: &output, Stderr: &stderr},
			}))
			t.Cleanup(func() {
				if err := connector.CloseAll(); err != nil {
					t.Error(err)
				}
			})
			o := NewExecOptions()
			command := newCmdExecWithOptions(o)
			flags := []string{"--host", "fixture", "--sudo", "-x", "--interpreter", test.interpreter, "--launch-dialect", "posix", "-c", "chosen"}
			if test.login {
				flags = append(flags, "--login-shell")
			} else if test.interpreter == "bash" {
				flags = append(flags, "--no-login")
			}
			if err := command.Flags().Parse(flags); err != nil {
				t.Fatal(err)
			}
			if err := o.Complete(command, nil); err != nil {
				t.Fatal(err)
			}
			err = o.runInteractive(ctx, connector, execHostTask{nodeID: "fixture", host: "fixture"}, "chosen")
			var exitErr *cryptoSSH.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitStatus() != 7 {
				t.Fatalf("exit status lost: %v", err)
			}
			if got := <-payloads; got != o.commandPlan.Payload() {
				t.Fatalf("payload %q, want %q", got, o.commandPlan.Payload())
			}
			after, err := term.GetState(int(slave.Fd()))
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("terminal not restored: %v", err)
			}
			if server.Executed.Load() != 1 || output.String() != "interactive-output\n" {
				t.Fatalf("unexpected execution/output: %d %q", server.Executed.Load(), output.String())
			}
		})
	}
}

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
