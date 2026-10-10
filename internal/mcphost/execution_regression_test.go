package mcphost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type executionFixtureProvider struct{ cfg ssh.ClientConfig }

func (p executionFixtureProvider) GetConfig(id string) (*ssh.ClientConfig, error) {
	if id != "node" {
		return nil, fmt.Errorf("unexpected node %q", id)
	}
	cfg := p.cfg
	return &cfg, nil
}

type executionFixtureTrust struct{ key cryptoSSH.PublicKey }

func (v executionFixtureTrust) Verify(ctx context.Context, _ ssh.HostKeyRequest, key cryptoSSH.PublicKey) error {
	if !bytes.Equal(v.key.Marshal(), key.Marshal()) {
		return fmt.Errorf("fixture host key changed")
	}
	return ctx.Err()
}

func TestLegacyHostBackendExecutionConfiguration(t *testing.T) {
	no := false
	for _, test := range []struct {
		name      string
		execution *ssh.ExecutionConfig
		sudo      bool
		mode      ssh.SudoMode
		payload   string
		invalid   bool
	}{
		{name: "legacy", payload: "bash -l -c 'uptime'"},
		{name: "explicit server", execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, payload: "uptime"},
		{name: "legacy sudo", sudo: true, mode: ssh.SudoModeRoot, payload: "bash -l -c 'uptime'"},
		{name: "configured sudo", execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &no}, sudo: true, mode: ssh.SudoModeRoot, payload: "bash -c 'uptime'"},
		{name: "server sudo rejected", execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, sudo: true, mode: ssh.SudoModeRoot, invalid: true},
		{name: "configured su rejected", execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &no}, sudo: true, mode: ssh.SudoModeSu, invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			b, server, permit, commands, ctx := newExecutionBackendFixture(t, test.mode)
			result, err := b.Run(ctx, permit, "node", ports.Command{Text: "uptime", Sudo: test.sudo, Execution: test.execution})
			if test.invalid {
				if !errors.Is(err, ssh.ErrExecutionValidation) || result.Outcome != ssh.ExecutionNotStarted || server.Executed.Load() != 0 {
					t.Fatalf("invalid config dispatched: %+v, %v", result, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := <-commands; got != test.payload {
				t.Fatalf("payload %q, want %q", got, test.payload)
			}
		})
	}
}

func TestLegacyHostBackendSudoSignalTermination(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{ExecHandler: func(_ string, ch cryptoSSH.Channel) {
		if _, err := io.WriteString(ch, "signal-output"); err != nil {
			t.Error(err)
			return
		}
		msg := struct {
			Signal     string
			CoreDumped bool
			ErrorMsg   string
			Lang       string
		}{
			Signal: "TERM",
		}
		if _, err := ch.SendRequest("exit-signal", false, cryptoSSH.Marshal(msg)); err != nil {
			t.Error(err)
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	host, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	connector := ssh.NewConnector(executionFixtureProvider{ssh.ClientConfig{NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", Password: sshfixture.Password, SudoMode: ssh.SudoModeRoot}}, ssh.WithHostKeyVerifier(executionFixtureTrust{server.HostKey}))
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	view := ports.OperationSnapshot{DomainID: "fixture", Targets: map[string]ports.Target{"node": {Info: ports.NodeInfo{ID: "node"}, Version: "1", Plan: ssh.ConnectionPlan{Scope: "fixture", Hops: []ssh.ConnectionConfig{{NodeID: "node", Address: host, Port: port, User: "fixture"}}}}}}
	binding, err := ports.Bind(view, "fixture", "xops_ssh_run", struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	permit, err := ports.NewPermit(ctx, ports.Admission{OperationID: "execution-regression", Phase: ports.Execute, Snapshot: view, Binding: binding}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := permit.Close(); err != nil {
			t.Error(err)
		}
	})
	b := &backend{connector: connector}
	result, err := b.Run(ctx, permit, "node", ports.Command{Text: "sleep 10", Sudo: true})
	if err == nil {
		t.Fatal("expected error for signal termination")
	}
	if result.Signal != "TERM" {
		t.Fatalf("result.Signal = %q, want %q", result.Signal, "TERM")
	}
	if result.ExitCode != nil {
		t.Fatalf("result.ExitCode = %v, want nil", *result.ExitCode)
	}
	if result.Outcome != ssh.ExecutionCompleted {
		t.Fatalf("result.Outcome = %v, want %v", result.Outcome, ssh.ExecutionCompleted)
	}
}

func newExecutionBackendFixture(t *testing.T, mode ssh.SudoMode) (*backend, *sshfixture.Server, ports.Permit, chan string, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	commands := make(chan string, 4)
	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{ExecHandler: func(command string, ch cryptoSSH.Channel) {
		commands <- command
		if _, err := io.WriteString(ch, "fixture-output"); err != nil {
			t.Error(err)
			return
		}
		if _, err := ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0})); err != nil {
			t.Error(err)
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	host, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	connector := ssh.NewConnector(executionFixtureProvider{ssh.ClientConfig{NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", Password: sshfixture.Password, SudoMode: mode}}, ssh.WithHostKeyVerifier(executionFixtureTrust{server.HostKey}))
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	view := ports.OperationSnapshot{DomainID: "fixture", Targets: map[string]ports.Target{"node": {Info: ports.NodeInfo{ID: "node"}, Version: "1", Plan: ssh.ConnectionPlan{Scope: "fixture", Hops: []ssh.ConnectionConfig{{NodeID: "node", Address: host, Port: port, User: "fixture"}}}}}}
	binding, err := ports.Bind(view, "fixture", "xops_ssh_run", struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	permit, err := ports.NewPermit(ctx, ports.Admission{OperationID: "execution-regression", Phase: ports.Execute, Snapshot: view, Binding: binding}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := permit.Close(); err != nil {
			t.Error(err)
		}
	})
	b := &backend{connector: connector}
	return b, server, permit, commands, ctx
}

func TestLegacyHostBackendFilesystemRejectsNonPOSIXDialects(t *testing.T) {
	for _, test := range []struct {
		name    string
		node    *ssh.ExecutionConfig
		request *ssh.ExecutionConfig
		cmd     ports.Command
		invalid bool
		wantCmd string
	}{
		{
			name:    "server cmd rejected with filesystem flag",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchCmd},
			cmd:     ports.Command{Text: "rm -rf '/tmp/test'", Filesystem: true},
			invalid: true,
		},
		{
			name:    "server cmd rejected with require posix flag",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchCmd},
			cmd:     ports.Command{Text: "rm -rf '/tmp/test'", RequirePOSIX: true},
			invalid: true,
		},
		{
			name:    "server powershell rejected",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchPowerShell},
			cmd:     ports.Command{Text: "cp -r '/tmp/a' '/tmp/b'", Filesystem: true},
			invalid: true,
		},
		{
			name:    "server unknown dialect rejected",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchUnknown},
			cmd:     ports.Command{Text: "rm -rf '/tmp/test'", Filesystem: true},
			invalid: true,
		},
		{
			name:    "server unconfigured dialect defaults to unknown and rejected",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer},
			cmd:     ports.Command{Text: "rm -rf '/tmp/test'", Filesystem: true},
			invalid: true,
		},
		{
			name:    "server posix allowed",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchPOSIX},
			cmd:     ports.Command{Text: "rm -rf '/tmp/test'", Filesystem: true},
			invalid: false,
			wantCmd: "rm -rf '/tmp/test'",
		},
		{
			name:    "default bash allowed",
			node:    nil,
			cmd:     ports.Command{Text: "rm -rf '/tmp/test'", Filesystem: true},
			invalid: false,
			wantCmd: "bash -l -c 'rm -rf '\\''/tmp/test'\\'''",
		},
		{
			name:    "explicit bash posix allowed",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX},
			cmd:     ports.Command{Text: "rm -rf '/tmp/test'", Filesystem: true},
			invalid: false,
			wantCmd: "bash -c 'rm -rf '\\''/tmp/test'\\'''",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			b, server, oldPermit, commands, ctx := newExecutionBackendFixture(t, ssh.SudoModeRoot)
			view := oldPermit.Snapshot()
			target := view.Targets["node"]
			target.Execution = test.node
			view.Targets["node"] = target
			binding, err := ports.Bind(view, "fixture", "xops_ssh_run", struct{}{})
			if err != nil {
				t.Fatal(err)
			}
			permit, err := ports.NewPermit(ctx, ports.Admission{OperationID: "filesystem-regression", Phase: ports.Execute, Snapshot: view, Binding: binding}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := permit.Close(); err != nil {
					t.Error(err)
				}
			})
			cmd := test.cmd
			cmd.Execution = test.request
			result, err := b.Run(ctx, permit, "node", cmd)
			if test.invalid {
				if !errors.Is(err, ssh.ErrExecutionValidation) || result.Outcome != ssh.ExecutionNotStarted || server.Executed.Load() != 0 {
					t.Fatalf("expected execution validation error and no dispatch, got result=%+v, err=%v, executed=%d", result, err, server.Executed.Load())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := <-commands; got != test.wantCmd {
				t.Fatalf("executed command %q, want %q", got, test.wantCmd)
			}
			if server.Executed.Load() != 1 {
				t.Fatalf("expected 1 execution, got %d", server.Executed.Load())
			}
		})
	}
}
