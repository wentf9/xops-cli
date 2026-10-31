package mcphost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
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

type executionFixtureSecrets struct{}

func (executionFixtureSecrets) ResolveSecret(ctx context.Context, _ ssh.SecretRequest) ([]byte, error) {
	return []byte(sshfixture.Password), ctx.Err()
}

func (v executionFixtureTrust) Verify(ctx context.Context, _ ssh.HostKeyRequest, key cryptoSSH.PublicKey) error {
	if !bytes.Equal(v.key.Marshal(), key.Marshal()) {
		return fmt.Errorf("fixture host key changed")
	}
	return ctx.Err()
}

func TestLegacyHostBackendExecutionConfiguration(t *testing.T) {
	yes, no := true, false
	for _, test := range []struct {
		name      string
		execution *ssh.ExecutionConfig
		sudo      bool
		mode      ssh.SudoMode
		payload   string
		invalid   bool
	}{
		{name: "unconfigured command defaults to server", payload: "uptime"},
		{name: "configured bash command", execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &yes}, payload: "bash -l -c 'uptime'"},
		{name: "explicit server", execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, payload: "uptime"},
		{name: "fish command", execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish, Login: &no}, payload: "fish -c 'uptime'"},
		{name: "zsh command", execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterZsh, LaunchDialect: ssh.LaunchPOSIX, Login: &no}, payload: "zsh -c 'uptime'"},
		{name: "fish sudo", execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish, Login: &no}, sudo: true, mode: ssh.SudoModeRoot, payload: "fish -c 'uptime'"},
		{name: "zsh sudo", execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterZsh, LaunchDialect: ssh.LaunchPOSIX, Login: &no}, sudo: true, mode: ssh.SudoModeRoot, payload: "zsh -c 'uptime'"},
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
	connector := ssh.NewConnector(executionFixtureProvider{ssh.ClientConfig{NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", Password: sshfixture.Password, SudoMode: ssh.SudoModeRoot}}, ssh.WithHostKeyVerifier(executionFixtureTrust{server.HostKey}), ssh.WithSecretResolver(executionFixtureSecrets{}))
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	view := ports.OperationSnapshot{DomainID: "fixture", Targets: map[string]ports.Target{"node": {Info: ports.NodeInfo{ID: "node"}, Version: "1", Plan: ssh.ConnectionPlan{Scope: "fixture", Hops: []ssh.ConnectionConfig{{NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", SudoMode: ssh.SudoModeRoot}}}}}}
	binding, err := ports.Bind(view, "fixture", "terminal", struct{}{})
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
	return newExecutionBackendFixtureWithHandler(t, mode, nil)
}

func newExecutionBackendFixtureWithHandler(t *testing.T, mode ssh.SudoMode, handler func(string, cryptoSSH.Channel)) (*backend, *sshfixture.Server, ports.Permit, chan string, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	commands := make(chan string, 8)
	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{ExecHandler: func(command string, ch cryptoSSH.Channel) {
		if handler != nil {
			handler(command, ch)
			return
		}
		if strings.Contains(command, "__XOPS_DIALECT_POSIX__") {
			_, _ = io.WriteString(ch, "__XOPS_DIALECT_POSIX__:Linux:/bin/bash\n")
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
			return
		}
		if strings.Contains(command, "__XOPS_INTERP__") {
			_, _ = io.WriteString(ch, "__XOPS_INTERP__:bash\n__XOPS_INTERP_END__\n")
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
			return
		}
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
	connector := ssh.NewConnector(executionFixtureProvider{ssh.ClientConfig{NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", Password: sshfixture.Password, SudoMode: mode}}, ssh.WithHostKeyVerifier(executionFixtureTrust{server.HostKey}), ssh.WithSecretResolver(executionFixtureSecrets{}))
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	view := ports.OperationSnapshot{DomainID: "fixture", Targets: map[string]ports.Target{"node": {Info: ports.NodeInfo{ID: "node"}, Version: "1", Plan: ssh.ConnectionPlan{Scope: "fixture", Hops: []ssh.ConnectionConfig{{NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", SudoMode: mode}}}}}}
	binding, err := ports.Bind(view, "fixture", "terminal", struct{}{})
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

func TestLegacyHostBackendProbeIsBoundAndCached(t *testing.T) {
	for _, interpreter := range []ssh.Interpreter{ssh.InterpreterFish, ssh.InterpreterZsh} {
		t.Run(string(interpreter), func(t *testing.T) {
			b, server, execution, _, ctx := newExecutionBackendFixtureWithHandler(t, ssh.SudoModeRoot, func(command string, ch cryptoSSH.Channel) {
				replyLegacyShellProbe(t, interpreter, command, ch)
			})
			if _, err := b.ProbeExecution(ctx, execution, "node"); !errors.Is(err, ports.ErrPurpose) || server.Executed.Load() != 0 {
				t.Fatalf("wrong permit reached discovery: %v", err)
			}
			inspection, err := ports.NewPermit(ctx, ports.Admission{OperationID: "probe", Phase: ports.Inspect, Snapshot: execution.Snapshot(), Binding: execution.Binding()}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := inspection.Close(); err != nil {
					t.Error(err)
				}
			})
			for attempt := 0; attempt < 2; attempt++ {
				before := server.Executed.Load()
				result, err := b.ProbeExecution(ctx, inspection, "node")
				if err != nil || result.RecommendedInterpreter != interpreter {
					t.Fatalf("legacy default shell: %+v %v", result, err)
				}
				if attempt == 1 && server.Executed.Load() != before {
					t.Fatal("legacy backend repeated cached probe")
				}
			}
			if err := inspection.Close(); err != nil {
				t.Fatal(err)
			}
			before := server.Executed.Load()
			if _, err := b.ProbeExecution(ctx, inspection, "node"); !errors.Is(err, context.Canceled) || server.Executed.Load() != before {
				t.Fatalf("closed permit reached discovery: %v", err)
			}
		})
	}
}

func TestLegacyHostBackendFilesystemRejectsNonPOSIXDialects(t *testing.T) {
	yes := true
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
			name:    "unconfigured node rejects filesystem commands due to unknown dialect",
			node:    nil,
			cmd:     ports.Command{Text: "rm -rf '/tmp/test'", Filesystem: true},
			invalid: true,
		},
		{
			name:    "configured bash allowed",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &yes},
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
			binding, err := ports.Bind(view, "fixture", "terminal", struct{}{})
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
				if test.cmd.RequirePOSIX && !strings.Contains(err.Error(), "POSIX shell target (X11/Wayland) is required") {
					t.Fatalf("expected error mentioning POSIX shell target (X11/Wayland) is required, got %v", err)
				}
				if test.cmd.Filesystem && !strings.Contains(err.Error(), "generated filesystem commands") {
					t.Fatalf("expected error mentioning generated filesystem commands, got %v", err)
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

func replyLegacyShellProbe(t *testing.T, interpreter ssh.Interpreter, command string, ch cryptoSSH.Channel) {
	t.Helper()
	output, status := "syntax error\n", uint32(1)
	switch {
	case strings.Contains(command, "__XOPS_INTERP_END__"):
		output, status = "__XOPS_INTERP__:bash\n__XOPS_INTERP__:sh\n__XOPS_INTERP__:"+string(interpreter)+"\n__XOPS_INTERP_END__\n", 0
	case interpreter == ssh.InterpreterZsh && strings.Contains(command, "__XOPS_DIALECT_POSIX__"):
		output, status = "__XOPS_DIALECT_POSIX__:Linux:/bin/zsh\n", 0
	case interpreter == ssh.InterpreterFish && strings.Contains(command, "__XOPS_DIALECT_FISH__"):
		output, status = "__XOPS_DIALECT_FISH__:3.7.0\n__XOPS_FISH_OS__:Linux\n__XOPS_FISH_SHELL__:/bin/fish\n", 0
	}
	if _, err := io.WriteString(ch, output); err != nil {
		t.Error(err)
	}
	if _, err := ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{status})); err != nil {
		t.Error(err)
	}
}

type mutableExecutionFixtureProvider struct {
	cfg   ssh.ClientConfig
	reads atomic.Int32
}

func (p *mutableExecutionFixtureProvider) GetConfig(string) (*ssh.ClientConfig, error) {
	p.reads.Add(1)
	copy := p.cfg
	return &copy, nil
}

type executionFixtureTrustSet []cryptoSSH.PublicKey

func (keys executionFixtureTrustSet) Verify(ctx context.Context, _ ssh.HostKeyRequest, key cryptoSSH.PublicKey) error {
	for _, expected := range keys {
		if bytes.Equal(expected.Marshal(), key.Marshal()) {
			return ctx.Err()
		}
	}
	return ssh.ErrHostKeyMismatch
}

func TestLegacyHostProbeUsesCapturedEndpointAfterProviderEdit(t *testing.T) {
	b, first, admitted, _, ctx := newExecutionBackendFixtureWithHandler(t, ssh.SudoModeRoot, func(command string, ch cryptoSSH.Channel) { replyLegacyShellProbe(t, ssh.InterpreterZsh, command, ch) })
	_, second, secondPermit, _, _ := newExecutionBackendFixtureWithHandler(t, ssh.SudoModeRoot, func(command string, ch cryptoSSH.Channel) { replyLegacyShellProbe(t, ssh.InterpreterFish, command, ch) })
	firstHop := admitted.Snapshot().Targets["node"].Plan.Hops[0]
	provider := &mutableExecutionFixtureProvider{cfg: ssh.ClientConfig{NodeID: "node", Address: firstHop.Address, Port: firstHop.Port, User: firstHop.User, AuthType: "password", Password: sshfixture.Password}}
	connector := ssh.NewConnector(provider, ssh.WithHostKeyVerifier(executionFixtureTrustSet{first.HostKey, second.HostKey}), ssh.WithSecretResolver(executionFixtureSecrets{}))
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	b.connector = connector
	inspection, err := ports.NewPermit(ctx, ports.Admission{OperationID: "captured-probe", Phase: ports.Inspect, Snapshot: admitted.Snapshot(), Binding: admitted.Binding()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := inspection.Close(); err != nil {
			t.Error(err)
		}
	})
	// Edit the live provider after admission, before any SSH connection exists.
	secondHop := secondPermit.Snapshot().Targets["node"].Plan.Hops[0]
	provider.cfg.Address, provider.cfg.Port = secondHop.Address, secondHop.Port
	result, err := b.ProbeExecution(ctx, inspection, "node")
	if err != nil || result.RecommendedInterpreter != ssh.InterpreterZsh {
		t.Fatalf("captured target probe: %+v %v", result, err)
	}
	if first.Executed.Load() != 2 || second.Executed.Load() != 0 || provider.reads.Load() != 0 {
		t.Fatalf("probe escaped snapshot: first=%d second=%d live reads=%d", first.Executed.Load(), second.Executed.Load(), provider.reads.Load())
	}
}

func TestLegacyHostRunUsesCapturedEndpointAfterProviderEdit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sudo    bool
		mode    ssh.SudoMode
		payload string
	}{
		{"command", false, ssh.SudoModeRoot, "zsh -c 'echo reviewed'"},
		{"sudo root", true, ssh.SudoModeRoot, "zsh -c 'echo reviewed'"},
		{"sudo NOPASSWD", true, ssh.SudoModeSudoer, "sudo -S -p '' bash -c 'echo reviewed'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commands := make(chan string, 1)
			b, first, admitted, _, ctx := newExecutionBackendFixtureWithHandler(t, tc.mode, func(command string, ch cryptoSSH.Channel) {
				if strings.Contains(command, "__XOPS_") {
					replyLegacyShellProbe(t, ssh.InterpreterZsh, command, ch)
					return
				}
				commands <- command
				replyCapturedExecution(t, ch, "executed-on-first")
			})
			_, second, other, _, _ := newExecutionBackendFixtureWithHandler(t, tc.mode, func(_ string, ch cryptoSSH.Channel) { replyCapturedExecution(t, ch, "executed-on-second") })
			firstHop := admitted.Snapshot().Targets["node"].Plan.Hops[0]
			provider := &mutableExecutionFixtureProvider{cfg: ssh.ClientConfig{NodeID: "node", Address: firstHop.Address, Port: firstHop.Port, User: firstHop.User, AuthType: "password", Password: sshfixture.Password, SudoMode: tc.mode}}
			connector := ssh.NewConnector(provider, ssh.WithHostKeyVerifier(executionFixtureTrustSet{first.HostKey, second.HostKey}), ssh.WithSecretResolver(executionFixtureSecrets{}))
			t.Cleanup(func() {
				if err := connector.CloseAll(); err != nil {
					t.Error(err)
				}
			})
			b.connector = connector
			inspection, err := ports.NewPermit(ctx, ports.Admission{OperationID: "captured-probe", Phase: ports.Inspect, Snapshot: admitted.Snapshot(), Binding: admitted.Binding()}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := inspection.Close(); err != nil {
					t.Error(err)
				}
			})
			probe, err := b.ProbeExecution(ctx, inspection, "node")
			if err != nil {
				t.Fatal(err)
			}
			execution := probe.SuggestedConfig.Clone()
			if tc.mode == ssh.SudoModeSudoer {
				// Exercise the legacy NOPASSWD adapter as well as the portable
				// zsh adapter, using an explicit request-level override.
				execution.Interpreter = ssh.InterpreterBash
			}
			// Admission has already frozen first. Editing the live provider must
			// not redirect the user command after probing or change sudo mode.
			secondHop := other.Snapshot().Targets["node"].Plan.Hops[0]
			provider.cfg.Address, provider.cfg.Port = secondHop.Address, secondHop.Port
			result, err := b.Run(ctx, admitted, "node", ports.Command{Text: "echo reviewed", Execution: execution, Sudo: tc.sudo})
			if err != nil || result.Output != "executed-on-first" || result.Outcome != ssh.ExecutionCompleted {
				t.Fatalf("captured execution: %+v %v", result, err)
			}
			if first.Executed.Load() != 3 || second.Executed.Load() != 0 || provider.reads.Load() != 0 || first.Authenticated.Load() != 1 {
				t.Fatalf("command escaped snapshot or probe transport: first=%d second=%d live reads=%d auth=%d", first.Executed.Load(), second.Executed.Load(), provider.reads.Load(), first.Authenticated.Load())
			}
			if payload := <-commands; payload != tc.payload {
				t.Fatalf("payload=%q want=%q", payload, tc.payload)
			}
		})
	}
}

func replyCapturedExecution(t *testing.T, ch cryptoSSH.Channel, output string) {
	t.Helper()
	if _, err := io.WriteString(ch, output); err != nil {
		t.Error(err)
	}
	if _, err := ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0})); err != nil {
		t.Error(err)
	}
}
