package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/i18n"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestExecExplicitExecutionOptions(t *testing.T) {
	for _, test := range []struct {
		name    string
		flags   []string
		payload string
		wantErr string
	}{
		{"server", []string{"--interpreter", "server"}, "echo '$HOME'", ""},
		{"dialect retains stage default", []string{"--launch-dialect", "posix"}, "echo '$HOME'", ""},
		{"login without known dialect", []string{"--login-shell"}, "", "server interpreter requires inherited login mode"},
		{"bash non-login", []string{"--interpreter", "bash", "--launch-dialect", "posix"}, "bash -c 'echo '\\''$HOME'\\'''", ""},
		{"bash login", []string{"--interpreter", "bash", "--launch-dialect", "posix", "--login-shell"}, "bash -l -c 'echo '\\''$HOME'\\'''", ""},
		{"bash explicit disabled", []string{"--interpreter", "bash", "--launch-dialect", "posix", "--login-shell=false"}, "bash -c 'echo '\\''$HOME'\\'''", ""},
		{"old no-login with explicit dialect", []string{"--launch-dialect", "posix", "--no-login"}, "bash -c 'echo '\\''$HOME'\\'''", ""},
		{"no-login with explicit unknown dialect rejected", []string{"--launch-dialect", "unknown", "--no-login"}, "", "bash interpreter requires posix, fish, or csh launch dialect"},
		{"sh non-login", []string{"--interpreter", "sh", "--launch-dialect", "posix"}, "sh -c 'echo '\\''$HOME'\\'''", ""},
		{"zsh non-login", []string{"--interpreter", "zsh", "--launch-dialect", "posix"}, "zsh -c 'echo '\\''$HOME'\\'''", ""},
		{"csh non-login", []string{"--interpreter", "csh", "--launch-dialect", "csh"}, "csh -c 'echo '\\''$HOME'\\'''", ""},
		{"tcsh non-login", []string{"--interpreter", "tcsh", "--launch-dialect", "csh"}, "tcsh -c 'echo '\\''$HOME'\\'''", ""},
		{"tcsh login rejected", []string{"--interpreter", "tcsh", "--launch-dialect", "csh", "--login-shell"}, "", "tcsh interpreter does not support login shell"},
		{"sh login rejected", []string{"--interpreter", "sh", "--launch-dialect", "posix", "--login-shell"}, "", "sh interpreter does not support login shell"},
		{"unknown interpreter", []string{"--interpreter", "invalid-shell"}, "", "unsupported command interpreter"},
		{"bash without dialect", []string{"--interpreter", "bash"}, "", "requires posix"},
		{"server login", []string{"--interpreter", "server", "--login-shell"}, "", "inherited login"},
		{"server explicit false", []string{"--interpreter", "server", "--login-shell=false"}, "", "inherited login"},
		{"server no-login", []string{"--interpreter", "server", "--no-login"}, "", "requires the bash"},
		{"login conflict", []string{"--interpreter", "bash", "--launch-dialect", "posix", "--no-login", "--login-shell"}, "", "mutually exclusive"},
		{"PTY", []string{"--interpreter", "server", "-x"}, "echo '$HOME'", ""},
		{"server sudo rejected", []string{"--interpreter", "server", "--sudo"}, "", "sudo requires a supported explicit"},
		{"bash sudo", []string{"--interpreter", "bash", "--launch-dialect", "posix", "--sudo"}, "bash -c 'echo '\\''$HOME'\\'''", ""},
		{"stream", []string{"--interpreter", "server", "--stream"}, "echo '$HOME'", ""},
		{"file output", []string{"--interpreter", "server", "--out-dir", "logs"}, "echo '$HOME'", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := NewExecOptions()
			command := newCmdExecWithOptions(o)
			flags := append([]string{"--host", "fixture", "-c", "echo '$HOME'"}, test.flags...)
			if err := command.Flags().Parse(flags); err != nil {
				t.Fatal(err)
			}
			err := o.Complete(command, command.Flags().Args())
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := o.Validate(); err != nil {
				t.Fatal(err)
			}
			if o.commandPlan == nil || o.commandPlan.Payload() != test.payload {
				t.Fatalf("unexpected plan: %+v", o.commandPlan)
			}
		})
	}
}

func TestExecExplicitInputRouting(t *testing.T) {
	for _, flags := range [][]string{
		{"--interpreter", "server", "--host", "fixture"},
		{"--interpreter", "server", "--host", "fixture", "--shell", "file.sh"},
		{"--host", "fixture", "-c", ""},
		{"--host", "fixture", ""},
		{"fixture", ""},
	} {
		o := NewExecOptions()
		command := newCmdExecWithOptions(o)
		if err := command.Flags().Parse(flags); err != nil {
			t.Fatal(err)
		}
		if err := o.Complete(command, command.Flags().Args()); err == nil {
			t.Fatalf("unsupported/empty input accepted: %q", flags)
		}
	}
	o := NewExecOptions()
	command := newCmdExecWithOptions(o)
	flags := preprocessSubArgs([]string{"fixture", "--interpreter", "server", "echo", "--remote-flag"}, command)
	if err := command.Flags().Parse(flags); err != nil {
		t.Fatal(err)
	}
	if err := o.Complete(command, command.Flags().Args()); err != nil {
		t.Fatal(err)
	}
	if o.commandPlan.Command() != "echo --remote-flag" {
		t.Fatalf("remote command changed: %q", o.commandPlan.Command())
	}
}

func TestExecLegacyDefaultIsPreserved(t *testing.T) {
	for _, flags := range [][]string{{}, {"--no-login"}} {
		o := NewExecOptions()
		command := newCmdExecWithOptions(o)
		flags = append([]string{"--host", "fixture", "-c", "echo legacy"}, flags...)
		if err := command.Flags().Parse(flags); err != nil {
			t.Fatal(err)
		}
		if err := o.Complete(command, nil); err != nil {
			t.Fatal(err)
		}
		if err := o.Validate(); err != nil {
			t.Fatal(err)
		}
		if o.commandPlan != nil {
			t.Fatal("legacy invocation switched execution paths")
		}
	}
}

func TestExecServerPlanPreservesCommandBytes(t *testing.T) {
	o := NewExecOptions()
	command := newCmdExecWithOptions(o)
	text := "  echo '$HOME' &\r\n雪\\%PATH%  "
	if err := command.Flags().Parse([]string{"--host", "fixture", "--interpreter", "server", "-c", text}); err != nil {
		t.Fatal(err)
	}
	if err := o.Complete(command, nil); err != nil {
		t.Fatal(err)
	}
	if o.commandPlan.Command() != text || o.commandPlan.Interpreter() != ssh.InterpreterServer {
		t.Fatal("server command changed")
	}
}

type execFixtureVerifier struct{ key cryptoSSH.PublicKey }

func (v execFixtureVerifier) Verify(ctx context.Context, _ ssh.HostKeyRequest, key cryptoSSH.PublicKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !bytes.Equal(v.key.Marshal(), key.Marshal()) {
		return fmt.Errorf("fixture host key mismatch")
	}
	return nil
}

func TestExecExplicitTaskUsesFrozenPlan(t *testing.T) {
	if err := i18n.Init("en"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	server, err := sshfixture.New(ctx)
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
	connector := ssh.NewConnector(tunnelTestProvider{cfg: &ssh.ClientConfig{
		NodeID: "fixture", Address: address, Port: port, User: "test", AuthType: "password", Password: sshfixture.Password,
	}}, ssh.WithHostKeyVerifier(execFixtureVerifier{server.HostKey}))
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	o := NewExecOptions()
	command := newCmdExecWithOptions(o)
	if err := command.Flags().Parse([]string{"--host", "fixture", "--interpreter", "server", "-c", "echo frozen"}); err != nil {
		t.Fatal(err)
	}
	if err := o.Complete(command, nil); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	o.stdout, o.stderr = &output, &output
	var mu sync.Mutex
	task := execHostTask{nodeID: "fixture", host: "fixture"}
	if err := o.executeTask(ctx, connector, task, "echo changed", false, 1, &mu); err == nil {
		t.Fatal("changed command accepted")
	}
	if server.Executed.Load() != 0 {
		t.Fatal("changed command reached server")
	}
	if err := o.executeTask(ctx, connector, task, "echo frozen", false, 1, &mu); err != nil {
		t.Fatal(err)
	}
	if server.Executed.Load() != 1 || !strings.Contains(output.String(), "fixture-output") {
		t.Fatalf("planned execution missing/replayed: %q", output.String())
	}
}

func TestExecInteractiveEffectivePlanning(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	server, err := sshfixture.New(ctx)
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
	// Node with invalid execution config (bash without posix dialect)
	connectorInvalid := ssh.NewConnector(tunnelTestProvider{cfg: &ssh.ClientConfig{
		NodeID: "fixture", Address: address, Port: port, User: "test", AuthType: "password", Password: sshfixture.Password,
		Execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchUnknown},
	}}, ssh.WithHostKeyVerifier(execFixtureVerifier{server.HostKey}))
	t.Cleanup(func() {
		if err := connectorInvalid.CloseAll(); err != nil {
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
	err = o.runInteractive(ctx, connectorInvalid, task, "uptime")
	if err == nil || !strings.Contains(err.Error(), "plan interactive command") || !strings.Contains(err.Error(), "requires posix") {
		t.Fatalf("expected planning error for invalid node execution dialect, got: %v", err)
	}
}

func TestExecConfiguredUnixLoginDefaults(t *testing.T) {
	for _, interpreter := range []ssh.Interpreter{ssh.InterpreterZsh, ssh.InterpreterFish} {
		for _, configuredLogin := range []bool{false, true} {
			for _, explicitNoLogin := range []bool{false, true} {
				execution := &ssh.ExecutionConfig{Interpreter: interpreter, LaunchDialect: ssh.LaunchPOSIX, Login: &configuredLogin}
				o := NewExecOptions()
				o.execution.noLoginSet, o.NoLoginShell = explicitNoLogin, explicitNoLogin
				run := &ssh.RunConfig{Interpreter: interpreter, LoginShell: configuredLogin}
				for _, option := range o.commandRunOptions(execution, []ssh.RunOption{ssh.WithRingBuffer(4096)}) {
					option(run)
				}
				wantInterpreter, wantLogin := interpreter, configuredLogin
				if explicitNoLogin {
					wantInterpreter, wantLogin = ssh.InterpreterBash, false
				}
				if run.Interpreter != wantInterpreter || run.LoginShell != wantLogin || run.RingMaxBytes != 4096 {
					t.Fatalf("configured interpreter=%s login=%v explicitNoLogin=%v: %+v", interpreter, configuredLogin, explicitNoLogin, run)
				}
			}
		}
	}
	o := NewExecOptions()
	o.execution.noLoginSet = true
	run := &ssh.RunConfig{Interpreter: ssh.InterpreterZsh, LoginShell: false}
	for _, option := range o.commandRunOptions(&ssh.ExecutionConfig{Interpreter: ssh.InterpreterZsh}, nil) {
		option(run)
	}
	if run.Interpreter != ssh.InterpreterBash || !run.LoginShell {
		t.Fatal("explicit --no-login=false lost legacy Bash login semantics")
	}
	o = NewExecOptions()
	run = &ssh.RunConfig{LoginShell: false}
	for _, option := range o.commandRunOptions(nil, nil) {
		option(run)
	}
	if !run.LoginShell {
		t.Fatal("legacy Bash login default changed")
	}
}

type blockedExecOutput struct{}

func (blockedExecOutput) Write([]byte) (int, error) { panic("unbound output") }
func (blockedExecOutput) WriteContext(ctx context.Context, _ []byte) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestExecTaskLockedStreamCancellation(t *testing.T) {
	fixtureCtx, stopFixture := context.WithTimeout(t.Context(), 5*time.Second)
	defer stopFixture()
	server, err := sshfixture.New(fixtureCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	}()
	address, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	connector := ssh.NewConnector(tunnelTestProvider{cfg: &ssh.ClientConfig{
		NodeID: "fixture", Address: address, Port: port, User: "test", AuthType: "password", Password: sshfixture.Password,
	}}, ssh.WithHostKeyVerifier(execFixtureVerifier{server.HostKey}))
	defer func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	}()
	o := NewExecOptions()
	o.Stream = true
	o.stdout = blockedExecOutput{}
	o.stderr = &bytes.Buffer{}
	var mu sync.Mutex
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- o.executeTask(ctx, connector, execHostTask{host: "fixture", nodeID: "fixture"}, "command", false, 1, &mu)
	}()
	select {
	case err := <-done:
		var outputErr *ssh.OutputError
		if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &outputErr) {
			t.Fatalf("stream cancellation lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		_ = connector.CloseAll()
		t.Fatal("locked stream did not join")
	}
	if server.Executed.Load() != 1 {
		t.Fatalf("command executed %d times", server.Executed.Load())
	}
}
