package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
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

func newExecCombinationFixture(t *testing.T, handler func(string, cryptoSSH.Channel), opts ...ssh.Option) (context.Context, *ssh.Connector, *sshfixture.Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{ExecHandler: handler})
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
	opts = append([]ssh.Option{ssh.WithHostKeyVerifier(execFixtureVerifier{server.HostKey})}, opts...)
	connector := ssh.NewConnector(tunnelTestProvider{cfg: &ssh.ClientConfig{
		NodeID: "fixture", Address: address, Port: port, User: "test", AuthType: "password", Password: sshfixture.Password,
		SudoMode: ssh.SudoModeSudoer,
		// Deliberately different defaults: the per-invocation selection must win.
		Execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterPwsh, LaunchDialect: ssh.LaunchCmd},
	}}, opts...)
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	return ctx, connector, server
}

type execCombinationCase struct {
	name, interpreter, dialect, output string
	script, sudo, login                bool
	status                             uint32
}

func TestExecExplicitCombinationsExecute(t *testing.T) {
	if err := i18n.Init("en"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []execCombinationCase{
		{name: "server stream", interpreter: "server", output: "stream"},
		{name: "bash stream", interpreter: "bash", dialect: "posix", output: "stream"},
		{name: "powershell stream", interpreter: "powershell", dialect: "cmd", output: "stream"},
		{name: "cmd file", interpreter: "cmd", dialect: "cmd", output: "file"},
		{name: "pwsh file", interpreter: "pwsh", dialect: "posix", output: "file"},
		{name: "fish stream", interpreter: "fish", dialect: "fish", output: "stream"},
		{name: "zsh file", interpreter: "zsh", dialect: "posix", output: "file"},
		{name: "bash sudo buffered", interpreter: "bash", dialect: "posix", sudo: true},
		{name: "bash sudo stream", interpreter: "bash", dialect: "posix", sudo: true, output: "stream"},
		{name: "sh sudo file", interpreter: "sh", dialect: "posix", sudo: true, output: "file"},
		{name: "bash login sudo file", interpreter: "bash", dialect: "posix", sudo: true, login: true, output: "file"},
		{name: "bash script buffered", interpreter: "bash", dialect: "posix", script: true},
		{name: "sh script stream", interpreter: "sh", dialect: "posix", script: true, output: "stream"},
		{name: "fish script file", interpreter: "fish", dialect: "fish", script: true, output: "file"},
		{name: "zsh script stream", interpreter: "zsh", dialect: "posix", script: true, output: "stream"},
		{name: "bash script sudo stream", interpreter: "bash", dialect: "posix", script: true, sudo: true, output: "stream"},
		{name: "sh script sudo file", interpreter: "sh", dialect: "posix", script: true, sudo: true, output: "file"},
		{name: "nonzero stream", interpreter: "sh", dialect: "posix", output: "stream", status: 7},
		{name: "nonzero sudo file", interpreter: "bash", dialect: "posix", sudo: true, output: "file", status: 9},
	} {
		t.Run(test.name, func(t *testing.T) {
			type request struct{ command, input string }
			requests := make(chan request, 1)
			ctx, connector, server := newExecCombinationFixture(t, func(command string, channel cryptoSSH.Channel) {
				var input []byte
				if test.script {
					var err error
					input, err = io.ReadAll(channel)
					if err != nil {
						t.Error(err)
						return
					}
				}
				requests <- request{command, string(input)}
				_, _ = io.WriteString(channel, "combined-out\n")
				_, _ = io.WriteString(channel.Stderr(), "combined-err\n")
				_, _ = channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{test.status}))
			})
			o, content, logDir := prepareExecCombination(t, test)
			var stdout, stderr bytes.Buffer
			o.stdout, o.stderr = &stdout, &stderr
			var mu sync.Mutex
			err := o.executeTask(ctx, connector, execHostTask{nodeID: "fixture", host: "fixture"}, content, test.script, 2, &mu)
			if test.status == 0 && err != nil {
				t.Fatal(err)
			}
			if test.status != 0 {
				var exitErr *cryptoSSH.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitStatus() != int(test.status) {
					t.Fatalf("exit status lost: %v", err)
				}
			}
			if server.Executed.Load() != 1 {
				t.Fatalf("command missing or replayed: %d", server.Executed.Load())
			}
			got := <-requests
			var expected string
			if test.script {
				expected = test.interpreter + " -s"
				if test.interpreter == "fish" {
					expected = "fish"
				}
				if got.input != content {
					t.Fatalf("script bytes changed: %q", got.input)
				}
			} else {
				expected = o.commandPlan.Payload()
			}
			if test.sudo {
				expected = "sudo -S -p '' " + expected
			}
			if got.command != expected {
				t.Fatalf("payload %q, want %q", got.command, expected)
			}
			assertExecCombinationOutput(t, test.output, logDir, stdout.String()+stderr.String())
			client, err := connector.Connect(ctx, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			if client.Execution().Interpreter != ssh.InterpreterPwsh || client.Execution().LaunchDialect != ssh.LaunchCmd {
				t.Fatal("invocation mutated shared execution defaults")
			}
		})
	}
}

func prepareExecCombination(t *testing.T, test execCombinationCase) (*ExecOptions, string, string) {
	t.Helper()
	o := NewExecOptions()
	command := newCmdExecWithOptions(o)
	flags := []string{"--host", "fixture", "--interpreter", test.interpreter}
	if test.dialect != "" {
		flags = append(flags, "--launch-dialect", test.dialect)
	}
	if test.login {
		flags = append(flags, "--login-shell")
	}
	if test.sudo {
		flags = append(flags, "--sudo")
	}
	content := "echo 'chosen interpreter'"
	if test.script {
		content = "#!/bin/sh\r\necho 'script bytes: 雪'\r\n"
		path := filepath.Join(t.TempDir(), "check.sh")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		flags = append(flags, "--shell", path)
	} else {
		flags = append(flags, "-c", content)
	}
	var logDir string
	switch test.output {
	case "stream":
		flags = append(flags, "--stream")
	case "file":
		logDir = t.TempDir()
		flags = append(flags, "--out-dir", logDir)
	}
	if err := command.Flags().Parse(flags); err != nil {
		t.Fatal(err)
	}
	if err := o.Complete(command, nil); err != nil {
		t.Fatal(err)
	}
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	return o, content, logDir
}

func assertExecCombinationOutput(t *testing.T, mode, logDir, output string) {
	t.Helper()
	if mode == "file" {
		data, err := os.ReadFile(filepath.Join(logDir, "fixture.log"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output, "combined-out") {
			t.Fatalf("log output duplicated to terminal: %q", output)
		}
		output = string(data)
	}
	for _, text := range []string{"combined-out", "combined-err"} {
		if strings.Count(output, text) != 1 {
			t.Fatalf("output missing or duplicated: %q", output)
		}
	}
	if mode == "stream" && !strings.Contains(output, "[fixture]") {
		t.Fatalf("multi-host stream prefix missing: %q", output)
	}
}

func TestExecExplicitUnsupportedCombinations(t *testing.T) {
	for _, test := range []struct {
		name  string
		flags []string
	}{
		{"server script", []string{"--interpreter", "server", "--shell", "check.sh"}},
		{"powershell script", []string{"--interpreter", "powershell", "--launch-dialect", "cmd", "--shell", "check.ps1"}},
		{"cmd sudo", []string{"--interpreter", "cmd", "--launch-dialect", "cmd", "--sudo", "-c", "dir"}},
		{"PTY script", []string{"--interpreter", "sh", "--launch-dialect", "posix", "--shell", "check.sh", "-x"}},
		{"PTY stream", []string{"--interpreter", "bash", "--launch-dialect", "posix", "--stream", "-x", "-c", "id"}},
		{"PTY file", []string{"--interpreter", "bash", "--launch-dialect", "posix", "--out-dir", "logs", "-x", "-c", "id"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := NewExecOptions()
			command := newCmdExecWithOptions(o)
			if err := command.Flags().Parse(append([]string{"--host", "fixture"}, test.flags...)); err != nil {
				t.Fatal(err)
			}
			if err := o.Complete(command, nil); err == nil {
				t.Fatal("unsupported combination accepted")
			}
		})
	}
}

func TestExecExplicitStdinScript(t *testing.T) {
	const content = "#!/usr/bin/python3\necho 'explicit sh wins'\n"
	path := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close() })
	old := os.Stdin
	os.Stdin = input
	t.Cleanup(func() { os.Stdin = old })
	o := NewExecOptions()
	command := newCmdExecWithOptions(o)
	if err := command.Flags().Parse([]string{"--host", "fixture", "--interpreter", "sh", "--launch-dialect", "posix", "--stream", "--sudo"}); err != nil {
		t.Fatal(err)
	}
	if err := o.Complete(command, nil); err != nil {
		t.Fatal(err)
	}
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	if !o.stdinScript || o.commandPlan != nil || o.Command != content {
		t.Fatal("stdin script was planned as an ordinary command or changed")
	}
	if _, err := input.Stat(); err != nil {
		t.Fatalf("borrowed stdin closed: %v", err)
	}
}

func TestExecExplicitOutputModesRejectChangedCommand(t *testing.T) {
	for _, mode := range []string{"--stream", "--out-dir"} {
		t.Run(mode, func(t *testing.T) {
			ctx, connector, server := newExecCombinationFixture(t, nil)
			o := NewExecOptions()
			command := newCmdExecWithOptions(o)
			flags := []string{"--host", "fixture", "--interpreter", "server", "-c", "original", mode}
			if mode == "--out-dir" {
				flags = append(flags, filepath.Join(t.TempDir(), "logs"))
			}
			if err := command.Flags().Parse(flags); err != nil {
				t.Fatal(err)
			}
			if err := o.Complete(command, nil); err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			if err := o.executeTask(ctx, connector, execHostTask{nodeID: "fixture", host: "fixture"}, "changed", false, 1, &mu); err == nil {
				t.Fatal("changed command accepted")
			}
			if server.Authenticated.Load() != 0 || server.Executed.Load() != 0 {
				t.Fatal("changed command connected to server")
			}
			if o.OutDir != "" {
				if _, err := os.Stat(o.OutDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("rejected command created output directory: %v", err)
				}
			}
		})
	}
}
