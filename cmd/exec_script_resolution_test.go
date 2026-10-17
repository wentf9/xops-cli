package cmd

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type execScriptRequest struct{ command, input string }

func partialScriptProvider(t *testing.T, server *sshfixture.Server) *tunnelTestProvider {
	t.Helper()
	host, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	login := true
	return &tunnelTestProvider{cfg: &ssh.ClientConfig{
		NodeID: "fixture", Address: host, Port: port, User: "test", AuthType: "password", Password: sshfixture.Password, SudoMode: ssh.SudoModeSudoer,
		Execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &login},
	}}
}

func TestExecScriptPartialOverridesResolveWithTarget(t *testing.T) {
	for _, test := range []struct {
		name, script, payload string
		flags                 []string
		invalid               bool
	}{
		{"dialect from CLI interpreter from shebang", "#!/bin/sh\necho chosen\n", "sh -s", []string{"--launch-dialect", "posix"}, false},
		{"login from CLI interpreter and dialect from node", "echo chosen\n", "bash -s", []string{"--login-shell=false"}, false},
		{"interpreter from CLI dialect from node", "#!/bin/bash\necho chosen\n", "sh -s", []string{"--interpreter", "sh"}, false},
		{"sudo with dialect only", "#!/bin/sh\necho chosen\n", "sudo -S -p '' sh -s", []string{"--launch-dialect", "posix", "--sudo"}, false},
		{"resolved sh rejects login", "#!/bin/sh\necho must-not-start\n", "", []string{"--login-shell"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := make(chan execScriptRequest, 1)
			ctx, _, server := newExecCombinationFixture(t, func(command string, channel cryptoSSH.Channel) {
				data, err := io.ReadAll(channel)
				if err != nil {
					t.Error(err)
					return
				}
				requests <- execScriptRequest{command, string(data)}
				_, _ = io.WriteString(channel, "script-output")
				_, _ = channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
			})
			provider := partialScriptProvider(t, server)
			connector := ssh.NewConnector(provider, ssh.WithHostKeyVerifier(execFixtureVerifier{server.HostKey}))
			t.Cleanup(func() {
				if err := connector.CloseAll(); err != nil {
					t.Error(err)
				}
			})
			path := filepath.Join(t.TempDir(), "check.sh")
			if err := os.WriteFile(path, []byte(test.script), 0600); err != nil {
				t.Fatal(err)
			}
			o := NewExecOptions()
			command := newCmdExecWithOptions(o)
			flags := append([]string{"--host", "fixture", "--shell", path}, test.flags...)
			if err := command.Flags().Parse(flags); err != nil {
				t.Fatal(err)
			}
			if err := o.Complete(command, nil); err != nil {
				t.Fatal(err)
			}
			if err := o.Validate(); err != nil {
				t.Fatal(err)
			}
			data, err := readExecScriptFile(ctx, path, ssh.MaxCommandInputBytes)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			o.stdout, o.stderr = &output, &output
			var mu sync.Mutex
			err = o.executeTask(ctx, connector, execHostTask{nodeID: "fixture", host: "fixture"}, string(data), true, 1, &mu)
			if test.invalid {
				if !errors.Is(err, ssh.ErrExecutionValidation) || server.Executed.Load() != 0 {
					t.Fatalf("invalid resolved script dispatched: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := <-requests
			if got.command != test.payload || got.input != test.script || server.Executed.Load() != 1 {
				t.Fatalf("script payload/input changed or replayed: %+v count=%d", got, server.Executed.Load())
			}
			client, err := connector.Connect(ctx, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(client.Execution(), provider.cfg.Execution) {
				t.Fatal("per-invocation override changed node defaults")
			}
		})
	}
}

func TestExecScriptOverridePreservesMissingFields(t *testing.T) {
	for _, flags := range [][]string{{"--launch-dialect", "posix"}, {"--login-shell=false"}, {"--interpreter", "sh"}} {
		o := NewExecOptions()
		command := newCmdExecWithOptions(o)
		if err := command.Flags().Parse(append([]string{"--host", "fixture", "--shell", "check.sh"}, flags...)); err != nil {
			t.Fatal(err)
		}
		if err := o.Complete(command, nil); err != nil {
			t.Fatal(err)
		}
		execution, err := o.cliExecutionConfig()
		if err != nil {
			t.Fatal(err)
		}
		if !o.execution.interpreterSet && execution.Interpreter != "" {
			t.Fatal("absent interpreter was set")
		}
		if !o.execution.dialectSet && execution.LaunchDialect != "" {
			t.Fatal("absent launch dialect was set")
		}
		if !o.execution.loginSet && execution.Login != nil {
			t.Fatal("absent login mode was set")
		}
	}
}
