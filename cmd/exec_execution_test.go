package cmd

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
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
		{"dialect retains stage default", []string{"--launch-dialect", "posix"}, "bash -l -c 'echo '\\''$HOME'\\'''", ""},
		{"login without known dialect", []string{"--login-shell"}, "", "requires posix"},
		{"bash non-login", []string{"--interpreter", "bash", "--launch-dialect", "posix"}, "bash -c 'echo '\\''$HOME'\\'''", ""},
		{"bash login", []string{"--interpreter", "bash", "--launch-dialect", "posix", "--login-shell"}, "bash -l -c 'echo '\\''$HOME'\\'''", ""},
		{"bash explicit disabled", []string{"--interpreter", "bash", "--launch-dialect", "posix", "--login-shell=false"}, "bash -c 'echo '\\''$HOME'\\'''", ""},
		{"old no-login with explicit dialect", []string{"--launch-dialect", "posix", "--no-login"}, "bash -c 'echo '\\''$HOME'\\'''", ""},
		{"empty interpreter", []string{"--interpreter="}, "", "must not be empty"},
		{"unknown interpreter", []string{"--interpreter", "sh"}, "", "unsupported command interpreter"},
		{"bash without dialect", []string{"--interpreter", "bash"}, "", "requires posix"},
		{"server login", []string{"--interpreter", "server", "--login-shell"}, "", "inherited login"},
		{"server explicit false", []string{"--interpreter", "server", "--login-shell=false"}, "", "inherited login"},
		{"server no-login", []string{"--interpreter", "server", "--no-login"}, "", "requires the bash"},
		{"login conflict", []string{"--interpreter", "bash", "--launch-dialect", "posix", "--no-login", "--login-shell"}, "", "mutually exclusive"},
		{"PTY", []string{"--interpreter", "server", "-x"}, "", "ordinary buffered"},
		{"sudo", []string{"--interpreter", "server", "--sudo"}, "", "ordinary buffered"},
		{"stream", []string{"--interpreter", "server", "--stream"}, "", "ordinary buffered"},
		{"file output", []string{"--interpreter", "server", "--out-dir", "logs"}, "", "ordinary buffered"},
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
		{"--interpreter", "bash", "--launch-dialect", "posix", "--host", "fixture", "--shell", "file.sh"},
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
