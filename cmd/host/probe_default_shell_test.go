package host

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestHostProbeSavesRemoteDefaultShell(t *testing.T) {
	for _, interpreter := range []ssh.Interpreter{ssh.InterpreterFish, ssh.InterpreterZsh} {
		for _, selector := range []string{"default-shell", "--all"} {
			t.Run(string(interpreter)+"/"+selector, func(t *testing.T) {
				repo, store := verificationRepository(t)
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{ExecHandler: func(command string, channel cryptoSSH.Channel) {
					replyDefaultShellProbe(t, interpreter, command, channel)
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
				port, err := strconv.ParseUint(portText, 10, 16)
				if err != nil {
					t.Fatal(err)
				}
				draft, err := prepareImport(repo, utils.HostInfo{Host: host, Port: uint16(port), User: "fixture", Password: sshfixture.Password, Alias: "default-shell"}, "fixture")
				if err != nil {
					t.Fatal(err)
				}
				draft.bundle.Node.Execution = &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}
				if err := draft.save(ctx, repo); err != nil {
					t.Fatal(err)
				}
				cmd := NewCmdInventoryProbe()
				var output bytes.Buffer
				cmd.SetArgs([]string{selector, "--save"})
				cmd.SetContext(ctx)
				cmd.SetOut(&output)
				cmd.SetErr(&output)
				if err := cmd.Execute(); err != nil {
					t.Fatal(err)
				}
				cfg, err := store.Load()
				if err != nil {
					t.Fatal(err)
				}
				node, found := cfg.Nodes.Get(draft.nodeID)
				dialect := ssh.LaunchPOSIX
				if interpreter == ssh.InterpreterFish {
					dialect = ssh.LaunchFish
				}
				if !found || node.Execution == nil || node.Execution.Interpreter != interpreter || node.Execution.LaunchDialect != dialect || node.Execution.Login == nil || *node.Execution.Login {
					t.Fatalf("default shell was not persisted: %+v", node.Execution)
				}
			})
		}
	}
}

func replyDefaultShellProbe(t *testing.T, interpreter ssh.Interpreter, command string, channel cryptoSSH.Channel) {
	t.Helper()
	output := "syntax error\n"
	status := uint32(127)
	switch {
	case interpreter == ssh.InterpreterZsh && strings.Contains(command, "__XOPS_DIALECT_POSIX__"):
		output, status = "__XOPS_DIALECT_POSIX__:Linux:/usr/bin/zsh\n", 0
	case interpreter == ssh.InterpreterFish && strings.Contains(command, "__XOPS_DIALECT_FISH__"):
		output, status = "__XOPS_DIALECT_FISH__:4.9.3\n__XOPS_FISH_OS__:Linux\n__XOPS_FISH_SHELL__:/usr/bin/fish\n", 0
	case strings.Contains(command, "__XOPS_INTERP__"):
		output, status = "__XOPS_INTERP__:bash\n__XOPS_INTERP__:sh\n__XOPS_INTERP__:zsh\n__XOPS_INTERP__:fish\n__XOPS_INTERP_END__\n", 0
	}
	if _, err := io.WriteString(channel, output); err != nil {
		t.Error(err)
		return
	}
	if _, err := channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{status})); err != nil {
		t.Error(err)
	}
}
