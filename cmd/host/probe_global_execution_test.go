package host

import (
	"bytes"
	"context"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/config"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestEnrollmentProbeIgnoresGlobalExecution(t *testing.T) {
	for _, mode := range []string{"add", "import"} {
		for _, dialect := range []ssh.LaunchDialect{ssh.LaunchCmd, ssh.LaunchPOSIX} {
			t.Run(mode+"/"+string(dialect), func(t *testing.T) {
				repo, store := verificationRepository(t)
				global := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}
				explicit := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterPowerShell}
				if dialect == ssh.LaunchPOSIX {
					global = &ssh.ExecutionConfig{Interpreter: ssh.InterpreterPowerShell, LaunchDialect: ssh.LaunchCmd}
					explicit.Interpreter = ssh.InterpreterSh
				}
				cfg := repo.Snapshot()
				cfg.Execution = global.Clone()
				if err := store.Save(cfg); err != nil {
					t.Fatal(err)
				}
				var err error
				repo, err = config.NewRepositoryWithoutOpenSSH(cfg, store)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				server, host, port := globalExecutionProbeServer(t, ctx, dialect)
				var output bytes.Buffer
				if mode == "add" {
					cmd := NewCmdInventoryAdd()
					cmd.SetArgs([]string{"--address", host, "--port", strconv.Itoa(int(port)), "--user", "fixture", "--password-stdin", "--interpreter", string(explicit.Interpreter)})
					cmd.SetIn(strings.NewReader(sshfixture.Password + "\n"))
					cmd.SetContext(ctx)
					cmd.SetOut(&output)
					cmd.SetErr(&output)
					err = cmd.Execute()
				} else {
					err = executeImport(ctx, repo, []utils.HostInfo{{Host: host, Port: port, User: "fixture", Password: sshfixture.Password}}, ImportOptions{Output: &output, Execution: explicit}, verifyInventoryNode)
				}
				if err != nil {
					t.Fatalf("global execution blocked %s probe: %v", mode, err)
				}
				after, err := store.Load()
				if err != nil {
					t.Fatal(err)
				}
				node, saved := after.Nodes.Get(config.FormatNodeID("fixture", host, port))
				if !saved || node.Execution == nil || node.Execution.Interpreter != explicit.Interpreter || node.Execution.LaunchDialect != dialect {
					t.Fatalf("explicit interpreter or detected dialect lost: %+v", node.Execution)
				}
				if !reflect.DeepEqual(after.Execution, global) || explicit.LaunchDialect != "" {
					t.Fatal("probe changed global settings or caller's explicit fields")
				}
				if server.Authenticated.Load() != 1 || server.Executed.Load() != 2 {
					t.Fatal("probe did not reuse the authentication connection")
				}
			})
		}
	}
}

func globalExecutionProbeServer(t *testing.T, ctx context.Context, dialect ssh.LaunchDialect) (*sshfixture.Server, string, uint16) {
	t.Helper()
	options := sshfixture.Options{}
	if dialect == ssh.LaunchCmd {
		options.ServerVersion = "SSH-2.0-OpenSSH_for_Windows_9.5"
	}
	options.ExecHandler = func(command string, channel cryptoSSH.Channel) {
		output := "__XOPS_INTERP__:bash\n__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n"
		if dialect == ssh.LaunchCmd {
			output = "__XOPS_INTERP__:powershell\n__XOPS_INTERP__:cmd\n__XOPS_INTERP_END__\n"
			if strings.HasPrefix(command, "echo __XOPS_DIALECT_CMD__:") {
				output = "__XOPS_DIALECT_CMD__:C:\\Windows\\system32\\cmd.exe\r\n"
			}
		} else if strings.Contains(command, "__XOPS_DIALECT_POSIX__") {
			output = "__XOPS_DIALECT_POSIX__:Linux:/bin/bash\n"
		}
		if _, err := io.WriteString(channel, output); err != nil {
			t.Error(err)
			return
		}
		if _, err := channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0})); err != nil {
			t.Error(err)
		}
	}
	server, err := sshfixture.NewWithOptions(ctx, options)
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
	return server, host, uint16(port)
}
