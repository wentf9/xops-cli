package sshexec_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/sshexec"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"go.uber.org/goleak"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type secrets struct{}

func (secrets) ResolveSecret(ctx context.Context, _ ssh.SecretRequest) ([]byte, error) {
	return []byte(sshfixture.Password), ctx.Err()
}

type trust struct{ key cryptoSSH.PublicKey }

func (t trust) Verify(ctx context.Context, _ ssh.HostKeyRequest, key cryptoSSH.PublicKey) error {
	if !bytes.Equal(t.key.Marshal(), key.Marshal()) {
		return errors.New("fixture host key changed")
	}
	return ctx.Err()
}

func setupBackend(t *testing.T) (*sshexec.Backend, ports.OperationSnapshot, *sshfixture.Server, context.Context) {
	return setupBackendWithHandler(t, nil)
}

func setupBackendWithHandler(t *testing.T, handler func(string, cryptoSSH.Channel)) (*sshexec.Backend, ports.OperationSnapshot, *sshfixture.Server, context.Context) {
	t.Helper()
	t.Cleanup(func() { goleak.VerifyNone(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
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
	host, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := sshexec.New(ctx, sshexec.Options{SSH: []ssh.Option{ssh.WithSecretResolver(secrets{}), ssh.WithHostKeyVerifier(trust{server.HostKey})}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := backend.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	view := ports.OperationSnapshot{DomainID: "fixture", Targets: map[string]ports.Target{"node": {Info: ports.NodeInfo{ID: "node"}, Version: "v1", Plan: ssh.ConnectionPlan{Scope: "fixture", Hops: []ssh.ConnectionConfig{{NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", AuthUpdateToken: "v1"}}}}}}
	return backend, view, server, ctx
}

func permit(t *testing.T, ctx context.Context, view ports.OperationSnapshot, phase ports.Phase) ports.Permit {
	t.Helper()
	binding, err := ports.Bind(view, "fixture", "fixture-operation", struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	permission, err := ports.NewPermit(ctx, ports.Admission{OperationID: "operation", Phase: phase, Snapshot: view, Binding: binding}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := permission.Close(); err != nil {
			t.Error(err)
		}
	})
	return permission
}

func TestBackendExecutesOnlyWithBoundPermission(t *testing.T) {
	backend, view, server, ctx := setupBackend(t)
	inspect := permit(t, ctx, view, ports.Inspect)
	if _, err := backend.Run(ctx, inspect, "node", ports.Command{Text: "hostname"}); !errors.Is(err, ports.ErrPurpose) {
		t.Fatal("inspection permit executed a command")
	}
	if _, err := backend.OpenFiles(ctx, inspect, "node"); !errors.Is(err, ports.ErrPurpose) {
		t.Fatal("inspection permit acquired writable SFTP")
	}
	if server.Executed.Load() != 0 {
		t.Fatal("rejected operation reached SSH")
	}
	execute := permit(t, ctx, view, ports.Execute)
	result, err := backend.Run(ctx, execute, "node", ports.Command{Text: "hostname"})
	if err != nil || result.Output != "fixture-output" {
		t.Fatalf("SSH roundtrip: %+v %v", result, err)
	}
	if err := execute.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Run(context.Background(), execute, "node", ports.Command{Text: "hostname"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed permit executed: %v", err)
	}
	if server.Executed.Load() != 1 {
		t.Fatal("cancelled execution reached SSH")
	}
}

func TestBackendStreamsAndCommitsThroughSeparatePermits(t *testing.T) {
	backend, view, _, ctx := setupBackend(t)
	stream := permit(t, ctx, view, ports.TransferStart)
	upload, err := backend.OpenTransfer(ctx, stream, "node")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := upload.Close(); err != nil {
			t.Error(err)
		}
	}()
	result, err := upload.Upload(ctx, "/temporary", strings.NewReader("payload"), 7, nil, nil)
	if err != nil || !result.Created || result.Bytes != 7 {
		t.Fatalf("upload: %+v %v", result, err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := upload.Commit(context.Background(), "/temporary", "/destination", false); !errors.Is(err, ports.ErrPurpose) {
		t.Fatalf("stream permission gained commit capability: %v", err)
	}
	commit := permit(t, ctx, view, ports.Commit)
	remote, err := backend.OpenTransfer(ctx, commit, "node")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := remote.Close(); err != nil {
			t.Error(err)
		}
	}()
	outcome, err := remote.Commit(ctx, "/temporary", "/destination", false)
	if err != nil || !outcome.Committed {
		t.Fatalf("commit: %+v %v", outcome, err)
	}
	if _, err := remote.Upload(ctx, "/other", strings.NewReader("x"), 1, nil, nil); !errors.Is(err, ports.ErrPurpose) {
		t.Fatal("commit permit started another upload")
	}
	downloadPermit := permit(t, ctx, view, ports.TransferStart)
	download, err := backend.OpenTransfer(ctx, downloadPermit, "node")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := download.Close(); err != nil {
			t.Error(err)
		}
	}()
	metadata, err := download.Inspect(ctx, "/destination", false, false)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, err := download.Download(ctx, metadata, &output, nil); err != nil {
		t.Fatal(err)
	}
	if output.String() != "payload" {
		t.Fatalf("download = %q", output.String())
	}
}

func TestBackendExecutionDefaultsAndSudoConfiguration(t *testing.T) {
	no := false
	for _, test := range []struct {
		name          string
		node, request *ssh.ExecutionConfig
		sudo          bool
		mode          ssh.SudoMode
		payload       string
		invalid       bool
	}{
		{name: "legacy command", payload: "bash -l -c 'uptime'"},
		{name: "explicit server", request: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, payload: "uptime"},
		{name: "legacy sudo root", sudo: true, mode: ssh.SudoModeRoot, payload: "bash -l -c 'uptime'"},
		{name: "configured sudo root", node: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &no}, sudo: true, mode: ssh.SudoModeRoot, payload: "bash -c 'uptime'"},
		{name: "configured NOPASSWD", request: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &no}, sudo: true, mode: ssh.SudoModeSudoer, payload: "sudo -S -p '' bash -c 'uptime'"},
		{name: "server escalation rejected", request: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, sudo: true, mode: ssh.SudoModeRoot, invalid: true},
		{name: "unknown Bash launch rejected", request: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchUnknown}, sudo: true, mode: ssh.SudoModeRoot, invalid: true},
		{name: "configured su rejected", request: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &no}, sudo: true, mode: ssh.SudoModeSu, invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			commands := make(chan string, 4)
			backend, view, server, ctx := setupBackendWithHandler(t, func(command string, ch cryptoSSH.Channel) {
				commands <- command
				if _, err := io.WriteString(ch, "fixture-output"); err != nil {
					t.Error(err)
					return
				}
				if _, err := ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0})); err != nil {
					t.Error(err)
				}
			})
			target := view.Targets["node"]
			target.Execution = test.node
			target.Plan.Hops[0].SudoMode = test.mode
			view.Targets["node"] = target
			result, err := backend.Run(ctx, permit(t, ctx, view, ports.Execute), "node", ports.Command{Text: "uptime", Sudo: test.sudo, Execution: test.request})
			if test.invalid {
				if !errors.Is(err, ssh.ErrExecutionValidation) || result.Outcome != ssh.ExecutionNotStarted || server.Executed.Load() != 0 {
					t.Fatalf("invalid execution dispatched: %+v, %v", result, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := <-commands; got != test.payload {
				t.Fatalf("payload %q, want %q", got, test.payload)
			}
			if server.Executed.Load() != 1 {
				t.Fatal("unexpected command or probe")
			}
		})
	}
}

func TestBackendSudoSignalTerminationPreserved(t *testing.T) {
	backend, view, _, ctx := setupBackendWithHandler(t, func(_ string, ch cryptoSSH.Channel) {
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
	})
	target := view.Targets["node"]
	target.Plan.Hops[0].SudoMode = ssh.SudoModeRoot
	view.Targets["node"] = target

	result, err := backend.Run(ctx, permit(t, ctx, view, ports.Execute), "node", ports.Command{
		Text: "sleep 10",
		Sudo: true,
	})
	if err == nil {
		t.Fatal("expected error for signal-terminated sudo command")
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

func TestBackendFilesystemRejectsNonPOSIXDialects(t *testing.T) {
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
			commands := make(chan string, 4)
			backend, view, server, ctx := setupBackendWithHandler(t, func(command string, ch cryptoSSH.Channel) {
				commands <- command
				if _, err := io.WriteString(ch, "ok"); err != nil {
					t.Error(err)
					return
				}
				if _, err := ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0})); err != nil {
					t.Error(err)
				}
			})
			target := view.Targets["node"]
			target.Execution = test.node
			view.Targets["node"] = target
			cmd := test.cmd
			cmd.Execution = test.request
			result, err := backend.Run(ctx, permit(t, ctx, view, ports.Execute), "node", cmd)
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
