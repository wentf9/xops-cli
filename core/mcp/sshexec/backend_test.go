package sshexec_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	return setupBackendWithOptions(t, sshfixture.Options{ExecHandler: handler})
}

func setupBackendWithOptions(t *testing.T, options sshfixture.Options) (*sshexec.Backend, ports.OperationSnapshot, *sshfixture.Server, context.Context) {
	t.Helper()
	t.Cleanup(func() { goleak.VerifyNone(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
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
	if _, err := backend.ProbeExecution(ctx, execute, "node"); !errors.Is(err, ports.ErrPurpose) {
		t.Fatalf("execution permit acquired probe authority: %v", err)
	}
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

func TestBackendProbeDefaultShellAndConnectionCache(t *testing.T) {
	for _, interpreter := range []ssh.Interpreter{ssh.InterpreterFish, ssh.InterpreterZsh} {
		t.Run(string(interpreter), func(t *testing.T) {
			backend, view, server, ctx := setupBackendWithHandler(t, func(command string, ch cryptoSSH.Channel) {
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
			})
			for attempt := 0; attempt < 2; attempt++ {
				inspection := permit(t, ctx, view, ports.Inspect)
				before := server.Executed.Load()
				result, err := backend.ProbeExecution(ctx, inspection, "node")
				if err != nil || result.RecommendedInterpreter != interpreter || result.SuggestedConfig.Interpreter != interpreter {
					t.Fatalf("default shell probe: %+v %v", result, err)
				}
				if attempt == 1 && server.Executed.Load() != before {
					t.Fatal("probe cache was not shared across connection leases")
				}
				if err := inspection.Close(); err != nil {
					t.Fatal(err)
				}
			}
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			before := server.Executed.Load()
			if _, err := backend.ProbeExecution(canceled, permit(t, ctx, view, ports.Inspect), "node"); !errors.Is(err, context.Canceled) || server.Executed.Load() != before {
				t.Fatalf("canceled discovery reached SSH: %v", err)
			}
		})
	}
}

func TestBackendProbeRecoversAfterRequestCancellation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var requests atomic.Int32
	backend, view, server, ctx := setupBackendWithHandler(t, func(command string, ch cryptoSSH.Channel) {
		if requests.Add(1) == 1 {
			close(started)
			// Released below, including on test failure, before fixture cleanup.
			select {
			case <-release:
			case <-t.Context().Done():
			}
			return
		}
		output := "fixture-output"
		switch {
		case strings.Contains(command, "__XOPS_DIALECT_POSIX__"):
			output = "__XOPS_DIALECT_POSIX__:Linux:/bin/sh\n"
		case strings.Contains(command, "__XOPS_INTERP_END__"):
			output = "__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n"
		}
		if _, err := io.WriteString(ch, output); err != nil {
			t.Error(err)
		}
		if _, err := ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0})); err != nil {
			t.Error(err)
		}
	})
	request, cancel := context.WithCancel(ctx)
	defer cancel()
	inspection := permit(t, ctx, view, ports.Inspect)
	done := make(chan error, 1)
	// Probe exits on request cancellation; joined before releasing the server.
	go func() { _, err := backend.ProbeExecution(request, inspection, "node"); done <- err }()
	select {
	case <-started:
	case <-ctx.Done():
		cancel()
		<-done
		t.Fatal(ctx.Err())
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("first request: %v", err)
	}
	releaseOnce.Do(func() { close(release) })
	if err := inspection.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := backend.ProbeExecution(ctx, permit(t, ctx, view, ports.Inspect), "node")
	if err != nil || result.RecommendedInterpreter != ssh.InterpreterSh {
		t.Fatalf("fresh request reused canceled result: %+v %v", result, err)
	}
	if server.Authenticated.Load() != 1 || server.Executed.Load() != 3 {
		t.Fatalf("recovery did not reuse healthy transport: auth=%d exec=%d", server.Authenticated.Load(), server.Executed.Load())
	}
	commandResult, err := backend.Run(ctx, permit(t, ctx, view, ports.Execute), "node", ports.Command{Text: "uptime", Execution: result.SuggestedConfig.Clone()})
	if err != nil || commandResult.Output != "fixture-output" || server.Executed.Load() != 4 {
		t.Fatalf("execution after recovery: %+v %v", commandResult, err)
	}
}

func TestBackendNativeFishAndZshNOPASSWD(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires native Unix shells")
	}
	for _, interpreter := range []ssh.Interpreter{ssh.InterpreterFish, ssh.InterpreterZsh} {
		t.Run(string(interpreter), func(t *testing.T) {
			shell, err := exec.LookPath(string(interpreter))
			if err != nil {
				t.Skipf("shell unavailable: %v", err)
			}
			directory := t.TempDir()
			// Test-only sudo forwards argv without changing credentials. Native
			// shell/control-frame behavior runs normally over the SSH channel.
			forwarder := "#!/bin/sh\n[ \"$1\" = -n ] && [ \"$2\" = -S ] && [ \"$3\" = -p ] && [ \"$5\" = -- ] || exit 93\nshift 5\nexec \"$@\"\n"
			if err := os.WriteFile(filepath.Join(directory, "sudo"), []byte(forwarder), 0700); err != nil {
				t.Fatal(err)
			}
			backend, view, _, ctx := setupBackendWithHandler(t, func(payload string, ch cryptoSSH.Channel) {
				work, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				command := exec.CommandContext(work, shell, "-c", payload)
				command.WaitDelay = time.Second
				command.Env = append(os.Environ(), "PATH="+directory+string(os.PathListSeparator)+os.Getenv("PATH"), "HOME="+directory, "ZDOTDIR="+directory, "XDG_CONFIG_HOME="+directory)
				command.Stdin, command.Stdout, command.Stderr = ch, ch, ch.Stderr()
				status := uint32(0)
				if err := command.Run(); err != nil {
					var exit *exec.ExitError
					if errors.As(err, &exit) && exit.ExitCode() >= 0 {
						status = uint32(exit.ExitCode())
					} else {
						t.Errorf("native privilege fixture: %v", err)
						status = 1
					}
				}
				if _, err := ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{status})); err != nil {
					t.Error(err)
				}
			})
			dialect, text := ssh.LaunchPOSIX, "values=(first second); print -rn -- $values[2]"
			if interpreter == ssh.InterpreterFish {
				dialect, text = ssh.LaunchFish, "set -l values first second; printf '%s' $values[2]"
			}
			login := false
			target := view.Targets["node"]
			target.Execution = &ssh.ExecutionConfig{Interpreter: interpreter, LaunchDialect: dialect, Login: &login}
			target.Plan.Hops[0].SudoMode = ssh.SudoModeSudoer
			view.Targets["node"] = target
			result, err := backend.Run(ctx, permit(t, ctx, view, ports.Execute), "node", ports.Command{Text: text, Sudo: true})
			if err != nil || result.Output != "second" || result.Outcome != ssh.ExecutionCompleted {
				t.Fatalf("native %s sudo: %+v %v", interpreter, result, err)
			}
		})
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
	yes, no := true, false
	for _, test := range []struct {
		name          string
		node, request *ssh.ExecutionConfig
		sudo          bool
		mode          ssh.SudoMode
		payload       string
		invalid       bool
	}{
		{name: "unconfigured command defaults to server", payload: "uptime"},
		{name: "configured bash command", node: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &yes}, payload: "bash -l -c 'uptime'"},
		{name: "explicit server", request: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, payload: "uptime"},
		{name: "configured fish", node: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish, Login: &no}, payload: "fish -c 'uptime'"},
		{name: "configured zsh", node: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterZsh, LaunchDialect: ssh.LaunchPOSIX, Login: &no}, payload: "zsh -c 'uptime'"},
		{name: "fish sudo override", node: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}, request: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish, Login: &no}, sudo: true, mode: ssh.SudoModeRoot, payload: "fish -c 'uptime'"},
		{name: "zsh sudo override", request: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterZsh, LaunchDialect: ssh.LaunchPOSIX, Login: &no}, sudo: true, mode: ssh.SudoModeRoot, payload: "zsh -c 'uptime'"},
		{name: "legacy sudo root", sudo: true, mode: ssh.SudoModeRoot, payload: "bash -l -c 'uptime'"},
		{name: "configured sudo root", node: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &no}, sudo: true, mode: ssh.SudoModeRoot, payload: "bash -c 'uptime'"},
		{name: "configured NOPASSWD", request: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &no}, sudo: true, mode: ssh.SudoModeSudoer, payload: "sudo -S -p '' bash -c 'uptime'"},
		{name: "server escalation rejected", request: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, sudo: true, mode: ssh.SudoModeRoot, invalid: true},
		{name: "unknown Bash launch rejected", request: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchUnknown}, sudo: true, mode: ssh.SudoModeRoot, invalid: true},
		{name: "configured su rejected", request: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &no}, sudo: true, mode: ssh.SudoModeSu, invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			commands := make(chan string, 8)
			backend, view, server, ctx := setupBackendWithHandler(t, func(command string, ch cryptoSSH.Channel) {
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
			wantExecuted := int32(1)
			if test.name == "legacy sudo root" {
				wantExecuted = 3 // 2 probe commands (dialect + interp) + 1 user command
			}
			if server.Executed.Load() != wantExecuted {
				t.Fatalf("unexpected command or probe: executed %d, want %d", server.Executed.Load(), wantExecuted)
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

func TestOpenPTYConcurrentWriteAndSignalOverSSHChannel(t *testing.T) {
	backend, view, _, ctx := setupBackend(t)
	pty, err := backend.OpenPTY(ctx, permit(t, ctx, view, ports.Execute), "node")
	if err != nil {
		t.Fatalf("OpenPTY failed: %v", err)
	}
	defer func() {
		if err := pty.Close(); err != nil {
			t.Errorf("pty.Close failed: %v", err)
		}
	}()

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = io.Copy(io.Discard, pty)
	}()

	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			for range 16 {
				if _, err := pty.Write([]byte("echo hi\n")); err != nil {
					t.Errorf("pty.Write failed: %v", err)
					return
				}
			}
		})
		wg.Go(func() {
			for range 16 {
				if err := pty.Signal("INT"); err != nil {
					t.Errorf("pty.Signal(INT) failed: %v", err)
					return
				}
			}
		})
	}
	wg.Wait()
	var closeWg sync.WaitGroup
	stopWriters := make(chan struct{})
	for range 2 {
		closeWg.Go(func() {
			for {
				select {
				case <-stopWriters:
					return
				default:
					_, _ = pty.Write([]byte("echo hi\n"))
				}
			}
		})
		closeWg.Go(func() {
			for {
				select {
				case <-stopWriters:
					return
				default:
					_ = pty.Signal("INT")
				}
			}
		})
	}
	time.Sleep(10 * time.Millisecond)
	if err := pty.Close(); err != nil {
		t.Fatalf("pty.Close failed: %v", err)
	}
	close(stopWriters)
	closeWg.Wait()
	<-readDone
}

func TestOpenPTYCloseUnblocksStalledWindowWrite(t *testing.T) {
	shellStall := make(chan struct{})
	firstByteReceived := make(chan struct{})
	backend, view, _, ctx := setupBackendWithOptions(t, sshfixture.Options{
		ShellHandler: func(ch cryptoSSH.Channel, requests <-chan *cryptoSSH.Request) {
			go cryptoSSH.DiscardRequests(requests)
			var one [1]byte
			if _, err := io.ReadFull(ch, one[:]); err == nil {
				close(firstByteReceived)
			}
			// Stop reading after the first byte so the client's SSH channel send
			// window (initial 2 MiB) fills up and pty.Write blocks inside
			// WriteExtended while holding p.writeMu.
			<-shellStall
		},
	})
	defer close(shellStall)

	pty, err := backend.OpenPTY(ctx, permit(t, ctx, view, ports.Execute), "node")
	if err != nil {
		t.Fatalf("OpenPTY failed: %v", err)
	}

	writeDone := make(chan error, 1)
	chunk := bytes.Repeat([]byte("A"), 4*1024*1024)
	go func() {
		_, err := pty.Write(chunk)
		writeDone <- err
	}()
	select {
	case <-firstByteReceived:
	case err := <-writeDone:
		t.Fatalf("write finished before server received channel data: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for pty.Write to send channel data")
	}
	// Give pty.Write a brief moment after the first packet arrives to exhaust the
	// remaining 2 MiB SSH channel window and stall inside WriteExtended.
	time.Sleep(10 * time.Millisecond)
	select {
	case err := <-writeDone:
		t.Fatalf("write finished before window stall: %v", err)
	default:
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- pty.Close()
	}()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("pty.Close failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pty.Close deadlocked when pty.Write was blocked on SSH channel window flow control")
	}

	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("expected blocked 4 MiB pty.Write to fail when pty.Close closed the SSH session")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked pty.Write did not unblock after pty.Close")
	}
}

func TestBackendExecutionFreeBSDSudoAutoProbe(t *testing.T) {
	commands := make(chan string, 8)
	backend, view, server, ctx := setupBackendWithHandler(t, func(command string, ch cryptoSSH.Channel) {
		if strings.Contains(command, "__XOPS_DIALECT_POSIX__") {
			_, _ = io.WriteString(ch, "__XOPS_DIALECT_POSIX__:FreeBSD:/bin/sh\n")
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
			return
		}
		if strings.Contains(command, "__XOPS_INTERP__") {
			_, _ = io.WriteString(ch, "__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n")
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
			return
		}
		if strings.Contains(command, "bash") {
			_, _ = io.WriteString(ch.Stderr(), "exec: bash: not found\n")
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{127}))
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
	})
	target := view.Targets["node"]
	target.Execution = nil
	target.Plan.Hops[0].SudoMode = ssh.SudoModeRoot
	view.Targets["node"] = target
	result, err := backend.Run(ctx, permit(t, ctx, view, ports.Execute), "node", ports.Command{Text: "uptime", Sudo: true})
	if err != nil {
		t.Fatalf("backend.Run failed: %v", err)
	}
	if result.Outcome != ssh.ExecutionCompleted {
		t.Fatalf("expected ExecutionCompleted, got %v", result.Outcome)
	}
	got := <-commands
	if got != "sh -c 'uptime'" {
		t.Fatalf("payload %q, want %q", got, "sh -c 'uptime'")
	}
	if server.Executed.Load() != 3 {
		t.Fatalf("executed %d, want 3 (2 probes + 1 command)", server.Executed.Load())
	}
}
