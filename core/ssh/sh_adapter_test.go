package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestShAdapter_PlanCommand(t *testing.T) {
	t.Run("sh command with posix dialect", func(t *testing.T) {
		plan, err := PlanCommand("echo 'hello'", CommandOptions{
			Interpreter:   InterpreterSh,
			LaunchDialect: LaunchPOSIX,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if plan.Payload() != "sh -c 'echo '\\''hello'\\'''" {
			t.Errorf("unexpected payload: %s", plan.Payload())
		}
		if plan.LoginMode() != LoginDisabled {
			t.Errorf("expected login disabled, got %v", plan.LoginMode())
		}
	})

	t.Run("sh command rejects login shell", func(t *testing.T) {
		_, err := PlanCommand("echo hi", CommandOptions{
			Interpreter:   InterpreterSh,
			LaunchDialect: LaunchPOSIX,
			Login:         LoginEnabled,
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("sh command rejects non-posix dialect", func(t *testing.T) {
		_, err := PlanCommand("echo hi", CommandOptions{
			Interpreter:   InterpreterSh,
			LaunchDialect: LaunchCmd,
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestShAdapter_BOMRejectionInRunScript(t *testing.T) {
	bomContent := "\xef\xbb\xbf#!/bin/sh\necho hi\n"
	client := &Client{}

	_, err := client.RunScript(context.Background(), bomContent)
	if err == nil {
		t.Fatal("expected BOM error in RunScript, got nil")
	}
	if !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected ErrExecutionValidation, got: %v", err)
	}

	_, err = client.RunScriptWithExecution(context.Background(), bomContent, nil)
	if err == nil {
		t.Fatal("expected BOM error in RunScriptWithExecution, got nil")
	}
	if !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected ErrExecutionValidation, got: %v", err)
	}

	_, err = client.RunScriptWithSudo(context.Background(), bomContent)
	if err == nil {
		t.Fatal("expected BOM error in RunScriptWithSudo, got nil")
	}
	if !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected ErrExecutionValidation, got: %v", err)
	}

	_, err = client.RunScriptWithSudoExecution(context.Background(), bomContent, nil)
	if err == nil {
		t.Fatal("expected BOM error in RunScriptWithSudoExecution, got nil")
	}
	if !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected ErrExecutionValidation, got: %v", err)
	}
}

func TestMaybeDetectSudoMode_SkipsOnNonPOSIX(t *testing.T) {
	cfg := &ClientConfig{
		Execution: &ExecutionConfig{
			Interpreter:   InterpreterCmd,
			LaunchDialect: LaunchCmd,
		},
	}
	client := newClient(nil, nil, cfg, nil, "")

	// Without connection, maybeDetectSudoMode would normally return "ssh client is not connected"
	// if it tried to probe, but for non-POSIX configs it returns nil immediately without probing.
	err := client.maybeDetectSudoMode(context.Background())
	if err != nil {
		t.Fatalf("expected nil for non-POSIX config, got: %v", err)
	}
}

type dummyWriteCloser struct {
	closed bool
}

func (d *dummyWriteCloser) Write(p []byte) (n int, err error) { return len(p), nil }
func (d *dummyWriteCloser) Close() error                      { d.closed = true; return nil }

func TestSetupStdinPipeline_RejectsConflictingScriptAndRuntimeStdin(t *testing.T) {
	pipe := &dummyWriteCloser{}
	stdin := strings.NewReader("runtime-stdin")
	initialPayload := "echo script\n"

	_, err := setupStdinPipeline(stdin, pipe, initialPayload)
	if err == nil {
		t.Fatal("expected error when both initialPayload and stdin are provided, got nil")
	}
	if !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected ErrExecutionValidation, got: %v", err)
	}
	if !pipe.closed {
		t.Error("expected pipe to be closed on conflict error")
	}
}

func TestLegacyRunAPIs_RejectUnsupportedInterpreters(t *testing.T) {
	connCfg := ConnectionConfig{
		Execution: &ExecutionConfig{
			Interpreter:   InterpreterPowerShell,
			LaunchDialect: LaunchCmd,
		},
	}
	client := NewTestClient(connCfg)
	ctx := context.Background()

	// 1. Run rejects non-bash/sh interpreter
	if _, err := client.Run(ctx, "Get-Date"); err == nil || !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected Run to reject InterpreterPowerShell with ErrExecutionValidation, got: %v", err)
	}

	// 2. RunScript rejects non-bash/sh interpreter
	if _, err := client.RunScript(ctx, "Get-Date"); err == nil || !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected RunScript to reject InterpreterPowerShell with ErrExecutionValidation, got: %v", err)
	}

	// 3. RunScriptWithExecution rejects non-bash/sh interpreter
	psExec := &ExecutionConfig{Interpreter: InterpreterPowerShell, LaunchDialect: LaunchCmd}
	if _, err := client.RunScriptWithExecution(ctx, "Get-Date", psExec); err == nil || !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected RunScriptWithExecution to reject InterpreterPowerShell with ErrExecutionValidation, got: %v", err)
	}

	// 4. RunWithSudo rejects non-bash/sh interpreter
	if _, err := client.RunWithSudo(ctx, "Get-Date"); err == nil || !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected RunWithSudo to reject InterpreterPowerShell with ErrExecutionValidation, got: %v", err)
	}

	// 5. RunScriptWithSudo rejects non-bash/sh interpreter
	if _, err := client.RunScriptWithSudo(ctx, "Get-Date"); err == nil || !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected RunScriptWithSudo to reject InterpreterPowerShell with ErrExecutionValidation, got: %v", err)
	}

	// 6. RunCommandWithIO rejects non-bash/sh interpreter
	if err := client.RunCommandWithIO(ctx, "Get-Date", false, nil, nil, nil); err == nil || !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected RunCommandWithIO to reject InterpreterPowerShell with ErrExecutionValidation, got: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Hermetic Mock SSH Server for FreeBSD Regression Testing (No bash installed)
// -----------------------------------------------------------------------------

type freebsdMockServer struct {
	listener   net.Listener
	rawClient  *cryptoSSH.Client
	recordedCh chan mockExecRecord
	isRoot     atomic.Bool
	isSudoer   atomic.Bool
	allowBash  atomic.Bool
}

func (s *freebsdMockServer) newClient(cfg *ClientConfig) *Client {
	return newClient(s.rawClient, nil, cfg, nil, "")
}

func (s *freebsdMockServer) drainRecord(t *testing.T) mockExecRecord {
	t.Helper()
	select {
	case rec := <-s.recordedCh:
		return rec
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for mock command execution record")
		return mockExecRecord{}
	}
}

func startFreeBSDMockSSHServer(t *testing.T) *freebsdMockServer {
	t.Helper()
	listener, serverConfig := startKeepAliveTestSSHServer(t)
	recordedCh := make(chan mockExecRecord, 50)
	server := &freebsdMockServer{
		listener:   listener,
		recordedCh: recordedCh,
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sConn, chans, reqs, err := cryptoSSH.NewServerConn(c, serverConfig)
				if err != nil {
					_ = c.Close()
					return
				}
				defer func() { _ = sConn.Close() }()
				go cryptoSSH.DiscardRequests(reqs)

				for newChannel := range chans {
					if newChannel.ChannelType() != "session" {
						_ = newChannel.Reject(cryptoSSH.UnknownChannelType, "unknown channel type")
						continue
					}
					channel, requests, err := newChannel.Accept()
					if err != nil {
						return
					}
					go handleFreeBSDMockSession(channel, requests, recordedCh, &server.isRoot, &server.isSudoer, &server.allowBash)
				}
			}(conn)
		}
	}()

	rawClient := dialKeepAliveTestClient(t, listener.Addr().String())
	server.rawClient = rawClient

	t.Cleanup(func() {
		_ = rawClient.Close()
		_ = listener.Close()
	})

	return server
}

//nolint:gocyclo // FreeBSD mock session handler handles probe queries, root/sudoer detection, and privilege exchange.
func handleFreeBSDMockSession(channel cryptoSSH.Channel, requests <-chan *cryptoSSH.Request, recordedCh chan<- mockExecRecord, isRoot, isSudoer, allowBash *atomic.Bool) {
	defer func() { _ = channel.Close() }()

	for req := range requests {
		if req.Type == "pty-req" {
			_ = req.Reply(true, nil)
			continue
		}
		if req.Type == "exec" {
			var rec mockExecRecord
			if len(req.Payload) >= 4 {
				cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
				if len(req.Payload) >= 4+cmdLen {
					rec.cmd = string(req.Payload[4 : 4+cmdLen])
				}
			}
			_ = req.Reply(true, nil)

			// 1. Dialect Probe response (POSIX FreeBSD)
			if strings.Contains(rec.cmd, "__XOPS_DIALECT_POSIX__") {
				if recordedCh != nil {
					recordedCh <- rec
				}
				_, _ = io.WriteString(channel, "__XOPS_DIALECT_POSIX__:FreeBSD:/bin/sh\n")
				_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				return
			}

			// 2. Interpreter Probe response (only sh available, no bash)
			if strings.Contains(rec.cmd, "__XOPS_INTERP__") {
				if recordedCh != nil {
					recordedCh <- rec
				}
				_, _ = io.WriteString(channel, "__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n")
				_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				return
			}

			// 3. FreeBSD Base System: bash does NOT exist -> return exit status 127
			if (allowBash == nil || !allowBash.Load()) && strings.Contains(rec.cmd, "bash") {
				_, _ = io.WriteString(channel.Stderr(), "exec: bash: not found\n")
				_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 127})
				if recordedCh != nil {
					recordedCh <- rec
				}
				return
			}

			// 4. Auto Root detection probe: id -u
			if rec.cmd == "sh -c 'id -u'" || rec.cmd == "bash -c 'id -u'" || rec.cmd == "id -u" {
				if recordedCh != nil {
					recordedCh <- rec
				}
				if isRoot != nil && isRoot.Load() {
					_, _ = io.WriteString(channel, "0\n")
					_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				} else {
					_, _ = io.WriteString(channel, "1001\n")
					_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				}
				return
			}

			// 5. Auto Passwordless sudo probe: sudo -n true
			if rec.cmd == "sh -c 'sudo -n true'" || rec.cmd == "bash -c 'sudo -n true'" || rec.cmd == "sudo -n true" {
				if recordedCh != nil {
					recordedCh <- rec
				}
				if isSudoer != nil && isSudoer.Load() {
					_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				} else {
					_, _ = io.WriteString(channel.Stderr(), "sudo: a password is required\n")
					_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
				}
				return
			}

			// 6. Gated privilege authentication or standard execution
			type readResult struct {
				text string
				err  error
			}
			readDone := make(chan readResult, 1)
			go func() {
				text, err := readMockPrivilegeInput(channel, rec.cmd)
				readDone <- readResult{text, err}
			}()

			var result readResult
			select {
			case result = <-readDone:
			case <-time.After(2 * time.Second):
				closeErr := channel.Close()
				result = <-readDone
				if closeErr != nil && !errors.Is(closeErr, io.EOF) {
					result.err = errors.Join(result.err, closeErr)
				}
			}
			rec.stdin, rec.stdinEOF = result.text, result.err == nil
			if recordedCh != nil {
				recordedCh <- rec
			}

			_, _ = io.WriteString(channel, "mock_freebsd_output\n")
			_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
			return
		}
		_ = req.Reply(false, nil)
	}
}

//nolint:gocyclo // Subtests comprehensively verify all FreeBSD privilege modes in one mock-server lifecycle.
func TestRunCommandWithIO_FreeBSDMock(t *testing.T) {
	mock := startFreeBSDMockSSHServer(t)
	ctx := t.Context()

	// 1. Regression Verification: Calling bash MUST fail with exit 127
	t.Run("BashMissingReturns127", func(t *testing.T) {
		c := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeNone,
			Execution: &ExecutionConfig{Interpreter: InterpreterBash},
		})
		var stdout, stderr bytes.Buffer
		err := c.RunCommandWithIO(ctx, "ls", false, nil, &stdout, &stderr)
		if err == nil {
			t.Fatal("expected error when bash is missing on FreeBSD mock, got nil")
		}
		if !strings.Contains(stderr.String(), "exec: bash: not found") {
			t.Errorf("expected 'exec: bash: not found' in stderr, got: %q", stderr.String())
		}
		rec := mock.drainRecord(t)
		if !strings.Contains(rec.cmd, "bash") {
			t.Errorf("expected executed command to contain bash, got: %q", rec.cmd)
		}
	})

	// 2. Mode: SudoModeAuto -> Root detected (id -u returns 0)
	t.Run("Auto_Root", func(t *testing.T) {
		mock.isRoot.Store(true)
		mock.isSudoer.Store(false)

		c := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeAuto,
			Execution: &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX},
		})
		var stdout, stderr bytes.Buffer
		err := c.RunCommandWithIO(ctx, "whoami", true, nil, &stdout, &stderr)
		if err != nil {
			t.Fatalf("RunCommandWithIO Auto_Root failed: %v", err)
		}
		if stdout.String() != "mock_freebsd_output\n" {
			t.Errorf("expected stdout 'mock_freebsd_output\\n', got %q", stdout.String())
		}

		// First command is id -u probe
		recProbe := mock.drainRecord(t)
		if !strings.Contains(recProbe.cmd, "id -u") || strings.Contains(recProbe.cmd, "bash") {
			t.Errorf("expected sh id -u probe without bash, got: %q", recProbe.cmd)
		}

		// Second command is elevated command
		recCmd := mock.drainRecord(t)
		if !strings.Contains(recCmd.cmd, "sh -c 'whoami'") || strings.Contains(recCmd.cmd, "bash") {
			t.Errorf("expected sh -c 'whoami' without bash, got: %q", recCmd.cmd)
		}
	})

	// 3. Mode: SudoModeAuto -> Passwordless Sudoer detected (id -u != 0, sudo -n true == 0)
	t.Run("Auto_Sudoer", func(t *testing.T) {
		mock.isRoot.Store(false)
		mock.isSudoer.Store(true)

		c := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeAuto,
			Execution: &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX},
		})
		var stdout, stderr bytes.Buffer
		err := c.RunCommandWithIO(ctx, "whoami", true, nil, &stdout, &stderr)
		if err != nil {
			t.Fatalf("RunCommandWithIO Auto_Sudoer failed: %v", err)
		}

		// Probe 1: id -u
		recID := mock.drainRecord(t)
		if !strings.Contains(recID.cmd, "id -u") || strings.Contains(recID.cmd, "bash") {
			t.Errorf("expected sh id -u probe, got: %q", recID.cmd)
		}

		// Probe 2: sudo -n true
		recSudo := mock.drainRecord(t)
		if !strings.Contains(recSudo.cmd, "sudo -n true") || strings.Contains(recSudo.cmd, "bash") {
			t.Errorf("expected sh sudo -n true probe, got: %q", recSudo.cmd)
		}

		// Executed command
		recCmd := mock.drainRecord(t)
		if !strings.Contains(recCmd.cmd, "sudo -S -p '' sh -c 'whoami'") || strings.Contains(recCmd.cmd, "bash") {
			t.Errorf("expected sudo -S -p '' sh -c 'whoami', got: %q", recCmd.cmd)
		}
	})

	// 4. Mode: SudoModeAuto -> Su fallback (id -u != 0, sudo -n true != 0)
	t.Run("Auto_SuFallback", func(t *testing.T) {
		mock.isRoot.Store(false)
		mock.isSudoer.Store(false)

		c := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeAuto,
			SuPwd:     "root_secret",
			Execution: &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX},
		})
		var stdout, stderr bytes.Buffer
		err := c.RunCommandWithIO(ctx, "whoami", true, nil, &stdout, &stderr)
		if err != nil {
			t.Fatalf("RunCommandWithIO Auto_SuFallback failed: %v", err)
		}

		// Probe 1: id -u
		_ = mock.drainRecord(t)
		// Probe 2: sudo -n true
		_ = mock.drainRecord(t)

		// Executed command in Su mode: must NOT contain bash!
		recCmd := mock.drainRecord(t)
		if strings.Contains(recCmd.cmd, "bash") {
			t.Errorf("expected no bash in Su fallback command, got: %q", recCmd.cmd)
		}
		if !strings.Contains(recCmd.cmd, "su - root -c ") || !strings.Contains(recCmd.cmd, "exec sh -c ") {
			t.Errorf("expected su - root -c with exec sh -c, got: %q", recCmd.cmd)
		}
		if !strings.HasPrefix(recCmd.stdin, "root_secret\n") {
			t.Errorf("expected stdin to contain su password, got: %q", recCmd.stdin)
		}
	})

	// 5. Mode: Explicit SudoModeRoot with InterpreterSh
	t.Run("Explicit_Root", func(t *testing.T) {
		c := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeRoot,
			Execution: &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX},
		})
		var stdout, stderr bytes.Buffer
		err := c.RunCommandWithIO(ctx, "ls /root", true, nil, &stdout, &stderr)
		if err != nil {
			t.Fatalf("RunCommandWithIO Root failed: %v", err)
		}
		rec := mock.drainRecord(t)
		if rec.cmd != "sh -c 'ls /root'" {
			t.Errorf("expected 'sh -c '\\''ls /root'\\'\\'', got: %q", rec.cmd)
		}
	})

	// 6. Mode: Explicit SudoModeSudoer with InterpreterSh
	t.Run("Explicit_Sudoer", func(t *testing.T) {
		c := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeSudoer,
			Execution: &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX},
		})
		var stdout, stderr bytes.Buffer
		err := c.RunCommandWithIO(ctx, "ls /root", true, nil, &stdout, &stderr)
		if err != nil {
			t.Fatalf("RunCommandWithIO Sudoer failed: %v", err)
		}
		rec := mock.drainRecord(t)
		if rec.cmd != "sudo -S -p '' sh -c 'ls /root'" {
			t.Errorf("expected 'sudo -S -p '\\'''\\'' sh -c '\\''ls /root'\\'\\'', got: %q", rec.cmd)
		}
	})

	// 7. Mode: Explicit SudoModeSudo with InterpreterSh (Password prompt exchange)
	t.Run("Explicit_Sudo", func(t *testing.T) {
		c := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeSudo,
			Password:  "sudo_secret",
			Execution: &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX},
		})
		var stdout, stderr bytes.Buffer
		err := c.RunCommandWithIO(ctx, "ls /root", true, nil, &stdout, &stderr)
		if err != nil {
			t.Fatalf("RunCommandWithIO Sudo failed: %v", err)
		}
		rec := mock.drainRecord(t)
		if strings.Contains(rec.cmd, "bash") {
			t.Errorf("expected no bash in Sudo command, got: %q", rec.cmd)
		}
		if !strings.Contains(rec.cmd, "sudo -S -p ") || !strings.Contains(rec.cmd, "-- sh -c ") {
			t.Errorf("expected sudo -S -p with -- sh -c, got: %q", rec.cmd)
		}
		if !strings.HasPrefix(rec.stdin, "sudo_secret\n") {
			t.Errorf("expected sudo password in stdin, got: %q", rec.stdin)
		}
	})

	// 8. Mode: Explicit SudoModeSu with InterpreterSh (Su password prompt exchange)
	t.Run("Explicit_Su", func(t *testing.T) {
		c := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeSu,
			SuPwd:     "root_secret",
			Execution: &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX},
		})
		var stdout, stderr bytes.Buffer
		err := c.RunCommandWithIO(ctx, "cat /etc/shadow", true, strings.NewReader("extra_input\n"), &stdout, &stderr)
		if err != nil {
			t.Fatalf("RunCommandWithIO Su failed: %v", err)
		}
		rec := mock.drainRecord(t)
		if strings.Contains(rec.cmd, "bash") {
			t.Errorf("expected no bash in Su command, got: %q", rec.cmd)
		}
		if !strings.Contains(rec.cmd, "su - root -c ") || !strings.Contains(rec.cmd, "exec sh -c ") {
			t.Errorf("expected su - root -c with exec sh -c, got: %q", rec.cmd)
		}
		expectedStdin := "root_secret\nextra_input\n"
		if rec.stdin != expectedStdin {
			t.Errorf("expected stdin strictly %q, got: %q", expectedStdin, rec.stdin)
		}
	})

	// 9. Unconfigured Node Auto-Probe Path (Execution == nil) resolving InterpreterSh
	t.Run("UnconfiguredNode_AutoProbe", func(t *testing.T) {
		mock.isRoot.Store(true)
		mock.isSudoer.Store(false)

		// Execution is nil -> unconfigured node needing execution probe
		c := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeAuto,
			Execution: nil,
		})
		var stdout, stderr bytes.Buffer
		err := c.RunCommandWithIO(ctx, "ls /var/log", true, nil, &stdout, &stderr)
		if err != nil {
			t.Fatalf("RunCommandWithIO unconfigured node failed: %v", err)
		}
		if stdout.String() != "mock_freebsd_output\n" {
			t.Errorf("expected output, got: %q", stdout.String())
		}

		// Verify c.Execution() remains nil (read-only contract) while probe cache holds InterpreterSh
		if c.Execution() != nil {
			t.Fatalf("expected c.Execution() to remain nil after privilege auto-probe, got: %+v", c.Execution())
		}
		cached, ok := c.CachedExecutionProbe()
		if !ok || cached == nil || cached.SuggestedConfig.Interpreter != InterpreterSh {
			t.Fatalf("expected execution probe to be cached as InterpreterSh, got: %+v (ok=%v)", cached, ok)
		}

		// Drain dialect probe
		recDialect := mock.drainRecord(t)
		if !strings.Contains(recDialect.cmd, "__XOPS_DIALECT_POSIX__") {
			t.Errorf("expected dialect probe, got: %q", recDialect.cmd)
		}

		// Drain interpreter probe
		recInterp := mock.drainRecord(t)
		if !strings.Contains(recInterp.cmd, "__XOPS_INTERP__") {
			t.Errorf("expected interpreter probe, got: %q", recInterp.cmd)
		}

		// Drain id -u probe
		recID := mock.drainRecord(t)
		if !strings.Contains(recID.cmd, "id -u") || strings.Contains(recID.cmd, "bash") {
			t.Errorf("expected sh id -u probe without bash, got: %q", recID.cmd)
		}

		// Drain command execution
		recCmd := mock.drainRecord(t)
		if !strings.Contains(recCmd.cmd, "sh -c 'ls /var/log'") || strings.Contains(recCmd.cmd, "bash") {
			t.Errorf("expected sh -c 'ls /var/log' without bash, got: %q", recCmd.cmd)
		}
	})

	// 10. RunWithSudo API with InterpreterSh
	t.Run("RunWithSudo_InterpreterSh", func(t *testing.T) {
		mock.isRoot.Store(false)
		mock.isSudoer.Store(true)

		c := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeSudoer,
			Execution: &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX},
		})
		out, err := c.RunWithSudo(ctx, "uname -s")
		if err != nil {
			t.Fatalf("RunWithSudo failed: %v", err)
		}
		if !strings.Contains(out, "mock_freebsd_output") {
			t.Errorf("expected output, got: %q", out)
		}
		rec := mock.drainRecord(t)
		if strings.Contains(rec.cmd, "bash") {
			t.Errorf("expected no bash in RunWithSudo, got: %q", rec.cmd)
		}
	})

	// 11. configuredSudoOptions allows InterpreterSh under SudoModeSu
	t.Run("ConfiguredSudoOptions_InterpreterSh_Su", func(t *testing.T) {
		c := mock.newClient(&ClientConfig{
			SudoMode: SudoModeSu,
			SuPwd:    "root_secret",
		})
		opts, err := c.configuredSudoOptions(ctx, "ls", &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX})
		if err != nil {
			t.Fatalf("expected configuredSudoOptions to permit InterpreterSh under SudoModeSu, got: %v", err)
		}
		if opts == nil {
			t.Fatal("expected non-nil run options")
		}
	})

	// 12. [P0 Issue 1] Stream and File output modes in RunWithSudo / RunScriptWithSudo
	// must NOT leak internal root/sudoer probe outputs or break root detection.
	t.Run("StreamOutput_DoesNotBreakRootProbeOrLeakProbeOutput", func(t *testing.T) {
		mock.isRoot.Store(true)
		mock.isSudoer.Store(false)

		c := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeAuto,
			Execution: &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX},
		})
		var streamBuf bytes.Buffer
		out, err := c.RunWithSudo(ctx, "whoami", WithStream(&streamBuf, "[bsd] "))
		if err != nil {
			t.Fatalf("RunWithSudo with WithStream failed: %v", err)
		}
		if out != "" {
			t.Errorf("expected empty returned string in stream mode, got: %q", out)
		}
		// Must detect root on the first probe (id -u) and then run the command once;
		// the stream buffer must ONLY contain the user command output, NOT "0\n" from id -u!
		if c.ConnectionConfig().SudoMode != SudoModeRoot {
			t.Errorf("expected SudoModeRoot to be detected in stream mode, got: %q", c.ConnectionConfig().SudoMode)
		}
		if streamBuf.String() != "[bsd] mock_freebsd_output\n" {
			t.Errorf("stream output polluted or unexpected: got %q, want %q", streamBuf.String(), "[bsd] mock_freebsd_output\n")
		}

		// Drain id -u probe and command execution
		recID := mock.drainRecord(t)
		if !strings.Contains(recID.cmd, "id -u") {
			t.Errorf("expected id -u probe, got: %q", recID.cmd)
		}
		recCmd := mock.drainRecord(t)
		if recCmd.cmd != "sh -c 'whoami'" {
			t.Errorf("expected sh -c 'whoami', got: %q", recCmd.cmd)
		}

		// Also verify WithOutFile (OutputModeFile) in RunScriptWithSudo does not break root detection or leak probe output
		cFile := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeAuto,
			Execution: &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX},
		})
		outFilePath := filepath.Join(t.TempDir(), "bsd.log")
		outFile, err := os.Create(outFilePath)
		if err != nil {
			t.Fatalf("create temp log file: %v", err)
		}
		outFileRes, err := cFile.RunScriptWithSudo(ctx, "echo hello\n", WithOutFile(outFile))
		_ = outFile.Close()
		if err != nil {
			t.Fatalf("RunScriptWithSudo with WithOutFile failed: %v", err)
		}
		if outFileRes != "" {
			t.Errorf("expected empty returned string in file mode, got: %q", outFileRes)
		}
		if cFile.ConnectionConfig().SudoMode != SudoModeRoot {
			t.Errorf("expected SudoModeRoot to be detected in file mode, got: %q", cFile.ConnectionConfig().SudoMode)
		}
		fileBytes, err := os.ReadFile(outFilePath)
		if err != nil {
			t.Fatalf("read temp log file: %v", err)
		}
		if string(fileBytes) != "mock_freebsd_output\n" {
			t.Errorf("file output polluted or unexpected: got %q, want %q", string(fileBytes), "mock_freebsd_output\n")
		}
		recFileID := mock.drainRecord(t)
		if !strings.Contains(recFileID.cmd, "id -u") {
			t.Errorf("expected id -u probe in file mode, got: %q", recFileID.cmd)
		}
		recFileCmd := mock.drainRecord(t)
		if recFileCmd.cmd != "sh -s" {
			t.Errorf("expected sh -s in file mode, got: %q", recFileCmd.cmd)
		}
	})

	// 13. [P0 Issue 2] Explicit per-operation ExecutionConfig on SudoModeAuto client
	// must NOT trigger execution probe or mutate c.Execution(), and non-sudo commands
	// after auto-probe must retain server passthrough (c.Execution() == nil).
	t.Run("ReadOnlyExecutionContract_PreservedAcrossPrivilegeProbes", func(t *testing.T) {
		mock.isRoot.Store(true)
		mock.isSudoer.Store(false)

		// Case A: Explicit RunWithSudoExecution on unconfigured SudoModeAuto client
		cExplicit := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeAuto,
			Execution: nil,
		})
		explicitSh := &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX}
		out, err := cExplicit.RunWithSudoExecution(ctx, "whoami", explicitSh)
		if err != nil {
			t.Fatalf("RunWithSudoExecution failed: %v", err)
		}
		if !strings.Contains(out, "mock_freebsd_output") {
			t.Errorf("unexpected output: %q", out)
		}
		if cExplicit.Execution() != nil {
			t.Fatalf("expected cExplicit.Execution() to remain nil, got: %+v", cExplicit.Execution())
		}
		if _, ok := cExplicit.CachedExecutionProbe(); ok {
			t.Fatal("expected no execution probe when explicit per-operation ExecutionConfig is provided")
		}
		// Only id -u probe and user command should have been sent (no dialect/interp probes)
		recID := mock.drainRecord(t)
		if !strings.Contains(recID.cmd, "id -u") {
			t.Errorf("expected id -u probe, got: %q", recID.cmd)
		}
		recCmd := mock.drainRecord(t)
		if recCmd.cmd != "sh -c 'whoami'" {
			t.Errorf("expected sh -c 'whoami', got: %q", recCmd.cmd)
		}

		// Case B: After auto-probe on unconfigured node, subsequent non-sudo RunCommandWithIO
		// and Run must still use server passthrough (not wrapped in sh -c).
		cAuto := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeRoot,
			Execution: nil,
		})
		var stdout, stderr bytes.Buffer
		if err := cAuto.RunCommandWithIO(ctx, "ls /root", true, nil, &stdout, &stderr); err != nil {
			t.Fatalf("sudo RunCommandWithIO failed: %v", err)
		}
		_ = mock.drainRecord(t) // dialect probe
		_ = mock.drainRecord(t) // interp probe
		recSudo := mock.drainRecord(t)
		if recSudo.cmd != "sh -c 'ls /root'" {
			t.Errorf("expected sudo command to use probed sh -c, got: %q", recSudo.cmd)
		}
		if cAuto.Execution() != nil {
			t.Fatalf("expected cAuto.Execution() to remain nil, got: %+v", cAuto.Execution())
		}
		// Now run non-sudo command on the same client: must be raw server passthrough
		if err := cAuto.RunCommandWithIO(ctx, "uname -a", false, nil, &stdout, &stderr); err != nil {
			t.Fatalf("non-sudo RunCommandWithIO failed: %v", err)
		}
		recPlain := mock.drainRecord(t)
		if recPlain.cmd != "uname -a" {
			t.Errorf("expected non-sudo command to preserve server passthrough 'uname -a', got: %q", recPlain.cmd)
		}
	})

	// 14. [P1 Issue 3] Pre-resolved SudoMode (Root, Sudoer, Sudo, Su) with nil Execution
	// must still auto-probe execution environment and use sh instead of bash.
	t.Run("KnownSudoMode_NilExecution_AutoProbesSh", func(t *testing.T) {
		for _, mode := range []SudoMode{SudoModeRoot, SudoModeSudoer, SudoModeSudo, SudoModeSu} {
			t.Run(string(mode), func(t *testing.T) {
				c := mock.newClient(&ClientConfig{
					SudoMode:  mode,
					Password:  "sudo_secret",
					SuPwd:     "root_secret",
					Execution: nil,
				})
				var stdout, stderr bytes.Buffer
				if err := c.RunCommandWithIO(ctx, "whoami", true, nil, &stdout, &stderr); err != nil {
					t.Fatalf("RunCommandWithIO with mode %s and nil Execution failed: %v", mode, err)
				}
				recDialect := mock.drainRecord(t)
				if !strings.Contains(recDialect.cmd, "__XOPS_DIALECT_POSIX__") {
					t.Errorf("expected dialect probe for mode %s, got: %q", mode, recDialect.cmd)
				}
				recInterp := mock.drainRecord(t)
				if !strings.Contains(recInterp.cmd, "__XOPS_INTERP__") {
					t.Errorf("expected interpreter probe for mode %s, got: %q", mode, recInterp.cmd)
				}
				recCmd := mock.drainRecord(t)
				if strings.Contains(recCmd.cmd, "bash") {
					t.Errorf("expected no bash for mode %s, got: %q", mode, recCmd.cmd)
				}
			})
		}
	})

	// 15. [P1 Issue 4] RunWithSudo and RunScriptWithSudo on unconfigured SudoModeRoot node
	// with WithLoginShell(true) (as passed by xops exec --sudo) must preserve probed sh
	// and not fail validation or fall back to bash.
	t.Run("RunWithSudoAndScript_RootWithCallerLoginOption_UsesProbedSh", func(t *testing.T) {
		c := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeRoot,
			Execution: nil,
		})
		var streamBuf bytes.Buffer
		// Simulate cmd/exec.go passing WithLoginShell(true) + WithStream when client.Execution() == nil
		_, err := c.RunWithSudo(ctx, "whoami", WithLoginShell(true), WithStream(&streamBuf, ""))
		if err != nil {
			t.Fatalf("RunWithSudo with SudoModeRoot and WithLoginShell(true) failed: %v", err)
		}
		_ = mock.drainRecord(t) // dialect probe
		_ = mock.drainRecord(t) // interp probe
		recCmd := mock.drainRecord(t)
		if recCmd.cmd != "sh -c 'whoami'" {
			t.Errorf("expected 'sh -c '\\''whoami'\\'\\'', got: %q", recCmd.cmd)
		}

		// Also verify RunScriptWithSudo under SudoModeRoot uses sh -s instead of bash -l -s
		outScript, err := c.RunScriptWithSudo(ctx, "echo hello_freebsd\n", WithLoginShell(true))
		if err != nil {
			t.Fatalf("RunScriptWithSudo with SudoModeRoot and WithLoginShell(true) failed: %v", err)
		}
		if !strings.Contains(outScript, "mock_freebsd_output") {
			t.Errorf("unexpected script output: %q", outScript)
		}
		recScript := mock.drainRecord(t)
		if recScript.cmd != "sh -s" {
			t.Errorf("expected 'sh -s' for RunScriptWithSudo on FreeBSD root node, got: %q", recScript.cmd)
		}
	})

	// 16. [Round 2 P1] Non-interactive missing privilege credential or unsupported/none SudoMode
	// must fail closed BEFORE opening any remote SSH session for execution probing across all entrypoints.
	t.Run("FailClosedBeforeExecutionProbe_MissingCredentialOrInvalidMode", func(t *testing.T) {
		entrypoints := []struct {
			name string
			call func(*Client) error
		}{
			{"RunWithSudo", func(c *Client) error { _, err := c.RunWithSudo(ctx, "whoami"); return err }},
			{"RunScriptWithSudo", func(c *Client) error { _, err := c.RunScriptWithSudo(ctx, "whoami\n"); return err }},
			{"RunCommandWithIO", func(c *Client) error { return c.RunCommandWithIO(ctx, "whoami", true, nil, nil, nil) }},
			{"RunInteractiveWithSudoIO", func(c *Client) error { return c.RunInteractiveWithSudoIO(ctx, "whoami", InteractiveIO{}) }},
			{"ShellWithSudoIO", func(c *Client) error { return c.ShellWithSudoIO(ctx, InteractiveIO{}) }},
		}
		for _, mode := range []SudoMode{SudoModeSudo, SudoModeSu, SudoModeNone, SudoMode("invalid_mode")} {
			for _, ep := range entrypoints {
				t.Run(string(mode)+"_"+ep.name, func(t *testing.T) {
					c := mock.newClient(&ClientConfig{
						SudoMode:  mode,
						Execution: nil, // would need execution probe if allowed
					})
					err := ep.call(c)
					if err == nil {
						t.Fatalf("expected %s with mode %q and no credentials to fail, got nil", ep.name, mode)
					}
					if (mode == SudoModeSudo || mode == SudoModeSu) && !errors.Is(err, ErrInteractionRequired) {
						t.Errorf("expected ErrInteractionRequired for %s with mode %q without credentials, got: %v", ep.name, mode, err)
					}
					if _, ok := c.CachedExecutionProbe(); ok {
						t.Errorf("expected no execution probe to run for %s with mode %q when failing closed", ep.name, mode)
					}
					select {
					case rec := <-mock.recordedCh:
						t.Fatalf("unexpected remote SSH session opened before fail-closed check for %s with mode %q: %+v", ep.name, mode, rec)
					default:
					}
				})
			}
		}

		// Also verify that if maybeProbePrivilegeExecution fails (e.g. context canceled before/during probe)
		// after ensureNonInteractivePrivilegeCredential resolves PrivilegeMaterial, the resolved material is zeroed.
		t.Run("ProbeFailureZerosPreResolvedMaterial", func(t *testing.T) {
			c := mock.newClient(&ClientConfig{
				SudoMode:  SudoModeSudo,
				Password:  "sudo_secret",
				Execution: nil,
			})
			mat, err := c.ensureNonInteractivePrivilegeCredential(ctx)
			if err != nil || mat == nil {
				t.Fatalf("ensureNonInteractivePrivilegeCredential failed: mat=%v, err=%v", mat, err)
			}
			mat.Zero()
			assertSliceAllZero(t, "mat.Password", mat.Password)

			cancelCtx, cancel := context.WithCancel(ctx)
			resolver := newProbeSecretResolver()
			resolver.setSecret(SecretKindSudoPassword, []byte("sudo_secret_for_cancel"))
			c.resolver = &cancelAfterResolveSecretResolver{next: resolver, cancel: cancel}
			retMat, probeErr := c.maybeProbeExecutionForPrivilege(cancelCtx)
			if !errors.Is(probeErr, context.Canceled) {
				t.Fatalf("expected context.Canceled from maybeProbeExecutionForPrivilege, got: %v", probeErr)
			}
			if retMat != nil {
				t.Fatalf("expected nil PrivilegeMaterial on probe error, got: %+v", retMat)
			}
		})
	})

	// 17. [Round 2 P2] Explicitly configured InterpreterSh node (NeedsExecutionProbe == false)
	// with caller passing WithLoginShell(true) and no WithInterpreter must still keep LoginShell == false.
	t.Run("ExplicitInterpreterSh_CallerWithLoginShellTrue_ForcesLoginFalse", func(t *testing.T) {
		c := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeRoot,
			Execution: &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX},
		})
		_, config := c.preparePrivilegeRunConfig(WithLoginShell(true))
		if config.Interpreter != InterpreterSh {
			t.Fatalf("expected config.Interpreter == InterpreterSh, got %q", config.Interpreter)
		}
		if config.LoginShell {
			t.Fatal("expected config.LoginShell to remain false for explicit InterpreterSh when caller did not specify WithInterpreter")
		}
		out, err := c.RunWithSudo(ctx, "whoami", WithLoginShell(true))
		if err != nil {
			t.Fatalf("RunWithSudo with explicit InterpreterSh and WithLoginShell(true) failed: %v", err)
		}
		if !strings.Contains(out, "mock_freebsd_output") {
			t.Errorf("unexpected output: %q", out)
		}
		rec := mock.drainRecord(t)
		if rec.cmd != "sh -c 'whoami'" {
			t.Errorf("expected 'sh -c '\\''whoami'\\'\\'', got: %q", rec.cmd)
		}
	})

	// 18. [Round 3 P1 Issue 1] RunWithSudoExecution and RunScriptWithSudoExecution with nil execution
	// on unconfigured FreeBSD node must auto-probe execution environment, discover sh,
	// and execute via sh without failing with bash: not found (127).
	t.Run("RunWithSudoExecution_NilExecution_UnconfiguredFreeBSDMock", func(t *testing.T) {
		mock.isRoot.Store(true)
		mock.isSudoer.Store(false)

		c := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeAuto,
			Execution: nil,
		})

		// 1) configuredSudoOptions with nil execution returns nil, nil
		opts, err := c.configuredSudoOptions(ctx, "whoami", nil)
		if err != nil {
			t.Fatalf("configuredSudoOptions(nil) returned error: %v", err)
		}
		if opts != nil {
			t.Fatalf("configuredSudoOptions(nil) returned non-nil options: %v", opts)
		}

		// 2) RunWithSudoExecution with nil execution
		outCmd, err := c.RunWithSudoExecution(ctx, "whoami", nil)
		if err != nil {
			t.Fatalf("RunWithSudoExecution with nil execution failed on unconfigured FreeBSD node: %v", err)
		}
		if !strings.Contains(outCmd, "mock_freebsd_output") {
			t.Errorf("unexpected output: %q", outCmd)
		}
		_ = mock.drainRecord(t) // dialect probe
		_ = mock.drainRecord(t) // interp probe
		_ = mock.drainRecord(t) // id -u probe
		recCmd := mock.drainRecord(t)
		if recCmd.cmd != "sh -c 'whoami'" {
			t.Errorf("expected sh -c 'whoami', got: %q", recCmd.cmd)
		}

		// 3) RunScriptWithSudoExecution with nil execution (using cached probe)
		outScript, err := c.RunScriptWithSudoExecution(ctx, "echo hello\n", nil)
		if err != nil {
			t.Fatalf("RunScriptWithSudoExecution with nil execution failed on unconfigured FreeBSD node: %v", err)
		}
		if !strings.Contains(outScript, "mock_freebsd_output") {
			t.Errorf("unexpected output: %q", outScript)
		}
		recScript := mock.drainRecord(t)
		if recScript.cmd != "sh -s" {
			t.Errorf("expected sh -s, got: %q", recScript.cmd)
		}

		// 4) RunWithSudoExecution with nil execution and caller passing extraOpts (e.g. WithLoginShell(true))
		outCmdLogin, err := c.RunWithSudoExecution(ctx, "whoami", nil, WithLoginShell(true))
		if err != nil {
			t.Fatalf("RunWithSudoExecution with WithLoginShell(true) failed on unconfigured FreeBSD node: %v", err)
		}
		if !strings.Contains(outCmdLogin, "mock_freebsd_output") {
			t.Errorf("unexpected output: %q", outCmdLogin)
		}
		recCmdLogin := mock.drainRecord(t)
		if recCmdLogin.cmd != "sh -c 'whoami'" {
			t.Errorf("expected sh -c 'whoami' (no login for sh), got: %q", recCmdLogin.cmd)
		}

		// 5) SudoModeSudoer with nil execution: auto-probes sh and runs sudo -S -p '' sh -c 'whoami'
		cSudoer := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeSudoer,
			Execution: nil,
		})
		outSudoer, err := cSudoer.RunWithSudoExecution(ctx, "whoami", nil)
		if err != nil {
			t.Fatalf("RunWithSudoExecution with SudoModeSudoer failed on unconfigured FreeBSD node: %v", err)
		}
		if !strings.Contains(outSudoer, "mock_freebsd_output") {
			t.Errorf("unexpected output: %q", outSudoer)
		}
		_ = mock.drainRecord(t) // dialect probe
		_ = mock.drainRecord(t) // interp probe
		recSudoer := mock.drainRecord(t)
		if recSudoer.cmd != "sudo -S -p '' sh -c 'whoami'" {
			t.Errorf("expected \"sudo -S -p '' sh -c 'whoami'\", got: %q", recSudoer.cmd)
		}

		// 6) SudoModeSudoer RunScriptWithSudoExecution with nil execution: runs sudo -S -p '' sh -s
		outSudoerScript, err := cSudoer.RunScriptWithSudoExecution(ctx, "echo sudoer_script\n", nil)
		if err != nil {
			t.Fatalf("RunScriptWithSudoExecution with SudoModeSudoer failed on unconfigured FreeBSD node: %v", err)
		}
		if !strings.Contains(outSudoerScript, "mock_freebsd_output") {
			t.Errorf("unexpected output: %q", outSudoerScript)
		}
		recSudoerScript := mock.drainRecord(t)
		if recSudoerScript.cmd != "sudo -S -p '' sh -s" {
			t.Errorf("expected \"sudo -S -p '' sh -s\", got: %q", recSudoerScript.cmd)
		}
		if recSudoerScript.stdin != "echo sudoer_script\n" {
			t.Errorf("expected stdin 'echo sudoer_script\\n', got: %q", recSudoerScript.stdin)
		}

		// 7) SudoModeSu RunWithSudoExecution with nil execution: auto-probes sh and runs su command without bash
		cSu := mock.newClient(&ClientConfig{
			SudoMode:  SudoModeSu,
			SuPwd:     "root_secret",
			Execution: nil,
		})
		outSu, err := cSu.RunWithSudoExecution(ctx, "whoami", nil)
		if err != nil {
			t.Fatalf("RunWithSudoExecution with SudoModeSu failed on unconfigured FreeBSD node: %v", err)
		}
		if !strings.Contains(outSu, "mock_freebsd_output") {
			t.Errorf("unexpected output: %q", outSu)
		}
		_ = mock.drainRecord(t) // dialect probe
		_ = mock.drainRecord(t) // interp probe
		recSu := mock.drainRecord(t)
		if strings.Contains(recSu.cmd, "bash") || !strings.Contains(recSu.cmd, "su") {
			t.Errorf("expected su command using sh without bash, got: %q", recSu.cmd)
		}
	})
}

// TestPrivilegeExecution_LoginShellPreservation verifies that privilegeExecution()
// clears SuggestedConfig.Login to nil, so defaultPrivilegeRunConfig and preparePrivilegeRunConfig
// preserve default login shell for bash while keeping non-login for sh/zsh/fish.
func TestPrivilegeExecution_LoginShellPreservation(t *testing.T) {
	tests := []struct {
		name               string
		dialect            LaunchDialect
		remoteShellPath    string
		availableInterps   []Interpreter
		expectedInterp     Interpreter
		expectDefaultLogin bool
		callerOption       RunOption
		expectCallerLogin  bool
	}{
		{
			name:               "Probed_Bash_PreservesDefaultLoginShell",
			dialect:            LaunchPOSIX,
			remoteShellPath:    "/bin/bash",
			availableInterps:   []Interpreter{InterpreterBash, InterpreterSh},
			expectedInterp:     InterpreterBash,
			expectDefaultLogin: true, // bash defaults to login shell (bash -l -c)
			callerOption:       WithLoginShell(false),
			expectCallerLogin:  false, // caller can explicitly disable login
		},
		{
			name:               "Probed_Sh_KeepsNonLogin_AndProtectsAgainstCallerLogin",
			dialect:            LaunchPOSIX,
			remoteShellPath:    "/bin/sh",
			availableInterps:   []Interpreter{InterpreterSh},
			expectedInterp:     InterpreterSh,
			expectDefaultLogin: false, // sh is always non-login
			callerOption:       WithLoginShell(true),
			expectCallerLogin:  false, // caller WithLoginShell(true) without WithInterpreter is ignored for sh
		},
		{
			name:               "Probed_Zsh_KeepsNonLogin_AndProtectsAgainstCallerLogin",
			dialect:            LaunchPOSIX,
			remoteShellPath:    "/bin/zsh",
			availableInterps:   []Interpreter{InterpreterZsh, InterpreterSh},
			expectedInterp:     InterpreterZsh,
			expectDefaultLogin: false, // zsh defaults to non-login (zsh -c)
			callerOption:       WithLoginShell(true),
			expectCallerLogin:  false, // caller WithLoginShell(true) without WithInterpreter is ignored for unconfigured zsh
		},
		{
			name:               "Probed_Fish_KeepsNonLogin_AndProtectsAgainstCallerLogin",
			dialect:            LaunchFish,
			remoteShellPath:    "/usr/bin/fish",
			availableInterps:   []Interpreter{InterpreterFish},
			expectedInterp:     InterpreterFish,
			expectDefaultLogin: false, // fish defaults to non-login (fish -c)
			callerOption:       WithLoginShell(true),
			expectCallerLogin:  false, // caller WithLoginShell(true) without WithInterpreter is ignored for unconfigured fish
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewTestClient(ConnectionConfig{
				SudoMode: SudoModeAuto,
			})
			probeSuggested := recommendProbeExecution(tc.dialect, tc.remoteShellPath, tc.availableInterps)
			if probeSuggested.Login == nil || *probeSuggested.Login != false {
				t.Fatalf("recommendProbeExecution must set Login=&false, got: %+v", probeSuggested.Login)
			}
			cache := c.executionProbeCache()
			done := make(chan struct{})
			close(done)
			cache.attempt = &executionProbeAttempt{
				done: done,
				result: &ProbeResult{
					DetectedDialect:       tc.dialect,
					AvailableInterpreters: tc.availableInterps,
					SuggestedConfig:       probeSuggested,
				},
			}

			// 1. Verify privilegeExecution() clears Login to nil
			privExec := c.privilegeExecution()
			if privExec == nil {
				t.Fatal("expected non-nil privilegeExecution()")
			}
			if privExec.Interpreter != tc.expectedInterp {
				t.Errorf("expected Interpreter %q, got %q", tc.expectedInterp, privExec.Interpreter)
			}
			if privExec.Login != nil {
				t.Errorf("expected privilegeExecution().Login to be nil, got: %v", *privExec.Login)
			}

			// 2. Verify defaultPrivilegeRunConfig preserves interpreter defaults
			defCfg := c.defaultPrivilegeRunConfig()
			if defCfg.Interpreter != tc.expectedInterp {
				t.Errorf("expected default config Interpreter %q, got %q", tc.expectedInterp, defCfg.Interpreter)
			}
			if defCfg.LoginShell != tc.expectDefaultLogin {
				t.Errorf("expected default config LoginShell=%v, got %v", tc.expectDefaultLogin, defCfg.LoginShell)
			}

			// 3. Verify preparePrivilegeRunConfig without caller options preserves default
			_, noOptCfg := c.preparePrivilegeRunConfig()
			if noOptCfg.LoginShell != tc.expectDefaultLogin {
				t.Errorf("expected no-opts preparePrivilegeRunConfig LoginShell=%v, got %v", tc.expectDefaultLogin, noOptCfg.LoginShell)
			}

			// 4. Verify preparePrivilegeRunConfig with callerOption produces expectCallerLogin
			var opts []RunOption
			if tc.callerOption != nil {
				opts = append(opts, tc.callerOption)
			}
			_, callerCfg := c.preparePrivilegeRunConfig(opts...)
			if callerCfg.LoginShell != tc.expectCallerLogin {
				t.Errorf("expected with callerOption preparePrivilegeRunConfig LoginShell=%v, got %v", tc.expectCallerLogin, callerCfg.LoginShell)
			}
		})
	}

	// Also verify explicit configuration is respected
	t.Run("ExplicitConfiguration_Respected", func(t *testing.T) {
		loginTrue := true
		loginFalse := false

		cExplicitZsh := NewTestClient(ConnectionConfig{
			SudoMode: SudoModeAuto,
			Execution: &ExecutionConfig{
				Interpreter:   InterpreterZsh,
				LaunchDialect: LaunchPOSIX,
				Login:         &loginTrue,
			},
		})
		defZsh := cExplicitZsh.defaultPrivilegeRunConfig()
		if defZsh.Interpreter != InterpreterZsh || !defZsh.LoginShell {
			t.Errorf("expected explicit zsh with Login=true to have LoginShell=true, got: %v", defZsh.LoginShell)
		}

		cExplicitBash := NewTestClient(ConnectionConfig{
			SudoMode: SudoModeAuto,
			Execution: &ExecutionConfig{
				Interpreter:   InterpreterBash,
				LaunchDialect: LaunchPOSIX,
				Login:         &loginFalse,
			},
		})
		defBash := cExplicitBash.defaultPrivilegeRunConfig()
		if defBash.Interpreter != InterpreterBash || defBash.LoginShell {
			t.Errorf("expected explicit bash with Login=false to have LoginShell=false, got: %v", defBash.LoginShell)
		}
	})
}

// 22. [Regression Test] RunScriptWithSudo & RunScriptWithSudoExecution preserve login shell flags on the wire
func TestShAdapter_RunScriptWithSudoLoginShellPreservation(t *testing.T) {
	mock := startFreeBSDMockSSHServer(t)
	mock.isSudoer.Store(true)
	mock.allowBash.Store(true)
	ctx := t.Context()

	for _, tc := range []struct {
		interp     Interpreter
		dialect    LaunchDialect
		login      bool
		wantToken  string
		avoidToken string
	}{
		{InterpreterBash, LaunchPOSIX, true, "bash -l -s", ""},
		{InterpreterBash, LaunchPOSIX, false, "bash -s", "-l"},
		{InterpreterBash, LaunchCsh, true, "bash -l -s", ""},
		{InterpreterZsh, LaunchPOSIX, true, "zsh -l -s", ""},
		{InterpreterZsh, LaunchPOSIX, false, "zsh -s", "-l"},
		{InterpreterFish, LaunchPOSIX, true, "fish -l", ""},
		{InterpreterFish, LaunchPOSIX, false, "fish", "-l"},
		{InterpreterCsh, LaunchCsh, true, "csh -s", "-l"},
		{InterpreterCsh, LaunchCsh, false, "csh -s", "-l"},
		{InterpreterTcsh, LaunchCsh, true, "tcsh -s", "-l"},
		{InterpreterTcsh, LaunchCsh, false, "tcsh -s", "-l"},
		{InterpreterSh, LaunchPOSIX, true, "sh -s", "-l"},
		{InterpreterSh, LaunchPOSIX, false, "sh -s", "-l"},
	} {
		t.Run(string(tc.interp)+"_login_"+fmt.Sprint(tc.login), func(t *testing.T) {
			c := mock.newClient(&ClientConfig{
				SudoMode: SudoModeSudoer,
				Execution: &ExecutionConfig{
					Interpreter:   tc.interp,
					LaunchDialect: tc.dialect,
				},
			})
			_, err := c.RunScriptWithSudo(ctx, "echo test\n", WithInterpreter(tc.interp), WithLaunchDialect(tc.dialect), WithLoginShell(tc.login))
			if err != nil {
				t.Fatalf("RunScriptWithSudo(%s, login=%v) failed: %v", tc.interp, tc.login, err)
			}
			rec := mock.drainRecord(t)
			if !strings.Contains(rec.cmd, tc.wantToken) {
				t.Errorf("RunScriptWithSudo(%s, login=%v): wire command %q does not contain %q", tc.interp, tc.login, rec.cmd, tc.wantToken)
			}
			if tc.avoidToken != "" && strings.Contains(rec.cmd, tc.avoidToken) {
				t.Errorf("RunScriptWithSudo(%s, login=%v): wire command %q unexpectedly contains %q", tc.interp, tc.login, rec.cmd, tc.avoidToken)
			}

			// Also test RunScriptWithSudoExecution
			loginCopy := tc.login
			execCfg := &ExecutionConfig{
				Interpreter:   tc.interp,
				LaunchDialect: tc.dialect,
				Login:         &loginCopy,
			}
			if tc.login && (tc.interp == InterpreterSh || tc.interp == InterpreterCsh || tc.interp == InterpreterTcsh) {
				if _, err = c.RunScriptWithSudoExecution(ctx, "echo test\n", execCfg); !errors.Is(err, ErrExecutionValidation) {
					t.Errorf("RunScriptWithSudoExecution(%s, login=true) expected ErrExecutionValidation, got: %v", tc.interp, err)
				}
			} else {
				_, err = c.RunScriptWithSudoExecution(ctx, "echo test\n", execCfg)
				if err != nil {
					t.Fatalf("RunScriptWithSudoExecution(%s, login=%v) failed: %v", tc.interp, tc.login, err)
				}
				recExec := mock.drainRecord(t)
				if !strings.Contains(recExec.cmd, tc.wantToken) {
					t.Errorf("RunScriptWithSudoExecution(%s, login=%v): wire command %q does not contain %q", tc.interp, tc.login, recExec.cmd, tc.wantToken)
				}
				if tc.avoidToken != "" && strings.Contains(recExec.cmd, tc.avoidToken) {
					t.Errorf("RunScriptWithSudoExecution(%s, login=%v): wire command %q unexpectedly contains %q", tc.interp, tc.login, recExec.cmd, tc.avoidToken)
				}
			}
		})
	}
}

type cancelAfterResolveSecretResolver struct {
	next   SecretResolver
	cancel context.CancelFunc
}

func (r *cancelAfterResolveSecretResolver) ResolveSecret(ctx context.Context, req SecretRequest) ([]byte, error) {
	val, err := r.next.ResolveSecret(ctx, req)
	if r.cancel != nil {
		r.cancel()
	}
	return val, err
}
