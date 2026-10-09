//go:build linux

package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func TestTerminalSessionExitAndRequestContracts(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, test := range []struct {
		name                              string
		status                            uint32
		signal, missing, shell, sudoShell bool
		mode                              SudoMode
	}{
		{name: "command nonzero", status: 7},
		{name: "command signal", signal: true},
		{name: "command missing status", missing: true},
		{name: "root nonzero", status: 7, mode: SudoModeRoot},
		{name: "sudoer nonzero", status: 7, mode: SudoModeSudoer},
		{name: "root signal", signal: true, mode: SudoModeRoot},
		{name: "sudoer missing status", missing: true, mode: SudoModeSudoer},
		{name: "shell retains legacy exit policy", status: 7, shell: true},
		{name: "sudoer shell retains legacy exit policy", status: 7, sudoShell: true, mode: SudoModeSudoer},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, stdin := openPrivilegeTestPTY(t)
			before, err := unix.IoctlGetTermios(int(stdin.Fd()), unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			scenario := &commandFixture{terminal: true, status: test.status, signal: test.signal, missing: test.missing, output: "command output", requestTypes: make(chan string, 3)}
			client := commandTestClient(t, scenario)
			client.cfgMu.Lock()
			client.connCfg.SudoMode = test.mode
			client.cfgMu.Unlock()
			var output bytes.Buffer
			streams := InteractiveIO{Stdin: stdin, Stdout: &output, Stderr: &output}
			var runErr error
			switch {
			case test.shell:
				runErr = client.ShellWithIO(t.Context(), streams)
			case test.sudoShell:
				runErr = client.ShellWithSudoIO(t.Context(), streams)
			case test.mode != "":
				runErr = client.RunInteractiveWithSudoIO(t.Context(), "command", streams)
			default:
				runErr = client.RunInteractiveCmdWithIO(t.Context(), "command", streams)
			}
			assertTerminalExit(t, runErr, test.status, test.signal, test.missing, test.shell || test.sudoShell)
			after, err := unix.IoctlGetTermios(int(stdin.Fd()), unix.TCGETS)
			if err != nil || *before != *after {
				t.Fatalf("terminal was not restored: %v", err)
			}
			if !strings.Contains(output.String(), "command output") || scenario.attempts.Load() != 1 {
				t.Fatal("output lost or command replayed")
			}
			if got := <-scenario.requestTypes; got != "pty-req" {
				t.Fatalf("first request %q", got)
			}
			want := "exec"
			if test.shell {
				want = "shell"
			}
			if got := <-scenario.requestTypes; got != want {
				t.Fatalf("operation request %q, want %q", got, want)
			}
		})
	}
}

func TestTerminalStartupTimeoutRestoresAndDoesNotReplay(t *testing.T) {
	for _, shell := range []bool{false, true} {
		t.Run(map[bool]string{false: "exec", true: "shell"}[shell], func(t *testing.T) {
			_, stdin := openPrivilegeTestPTY(t)
			before, err := unix.IoctlGetTermios(int(stdin.Fd()), unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			scenario := &commandFixture{terminal: true, hangRequest: true}
			client := commandTestClient(t, scenario)
			client.handshakeTimeout = 30 * time.Millisecond
			streams := InteractiveIO{Stdin: stdin, Stdout: io.Discard, Stderr: io.Discard}
			var runErr error
			if shell {
				runErr = client.ShellWithIO(context.Background(), streams)
			} else {
				runErr = client.RunInteractiveCmdWithIO(context.Background(), "command", streams)
			}
			if !errors.Is(runErr, context.DeadlineExceeded) || scenario.attempts.Load() != 1 {
				t.Fatalf("unbounded/replayed terminal startup: %v", runErr)
			}
			after, err := unix.IoctlGetTermios(int(stdin.Fd()), unix.TCGETS)
			if err != nil || *before != *after {
				t.Fatalf("startup changed terminal: %v", err)
			}
		})
	}
}

func TestInteractivePlanAndLegacyLoginSelection(t *testing.T) {
	for _, test := range []struct {
		name, payload   string
		explicit, login bool
	}{
		{"server", "command", true, false},
		{"legacy non-login", "bash -c 'command'", false, false},
		{"legacy login", "bash -l -c 'command'", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, stdin := openPrivilegeTestPTY(t)
			scenario := &commandFixture{terminal: true, commands: make(chan string, 1)}
			client := commandTestClient(t, scenario)
			streams := InteractiveIO{Stdin: stdin, Stdout: io.Discard, Stderr: io.Discard}
			client.environment.InteractiveIO = streams
			var err error
			if test.explicit {
				plan, planErr := PlanCommand("command", CommandOptions{})
				if planErr != nil {
					t.Fatal(planErr)
				}
				err = client.RunInteractivePlanWithIO(t.Context(), plan, streams)
			} else {
				err = client.RunInteractiveWithOptions(t.Context(), "command", WithLoginShell(test.login))
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := <-scenario.commands; got != test.payload {
				t.Fatalf("unexpected payload %q, want %q", got, test.payload)
			}
		})
	}
}

func TestFileInputEOFDoesNotSpinOrCloseCaller(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	cancel, done, err := copyStdinTo(reader, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cancel(); err != nil {
			t.Error(err)
		}
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("EOF left input polling forever")
	}
	if _, err := reader.Stat(); err != nil {
		t.Fatalf("caller input was closed: %v", err)
	}
}

func assertTerminalExit(t *testing.T, err error, status uint32, signal, missing, ignore bool) {
	t.Helper()
	if ignore {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if missing {
		var missing *cryptoSSH.ExitMissingError
		if !errors.As(err, &missing) {
			t.Fatalf("missing exit status hidden: %v", err)
		}
		return
	}
	var exit *cryptoSSH.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("command exit hidden: %v", err)
	}
	if signal && exit.Signal() != "TERM" {
		t.Fatalf("lost signal: %v", err)
	}
	if !signal && exit.ExitStatus() != int(status) {
		t.Fatalf("lost exit status: %v", err)
	}
}

func TestInteractivePlanBlockedOutputCancelsWithoutClosingCaller(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	_, stdin := openPrivilegeTestPTY(t)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := writer.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(bytes.Repeat([]byte("x"), 1<<20)); err == nil {
		t.Fatal("pipe did not fill")
	}
	if err := writer.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	before := outputDescriptorFlags(t, writer)
	scenario := &commandFixture{terminal: true, output: "blocked output"}
	client := commandTestClient(t, scenario)
	plan, err := PlanCommand("command", CommandOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = client.RunInteractivePlanWithIO(ctx, plan, InteractiveIO{Stdin: stdin, Stdout: writer, Stderr: io.Discard})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("blocked output did not cancel: %v", err)
	}
	if _, err := writer.Stat(); err != nil {
		t.Fatalf("borrowed output closed: %v", err)
	}
	if after := outputDescriptorFlags(t, writer); after != before {
		t.Fatal("borrowed output flags changed")
	}
	if scenario.attempts.Load() != 1 {
		t.Fatal("blocked output caused replay")
	}
}

func outputDescriptorFlags(t *testing.T, file *os.File) int {
	t.Helper()
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	var flagsErr error
	if err := raw.Control(func(fd uintptr) { flags, flagsErr = unix.FcntlInt(fd, unix.F_GETFL, 0) }); err != nil {
		t.Fatal(err)
	}
	if flagsErr != nil {
		t.Fatal(flagsErr)
	}
	return flags
}

func TestInteractivePlanBoundsOutputDrainAfterRemoteExit(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	_, stdin := openPrivilegeTestPTY(t)
	scenario := &commandFixture{terminal: true, output: "output"}
	client := commandTestClient(t, scenario)
	plan, err := PlanCommand("command", CommandOptions{})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = client.RunInteractivePlanWithIO(t.Context(), plan, InteractiveIO{Stdin: stdin, Stdout: cancelableTerminalWriter{}, Stderr: io.Discard})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second || scenario.attempts.Load() != 1 {
		t.Fatalf("output drain was not bounded or caused replay: %v", err)
	}
}
