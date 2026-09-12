//go:build linux

package ssh

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func openPrivilegeTestPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := master.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(filepath.Join("/dev/pts", strconv.Itoa(number)), os.O_RDWR|unix.O_NOCTTY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := slave.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 80}); err != nil {
		t.Fatal(err)
	}
	return master, slave
}

type canonicalPrivilegeUI struct {
	recoveryTestUI
	terminal *os.File
}

func (h *canonicalPrivilegeUI) PromptSecret(ctx context.Context, req SecretRequest) (string, error) {
	state, err := unix.IoctlGetTermios(int(h.terminal.Fd()), unix.TCGETS)
	if err != nil {
		return "", err
	}
	if state.Lflag&unix.ICANON == 0 {
		return "", errors.New("password prompt ran in raw mode")
	}
	return h.recoveryTestUI.PromptSecret(ctx, req)
}

func TestInteractivePrivilegePTYRestoresModeAndFirstInput(t *testing.T) {
	for _, test := range []struct {
		mode  SudoMode
		shell bool
	}{{SudoModeSudo, false}, {SudoModeSu, false}, {SudoModeSudo, true}, {SudoModeSu, true}} {
		mode := test.mode
		t.Run(string(mode)+"/shell="+strconv.FormatBool(test.shell), func(t *testing.T) {
			setTestHome(t)
			master, slave := openPrivilegeTestPTY(t)
			before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			addr, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: mode, password: "valid", status: 7, inputBytes: 1})
			ui := &canonicalPrivilegeUI{recoveryTestUI: recoveryTestUI{values: []string{"wrong", "valid"}}, terminal: slave}
			recorder := &testRecorder{}
			client := exchangeTestClient(t, addr, mode, ui, recorder)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if err := master.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			sent := make(chan error, 1)
			go func() {
				select {
				case <-evidence.terminalSignaled:
				case <-ctx.Done():
					sent <- ctx.Err()
					return
				}
				_, err := master.Write([]byte("Z"))
				sent <- err
			}()
			var output bytes.Buffer
			streams := InteractiveIO{Stdin: slave, Stdout: &output, Stderr: &output}
			var runErr error
			if test.shell {
				runErr = client.ShellWithSudoIO(ctx, streams)
			} else {
				runErr = client.RunInteractiveWithSudoIO(ctx, "command", streams)
			}
			cancel()
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
			if runErr != nil {
				t.Fatal(runErr)
			}
			after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil || *before != *after {
				t.Fatalf("terminal mode not restored: %v", err)
			}
			if got := <-evidence.input; got != "Z" {
				t.Fatalf("first input lost: %q", got)
			}
			// Input entered after return belongs to the caller, not a lingering
			// SSH stdin reader (the original swallowed-first-character failure).
			if err := slave.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := master.Write([]byte("NEXT\n")); err != nil {
				t.Fatal(err)
			}
			next, err := bufio.NewReader(slave).ReadString('\n')
			if err != nil || next != "NEXT\n" {
				t.Fatalf("post-session input was consumed: %q, %v", next, err)
			}
			if recorder.sudoCalls != 1 || evidence.commands.Load() != 1 {
				t.Fatal("verified credential not saved or command replayed")
			}
		})
	}
}

func TestPrivilegeRemotePTYEnablesEchoAfterAcknowledgement(t *testing.T) {
	testPrivilegeRemotePTYHandoff(t, false, "")
}

func TestPrivilegeSudoLoginPTYHandoff(t *testing.T) {
	testPrivilegeRemotePTYHandoff(t, true, "")
}

// CI runs this as a dedicated unprivileged user with password-required sudo.
func TestPrivilegeNativePasswordSudoPTY(t *testing.T) {
	password := os.Getenv("XOPS_TEST_NATIVE_SUDO_PASSWORD")
	if password == "" {
		t.Skip("requires a disposable user with password-required sudo")
	}
	if os.Geteuid() == 0 {
		t.Fatal("native password-sudo regression must not run as root")
	}
	testPrivilegeRemotePTYHandoff(t, true, password)
}

func testPrivilegeRemotePTYHandoff(t *testing.T, sudoLogin bool, password string) {
	t.Helper()
	t.Setenv("BASH_ENV", "")
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("remote terminal protocol test requires bash")
	}
	master, slave := openPrivilegeTestPTY(t)
	state, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	state.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(int(slave.Fd()), unix.TCSETS, state); err != nil {
		t.Fatal(err)
	}
	exchange := newPrivilegeExchange(nil, SudoModeSu, false)
	exchange.terminal = &privilegeTerminal{}
	exchange.terminalToken = "[xops-terminal-test]"
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	script := exchange.body("printf user-output")
	if sudoLogin {
		exchange.mode = SudoModeSudo
		userCommand := `xops_output=user-output; printf '%s' "$xops_output"`
		if password != "" {
			userCommand = `test "$(id -u)" = 0 && ` + userCommand
		}
		script = exchange.command(userCommand)
		if password == "" {
			script = sudoLoginTestPrelude + script
		}
	}
	command := exec.CommandContext(ctx, bash, "-c", script)
	command.Stdin, command.Stdout, command.Stderr = slave, slave, slave
	if password != "" {
		command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	}
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	joined := false
	defer func() {
		cancel()
		if !joined {
			<-done
		}
	}()
	if err := master.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	verifyPrivilegePTYHandoff(t, master, slave, exchange, password)
	err = <-done
	joined = true
	if err != nil {
		t.Fatal(err)
	}
}

func verifyPrivilegePTYHandoff(t *testing.T, master, slave *os.File, exchange *privilegeExchange, password string) {
	t.Helper()
	reader := bufio.NewReader(master)
	if password != "" {
		prompt, err := reader.ReadString(']')
		if err != nil || !strings.HasSuffix(prompt, exchange.promptToken) {
			t.Fatalf("native sudo did not request a password: %v", err)
		}
		if _, err := fmt.Fprintln(master, password); err != nil {
			t.Fatal(err)
		}
	}
	ready, err := reader.ReadString(']')
	if err != nil || strings.TrimSpace(ready) != exchange.readyToken {
		t.Fatalf("readiness: %q, %v", ready, err)
	}
	if _, err := fmt.Fprintln(master, exchange.ackToken); err != nil {
		t.Fatal(err)
	}
	handoff, err := reader.ReadString(']')
	if err != nil || handoff != exchange.terminalToken {
		t.Fatalf("acknowledgement echoed or terminal not ready: %q, %v", handoff, err)
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	// Native sudo with use_pty owns a separate inner terminal. Its successful
	// handoff confirms stty echo there; the outer slave can remain in raw mode.
	if err != nil || (password == "" && after.Lflag&unix.ECHO == 0) {
		t.Fatalf("remote terminal echo not restored: %v", err)
	}
	output := make([]byte, len("user-output"))
	if _, err := io.ReadFull(reader, output); err != nil {
		t.Fatal(err)
	}
	if string(output) != "user-output" {
		t.Fatalf("unexpected command output: %q", output)
	}
}
