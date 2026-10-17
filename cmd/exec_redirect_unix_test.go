//go:build !windows

package cmd

import (
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/testpty"
	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func TestExecExplicitInteractiveFileRedirection(t *testing.T) {
	master, stdin, err := testpty.Open()
	if err != nil {
		t.Skipf("PTY unavailable: %v", err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = master.Close() })
	before, err := term.GetState(int(stdin.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := os.CreateTemp(t.TempDir(), "stdout-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdout.Close() })
	stderr, err := os.CreateTemp(t.TempDir(), "stderr-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stderr.Close() })
	payloads := make(chan string, 1)
	ctx, connector, server := newExecCombinationFixture(t, func(command string, channel cryptoSSH.Channel) {
		payloads <- command
		_, _ = io.WriteString(channel, "stdout 雪🙂\n")
		_, _ = io.WriteString(channel.Stderr(), "stderr\n")
		_, _ = channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{7}))
	}, ssh.WithEnvironment(ssh.Environment{InteractiveIO: ssh.InteractiveIO{Stdin: stdin, Stdout: stdout, Stderr: stderr}}))
	o := NewExecOptions()
	command := newCmdExecWithOptions(o)
	if err := command.Flags().Parse([]string{"--host", "fixture", "--interpreter", "server", "-x", "-c", "chosen"}); err != nil {
		t.Fatal(err)
	}
	if err := o.Complete(command, nil); err != nil {
		t.Fatal(err)
	}
	runErr := o.runInteractive(ctx, connector, execHostTask{nodeID: "fixture", host: "fixture"}, "chosen")
	var exitErr *cryptoSSH.ExitError
	if !errors.As(runErr, &exitErr) || exitErr.ExitStatus() != 7 {
		t.Fatalf("exit code lost: %v", runErr)
	}
	if got := <-payloads; got != "chosen" || server.Executed.Load() != 1 {
		t.Fatalf("payload changed or replayed: %q", got)
	}
	assertExecRedirectFile(t, stdout, "stdout 雪🙂\n")
	assertExecRedirectFile(t, stderr, "stderr\n")
	after, err := term.GetState(int(stdin.Fd()))
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("terminal not restored: %v", err)
	}
}

func assertExecRedirectFile(t *testing.T, file *os.File, expected string) {
	t.Helper()
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), expected) != 1 {
		t.Fatalf("redirected output missing or duplicated: %q", data)
	}
	if _, err := file.WriteString("caller"); err != nil {
		t.Fatalf("borrowed output closed: %v", err)
	}
}
