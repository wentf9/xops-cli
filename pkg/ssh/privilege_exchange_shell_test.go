//go:build !windows

package ssh

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Validate the actual remote Bash script, not only the Go SSH fixture's parser.
func TestPrivilegeShellRequiresAcknowledgement(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("remote Bash syntax test requires bash")
	}
	for _, valid := range []bool{false, true} {
		exchange := newPrivilegeExchange(nil, SudoModeSudo, false)
		ack := "wrong"
		if valid {
			ack = exchange.ackToken
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		command := exec.CommandContext(ctx, bash, "-c", exchange.body("printf '%s' 'user-result'; exit 7"))
		command.Stdin = strings.NewReader(ack + "\n")
		output, runErr := command.CombinedOutput()
		cancel()
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			t.Fatalf("expected exit status: %v", runErr)
		}
		if !strings.HasPrefix(string(output), exchange.readyToken) {
			t.Fatalf("readiness not emitted: %q", output)
		}
		if valid {
			if exitErr.ExitCode() != 7 || string(output) != exchange.readyToken+"user-result" {
				t.Fatalf("acknowledged command: %q %v", output, runErr)
			}
		} else if strings.Contains(string(output), "user-result") {
			t.Fatal("command ran without acknowledgement")
		}
	}
}

func TestPrivilegeShellSeparatesAcknowledgementFromInput(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("remote Bash syntax test requires bash")
	}
	exchange := newPrivilegeExchange(nil, SudoModeSudo, false)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, bash, "-c", exchange.body("cat"))
	command.Stdin = strings.NewReader(exchange.ackToken + "\nuser-input\n")
	output, err := command.CombinedOutput()
	if err != nil || string(output) != exchange.readyToken+"user-input\n" {
		t.Fatalf("acknowledgement leaked into command input: %q, %v", output, err)
	}
}

func TestPrivilegeShellEOFBeforeAcknowledgementDoesNotExecute(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("remote Bash syntax test requires bash")
	}
	exchange := newPrivilegeExchange(nil, SudoModeSu, false)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, bash, "-c", exchange.body("printf user-command-ran"))
	command.Stdin = strings.NewReader("")
	output, err := command.CombinedOutput()
	if err == nil || string(output) != exchange.readyToken {
		t.Fatalf("command ran without acknowledgement: %q, %v", output, err)
	}
}
