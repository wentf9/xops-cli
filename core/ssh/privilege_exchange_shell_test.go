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

// Model sudo's documented -i argv escaping, then let a real Bash parse it.
// In particular '$' is deliberately NOT escaped, unlike quotes and backslashes.
const sudoLoginTestPrelude = `
sudo() {
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
    shift
    local line="" arg ch i
    for arg in "$@"; do
        for ((i=0; i<${#arg}; i++)); do
            ch=${arg:i:1}
            case "$ch" in
                [a-zA-Z0-9_\$-]) line+="$ch" ;;
                *) line+="\\$ch" ;;
            esac
        done
        line+=" "
    done
    bash -c "$line"
}
`

func TestSudoLoginPreservesInnerScriptExpansion(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("sudo login parsing regression requires bash")
	}
	for _, tc := range []struct {
		name, script, want string
	}{
		{"variable", `value=inner; printf '%s' "$value"`, "inner"},
		{"literal dollar", `printf '%s' '$HOME'`, "$HOME"},
		{"substitution", `printf '%s' "$(printf nested)"`, "nested"},
		{"ANSI literal", `printf '%s' $'line\nquote\x27\\end'`, "line\nquote'\\end"},
		{"unicode", `value=中文; printf '%s' "$value"`, "中文"},
		{"multiline", "value=inner\n" + `printf '%s' "$value"`, "inner"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrapped, err := interactivePrivilegeCommand(SudoModeSudoer, tc.script)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, bash, "-c", sudoLoginTestPrelude+wrapped)
			output, err := command.CombinedOutput()
			if err != nil || string(output) != tc.want {
				t.Fatalf("login shell changed inner script: output=%q err=%v", output, err)
			}
		})
	}
}
