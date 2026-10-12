package playbook

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestZshEnsureUsesNativeCheckAndAction(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skipf("zsh unavailable: %v", err)
	}
	directory := t.TempDir()
	client, _ := executionTestClient(t, func(payload string, channel cryptoSSH.Channel) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, zsh, "-c", payload)
		command.WaitDelay = time.Second
		command.Env = append(os.Environ(), "ZDOTDIR="+directory)
		command.Stdout, command.Stderr = channel, channel.Stderr()
		status := uint32(0)
		if err := command.Run(); err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) && exit.ExitCode() >= 0 {
				status = uint32(exit.ExitCode())
			} else {
				t.Errorf("run zsh ensure: %v", err)
				status = 1
			}
		}
		writeLazyResult(t, channel, "", status)
	})
	marker := filepath.Join(directory, "repaired")
	spec := &EnsureSpec{Check: "[[ -f '" + marker + "' ]]", Action: "typeset -a items; items=(first second); print -rn -- ${items[2]} > '" + marker + "'"}
	engine := &Engine{}
	node := models.Node{Execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterZsh, LaunchDialect: ssh.LaunchPOSIX}}
	result := engine.runEnsure(t.Context(), client, spec, nil, false, node)
	if result.Status != StatusChanged {
		t.Fatalf("zsh ensure repair failed: %+v", result)
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "second" {
		t.Fatalf("zsh action changed semantics: %q, %v", data, err)
	}
	result = engine.runEnsure(t.Context(), client, spec, nil, false, node)
	if result.Status != StatusSkipped {
		t.Fatalf("zsh ensure failed to recognize repaired state: %+v", result)
	}
}
