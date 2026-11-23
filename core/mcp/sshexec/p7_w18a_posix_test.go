package sshexec_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestP7W18a_AB18H1_BackendPOSIXBournePlanValidation(t *testing.T) {
	no := false
	cases := []struct {
		name    string
		node    *ssh.ExecutionConfig
		cmd     ports.Command
		invalid bool
		wantCmd string
	}{
		{
			name:    "fish_over_posix_rejected_for_require_posix",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchPOSIX, Login: &no},
			cmd:     ports.Command{Text: "echo ok", RequirePOSIX: true},
			invalid: true,
		},
		{
			name:    "csh_over_posix_rejected_for_require_posix",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterCsh, LaunchDialect: ssh.LaunchPOSIX, Login: &no},
			cmd:     ports.Command{Text: "echo ok", RequirePOSIX: true},
			invalid: true,
		},
		{
			name:    "tcsh_over_posix_rejected_for_filesystem",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterTcsh, LaunchDialect: ssh.LaunchPOSIX, Login: &no},
			cmd:     ports.Command{Text: "rm -rf '/tmp/test'", Filesystem: true},
			invalid: true,
		},
		{
			name:    "pwsh_over_posix_rejected_for_require_posix",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterPwsh, LaunchDialect: ssh.LaunchPOSIX},
			cmd:     ports.Command{Text: "echo ok", RequirePOSIX: true},
			invalid: true,
		},
		{
			name:    "pwsh_over_posix_rejected_for_filesystem",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterPwsh, LaunchDialect: ssh.LaunchPOSIX},
			cmd:     ports.Command{Text: "rm -rf '/tmp/test'", Filesystem: true},
			invalid: true,
		},
		{
			name:    "sh_over_fish_allowed_for_require_posix",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterSh, LaunchDialect: ssh.LaunchFish, Login: &no},
			cmd:     ports.Command{Text: `echo 'hi'`, RequirePOSIX: true},
			invalid: false,
			wantCmd: `sh -c 'echo \'hi\''`,
		},
		{
			name:    "bash_over_csh_allowed_for_filesystem",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchCsh, Login: &no},
			cmd:     ports.Command{Text: "rm -rf '/tmp/a'", Filesystem: true},
			invalid: false,
			wantCmd: `bash -c 'rm -rf '\''/tmp/a'\'''`,
		},
		{
			name:    "zsh_over_fish_allowed_for_require_posix",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterZsh, LaunchDialect: ssh.LaunchFish, Login: &no},
			cmd:     ports.Command{Text: "echo ok", RequirePOSIX: true},
			invalid: false,
			wantCmd: "zsh -c 'echo ok'",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			commands := make(chan string, 2)
			backend, view, server, ctx := setupBackendWithHandler(t, func(command string, ch cryptoSSH.Channel) {
				commands <- command
				_, _ = io.WriteString(ch, "ok")
				_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
			})
			target := view.Targets["node"]
			target.Execution = tc.node
			view.Targets["node"] = target

			res, err := backend.Run(ctx, permit(t, ctx, view, ports.Execute), "node", tc.cmd)
			if tc.invalid {
				if !errors.Is(err, ssh.ErrExecutionValidation) || res.Outcome != ssh.ExecutionNotStarted || server.Executed.Load() != 0 {
					t.Fatalf("got res=%+v err=%v executed=%d, want ErrExecutionValidation + not_started + 0 execs", res, err, server.Executed.Load())
				}
				if tc.cmd.RequirePOSIX && !strings.Contains(err.Error(), "POSIX shell target (X11/Wayland) is required") {
					t.Fatalf("unexpected RequirePOSIX error: %v", err)
				}
				if tc.cmd.Filesystem && !strings.Contains(err.Error(), "generated filesystem commands") {
					t.Fatalf("unexpected Filesystem error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got := <-commands; got != tc.wantCmd {
				t.Fatalf("payload = %q, want %q", got, tc.wantCmd)
			}
		})
	}
}

func TestP7W18a_AB18M1_BackendInspectPathRespectsPermitPhase(t *testing.T) {
	backend, view, _, ctx := setupBackend(t)

	// OpenFiles MUST continue rejecting Inspect permits.
	inspectPermit := permit(t, ctx, view, ports.Inspect)
	if _, err := backend.OpenFiles(ctx, inspectPermit, "node"); !errors.Is(err, ports.ErrPurpose) {
		t.Fatalf("OpenFiles(Inspect) = %v, want ErrPurpose", err)
	}

	// InspectPath rejects TransferStart permits.
	transferPermit := permit(t, ctx, view, ports.TransferStart)
	if _, err := backend.InspectPath(ctx, transferPermit, "node", ports.PathInspectRequest{Path: "/tmp/file"}); !errors.Is(err, ports.ErrPurpose) {
		t.Fatalf("InspectPath(TransferStart) = %v, want ErrPurpose", err)
	}

	// InspectPath succeeds with Inspect permit.
	res, err := backend.InspectPath(ctx, inspectPermit, "node", ports.PathInspectRequest{Path: "/tmp/file"})
	if err != nil {
		t.Fatalf("InspectPath(Inspect): %v", err)
	}
	if res.CanonicalPath != "/tmp/file" {
		t.Fatalf("InspectPath CanonicalPath = %q, want /tmp/file", res.CanonicalPath)
	}
}
