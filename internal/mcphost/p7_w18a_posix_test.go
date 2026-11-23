package mcphost

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
)

func TestP7W18a_AB18H1_LegacyHostPOSIXBournePlanValidation(t *testing.T) {
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
			name:    "pwsh_over_posix_rejected_for_require_posix",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterPwsh, LaunchDialect: ssh.LaunchPOSIX},
			cmd:     ports.Command{Text: "echo ok", RequirePOSIX: true},
			invalid: true,
		},
		{
			name:    "fish_over_posix_rejected_for_filesystem",
			node:    &ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchPOSIX, Login: &no},
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, server, oldPermit, commands, ctx := newExecutionBackendFixture(t, ssh.SudoModeRoot)
			view := oldPermit.Snapshot()
			target := view.Targets["node"]
			target.Execution = tc.node
			view.Targets["node"] = target
			binding, err := ports.Bind(view, "fixture", "gui", struct{}{})
			if err != nil {
				t.Fatal(err)
			}
			execPermit, err := ports.NewPermit(ctx, ports.Admission{OperationID: "w18a-posix", Phase: ports.Execute, Snapshot: view, Binding: binding}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := execPermit.Close(); err != nil {
					t.Error(err)
				}
			})

			res, err := b.Run(ctx, execPermit, "node", tc.cmd)
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
