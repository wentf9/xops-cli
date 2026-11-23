package ports_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
)

func TestP7W18a_AB18H1_ValidatePOSIXBournePlan(t *testing.T) {
	validCases := []struct {
		name    string
		options ssh.CommandOptions
	}{
		{name: "server_posix", options: ssh.CommandOptions{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchPOSIX}},
		{name: "sh_posix", options: ssh.CommandOptions{Interpreter: ssh.InterpreterSh, LaunchDialect: ssh.LaunchPOSIX}},
		{name: "bash_posix", options: ssh.CommandOptions{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}},
		{name: "zsh_posix", options: ssh.CommandOptions{Interpreter: ssh.InterpreterZsh, LaunchDialect: ssh.LaunchPOSIX}},
		{name: "sh_fish", options: ssh.CommandOptions{Interpreter: ssh.InterpreterSh, LaunchDialect: ssh.LaunchFish}},
		{name: "bash_fish", options: ssh.CommandOptions{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchFish}},
		{name: "zsh_fish", options: ssh.CommandOptions{Interpreter: ssh.InterpreterZsh, LaunchDialect: ssh.LaunchFish}},
		{name: "sh_csh", options: ssh.CommandOptions{Interpreter: ssh.InterpreterSh, LaunchDialect: ssh.LaunchCsh}},
		{name: "bash_csh", options: ssh.CommandOptions{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchCsh}},
		{name: "zsh_csh", options: ssh.CommandOptions{Interpreter: ssh.InterpreterZsh, LaunchDialect: ssh.LaunchCsh}},
	}
	for _, tc := range validCases {
		t.Run("valid_"+tc.name, func(t *testing.T) {
			plan, err := ssh.PlanCommand("echo ok", tc.options)
			if err != nil {
				t.Fatalf("PlanCommand(%+v): %v", tc.options, err)
			}
			if err := ports.ValidatePOSIXBournePlan(plan, "POSIX shell target (X11/Wayland) is required"); err != nil {
				t.Fatalf("ValidatePOSIXBournePlan(%+v) = %v, want nil", tc.options, err)
			}
		})
	}

	invalidCases := []struct {
		name    string
		options ssh.CommandOptions
	}{
		{name: "server_unknown", options: ssh.CommandOptions{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchUnknown}},
		{name: "server_fish", options: ssh.CommandOptions{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchFish}},
		{name: "server_csh", options: ssh.CommandOptions{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchCsh}},
		{name: "server_cmd", options: ssh.CommandOptions{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchCmd}},
		{name: "server_powershell", options: ssh.CommandOptions{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchPowerShell}},
		{name: "fish_posix", options: ssh.CommandOptions{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchPOSIX}},
		{name: "fish_fish", options: ssh.CommandOptions{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish}},
		{name: "csh_posix", options: ssh.CommandOptions{Interpreter: ssh.InterpreterCsh, LaunchDialect: ssh.LaunchPOSIX}},
		{name: "csh_csh", options: ssh.CommandOptions{Interpreter: ssh.InterpreterCsh, LaunchDialect: ssh.LaunchCsh}},
		{name: "tcsh_posix", options: ssh.CommandOptions{Interpreter: ssh.InterpreterTcsh, LaunchDialect: ssh.LaunchPOSIX}},
		{name: "pwsh_posix", options: ssh.CommandOptions{Interpreter: ssh.InterpreterPwsh, LaunchDialect: ssh.LaunchPOSIX}},
		{name: "pwsh_cmd", options: ssh.CommandOptions{Interpreter: ssh.InterpreterPwsh, LaunchDialect: ssh.LaunchCmd}},
		{name: "powershell_powershell", options: ssh.CommandOptions{Interpreter: ssh.InterpreterPowerShell, LaunchDialect: ssh.LaunchPowerShell}},
		{name: "cmd_cmd", options: ssh.CommandOptions{Interpreter: ssh.InterpreterCmd, LaunchDialect: ssh.LaunchCmd}},
	}
	for _, tc := range invalidCases {
		t.Run("invalid_"+tc.name, func(t *testing.T) {
			plan, err := ssh.PlanCommand("echo ok", tc.options)
			if err != nil {
				t.Fatalf("PlanCommand(%+v): %v", tc.options, err)
			}
			for _, purpose := range []string{"POSIX shell target (X11/Wayland) is required", "generated filesystem commands"} {
				err := ports.ValidatePOSIXBournePlan(plan, purpose)
				if !errors.Is(err, ssh.ErrExecutionValidation) {
					t.Fatalf("ValidatePOSIXBournePlan(%s, %q) = %v, want ErrExecutionValidation", tc.name, purpose, err)
				}
				if !strings.Contains(err.Error(), purpose) {
					t.Fatalf("ValidatePOSIXBournePlan(%s) = %q, want purpose %q", tc.name, err.Error(), purpose)
				}
			}
		})
	}

	t.Run("zero_value_plan_rejected", func(t *testing.T) {
		if err := ports.ValidatePOSIXBournePlan(ssh.CommandPlan{}, ""); !errors.Is(err, ssh.ErrExecutionValidation) {
			t.Fatalf("ValidatePOSIXBournePlan(zero) = %v, want ErrExecutionValidation", err)
		}
	})
}

func TestP7W18a_AB18H1_ResolvePOSIXBourneExecutionAndProbe(t *testing.T) {
	yes, no := true, false
	t.Run("configured_valid_and_coerced", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			in          *ssh.ExecutionConfig
			wantInterp  ssh.Interpreter
			wantDialect ssh.LaunchDialect
		}{
			{"server_posix", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchPOSIX}, ssh.InterpreterServer, ssh.LaunchPOSIX},
			{"implicit_server_posix", &ssh.ExecutionConfig{LaunchDialect: ssh.LaunchPOSIX}, "", ssh.LaunchPOSIX},
			{"bash_fish", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchFish}, ssh.InterpreterBash, ssh.LaunchFish},
			{"sh_csh", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterSh, LaunchDialect: ssh.LaunchCsh}, ssh.InterpreterSh, ssh.LaunchCsh},
			{"unpinned_fish_coerces_to_sh", &ssh.ExecutionConfig{LaunchDialect: ssh.LaunchFish}, ssh.InterpreterSh, ssh.LaunchFish},
			{"unpinned_csh_coerces_to_sh", &ssh.ExecutionConfig{LaunchDialect: ssh.LaunchCsh, Login: &no}, ssh.InterpreterSh, ssh.LaunchCsh},
		} {
			got, err := ports.ResolvePOSIXBourneExecution(tc.in)
			if err != nil {
				t.Fatalf("%s: unexpected err: %v", tc.name, err)
			}
			if got.Interpreter != tc.wantInterp || got.LaunchDialect != tc.wantDialect {
				t.Fatalf("%s: got %+v, want interpreter=%q dialect=%q", tc.name, got, tc.wantInterp, tc.wantDialect)
			}
		}
	})

	t.Run("configured_invalid_fails_closed", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			in   *ssh.ExecutionConfig
		}{
			{"nil", nil},
			{"unknown", &ssh.ExecutionConfig{LaunchDialect: ssh.LaunchUnknown}},
			{"explicit_fish_posix", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchPOSIX}},
			{"explicit_fish_fish", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish}},
			{"explicit_csh_posix", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterCsh, LaunchDialect: ssh.LaunchPOSIX}},
			{"explicit_tcsh_csh", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterTcsh, LaunchDialect: ssh.LaunchCsh}},
			{"explicit_pwsh_posix", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterPwsh, LaunchDialect: ssh.LaunchPOSIX}},
			{"explicit_server_fish", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchFish}},
			{"unpinned_fish_login_true", &ssh.ExecutionConfig{LaunchDialect: ssh.LaunchFish, Login: &yes}},
			{"cmd", &ssh.ExecutionConfig{LaunchDialect: ssh.LaunchCmd}},
			{"powershell", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterPowerShell, LaunchDialect: ssh.LaunchPowerShell}},
		} {
			if got, err := ports.ResolvePOSIXBourneExecution(tc.in); !errors.Is(err, ssh.ErrExecutionValidation) {
				t.Fatalf("%s: got (%+v, %v), want ErrExecutionValidation", tc.name, got, err)
			}
		}
	})

	t.Run("probed_coercion_and_rejection", func(t *testing.T) {
		fishWithSh := &ssh.ProbeResult{
			DetectedDialect:       ssh.LaunchFish,
			AvailableInterpreters: []ssh.Interpreter{ssh.InterpreterBash, ssh.InterpreterSh, ssh.InterpreterFish},
			SuggestedConfig:       ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish, Login: &no},
		}
		got, err := ports.ResolvePOSIXBourneExecutionFromProbe(fishWithSh)
		if err != nil || got.Interpreter != ssh.InterpreterSh || got.LaunchDialect != ssh.LaunchFish {
			t.Fatalf("fish with sh: got (%+v, %v), want sh over fish", got, err)
		}

		cshWithBashOnly := &ssh.ProbeResult{
			DetectedDialect:       ssh.LaunchCsh,
			AvailableInterpreters: []ssh.Interpreter{ssh.InterpreterBash, ssh.InterpreterCsh},
			SuggestedConfig:       ssh.ExecutionConfig{Interpreter: ssh.InterpreterCsh, LaunchDialect: ssh.LaunchCsh, Login: &no},
		}
		got, err = ports.ResolvePOSIXBourneExecutionFromProbe(cshWithBashOnly)
		if err != nil || got.Interpreter != ssh.InterpreterBash || got.LaunchDialect != ssh.LaunchCsh {
			t.Fatalf("csh with bash only: got (%+v, %v), want bash over csh", got, err)
		}

		fishWithZshOnly := &ssh.ProbeResult{
			DetectedDialect:       ssh.LaunchFish,
			AvailableInterpreters: []ssh.Interpreter{ssh.InterpreterZsh, ssh.InterpreterFish},
			SuggestedConfig:       ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish, Login: &no},
		}
		got, err = ports.ResolvePOSIXBourneExecutionFromProbe(fishWithZshOnly)
		if err != nil || got.Interpreter != ssh.InterpreterZsh || got.LaunchDialect != ssh.LaunchFish {
			t.Fatalf("fish with zsh only: got (%+v, %v), want zsh over fish", got, err)
		}

		fishOnly := &ssh.ProbeResult{
			DetectedDialect:       ssh.LaunchFish,
			AvailableInterpreters: []ssh.Interpreter{ssh.InterpreterFish},
			SuggestedConfig:       ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish, Login: &no},
		}
		if got, err := ports.ResolvePOSIXBourneExecutionFromProbe(fishOnly); !errors.Is(err, ssh.ErrExecutionValidation) {
			t.Fatalf("fish only: got (%+v, %v), want ErrExecutionValidation", got, err)
		}

		winCmdWithGitBash := &ssh.ProbeResult{
			DetectedDialect:       ssh.LaunchCmd,
			AvailableInterpreters: []ssh.Interpreter{ssh.InterpreterBash, ssh.InterpreterSh, ssh.InterpreterCmd},
			SuggestedConfig:       ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchCmd},
		}
		if got, err := ports.ResolvePOSIXBourneExecutionFromProbe(winCmdWithGitBash); !errors.Is(err, ssh.ErrExecutionValidation) {
			t.Fatalf("win cmd: got (%+v, %v), want ErrExecutionValidation", got, err)
		}

		winPS := &ssh.ProbeResult{
			DetectedDialect:       ssh.LaunchPowerShell,
			AvailableInterpreters: []ssh.Interpreter{ssh.InterpreterPowerShell, ssh.InterpreterSh},
			SuggestedConfig:       ssh.ExecutionConfig{Interpreter: ssh.InterpreterPowerShell, LaunchDialect: ssh.LaunchPowerShell},
		}
		if got, err := ports.ResolvePOSIXBourneExecutionFromProbe(winPS); !errors.Is(err, ssh.ErrExecutionValidation) {
			t.Fatalf("win powershell: got (%+v, %v), want ErrExecutionValidation", got, err)
		}
	})
}
