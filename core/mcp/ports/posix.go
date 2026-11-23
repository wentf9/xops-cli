package ports

import (
	"fmt"
	"slices"

	"github.com/wentf9/xops-cli/core/ssh"
)

// IsPOSIXBourneInterpreter reports whether interpreter executes POSIX Bourne
// shell syntax (sh, bash, or zsh).
func IsPOSIXBourneInterpreter(interpreter ssh.Interpreter) bool {
	switch interpreter {
	case ssh.InterpreterSh, ssh.InterpreterBash, ssh.InterpreterZsh:
		return true
	default:
		return false
	}
}

func isUnixLaunchDialect(dialect ssh.LaunchDialect) bool {
	switch dialect {
	case ssh.LaunchPOSIX, ssh.LaunchFish, ssh.LaunchCsh:
		return true
	default:
		return false
	}
}

// ValidatePOSIXBournePlan verifies that plan executes its command body under a
// POSIX Bourne shell interpreter. A CommandPlan is POSIX Bourne iff:
//   - Interpreter == InterpreterServer && LaunchDialect == LaunchPOSIX, OR
//   - Interpreter in {sh, bash, zsh} && LaunchDialect is a known Unix launch
//     dialect (posix, fish, or csh; never unknown, cmd, or powershell).
func ValidatePOSIXBournePlan(plan ssh.CommandPlan, purpose string) error {
	interp := plan.Interpreter()
	dialect := plan.LaunchDialect()
	if (interp == ssh.InterpreterServer && dialect == ssh.LaunchPOSIX) ||
		(IsPOSIXBourneInterpreter(interp) && dialect != ssh.LaunchUnknown && isUnixLaunchDialect(dialect)) {
		return nil
	}
	if purpose == "" {
		purpose = "POSIX Bourne shell execution is required"
	}
	return fmt.Errorf("%w: non-POSIX execution plan (interpreter=%q, launch_dialect=%q) is not supported; %s",
		ssh.ErrExecutionValidation, interp, dialect, purpose)
}

// ResolvePOSIXBourneExecution validates or derives an execution config that
// guarantees POSIX Bourne execution without overriding an explicitly pinned
// non-POSIX interpreter.
//
// When effective has no explicit interpreter override (Interpreter == "") on a
// fish or csh login shell (LaunchFish / LaunchCsh) without login=true, it
// coerces the interpreter to sh over the trusted launch dialect. Windows
// dialects (cmd/powershell), unknown dialects, and explicitly pinned non-POSIX
// interpreters fail closed with ssh.ErrExecutionValidation.
func ResolvePOSIXBourneExecution(effective *ssh.ExecutionConfig) (*ssh.ExecutionConfig, error) {
	if effective == nil {
		return nil, fmt.Errorf("%w: unknown execution dialect is not supported; POSIX shell target (X11/Wayland) is required", ssh.ErrExecutionValidation)
	}
	if err := effective.Validate(); err != nil {
		return nil, err
	}
	if effective.EffectiveInterpreter() == ssh.InterpreterServer && effective.LaunchDialect == ssh.LaunchPOSIX {
		return effective.Clone(), nil
	}
	if IsPOSIXBourneInterpreter(effective.Interpreter) && isUnixLaunchDialect(effective.LaunchDialect) {
		return effective.Clone(), nil
	}
	if effective.Interpreter == "" && (effective.LaunchDialect == ssh.LaunchFish || effective.LaunchDialect == ssh.LaunchCsh) {
		if effective.Login != nil && *effective.Login {
			return nil, fmt.Errorf("%w: non-POSIX execution config (interpreter=%q, launch_dialect=%q, login=true) is not supported; POSIX shell target (X11/Wayland) is required",
				ssh.ErrExecutionValidation, effective.EffectiveInterpreter(), effective.LaunchDialect)
		}
		login := false
		return &ssh.ExecutionConfig{
			Interpreter:   ssh.InterpreterSh,
			LaunchDialect: effective.LaunchDialect,
			Login:         &login,
		}, nil
	}
	return nil, fmt.Errorf("%w: non-POSIX execution config (interpreter=%q, launch_dialect=%q) is not supported; POSIX shell target (X11/Wayland) is required",
		ssh.ErrExecutionValidation, effective.EffectiveInterpreter(), effective.LaunchDialect)
}

// ResolvePOSIXBourneExecutionFromProbe selects a POSIX Bourne execution config
// from a completed SSH execution probe. If the probed target uses a fish or csh
// login shell (or suggested a non-POSIX interpreter over a Unix launch dialect)
// and sh, bash, or zsh is present in AvailableInterpreters, it coerces the
// interpreter to sh (else bash, else zsh) over the detected launch dialect.
// Windows targets or Unix targets without any available POSIX Bourne shell fail
// closed with ssh.ErrExecutionValidation.
func ResolvePOSIXBourneExecutionFromProbe(result *ssh.ProbeResult) (*ssh.ExecutionConfig, error) {
	if result == nil {
		return nil, fmt.Errorf("%w: missing execution probe result; POSIX shell target (X11/Wayland) is required", ssh.ErrExecutionValidation)
	}
	if err := result.SuggestedConfig.Validate(); err != nil {
		return nil, err
	}
	if !isUnixLaunchDialect(result.DetectedDialect) {
		return nil, fmt.Errorf("%w: non-POSIX execution dialect %q is not supported; POSIX shell target (X11/Wayland) is required",
			ssh.ErrExecutionValidation, result.DetectedDialect)
	}
	suggested := result.SuggestedConfig.Clone()
	if (suggested.EffectiveInterpreter() == ssh.InterpreterServer && suggested.LaunchDialect == ssh.LaunchPOSIX) ||
		(IsPOSIXBourneInterpreter(suggested.Interpreter) && isUnixLaunchDialect(suggested.LaunchDialect)) {
		return suggested, nil
	}
	for _, candidate := range []ssh.Interpreter{ssh.InterpreterSh, ssh.InterpreterBash, ssh.InterpreterZsh} {
		if slices.Contains(result.AvailableInterpreters, candidate) {
			login := false
			return &ssh.ExecutionConfig{
				Interpreter:   candidate,
				LaunchDialect: result.DetectedDialect,
				Login:         &login,
			}, nil
		}
	}
	return nil, fmt.Errorf("%w: probed %s target has no available POSIX Bourne shell (sh, bash, zsh); POSIX shell target (X11/Wayland) is required",
		ssh.ErrExecutionValidation, result.DetectedDialect)
}
