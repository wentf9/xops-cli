package ssh

import (
	"fmt"
	"strings"
)

// FormatWorkingDirCommand formats a command prepended with working directory change
// based on the execution configuration, or returns an error if cwd cannot be applied.
func FormatWorkingDirCommand(cwd, command string, execution *ExecutionConfig) (string, error) {
	if cwd == "" {
		return command, nil
	}
	if strings.ContainsAny(cwd, "\r\n\x00") {
		return "", fmt.Errorf("%w: working directory contains illegal newline or null character", ErrExecutionValidation)
	}
	interp := execution.EffectiveInterpreter()

	switch interp {
	case InterpreterServer:
		return "", fmt.Errorf("%w: server interpreter does not support inheriting working directory %q", ErrExecutionValidation, cwd)

	case InterpreterBash, InterpreterSh:
		escaped := strings.ReplaceAll(cwd, "'", "'\\''")
		return fmt.Sprintf("cd -- '%s' && %s", escaped, command), nil

	case InterpreterCmd:
		if strings.ContainsAny(cwd, "%!^\r\n\"\x00") {
			return "", fmt.Errorf("%w: cmd working directory contains unsupported or expandable characters: %q", ErrExecutionValidation, cwd)
		}
		return fmt.Sprintf(`cd /d "%s" && %s`, cwd, command), nil

	case InterpreterPowerShell, InterpreterPwsh:
		escaped := strings.ReplaceAll(cwd, "'", "''")
		return fmt.Sprintf("Set-Location -LiteralPath '%s' -ErrorAction Stop; %s", escaped, command), nil

	default:
		return "", fmt.Errorf("%w: unsupported interpreter %q for working directory", ErrExecutionValidation, interp)
	}
}
