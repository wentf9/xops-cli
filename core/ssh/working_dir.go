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
	interp := InterpreterBash
	if execution != nil && execution.EffectiveInterpreter() != "" {
		interp = execution.EffectiveInterpreter()
	}

	switch interp {
	case InterpreterServer:
		if cwd != "/" {
			return "", fmt.Errorf("%w: server interpreter does not support inheriting working directory %q", ErrExecutionValidation, cwd)
		}
		return command, nil

	case InterpreterBash, InterpreterSh:
		escaped := strings.ReplaceAll(cwd, "'", "'\\''")
		return fmt.Sprintf("cd -- '%s' && %s", escaped, command), nil

	case InterpreterCmd:
		escaped := strings.ReplaceAll(cwd, `"`, `\"`)
		return fmt.Sprintf(`cd /d "%s" && %s`, escaped, command), nil

	case InterpreterPowerShell, InterpreterPwsh:
		escaped := strings.ReplaceAll(cwd, "'", "''")
		return fmt.Sprintf("Set-Location -LiteralPath '%s' -ErrorAction Stop; %s", escaped, command), nil

	default:
		return "", fmt.Errorf("%w: unsupported interpreter %q for working directory", ErrExecutionValidation, interp)
	}
}
