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
		cwd = NormalizeWindowsSFTPWorkingDir(cwd)
		if strings.ContainsAny(cwd, "%!^\r\n\"\x00") {
			return "", fmt.Errorf("%w: cmd working directory contains unsupported or expandable characters: %q", ErrExecutionValidation, cwd)
		}
		return fmt.Sprintf(`cd /d "%s" && %s`, cwd, command), nil

	case InterpreterPowerShell, InterpreterPwsh:
		if interp == InterpreterPowerShell || execution.LaunchDialect == LaunchCmd {
			cwd = NormalizeWindowsSFTPWorkingDir(cwd)
		}
		if interp == InterpreterPwsh {
			if native := NormalizeWindowsSFTPWorkingDir(cwd); native != cwd {
				// pwsh can run under either a POSIX or PowerShell outer shell.
				// Select using its own platform, including on cold connections.
				path := fmt.Sprintf("$(if ($IsWindows) { '%s' } else { '%s' })", strings.ReplaceAll(native, "'", "''"), strings.ReplaceAll(cwd, "'", "''"))
				return fmt.Sprintf("Set-Location -LiteralPath %s -ErrorAction Stop; %s", path, command), nil
			}
		}
		escaped := strings.ReplaceAll(cwd, "'", "''")
		return fmt.Sprintf("Set-Location -LiteralPath '%s' -ErrorAction Stop; %s", escaped, command), nil

	default:
		return "", fmt.Errorf("%w: unsupported interpreter %q for working directory", ErrExecutionValidation, interp)
	}
}

// NormalizeWindowsSFTPWorkingDir converts OpenSSH SFTP drive paths /C:/... to
// C:/... for cmd.exe and Windows PowerShell. Other paths stay untouched.
// Callers must establish Windows semantics before using it.
func NormalizeWindowsSFTPWorkingDir(cwd string) string {
	if len(cwd) >= 3 && cwd[0] == '/' && cwd[2] == ':' &&
		((cwd[1] >= 'A' && cwd[1] <= 'Z') || (cwd[1] >= 'a' && cwd[1] <= 'z')) {
		if len(cwd) == 3 {
			return cwd[1:] + "/"
		}
		if cwd[3] == '/' {
			return cwd[1:]
		}
	}
	return cwd
}
