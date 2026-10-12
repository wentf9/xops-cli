package playbook

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

func (e *Engine) resolveRuntimeScriptExecution(ctx context.Context, client *ssh.Client, step, settings, node, global *ssh.ExecutionConfig, content []byte) (*ssh.ExecutionConfig, error) {
	shebang := ssh.ParseShebang(content)
	if !shebang.HasBOM && !shebang.HasShebang {
		effective, err := ssh.EffectiveExecution(step, settings, node, global)
		if err != nil {
			return nil, err
		}
		if ssh.NeedsExecutionProbe(effective) {
			probed, err := client.ProbeControlledExecution(ctx, effective)
			if err != nil {
				return nil, err
			}
			return ssh.ResolveScriptExecution(probed, nil, nil, nil, content)
		}
	}
	return ssh.ResolveScriptExecution(step, settings, node, global, content)
}

func (e *Engine) resolveEnsureExecution(ctx context.Context, client *ssh.Client, step *ssh.ExecutionConfig, node models.Node) (*ssh.ExecutionConfig, error) {
	var settings *ssh.ExecutionConfig
	if e.pb != nil {
		settings = e.pb.Settings.Execution
	}
	effective, err := ssh.EffectiveExecution(step, settings, node.Execution, e.globalExecution())
	if err != nil {
		return nil, err
	}
	effective, err = client.ProbeControlledExecution(ctx, effective)
	if err != nil {
		return nil, err
	}
	if effective.EffectiveInterpreter() == ssh.InterpreterServer {
		return nil, fmt.Errorf("ensure check unsupported with server interpreter: cannot verify check result origin without controlled shell adapter")
	}
	if (effective.LaunchDialect != ssh.LaunchPOSIX && effective.LaunchDialect != ssh.LaunchFish) || (effective.Interpreter != ssh.InterpreterBash && effective.Interpreter != ssh.InterpreterSh && effective.Interpreter != ssh.InterpreterZsh && effective.Interpreter != ssh.InterpreterFish) {
		return nil, fmt.Errorf("%w: ensure requires a bash, sh, zsh or fish adapter with a posix or fish launch dialect", ssh.ErrExecutionValidation)
	}
	return effective, nil
}

// Check completion is framed inside the selected interpreter, including checks
// that explicitly exit. An exec replacement or parse failure emits no frame,
// so the caller fails closed instead of running an action on uncertain state.
func wrapEnsureCheck(command, marker string, interpreter ssh.Interpreter) string {
	if interpreter == ssh.InterpreterFish {
		return fmt.Sprintf("function %s --on-event fish_exit\n  builtin printf '\\n%s:%%d\\n' $status\nend\n%s\n", marker, marker, command)
	}
	return fmt.Sprintf("{\n  trap 'printf \"\\n%s:%%d\\n\" \"$?\"' EXIT\n  %s\n}", marker, command)
}

// Reserved shell statuses can describe a failure before the condition ran.
// Treat them conservatively even when user code explicitly returns that value.
func ensureCheckExecutionError(interpreter ssh.Interpreter, code uint32) error {
	if code == 126 || code == 127 {
		return fmt.Errorf("ensure check exited with reserved execution-error status %d, action not executed", code)
	}
	if interpreter == ssh.InterpreterFish {
		switch code {
		case 121, 123, 124, 125:
			return fmt.Errorf("fish ensure check exited with reserved execution-error status %d, action not executed", code)
		}
	}
	return nil
}
