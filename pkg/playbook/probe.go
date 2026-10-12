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
	if effective.LaunchDialect != ssh.LaunchPOSIX || (effective.Interpreter != ssh.InterpreterBash && effective.Interpreter != ssh.InterpreterSh) {
		return nil, fmt.Errorf("%w: ensure requires a POSIX bash or sh adapter", ssh.ErrExecutionValidation)
	}
	return effective, nil
}
