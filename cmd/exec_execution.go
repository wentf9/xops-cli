package cmd

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

type execExecutionOptions struct {
	interpreter                                      string
	dialect                                          string
	login                                            bool
	interpreterSet, dialectSet, loginSet, noLoginSet bool
}

func (o *execExecutionOptions) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.interpreter, "interpreter", "", i18n.T("flag_exec_interpreter"))
	cmd.Flags().StringVar(&o.dialect, "launch-dialect", "", i18n.T("flag_exec_launch_dialect"))
	cmd.Flags().BoolVar(&o.login, "login-shell", false, i18n.T("flag_exec_login_shell"))
}

func (o *execExecutionOptions) capturePresence(cmd *cobra.Command) {
	if cmd == nil {
		return
	}
	o.interpreterSet = cmd.Flags().Changed("interpreter")
	o.dialectSet = cmd.Flags().Changed("launch-dialect")
	o.loginSet = cmd.Flags().Changed("login-shell")
	o.noLoginSet = cmd.Flags().Changed("no-login")
}

func (o execExecutionOptions) enabled() bool { return o.interpreterSet || o.dialectSet || o.loginSet }

func (o *ExecOptions) prepareCommandPlan() error {
	if !o.execution.enabled() {
		return nil
	}
	if o.Interactive || o.Sudo || o.ShellFile != "" || o.stdinScript || o.Stream || o.OutDir != "" {
		return fmt.Errorf("explicit execution currently supports ordinary buffered commands only, without scripts, PTY, sudo, --stream or --out-dir")
	}
	options, err := o.execution.commandOptions(o.NoLoginShell)
	if err != nil {
		return err
	}
	plan, err := ssh.PlanCommand(o.Command, options)
	if err != nil {
		return fmt.Errorf("plan explicit command: %w", err)
	}
	o.commandPlan = &plan
	return nil
}

func (o execExecutionOptions) commandOptions(noLogin bool) (ssh.CommandOptions, error) {
	if (o.interpreterSet && o.interpreter == "") || (o.dialectSet && o.dialect == "") {
		return ssh.CommandOptions{}, fmt.Errorf("explicit interpreter and launch dialect must not be empty")
	}
	options := ssh.CommandOptions{Interpreter: ssh.Interpreter(o.interpreter), LaunchDialect: ssh.LaunchDialect(o.dialect)}
	// P1 retains the entry point's Bash+login default. A dialect/login override
	// alone must not opt the caller into server mode before the default switch.
	if !o.interpreterSet {
		options.Interpreter, options.Login = ssh.InterpreterBash, ssh.LoginEnabled
	}
	if o.loginSet {
		options.Login = ssh.LoginDisabled
		if o.login {
			options.Login = ssh.LoginEnabled
		}
	}
	if o.noLoginSet {
		if o.loginSet {
			return ssh.CommandOptions{}, fmt.Errorf("--no-login and --login-shell are mutually exclusive")
		}
		if options.Interpreter != "" && options.Interpreter != ssh.InterpreterBash {
			return ssh.CommandOptions{}, fmt.Errorf("--no-login requires the bash interpreter")
		}
		options.Interpreter, options.Login = ssh.InterpreterBash, ssh.LoginEnabled
		if noLogin {
			options.Login = ssh.LoginDisabled
		}
		if options.LaunchDialect == "" {
			options.LaunchDialect = ssh.LaunchPOSIX
		}
	}
	return options, nil
}

func (o *ExecOptions) executePlannedTask(ctx context.Context, connector *ssh.Connector, task execHostTask, command string, isScript bool, stdoutMu *sync.Mutex) error {
	if isScript || o.commandPlan.Command() != command {
		return fmt.Errorf("[%s] command changed after execution planning", task.host)
	}
	client, err := connector.Connect(ctx, task.nodeID)
	if err != nil {
		return fmt.Errorf("[%s] connect failed: %w", task.host, err)
	}
	result := client.ExecuteCommand(ctx, *o.commandPlan)
	execErr := result.Err()
	printErr := o.printTaskResult(task, result.Output, execErr, stdoutMu)
	if execErr != nil {
		return errors.Join(fmt.Errorf("[%s] command outcome=%s phase=%s: %w", task.host, result.Outcome, result.Phase, execErr), printErr)
	}
	return printErr
}
