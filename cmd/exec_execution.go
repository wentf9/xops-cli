package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

func (o execExecutionOptions) needsNodeResolution() bool {
	return o.interpreterSet && !o.dialectSet && o.interpreter != "" && o.interpreter != string(ssh.InterpreterServer) && !o.noLoginSet
}

func (o execExecutionOptions) toExecutionConfig(noLogin bool) (*ssh.ExecutionConfig, error) {
	if !o.enabled() && !o.noLoginSet {
		return nil, nil
	}
	if o.noLoginSet {
		opts, err := o.commandOptions(noLogin)
		if err != nil {
			return nil, err
		}
		login := opts.Login == ssh.LoginEnabled
		return &ssh.ExecutionConfig{Interpreter: opts.Interpreter, LaunchDialect: opts.LaunchDialect, Login: &login}, nil
	}
	if (o.interpreterSet && o.interpreter == "") || (o.dialectSet && o.dialect == "") {
		return nil, fmt.Errorf("explicit interpreter and launch dialect must not be empty")
	}
	cliExec := &ssh.ExecutionConfig{}
	if o.interpreterSet {
		cliExec.Interpreter = ssh.Interpreter(o.interpreter)
	}
	if o.dialectSet {
		cliExec.LaunchDialect = ssh.LaunchDialect(o.dialect)
	}
	if o.loginSet {
		login := o.login
		cliExec.Login = &login
	}
	return cliExec, cliExec.Validate()
}

func probeDialectForInterpreter(interp ssh.Interpreter) ssh.LaunchDialect {
	switch interp {
	case ssh.InterpreterBash, ssh.InterpreterSh, ssh.InterpreterZsh:
		return ssh.LaunchPOSIX
	case ssh.InterpreterFish:
		return ssh.LaunchFish
	case ssh.InterpreterCsh, ssh.InterpreterTcsh:
		return ssh.LaunchCsh
	case ssh.InterpreterPowerShell, ssh.InterpreterPwsh, ssh.InterpreterCmd:
		return ssh.LaunchCmd
	default:
		return ""
	}
}

func validateDeferredCommandOptions(command string, options ssh.CommandOptions, sudo bool, cliExec *ssh.ExecutionConfig) error {
	probeOpts := options
	if probeDialect := probeDialectForInterpreter(options.Interpreter); probeDialect != "" {
		probeOpts.LaunchDialect = probeDialect
	}
	if sudo && cliExec != nil {
		probeExec := cliExec.Clone()
		probeExec.LaunchDialect = probeOpts.LaunchDialect
		if _, err := probeExec.SudoRunOptions(command); err != nil {
			return err
		}
	}
	_, err := ssh.PlanCommand(command, probeOpts)
	return err
}

func isSupportedScriptInterpreter(interp ssh.Interpreter) bool {
	switch interp {
	case "", ssh.InterpreterBash, ssh.InterpreterSh, ssh.InterpreterZsh, ssh.InterpreterFish, ssh.InterpreterCsh, ssh.InterpreterTcsh:
		return true
	default:
		return false
	}
}

func (o *ExecOptions) validateScriptArgs() error {
	if len(o.ScriptArgs) > 0 && o.ShellFile == "" {
		return fmt.Errorf("script arguments can only be specified when running a script with --shell")
	}
	for _, arg := range o.ScriptArgs {
		if strings.ContainsRune(arg, '\x00') {
			return fmt.Errorf("script arguments must not contain NUL bytes")
		}
	}
	return nil
}

func (o *ExecOptions) prepareDeferredCommandPlan(command string, options ssh.CommandOptions) error {
	var cliExec *ssh.ExecutionConfig
	if o.Sudo {
		var err error
		cliExec, err = o.cliExecutionConfig()
		if err != nil {
			return err
		}
	}
	if err := validateDeferredCommandOptions(command, options, o.Sudo, cliExec); err != nil {
		if o.Command == "" || o.Sudo {
			return err
		}
		return fmt.Errorf("plan explicit command: %w", err)
	}
	return nil
}

func (o *ExecOptions) prepareCommandPlan() error {
	if err := o.validateScriptArgs(); err != nil {
		return err
	}
	if !o.execution.enabled() {
		return nil
	}
	o.commandPlan = nil

	if o.ShellFile != "" || o.stdinScript || (o.Command == "" && !o.Interactive) {
		execution, err := o.cliExecutionConfig()
		if err != nil {
			return err
		}
		if !isSupportedScriptInterpreter(execution.Interpreter) {
			return fmt.Errorf("%w: scripts require bash, sh, zsh, fish, csh or tcsh", ssh.ErrExecutionValidation)
		}
		// Full resolution needs the actual script and the target node. Do not
		// turn an absent interpreter/dialect into an explicit server/unknown.
		return nil
	}
	options, err := o.execution.commandOptions(o.NoLoginShell)
	if err != nil {
		return err
	}
	command := o.Command
	if command == "" {
		command = ":" // Validate options before consuming a possible stdin script.
	}
	if o.execution.needsNodeResolution() {
		return o.prepareDeferredCommandPlan(command, options)
	}
	if o.Sudo {
		execution, err := o.cliExecutionConfig()
		if err != nil {
			return err
		}
		if _, err := execution.SudoRunOptions(command); err != nil {
			return err
		}
	}
	if o.Command == "" {
		_, err := ssh.PlanCommand(command, options)
		return err
	}
	plan, err := ssh.PlanCommand(o.Command, options)
	if err != nil {
		return fmt.Errorf("plan explicit command: %w", err)
	}
	o.commandPlan = &plan
	return nil
}

func (o *ExecOptions) resolveCommandPlan(command string, nodeExec *ssh.ExecutionConfig) (ssh.CommandPlan, error) {
	if o.commandPlan != nil {
		if o.commandPlan.Command() != command {
			return ssh.CommandPlan{}, fmt.Errorf("command changed after execution planning")
		}
		return *o.commandPlan, nil
	}
	cliExec, err := o.cliExecutionConfig()
	if err != nil {
		return ssh.CommandPlan{}, err
	}
	resolved, err := ssh.ResolveExecution(cliExec, nodeExec)
	if err != nil {
		return ssh.CommandPlan{}, fmt.Errorf("plan explicit command: %w", err)
	}
	plan, err := ssh.PlanCommand(command, resolved.CommandOptions())
	if err != nil {
		return ssh.CommandPlan{}, fmt.Errorf("plan explicit command: %w", err)
	}
	return plan, nil
}

func (o execExecutionOptions) commandOptions(noLogin bool) (ssh.CommandOptions, error) {
	if (o.interpreterSet && o.interpreter == "") || (o.dialectSet && o.dialect == "") {
		return ssh.CommandOptions{}, fmt.Errorf("explicit interpreter and launch dialect must not be empty")
	}
	options := ssh.CommandOptions{Interpreter: ssh.Interpreter(o.interpreter), LaunchDialect: ssh.LaunchDialect(o.dialect)}
	if !o.interpreterSet {
		options.Interpreter, options.LaunchDialect, options.Login = ssh.InterpreterServer, ssh.LaunchUnknown, ssh.LoginInherit
		if o.dialectSet {
			options.LaunchDialect = ssh.LaunchDialect(o.dialect)
		}
	}
	if o.loginSet {
		if options.Interpreter == ssh.InterpreterServer {
			return ssh.CommandOptions{}, fmt.Errorf("server interpreter requires inherited login mode")
		}
		options.Login = ssh.LoginDisabled
		if o.login {
			options.Login = ssh.LoginEnabled
		}
	}
	if o.noLoginSet {
		if o.loginSet {
			return ssh.CommandOptions{}, fmt.Errorf("--no-login and --login-shell are mutually exclusive")
		}
		if o.interpreterSet && options.Interpreter != ssh.InterpreterBash {
			return ssh.CommandOptions{}, fmt.Errorf("--no-login requires the bash interpreter")
		}
		options.Interpreter, options.Login = ssh.InterpreterBash, ssh.LoginEnabled
		if noLogin {
			options.Login = ssh.LoginDisabled
		}
		if !o.dialectSet {
			options.LaunchDialect = ssh.LaunchPOSIX
		}
	}
	return options, nil
}

func (o *ExecOptions) executePlannedTask(ctx context.Context, connector *ssh.Connector, task execHostTask, command string, isScript bool, stdoutMu *sync.Mutex) error {
	if isScript || (o.commandPlan != nil && o.commandPlan.Command() != command) || (o.commandPlan == nil && o.Command != command) {
		return fmt.Errorf("[%s] command changed after execution planning", task.host)
	}
	client, err := connector.Connect(ctx, task.nodeID)
	if err != nil {
		return fmt.Errorf("[%s] connect failed: %w", task.host, err)
	}
	plan, err := o.resolveCommandPlan(command, client.Execution())
	if err != nil {
		return fmt.Errorf("[%s] %w", task.host, err)
	}
	result := client.ExecuteCommand(ctx, plan)
	execErr := result.Err()
	printErr := o.printTaskResult(ctx, task, result.Output, execErr, stdoutMu)
	if execErr != nil {
		return errors.Join(fmt.Errorf("[%s] command outcome=%s phase=%s: %w", task.host, result.Outcome, result.Phase, execErr), printErr)
	}
	return printErr
}
