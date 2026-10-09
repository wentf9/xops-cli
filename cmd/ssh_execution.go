package cmd

import (
	"fmt"
	"runtime"

	"github.com/wentf9/xops-cli/core/ssh"
)

func (o *SshOptions) prepareCommandPlan() error {
	if !o.execution.enabled() && !o.execution.noLoginSet {
		return nil
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("explicit execution on %s is not supported yet: cancelable native output is only available on Linux", runtime.GOOS)
	}
	if o.Sudo {
		return fmt.Errorf("explicit execution currently supports ordinary commands without sudo")
	}
	if o.NoCmd {
		return fmt.Errorf("explicit execution cannot be combined with -N / --no-cmd")
	}
	if o.Command == "" {
		return o.validateEmptyCommandExecution()
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

func (o *SshOptions) validateEmptyCommandExecution() error {
	if (o.execution.interpreterSet && o.execution.interpreter == "") || (o.execution.dialectSet && o.execution.dialect == "") {
		return fmt.Errorf("explicit interpreter and launch dialect must not be empty")
	}
	if o.stdinScript {
		if !o.execution.interpreterSet || o.execution.interpreter != string(ssh.InterpreterServer) {
			return fmt.Errorf("explicit script execution is not supported yet")
		}
		if o.execution.loginSet || o.execution.noLoginSet {
			return fmt.Errorf("server interpreter requires inherited login mode")
		}
		if o.execution.dialectSet && o.execution.dialect != "" && o.execution.dialect != string(ssh.LaunchPOSIX) && o.execution.dialect != string(ssh.LaunchUnknown) {
			return fmt.Errorf("server interpreter does not support launch dialect %q", o.execution.dialect)
		}
		return nil
	}
	if (o.execution.interpreterSet && o.execution.interpreter != string(ssh.InterpreterServer)) || o.execution.loginSet || o.execution.noLoginSet || o.execution.dialectSet {
		return fmt.Errorf("terminal shell session does not support explicit interpreter or login options; use an explicit command or server interpreter")
	}
	return nil
}
