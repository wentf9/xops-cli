package ssh

import (
	"fmt"
	"os/exec"
	"syscall"
)

func configureProbeShellCommand(command *exec.Cmd, shell string, dialect LaunchDialect, payload string) {
	if dialect == LaunchCmd {
		// CMD does not use CommandLineToArgvW quoting. Preserve its raw /s /c
		// string exactly as an SSH server would pass it to the default shell.
		command.SysProcAttr = &syscall.SysProcAttr{CmdLine: fmt.Sprintf(`"%s" /d /s /c "%s"`, shell, payload)}
	}
}
