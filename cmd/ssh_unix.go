//go:build !windows

package cmd

import (
	"os/exec"
	"syscall"
)

func startDaemonProcess(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
	return cmd.Start()
}
