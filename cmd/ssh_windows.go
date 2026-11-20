//go:build windows

package cmd

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func startDaemonProcess(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
	}
	return cmd.Start()
}
