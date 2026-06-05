//go:build windows

package cmd

import (
	"os/exec"
)

func startDaemonProcess(cmd *exec.Cmd) error {
	return cmd.Start()
}
