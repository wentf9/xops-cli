//go:build windows

package credentialhelper

import (
	"os/exec"
)

func configureProcessIsolation(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
}
