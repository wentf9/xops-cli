//go:build windows

package credentialhelper

import (
	"os/exec"
)

func resolveDefaultSystemHelper() (string, error) {
	cmdName := DefaultSystemHelperCommand + ".exe"
	if p, err := exec.LookPath(cmdName); err == nil {
		return p, nil
	}
	return cmdName, nil
}

func checkPlatformSystemAvailability() error {
	return nil
}
