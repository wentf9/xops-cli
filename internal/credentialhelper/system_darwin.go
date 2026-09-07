//go:build darwin

package credentialhelper

import (
	"os/exec"
)

func resolveDefaultSystemHelper() (string, error) {
	if p, err := exec.LookPath(DefaultSystemHelperCommand); err == nil {
		return p, nil
	}
	return DefaultSystemHelperCommand, nil
}

func checkPlatformSystemAvailability() error {
	return nil
}
