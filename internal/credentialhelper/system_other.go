//go:build !linux && !darwin && !windows

package credentialhelper

import (
	"fmt"
	"runtime"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func resolveDefaultSystemHelper() (string, error) {
	return "", fmt.Errorf("%w: system credential store is not supported on %s", credential.ErrCredentialStoreUnavailable, runtime.GOOS)
}

func checkPlatformSystemAvailability() error {
	return fmt.Errorf("%w: system credential store is not supported on %s", credential.ErrCredentialStoreUnavailable, runtime.GOOS)
}
