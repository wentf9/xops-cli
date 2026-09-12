//go:build !linux && !darwin && !windows

package credentialhelper

import (
	"fmt"
	"runtime"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func newNativeSystemStore(storeID string, cfg SystemStoreConfig) (credential.Store, error) {
	return nil, fmt.Errorf("%w: system credential store is not supported on %s", credential.ErrCredentialStoreUnavailable, runtime.GOOS)
}

func checkPlatformSystemAvailability() error {
	return fmt.Errorf("%w: system credential store is not supported on %s", credential.ErrCredentialStoreUnavailable, runtime.GOOS)
}

func handlePlatformSystemHelper(action Action, req *Request) (*Response, int) {
	return &Response{Code: "unavailable", Message: "unsupported platform"}, 1
}
