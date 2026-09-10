package utils

import (
	"fmt"
	"sync"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
)

var credentialOwner struct {
	sync.RWMutex
	runtime *config.EncryptedRuntime
}

// InstallCredentialRuntime lends the command owner's runtime to all CLI services.
// The returned function detaches it; the owner still must wait for Close.
func InstallCredentialRuntime(r *config.EncryptedRuntime) (func(), error) {
	credentialOwner.Lock()
	defer credentialOwner.Unlock()
	if credentialOwner.runtime != nil {
		return nil, fmt.Errorf("credential runtime already installed")
	}
	credentialOwner.runtime = r
	return func() { credentialOwner.Lock(); defer credentialOwner.Unlock(); credentialOwner.runtime = nil }, nil
}

// CredentialRuntime returns the current command's borrowed runtime.
func CredentialRuntime() (*config.EncryptedRuntime, error) {
	credentialOwner.RLock()
	defer credentialOwner.RUnlock()
	if credentialOwner.runtime == nil {
		return nil, fmt.Errorf("%w: command credential runtime is not installed", credential.ErrCredentialStoreUnavailable)
	}
	return credentialOwner.runtime, nil
}

// BuildCredentialRegistry uses the owner's runtime when present. Library callers
// without an owner retain the fail-closed factory behavior for offline stores.
func BuildCredentialRegistry(cfg *config.CredentialConfig) (*credential.Registry, error) {
	credentialOwner.RLock()
	r := credentialOwner.runtime
	credentialOwner.RUnlock()
	if r != nil {
		return r.Registry(cfg)
	}
	return config.BuildRegistryFromConfig(cfg)
}
