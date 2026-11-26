//go:build darwin

package vault

import (
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/vault/keychain"
)

// NewPlatformOSKeychain 返回当前平台原生系统钥匙串适配器（macOS Security.framework Keychain）。
func NewPlatformOSKeychain(_ ports.EnvPort, _ ports.Entropy) (ports.SecretVault, error) {
	return keychain.NewStore(), nil
}
