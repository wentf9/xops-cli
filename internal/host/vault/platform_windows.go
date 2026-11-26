//go:build windows

package vault

import (
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/vault/wincred"
)

// NewPlatformOSKeychain 返回当前平台原生系统钥匙串适配器（Windows Credential Manager）。
func NewPlatformOSKeychain(_ ports.EnvPort, _ ports.Entropy) (ports.SecretVault, error) {
	return wincred.NewStore(), nil
}
