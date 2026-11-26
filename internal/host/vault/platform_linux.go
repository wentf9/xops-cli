//go:build linux

package vault

import (
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/vault/secretservice"
)

// NewPlatformOSKeychain 返回当前平台原生系统钥匙串适配器（Linux FreeDesktop Secret Service）。
func NewPlatformOSKeychain(env ports.EnvPort, entropy ports.Entropy) (ports.SecretVault, error) {
	return secretservice.NewStore(secretservice.Spec{
		Env:                env,
		Entropy:            entropy,
		AllowPlainFallback: true,
	})
}
