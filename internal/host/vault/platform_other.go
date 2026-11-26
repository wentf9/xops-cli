//go:build !windows && !darwin && !linux

package vault

import (
	"context"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
)

type unsupportedOSKeychain struct{}

// NewPlatformOSKeychain 在无原生 OS Keychain 的平台（如 FreeBSD）返回失败关闭的 ErrUnsupported 适配器。
func NewPlatformOSKeychain(_ ports.EnvPort, _ ports.Entropy) (ports.SecretVault, error) {
	return unsupportedOSKeychain{}, nil
}

//xops:syncclosure
//xops:borrowed
func (unsupportedOSKeychain) WithSecret(ctx context.Context, ref secret.Ref, fn func(box *secret.SecretBox) error) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	if !ref.IsValid() {
		return ports.ErrInvalidArgument
	}
	return ports.ErrUnsupported
}

func (unsupportedOSKeychain) PutAndVerify(ctx context.Context, ref secret.Ref, box *secret.SecretBox) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !ref.IsValid() || !box.IsValid() {
		return ports.ErrInvalidArgument
	}
	return ports.ErrUnsupported
}

func (unsupportedOSKeychain) Delete(ctx context.Context, ref secret.Ref) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !ref.IsValid() {
		return ports.ErrInvalidArgument
	}
	return ports.ErrUnsupported
}
