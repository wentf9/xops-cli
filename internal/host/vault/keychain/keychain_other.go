//go:build !darwin

package keychain

import (
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
)

type unsupportedBackend struct{}

func newPlatformBackend() Backend                                        { return unsupportedBackend{} }
func (unsupportedBackend) Read(string, string) ([]byte, error)           { return nil, ports.ErrUnsupported }
func (unsupportedBackend) Write(string, string, *secret.SecretBox) error { return ports.ErrUnsupported }
func (unsupportedBackend) Delete(string, string) error                   { return ports.ErrUnsupported }
