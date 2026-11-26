//go:build !windows

package wincred

import (
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
)

type unsupportedBackend struct{}

func newPlatformBackend() Backend                                        { return unsupportedBackend{} }
func (unsupportedBackend) Read(string) ([]byte, error)                   { return nil, ports.ErrUnsupported }
func (unsupportedBackend) Write(string, string, *secret.SecretBox) error { return ports.ErrUnsupported }
func (unsupportedBackend) Delete(string) error                           { return ports.ErrUnsupported }
