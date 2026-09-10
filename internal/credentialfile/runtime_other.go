//go:build !linux || !amd64

package credentialfile

import (
	"context"
	"github.com/wentf9/xops-cli/internal/kdfhelper"
)

// Runtime is unavailable until native session/process validation is completed.
type Runtime struct{}

// NewRuntime preserves the API without enabling an unvalidated platform.
func NewRuntime(context.Context, PromptProvider, kdfhelper.Deriver) *Runtime { return &Runtime{} }

// OpenStore refuses unsupported platforms without reading files or prompting.
func (*Runtime) OpenStore(context.Context, string, string, Options, SessionOptions) (*Store, error) {
	return nil, ErrUnsupported
}

// Close owns no resources on unsupported platforms.
func (*Runtime) Close() error { return nil }

// Lock refuses unsupported platforms.
func (*Store) Lock(context.Context) error { return ErrUnsupported }

// Unlock refuses unsupported platforms.
func (*Store) Unlock(context.Context) error { return ErrUnsupported }
