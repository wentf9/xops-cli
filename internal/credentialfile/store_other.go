//go:build !linux || !amd64

package credentialfile

import (
	"context"

	"github.com/wentf9/xops-cli/pkg/credential"
)

// Store is unavailable until this platform's file semantics pass native validation.
type Store struct{}

// Open fails closed on unvalidated platforms.
func Open(context.Context, string, string, Options) (*Store, error) { return nil, ErrUnsupported }

// Close releases no resources on unsupported platforms.
func (*Store) Close() error { return nil }

// Get fails closed on unvalidated platforms.
func (*Store) Get(context.Context, credential.Ref) (credential.Secret, error) {
	return credential.Secret{}, ErrUnsupported
}

// Put fails closed on unvalidated platforms.
func (*Store) Put(context.Context, credential.Ref, credential.Secret) error { return ErrUnsupported }

// Delete fails closed on unvalidated platforms.
func (*Store) Delete(context.Context, credential.Ref) error { return ErrUnsupported }
