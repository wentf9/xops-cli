//go:build !linux

package secretservice

import (
	"context"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// Spec 是构造 Linux FreeDesktop Secret Service 凭据库适配器 Store 的显式入参规格。
type Spec struct {
	Env                ports.EnvPort
	Entropy            ports.Entropy
	BusAddress         string
	AllowPlainFallback bool
}

// Store 在非 Linux 平台上实现 ports.SecretVault 失败关闭占位适配器，固定返回 ports.ErrUnsupported。
//
//xops:opaque
//xops:failclosed
type Store struct{ valid bool }

// NewStore 校验参数并构造非 Linux 平台占位 Store。
func NewStore(spec Spec) (*Store, error) {
	if spec.Entropy == nil {
		return nil, i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostNilDependency, i18n.Str("field", "secretservice.Entropy"))
	}
	return &Store{valid: true}, nil
}

// WithSecret 在非 Linux 平台上返回 ports.ErrUnsupported。
//
//xops:syncclosure
//xops:borrowed
func (s *Store) WithSecret(ctx context.Context, ref secret.Ref, fn func(box *secret.SecretBox) error) error {
	if err := s.checkArgs(ctx, ref); err != nil {
		return err
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	return ports.ErrUnsupported
}

// PutAndVerify 在非 Linux 平台上返回 ports.ErrUnsupported。
func (s *Store) PutAndVerify(ctx context.Context, ref secret.Ref, box *secret.SecretBox) error {
	if err := s.checkArgs(ctx, ref); err != nil {
		return err
	}
	if !box.IsValid() {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidSecretBox)
	}
	return ports.ErrUnsupported
}

// Delete 在非 Linux 平台上返回 ports.ErrUnsupported。
func (s *Store) Delete(ctx context.Context, ref secret.Ref) error {
	if err := s.checkArgs(ctx, ref); err != nil {
		return err
	}
	return ports.ErrUnsupported
}

func (s *Store) checkArgs(ctx context.Context, ref secret.Ref) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || !s.valid {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostNotInitialized, i18n.Str("component", "secretservice.Store"))
	}
	if !ref.IsValid() {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidSecretRef)
	}
	return nil
}
