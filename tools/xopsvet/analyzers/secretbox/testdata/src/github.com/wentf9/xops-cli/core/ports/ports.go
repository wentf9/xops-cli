package ports

import (
	"context"

	"github.com/wentf9/xops-cli/core/domain/secret"
)

type Option[T any] struct {
	val T
	set bool
}

type SecretVault interface {
	WithSecret(ctx context.Context, ref string, fn func(box *secret.SecretBox) error) error
	PutAndVerify(ctx context.Context, ref string, box *secret.SecretBox) error
}

type AuditSink interface {
	Append(ctx context.Context, entry any) error
}

type InteractionPort interface {
	PromptSecret(ctx context.Context, prompt string, fn func(box *secret.SecretBox) error) error
	Notify(ctx context.Context, msg any) error
}

// v2.3.3 CRIT-3: ContainsValueType 不穿透 Interface.Methods，
// 携带 ports.SecretVault / InteractionPort 的 Request/Config/Option 绝不误杀。
type RotateRequest struct {
	Vault       SecretVault
	Interaction InteractionPort
	OptVault    Option[SecretVault]
}

func okUsePortInterfaces(req RotateRequest) any {
	_ = req.OptVault
	return req.Vault
}
