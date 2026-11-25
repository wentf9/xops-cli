package ports

import (
	"context"
	"io"

	"github.com/wentf9/xops-cli/core/domain/secret"
)

type RemoteSession interface {
	StdinPipe() (io.WriteCloser, error)
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
