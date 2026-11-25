package ports

import (
	"context"

	"github.com/wentf9/xops-cli/core/domain/secret"
)

type SecretVault interface {
	//xops:syncclosure
	//xops:borrowed
	WithSecret(ctx context.Context, ref string, fn func(box *secret.SecretBox) error) error
}

type InteractionPort interface {
	//xops:syncclosure
	//xops:borrowed
	PromptSecret(ctx context.Context, prompt string, fn func(box *secret.SecretBox) error) error
}
