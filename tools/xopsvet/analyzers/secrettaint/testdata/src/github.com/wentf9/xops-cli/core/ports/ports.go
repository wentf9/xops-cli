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
	//xops:syncclosure
	//xops:borrowed
	WithSecret(ctx context.Context, ref string, fn func(box *secret.SecretBox) error) error
	PutAndVerify(ctx context.Context, ref string, box *secret.SecretBox) error
}

type AuditSink interface {
	Append(ctx context.Context, entry any) error
}

type InteractionPort interface {
	//xops:syncclosure
	//xops:borrowed
	PromptSecret(ctx context.Context, prompt string, fn func(box *secret.SecretBox) error) error
	Notify(ctx context.Context, msg any) error
}

type ProcessSpec struct{ Command string }
type ProcessResult struct{ Stdout []byte }

type ProcessPort interface {
	Run(ctx context.Context, spec ProcessSpec, stdin io.Reader) (ProcessResult, error)
}

//xops:syncclosure
func RunSyncStr(fn func() string) string {
	return fn()
}

//xops:syncclosure
func RunSyncErr(fn func() error) error {
	return fn()
}

//xops:secretuse
type SecretConsumerCB func(plain []byte) error

func WithMixedCallback(nonSec func(), sec SecretConsumerCB) error {
	if nonSec != nil {
		nonSec()
	}
	if sec != nil {
		return sec(nil)
	}
	return nil
}
