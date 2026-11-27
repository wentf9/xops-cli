package i18n

import (
	"bytes"
	"context"
	"embed"
	"io/fs"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"go.yaml.in/yaml/v3"
)

type Catalog struct {
	FS   embed.FS
	Node yaml.Node
	Dur  algebraic.Duration
	N    *conc.Nursery
	Cur  atomic.Int64
}

func Touch(ctx context.Context, fsys fs.FS) []byte {
	_ = ctx
	_ = fsys
	return bytes.Clone(nil)
}
