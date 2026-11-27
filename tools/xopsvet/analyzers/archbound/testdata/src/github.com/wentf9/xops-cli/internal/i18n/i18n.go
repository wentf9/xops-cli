package i18n

import (
	"bytes"
	"context"
	"embed"
	"io/fs"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"go.yaml.in/yaml/v3"
)

type Catalog struct {
	FS   embed.FS
	Node yaml.Node
	Dur  algebraic.Duration
	N    *conc.Nursery
	TTL  time.Duration
}

func Touch(ctx context.Context, fsys fs.FS, d time.Duration) []byte {
	_ = ctx
	_ = fsys
	_ = d
	return bytes.Clone(nil)
}
