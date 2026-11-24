package osfs

import (
	"os"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/ports"
)

type LocalFS struct {
	Root *os.Root
}

func (LocalFS) WithRoot(_ algebraic.Duration) error { return nil }
func (LocalFS) WithOperatorRead(_ string) error   { return nil }

var _ ports.ScopedRootFS = LocalFS{}
var _ ports.OperatorReadFS = LocalFS{}
