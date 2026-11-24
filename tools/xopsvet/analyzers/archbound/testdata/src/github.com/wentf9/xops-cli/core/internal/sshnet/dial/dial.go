package dial

import (
	"github.com/wentf9/xops-cli/core/internal/foundation/conc"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

type Dialer struct {
	N *conc.Nursery
	L osfs.LocalFS
	F ports.ScopedRootFS
}
