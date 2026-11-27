package sys

import (
	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
)

type HostSys struct {
	N *conc.Nursery
	D algebraic.Duration
	L osfs.LocalFS
	F ports.OperatorReadFS
	C *i18n.Catalog
}
