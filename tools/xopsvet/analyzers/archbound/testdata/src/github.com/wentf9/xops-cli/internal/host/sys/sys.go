package sys

import (
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

type HostSys struct {
	D algebraic.Duration
	L osfs.LocalFS
	F ports.OperatorReadFS
}
