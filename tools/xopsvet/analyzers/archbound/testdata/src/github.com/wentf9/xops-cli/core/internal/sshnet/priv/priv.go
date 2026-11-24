package priv

import (
	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/osfs"
)

type KeyLoader struct {
	N *conc.Nursery
	D *dial.Dialer
	L osfs.LocalFS
}
