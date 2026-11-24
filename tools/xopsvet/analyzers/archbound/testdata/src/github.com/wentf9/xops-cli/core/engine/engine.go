package engine

import (
	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/internal/foundation/actor"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/internal/sshnet/priv"
	"github.com/wentf9/xops-cli/core/osfs"
)

type Engine struct {
	N *conc.Nursery
	A *actor.DualActor
	P *pool.Pool
	G *gate.Gate
	D *dial.Dialer
	K *priv.KeyLoader
	M *mcpruntime.Server
	L osfs.LocalFS
}
