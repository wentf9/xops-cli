package engine

import (
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/osfs"
)

type Engine struct {
	P *pool.Pool
	G *gate.Gate
	D *dial.Dialer
	M *mcpruntime.Server
	L osfs.LocalFS
}
