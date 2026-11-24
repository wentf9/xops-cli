package session

import (
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
)

type Service struct {
	G *gate.Gate
	P *pool.Pool
	F ports.OperatorReadFS
}

func LeakOpFS() ports.OperatorReadFS {
	return nil
}
