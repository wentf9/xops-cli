package pool

import (
	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/foundation/actor"
	"github.com/wentf9/xops-cli/core/ports"
)

type Pool struct {
	N *conc.Nursery
	A *actor.DualActor
	E events.Event
	F ports.ScopedRootFS
}
