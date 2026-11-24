package pool

import (
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/foundation/conc"
	"github.com/wentf9/xops-cli/core/ports"
)

type Pool struct {
	N *conc.Nursery
	E events.Event
	F ports.ScopedRootFS
}
