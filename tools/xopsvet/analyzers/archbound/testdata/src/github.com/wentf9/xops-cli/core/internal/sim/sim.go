package sim

import (
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/ports"
)

type SimFS struct {
	E events.Event
	F ports.ScopedRootFS
}
