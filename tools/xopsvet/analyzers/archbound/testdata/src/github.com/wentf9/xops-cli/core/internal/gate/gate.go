package gate

import (
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
	"github.com/wentf9/xops-cli/core/ports"
)

type Gate struct {
	E events.Event
	F ports.ScopedRootFS
}

var _ = trace.WithTrace
