package cli

import (
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
)

type CLI struct {
	D algebraic.Duration
	E *engine.Engine
	V events.Event
}
