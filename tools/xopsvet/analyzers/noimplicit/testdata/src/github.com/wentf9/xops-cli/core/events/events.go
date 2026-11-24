package events

import (
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
)

type GoodEvent struct {
	Elapsed algebraic.Duration
}

type BadUntaggedEvent struct {
	Elapsed time.Duration // want "禁止裸用 time.Duration"
}
