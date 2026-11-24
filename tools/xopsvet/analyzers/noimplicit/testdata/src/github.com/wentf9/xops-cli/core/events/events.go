package events

import (
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
)

type GoodEvent struct {
	Elapsed algebraic.Duration
}

type GoodOptionEvent struct {
	Elapsed algebraic.Option[algebraic.Duration]
	Ptr     *algebraic.Duration
	List    []algebraic.Duration
}

type customDurationWrapper struct {
	Raw time.Duration
}

type BadEvent struct {
	Elapsed time.Duration // want "禁止裸用 time.Duration"
}

type BadUntaggedEvent struct {
	Elapsed time.Duration // want "禁止裸用 time.Duration"
}

type BadOptionEvent struct {
	Elapsed algebraic.Option[time.Duration] // want "禁止裸用 time.Duration"
}

type BadWrappedEvent struct {
	Wrap customDurationWrapper // want "禁止裸用 time.Duration"
}
