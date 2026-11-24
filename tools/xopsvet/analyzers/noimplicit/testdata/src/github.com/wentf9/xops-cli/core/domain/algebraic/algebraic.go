package algebraic

import "time"

type Duration struct {
	d time.Duration
}

func FromStdDuration(d time.Duration) Duration {
	return Duration{d: d}
}

type Config struct {
	Raw time.Duration
}

type Option[T any] struct {
	valid bool
	val   T
}
