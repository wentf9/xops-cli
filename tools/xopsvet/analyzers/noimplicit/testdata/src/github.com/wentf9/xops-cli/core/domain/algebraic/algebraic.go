package algebraic

import "time"

type Duration int64

func FromStdDuration(d time.Duration) Duration {
	return Duration(d)
}

type Config struct {
	Raw time.Duration
}

type Option[T any] struct {
	valid bool
	val   T
}
