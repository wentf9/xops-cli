package ports

import "github.com/wentf9/xops-cli/core/domain/algebraic"

type ScopedRootFS interface {
	WithRoot(ttl algebraic.Duration) error
}

type OperatorReadFS interface {
	WithOperatorRead(name string) error
}
