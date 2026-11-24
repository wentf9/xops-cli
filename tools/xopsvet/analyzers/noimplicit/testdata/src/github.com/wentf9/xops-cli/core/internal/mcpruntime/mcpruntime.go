package mcpruntime

import (
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
)

type httpServerRuntime struct {
	ReadHeaderTimeout time.Duration
}

type GoodParams struct {
	Timeout algebraic.Duration `json:"timeout"`
}

type BadParams struct {
	Timeout time.Duration // want "禁止裸用 time.Duration"
}

func useRuntime() httpServerRuntime {
	return httpServerRuntime{ReadHeaderTimeout: time.Second}
}
