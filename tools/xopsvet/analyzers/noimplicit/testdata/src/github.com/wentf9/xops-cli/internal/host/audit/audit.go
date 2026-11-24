package audit

import (
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
)

type AuditEntry struct {
	Duration algebraic.Duration `json:"duration"`
}

type BadAuditRecord struct {
	Duration time.Duration // want "禁止裸用 time.Duration"
}
