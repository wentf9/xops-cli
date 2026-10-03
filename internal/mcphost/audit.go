package mcphost

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/policy"
)

func defaultPolicyConfig() *policy.Config {
	cfg := guardrail.DefaultGuardrailConfig()
	cfg.AuditLog = "~/.xops/audit.log"
	return cfg
}

func newAuditLogger(path string) *guardrail.AuditLogger {
	if strings.HasPrefix(path, "~/") {
		if directory, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(directory, path[2:])
		}
	}
	// Unresolved shorthand is rejected on write by the shared audit logger.
	return guardrail.NewAuditLogger(path)
}
