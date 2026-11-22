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

func expandAuditLogPath(path string) string {
	switch {
	case path == "~":
		if directory, err := os.UserHomeDir(); err == nil && directory != "" {
			return directory
		}
	case strings.HasPrefix(path, "~/"), strings.HasPrefix(path, `~\`):
		if directory, err := os.UserHomeDir(); err == nil && directory != "" {
			rel := strings.ReplaceAll(path[2:], `\`, "/")
			return filepath.Join(directory, filepath.FromSlash(rel))
		}
	}
	return path
}

func newAuditLogger(path string) *guardrail.AuditLogger {
	// Unresolved shorthand is rejected on write by the shared audit logger.
	return guardrail.NewAuditLogger(expandAuditLogPath(path))
}
