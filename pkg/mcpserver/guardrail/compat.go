// Package guardrail preserves CLI audit-path defaults around the shared policy engine.
package guardrail

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	core "github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/policy"
)

type Guardrail = core.Guardrail
type Policy = core.Policy
type AuditEntry = core.AuditEntry
type AuditWriter = core.AuditWriter
type AuditLogger = core.AuditLogger
type ExecutedPostAuditError = core.ExecutedPostAuditError
type Decision = core.Decision
type RiskLevel = core.RiskLevel
type RiskInput = core.RiskInput

const (
	Allow             = core.Allow
	NeedApproval      = core.NeedApproval
	Deny              = core.Deny
	Safe              = core.Safe
	Moderate          = core.Moderate
	Dangerous         = core.Dangerous
	FallbackDeny      = core.FallbackDeny
	FallbackAllow     = core.FallbackAllow
	FallbackDowngrade = core.FallbackDowngrade
)

func DefaultGuardrailConfig() *policy.Config {
	cfg := core.DefaultGuardrailConfig()
	cfg.AuditLog = "~/.xops/audit.log"
	return cfg
}

func New(cfg *policy.Config) *Guardrail {
	if cfg == nil {
		cfg = DefaultGuardrailConfig()
	}
	copy := *cfg
	copy.AuditLog = expandAuditPath(copy.AuditLog)
	return core.New(&copy)
}

func NewPolicy(cfg *policy.Config) *Policy    { return core.NewPolicy(cfg) }
func ValidateConfig(cfg *policy.Config) error { return core.ValidateConfig(cfg) }
func NewAuditLogger(path string) *AuditLogger { return core.NewAuditLogger(expandAuditPath(path)) }

func expandAuditPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		if directory, err := os.UserHomeDir(); err == nil {
			return filepath.Join(directory, path[2:])
		}
	}
	// Unresolved shorthand is rejected on write by the shared audit logger.
	return path
}

func IsBlocked(command string) bool           { return core.IsBlocked(command) }
func AnalyzeCommand(command string) RiskLevel { return core.AnalyzeCommand(command) }
func AnalyzePaths(paths []string) RiskLevel   { return core.AnalyzePaths(paths) }
func Classify(input RiskInput) RiskLevel      { return core.Classify(input) }
func ParseRiskLevel(value string) RiskLevel   { return core.ParseRiskLevel(value) }
func RequestApproval(ctx context.Context, session *mcp.ServerSession, risk RiskLevel, input RiskInput, fallback string) error {
	return core.RequestApproval(ctx, session, risk, input, fallback)
}
func WithGuardrail[In, Out any](g *Guardrail, tool string, risk func(In) RiskInput, handler mcp.ToolHandlerFor[In, Out]) mcp.ToolHandlerFor[In, Out] {
	return core.WithGuardrail(g, tool, risk, handler)
}
