package guardrail

import (
	"path/filepath"

	"github.com/wentf9/xops-cli/pkg/config"
)

// Decision represents the outcome of a policy evaluation.
type Decision int

const (
	Allow        Decision = iota // execute without approval
	NeedApproval                 // require user confirmation via Elicitation
	Deny                         // reject unconditionally
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case NeedApproval:
		return "need_approval"
	case Deny:
		return "deny"
	default:
		return "unknown"
	}
}

// DefaultGuardrailConfig returns sensible defaults when no config is provided.
func DefaultGuardrailConfig() *config.GuardrailConfig {
	return &config.GuardrailConfig{
		Enabled:           true,
		AuditLog:          "~/.xops/audit.log",
		ApprovalThreshold: "dangerous",
		NoElicitFallback:  FallbackDowngrade,
		ProtectedPaths:    []string{"/etc", "/boot", "/usr", "/sbin", "/root"},
	}
}

// Policy evaluates tool invocations against configurable rules.
type Policy struct {
	cfg *config.GuardrailConfig
}

// NewPolicy creates a policy engine from config.
func NewPolicy(cfg *config.GuardrailConfig) *Policy {
	return &Policy{cfg: cfg}
}

// Evaluate determines whether an invocation should be allowed, needs approval, or is denied.
func (p *Policy) Evaluate(risk RiskLevel, input RiskInput) Decision {
	if !p.cfg.Enabled {
		return Allow
	}

	if input.ToolName == "xops_ssh_run" && IsBlocked(input.Command) {
		return Deny
	}

	for _, pattern := range p.cfg.BlockedPatterns {
		if matched, _ := filepath.Match(pattern, input.Command); matched {
			return Deny
		}
	}

	if p.isPathProtected(input.Paths) && risk < Dangerous {
		risk = Moderate
	}

	threshold := p.thresholdForNode(input.NodeID)
	if risk >= threshold {
		return NeedApproval
	}
	return Allow
}

func (p *Policy) thresholdForNode(nodeID string) RiskLevel {
	for pattern, override := range p.cfg.NodeOverrides {
		if matched, _ := filepath.Match(pattern, nodeID); matched {
			return ParseRiskLevel(override.ApprovalThreshold)
		}
	}
	return ParseRiskLevel(p.cfg.ApprovalThreshold)
}

func (p *Policy) isPathProtected(paths []string) bool {
	allProtected := make([]string, 0, len(sensitivePaths)+len(p.cfg.ProtectedPaths))
	allProtected = append(allProtected, sensitivePaths...)
	allProtected = append(allProtected, p.cfg.ProtectedPaths...)
	for _, target := range paths {
		cleaned := filepath.Clean(target)
		for _, protected := range allProtected {
			if cleaned == protected || matchesUnder(cleaned, protected) {
				return true
			}
		}
	}
	return false
}

func matchesUnder(path, prefix string) bool {
	prefix = filepath.Clean(prefix)
	if len(path) > len(prefix) && path[:len(prefix)] == prefix && path[len(prefix)] == '/' {
		return true
	}
	return false
}
