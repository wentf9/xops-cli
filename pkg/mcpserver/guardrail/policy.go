package guardrail

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

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

// ValidateConfig checks if all glob patterns in the config are syntactically valid.
func ValidateConfig(cfg *config.GuardrailConfig) error {
	if cfg == nil {
		return nil
	}
	for _, pattern := range cfg.BlockedPatterns {
		if _, err := filepath.Match(pattern, ""); err != nil {
			return fmt.Errorf("invalid blocked pattern %q: %w", pattern, err)
		}
	}
	for pattern := range cfg.NodeOverrides {
		if _, err := filepath.Match(pattern, ""); err != nil {
			return fmt.Errorf("invalid node override pattern %q: %w", pattern, err)
		}
	}
	return nil
}

// Policy evaluates tool invocations against configurable rules.
type Policy struct {
	cfg *config.GuardrailConfig
}

// NewPolicy creates a policy engine from config.
func NewPolicy(cfg *config.GuardrailConfig) *Policy {
	if cfg == nil {
		cfg = DefaultGuardrailConfig()
	}
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
		matched, err := filepath.Match(pattern, input.Command)
		if err != nil || matched {
			// Fail-closed: deny if pattern matches or if pattern matching produces an error
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
		matched, err := filepath.Match(pattern, nodeID)
		if err != nil {
			// Fail-closed: use lowest threshold (strictest approval) on pattern error
			return Safe
		}
		if matched {
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
		for _, protected := range allProtected {
			if matchesUnder(target, protected) {
				return true
			}
		}
	}
	return false
}

func matchesUnder(target, prefix string) bool {
	target = normalizeRemotePath(target)
	prefix = normalizeRemotePath(prefix)
	if target == prefix {
		return true
	}
	if prefix == "/" {
		return strings.HasPrefix(target, "/")
	}
	return strings.HasPrefix(target, prefix+"/")
}

func normalizeRemotePath(value string) string {
	return path.Clean(strings.ReplaceAll(value, `\`, "/"))
}
