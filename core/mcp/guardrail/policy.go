package guardrail

import (
	"fmt"
	"path"
	"strings"

	"github.com/wentf9/xops-cli/core/mcp/policy"
)

// Decision represents the outcome of a policy evaluation.
type Decision int

const (
	Deny         Decision = iota // reject unconditionally (fail-closed zero value)
	NeedApproval                 // require user confirmation via Elicitation
	Allow                        // execute without approval
)

func (d Decision) String() string {
	switch d {
	case Deny:
		return "deny"
	case NeedApproval:
		return "need_approval"
	case Allow:
		return "allow"
	default:
		return "unknown"
	}
}

// DefaultGuardrailConfig returns sensible defaults when no config is provided.
func DefaultGuardrailConfig() *policy.Config {
	return &policy.Config{
		ApprovalThreshold: "dangerous",
		NoElicitFallback:  FallbackDowngrade,
		ProtectedPaths:    []string{"/etc", "/boot", "/usr", "/sbin", "/root"},
	}
}

// ValidateConfig checks if all glob patterns in the config are syntactically valid.
func ValidateConfig(cfg *policy.Config) error {
	if cfg == nil {
		return nil
	}
	for _, pattern := range cfg.BlockedPatterns {
		if err := validateGuardrailGlob(pattern); err != nil {
			return fmt.Errorf("invalid blocked pattern %q: %w", pattern, err)
		}
	}
	for pattern := range cfg.NodeOverrides {
		if err := validateGuardrailGlob(pattern); err != nil {
			return fmt.Errorf("invalid node override pattern %q: %w", pattern, err)
		}
	}
	return nil
}

// Policy evaluates tool invocations against configurable rules.
type Policy struct {
	cfg *policy.Config
}

// NewPolicy creates a policy engine from config.
func NewPolicy(cfg *policy.Config) *Policy {
	if cfg == nil {
		cfg = DefaultGuardrailConfig()
	}
	return &Policy{cfg: cfg}
}

// Evaluate determines whether an invocation should be allowed, needs approval, or is denied.
func (p *Policy) Evaluate(risk RiskLevel, input RiskInput) Decision {
	if p == nil || p.cfg == nil {
		return Deny
	}
	if p.cfg.Disabled {
		return Allow
	}

	if input.ToolName == "terminal" && IsBlocked(input.Command) {
		return Deny
	}
	if input.Text != "" && IsBlocked(input.Text) {
		return Deny
	}

	candidates := []string{input.Command}
	if input.Text != "" {
		candidates = append(candidates, input.Text)
	}
	for _, pattern := range p.cfg.BlockedPatterns {
		for _, candidate := range candidates {
			matched, err := matchGuardrailGlob(pattern, candidate)
			if err != nil || matched {
				// Fail-closed: deny if pattern matches or if pattern matching produces an error
				return Deny
			}
		}
	}

	if p.isPathProtected(input.Paths) && risk < Dangerous {
		risk = Moderate
	}

	threshold := p.thresholdForNode(input.NodeID)
	if risk >= threshold {
		return NeedApproval
	}
	// Batch operations must satisfy both their existing scope policy and every
	// covered node. One approval covers the complete, bound node set.
	for _, nodeID := range input.NodeIDs {
		if risk >= p.thresholdForNode(nodeID) {
			return NeedApproval
		}
	}
	return Allow
}

func (p *Policy) thresholdForNode(nodeID string) RiskLevel {
	// An absent node selects the global policy. In particular, "*" must
	// only override actual nodes, never the threshold of an unfiltered query.
	if nodeID == "" {
		return ParseRiskLevel(p.cfg.ApprovalThreshold)
	}
	var (
		matchedAny bool
		strictest  RiskLevel
	)
	for pattern, override := range p.cfg.NodeOverrides {
		matched, err := matchGuardrailGlob(pattern, nodeID)
		if err != nil {
			// Fail-closed: any malformed override pattern enforces the strictest
			// approval threshold regardless of map iteration order.
			return Safe
		}
		if matched {
			level := ParseRiskLevel(override.ApprovalThreshold)
			if !matchedAny || level < strictest {
				strictest = level
				matchedAny = true
			}
		}
	}
	if matchedAny {
		return strictest
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
	if target == "" || prefix == "" {
		return false
	}
	// POSIX-first check: never let Win32 UNC/device/drive reclassification hide
	// a literal POSIX ProtectedPaths match (e.g. "/opt/custom-protected/\../drop"
	// or a POSIX prefix configured as "/\protected").
	if matchesCleanPath(path.Clean(target), path.Clean(prefix)) {
		return true
	}
	if matchesUnderNormalized(target, prefix) {
		return true
	}
	// Defense-in-depth for paths carrying Windows backslash separators
	// (e.g. `\etc\passwd` or `/tmp/\../etc/passwd`). Evaluating POSIX-clean
	// first and OR-ing with slash-converted clean is strictly more protective:
	// POSIX `/opt/custom-protected/\../drop` matches via POSIX-clean while
	// Windows backslash separators match via slash-clean. Win32 device/UNC
	// paths (including those revealed after collapsing leading POSIX ".." or
	// "//") already handle separator canonicalization natively and must not
	// be reinterpreted as POSIX paths.
	if strings.Contains(target, "\\") || strings.Contains(prefix, "\\") {
		altTarget := target
		if !isWin32DeviceOrUNCPath(win32CollapseCandidate(target)) {
			altTarget = strings.ReplaceAll(target, "\\", "/")
		}
		altPrefix := prefix
		if !isWin32DeviceOrUNCPath(win32CollapseCandidate(prefix)) {
			altPrefix = strings.ReplaceAll(prefix, "\\", "/")
		}
		if (altTarget != target || altPrefix != prefix) && matchesUnderNormalized(altTarget, altPrefix) {
			return true
		}
	}
	return false
}

func matchesUNCPath(tUNC, pUNC win32UNCPath) bool {
	if tUNC.server != pUNC.server {
		return false
	}
	if pUNC.share == "" {
		return true
	}
	return tUNC.share == pUNC.share && matchesCleanPath(strings.ToLower(tUNC.cleanRest), strings.ToLower(pUNC.cleanRest))
}

func matchesDeviceNamespace(target, prefix string) (matched bool, handled bool) {
	tDev, tDevRest, tIsDev := canonicalDeviceNamespacePath(target)
	pDev, pDevRest, pIsDev := canonicalDeviceNamespacePath(prefix)
	if tIsDev && pIsDev {
		if tDev != pDev {
			return false, true
		}
		return matchesCleanPath(strings.ToLower(tDevRest), strings.ToLower(pDevRest)), true
	}
	if tIsDev {
		return path.Clean(prefix) == "/", true
	}
	if pIsDev {
		return false, true
	}
	return false, false
}

func matchesUnderNormalized(target, prefix string) bool {
	winTarget := win32CollapseCandidate(target)
	winPrefix := win32CollapseCandidate(prefix)

	tUNC, tIsUNC := canonicalUNCPath(winTarget)
	pUNC, pIsUNC := canonicalUNCPath(winPrefix)
	if tIsUNC && pIsUNC && matchesUNCPath(tUNC, pUNC) {
		return true
	}

	tDrive, tRest, _, tIsDrive := canonicalDrivePath(winTarget)
	pDrive, pRest, _, pIsDrive := canonicalDrivePath(winPrefix)
	if tIsDrive && pIsDrive {
		return tDrive == pDrive && matchesCleanPath(strings.ToLower(tRest), strings.ToLower(pRest))
	}
	if tIsDrive || tIsUNC {
		return !pIsDrive && !pIsUNC && path.Clean(prefix) == "/"
	}
	if pIsDrive || pIsUNC {
		return false
	}
	if matched, handled := matchesDeviceNamespace(winTarget, winPrefix); handled {
		return matched
	}
	return matchesCleanPath(path.Clean(target), path.Clean(prefix))
}

func matchesCleanPath(target, prefix string) bool {
	if target == prefix {
		return true
	}
	if prefix == "/" {
		return strings.HasPrefix(target, "/")
	}
	return strings.HasPrefix(target, prefix+"/")
}
