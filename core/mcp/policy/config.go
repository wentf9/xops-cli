// Package policy defines storage-independent MCP policy configuration.
package policy

// Config configures the MCP safety guardrail.
type Config struct {
	Enabled           bool                  `yaml:"enabled"`
	AuditLog          string                `yaml:"audit_log,omitempty"`
	ApprovalThreshold string                `yaml:"approval_threshold,omitempty"` // "safe"|"moderate"|"dangerous"
	BlockedPatterns   []string              `yaml:"blocked_patterns,omitempty"`
	ProtectedPaths    []string              `yaml:"protected_paths,omitempty"`
	NodeOverrides     map[string]NodeConfig `yaml:"nodes,omitempty"`

	// NoElicitFallback controls behavior when the MCP client does not support
	// Elicitation (e.g. Gemini CLI).
	//   "deny"      — reject all operations that need approval (most secure)
	//   "allow"     — allow all, trust client-side tool approval + ToolAnnotations
	//   "downgrade" — allow moderate, still deny dangerous (recommended default)
	NoElicitFallback string `yaml:"no_elicit_fallback,omitempty"`
}

// NodeConfig holds per-node (glob pattern) policy overrides.
type NodeConfig struct {
	ApprovalThreshold string `yaml:"approval_threshold"`
}
