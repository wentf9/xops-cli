package config

import (
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

// Configuration 对应 yaml 文件的顶层结构
type Configuration struct {
	Identities            *concurrent.Map[string, models.Identity] `yaml:"identities"`
	Hosts                 *concurrent.Map[string, models.Host]     `yaml:"hosts"`
	Nodes                 *concurrent.Map[string, models.Node]     `yaml:"nodes"`
	Guardrail             *GuardrailConfig                         `yaml:"guardrail,omitempty"`
	PasswordPromptPattern string                                   `yaml:"password_prompt_pattern,omitempty"` // 全局级自定义密码提示正则
}

// GuardrailConfig configures the MCP safety guardrail.
type GuardrailConfig struct {
	Enabled           bool                        `yaml:"enabled"`
	AuditLog          string                      `yaml:"audit_log,omitempty"`
	ApprovalThreshold string                      `yaml:"approval_threshold,omitempty"` // "safe"|"moderate"|"dangerous"
	BlockedPatterns   []string                    `yaml:"blocked_patterns,omitempty"`
	ProtectedPaths    []string                    `yaml:"protected_paths,omitempty"`
	NodeOverrides     map[string]NodeGuardrailCfg `yaml:"nodes,omitempty"`

	// NoElicitFallback controls behavior when the MCP client does not support
	// Elicitation (e.g. Gemini CLI).
	//   "deny"      — reject all operations that need approval (most secure)
	//   "allow"     — allow all, trust client-side tool approval + ToolAnnotations
	//   "downgrade" — allow moderate, still deny dangerous (recommended default)
	NoElicitFallback string `yaml:"no_elicit_fallback,omitempty"`
}

// NodeGuardrailCfg holds per-node (glob pattern) policy overrides.
type NodeGuardrailCfg struct {
	ApprovalThreshold string `yaml:"approval_threshold"`
}

// ConfigProvider is the read-only configuration view consumed by commands,
// connectors, and presentation code. Durable mutations intentionally do not
// belong here: they must go through Repository, which verifies preconditions
// inside one cross-process transaction.
type ConfigProvider interface {
	Resolve(name string) (models.Node, models.Host, models.Identity, error)
	// ResolveConnection returns one complete connection view. The optional
	// UpdateRef is present only when discovery may be conditionally persisted.
	ResolveConnection(name string) (ConnectionSnapshot, error)
	GetNode(name string) (models.Node, bool)
	GetHost(name string) (models.Host, bool)
	GetIdentity(name string) (models.Identity, bool)
	ListNodes() map[string]models.Node
	GetNodesByTag(tag string) map[string]models.Node
	ListIdentities() map[string]models.Identity
	Find(input string) string
	ResolveSelector(input string) (string, error)
	FindAlias(alias string) string
	Snapshot() *Configuration
}

// ConnectionSnapshot is one internally consistent connection configuration.
// UpdateRef is nil for read-only sources, including OpenSSH virtual nodes.
type ConnectionSnapshot struct {
	Node      models.Node
	Host      models.Host
	Identity  models.Identity
	UpdateRef *ConnectionUpdateRef
}

// ConnectionUpdateRef carries the field versions observed with a persistent
// connection snapshot. Both versions must originate from that same snapshot.
type ConnectionUpdateRef struct {
	AuthVersion Version
	SudoVersion Version
}
