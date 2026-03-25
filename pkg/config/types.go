package config

import (
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

// Configuration 对应 yaml 文件的顶层结构
type Configuration struct {
	Identities *concurrent.Map[string, models.Identity] `yaml:"identities"`
	Hosts      *concurrent.Map[string, models.Host]     `yaml:"hosts"`
	Nodes      *concurrent.Map[string, models.Node]     `yaml:"nodes"`
	Guardrail  *GuardrailConfig                         `yaml:"guardrail,omitempty"`
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

// ConfigProvider 定义 Connector 获取配置数据的接口
type ConfigProvider interface {
	GetNode(name string) (models.Node, bool)
	GetHost(name string) (models.Host, bool)
	GetIdentity(name string) (models.Identity, bool)
	AddHost(name string, host models.Host)
	AddIdentity(name string, identity models.Identity)
	AddNode(name string, node models.Node)
	DeleteNode(name string)
	ListNodes() map[string]models.Node
	GetNodesByTag(tag string) map[string]models.Node
	ListIdentities() map[string]models.Identity
	DeleteIdentity(name string)
	Find(input string) string
	FindAlias(alias string) string
	GetConfig() *Configuration
}
