// Package policy defines storage-independent MCP policy configuration.
package policy

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

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

// UnmarshalYAML decodes Config while failing closed when the YAML block omits
// "enabled" (defaulting Enabled to true). Explicit "enabled: false" still sets
// Enabled to false, and Go struct literals keep Enabled as a plain bool.
func (c *Config) UnmarshalYAML(value *yaml.Node) error {
	if value == nil {
		return nil
	}
	for value.Kind == yaml.AliasNode && value.Alias != nil {
		value = value.Alias
	}
	if value.Kind == yaml.ScalarNode && value.Tag == "!!null" {
		*c = Config{Enabled: true}
		return nil
	}
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("guardrail config must be a YAML mapping")
	}

	knownFields := map[string]struct{}{
		"enabled":            {},
		"audit_log":          {},
		"approval_threshold": {},
		"blocked_patterns":   {},
		"protected_paths":    {},
		"nodes":              {},
		"no_elicit_fallback": {},
	}
	if err := validateKnownMappingKeys(value, knownFields, "guardrail configuration"); err != nil {
		return err
	}

	type rawConfig struct {
		Enabled           *bool                 `yaml:"enabled"`
		AuditLog          string                `yaml:"audit_log,omitempty"`
		ApprovalThreshold string                `yaml:"approval_threshold,omitempty"`
		BlockedPatterns   []string              `yaml:"blocked_patterns,omitempty"`
		ProtectedPaths    []string              `yaml:"protected_paths,omitempty"`
		NodeOverrides     map[string]NodeConfig `yaml:"nodes,omitempty"`
		NoElicitFallback  string                `yaml:"no_elicit_fallback,omitempty"`
	}

	var decoded rawConfig
	if err := value.Decode(&decoded); err != nil {
		return err
	}

	enabled := true
	if decoded.Enabled != nil {
		enabled = *decoded.Enabled
	}

	*c = Config{
		Enabled:           enabled,
		AuditLog:          decoded.AuditLog,
		ApprovalThreshold: decoded.ApprovalThreshold,
		BlockedPatterns:   decoded.BlockedPatterns,
		ProtectedPaths:    decoded.ProtectedPaths,
		NodeOverrides:     decoded.NodeOverrides,
		NoElicitFallback:  decoded.NoElicitFallback,
	}
	return nil
}

// UnmarshalYAML decodes NodeConfig and rejects unknown fields so strict config
// decoders continue catching typos inside per-node overrides.
func (n *NodeConfig) UnmarshalYAML(value *yaml.Node) error {
	if value == nil {
		return nil
	}
	for value.Kind == yaml.AliasNode && value.Alias != nil {
		value = value.Alias
	}
	if value.Kind == yaml.ScalarNode && value.Tag == "!!null" {
		*n = NodeConfig{}
		return nil
	}
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("guardrail node override must be a YAML mapping")
	}
	knownFields := map[string]struct{}{
		"approval_threshold": {},
	}
	if err := validateKnownMappingKeys(value, knownFields, "guardrail node override"); err != nil {
		return err
	}

	type rawNodeConfig NodeConfig
	var decoded rawNodeConfig
	if err := value.Decode(&decoded); err != nil {
		return err
	}
	*n = NodeConfig(decoded)
	return nil
}

func validateKnownMappingKeys(node *yaml.Node, known map[string]struct{}, scope string) error {
	visited := make(map[*yaml.Node]bool)
	return validateKnownMappingKeysVisited(node, known, scope, visited)
}

func validateKnownMappingKeysVisited(node *yaml.Node, known map[string]struct{}, scope string, visited map[*yaml.Node]bool) error {
	for node != nil && node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	if node == nil || node.Kind != yaml.MappingNode {
		return fmt.Errorf("%s must be a YAML mapping", scope)
	}
	if visited[node] {
		return nil
	}
	visited[node] = true

	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		val := node.Content[i+1]
		if key.Tag == "!!merge" || key.Value == "<<" {
			target := val
			for target != nil && target.Kind == yaml.AliasNode {
				target = target.Alias
			}
			if target == nil {
				return fmt.Errorf("%s has invalid merge key", scope)
			}
			switch target.Kind {
			case yaml.MappingNode:
				if err := validateKnownMappingKeysVisited(target, known, scope, visited); err != nil {
					return err
				}
			case yaml.SequenceNode:
				for _, elem := range target.Content {
					if err := validateKnownMappingKeysVisited(elem, known, scope, visited); err != nil {
						return err
					}
				}
			default:
				return fmt.Errorf("%s merge key must reference a mapping", scope)
			}
			continue
		}
		if _, ok := known[key.Value]; !ok {
			return fmt.Errorf("unknown field %q in %s", key.Value, scope)
		}
	}
	return nil
}
