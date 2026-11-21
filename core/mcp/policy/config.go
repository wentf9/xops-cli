// Package policy defines storage-independent MCP policy configuration.
package policy

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Config configures the MCP safety guardrail.
//
// Zero value fails closed: Disabled == false means the guardrail is active.
// Set Disabled to true (YAML "disabled: true") to explicitly disable it.
type Config struct {
	Disabled          bool                  `yaml:"disabled,omitempty"`
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

// UnmarshalYAML decodes Config and rejects unknown fields (including the removed
// legacy "enabled" key; use "disabled: true" to disable the guardrail).
func (c *Config) UnmarshalYAML(value *yaml.Node) error {
	if value == nil {
		return nil
	}
	for value.Kind == yaml.AliasNode && value.Alias != nil {
		value = value.Alias
	}
	if value.Kind == yaml.ScalarNode && value.Tag == "!!null" {
		*c = Config{}
		return nil
	}
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("guardrail config must be a YAML mapping")
	}

	knownFields := map[string]struct{}{
		"disabled":           {},
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

	type rawConfig Config
	var decoded rawConfig
	if err := value.Decode(&decoded); err != nil {
		return err
	}
	*c = Config(decoded)
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
