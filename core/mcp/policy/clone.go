package policy

import (
	"maps"
	"slices"
)

// Clone makes a defensive configuration value for one operation. AuditLog is
// legacy host configuration and is not interpreted by the policy evaluator.
func Clone(cfg Config) Config {
	cfg.BlockedPatterns = slices.Clone(cfg.BlockedPatterns)
	cfg.ProtectedPaths = slices.Clone(cfg.ProtectedPaths)
	cfg.NodeOverrides = maps.Clone(cfg.NodeOverrides)
	return cfg
}
