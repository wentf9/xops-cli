package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

// DefaultControlPath specifies the standard OpenSSH multiplexing socket pattern.
const DefaultControlPath = "~/.ssh/cm-%r@%h:%p"

// ValidateSSHOptions validates standalone ssh.Options field syntax and cross-field consistency.
func ValidateSSHOptions(opts *ssh.Options) error {
	if opts == nil {
		return nil
	}
	if err := opts.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrSchemaValidation, err)
	}
	return nil
}

// ValidateEffectiveSSHOptions verifies the resolved effective OpenSSH options for a node.
func ValidateEffectiveSSHOptions(opts *ssh.Options) error {
	if opts == nil {
		return nil
	}
	if err := opts.ValidateEffective(); err != nil {
		return fmt.Errorf("%w: %w", ErrSchemaValidation, err)
	}
	return nil
}

// ValidateControlConfig validates standalone ControlConfig field syntax and cross-field consistency
// by delegating to the canonical core/ssh Options validator.
func ValidateControlConfig(ctrl *ssh.ControlConfig) error {
	if ctrl == nil {
		return nil
	}
	return ValidateSSHOptions(ssh.OptionsFromControl(ctrl))
}

// ValidateControlPathSyntax verifies raw ControlPath string token syntax without environment dependencies.
func ValidateControlPathSyntax(rawPath string) error {
	return ssh.ValidateControlPathSyntax(rawPath)
}

// ValidateEffectiveControl verifies the resolved effective multiplexing configuration for a node
// by delegating to the canonical core/ssh Options effective validator.
func ValidateEffectiveControl(ctrl *ssh.ControlConfig) error {
	if ctrl == nil {
		return nil
	}
	return ValidateEffectiveSSHOptions(ssh.OptionsFromControl(ctrl))
}

// ValidateGraph enforces all configuration invariants across the complete entity
// graph: schema/field validation, effective execution and SSH options, strict
// node/host alias validity and uniqueness, TargetRef round-trip consistency, and
// full-graph ProxyJump chain syntax, self-reference, and cycle detection.
func ValidateGraph(cfg *Configuration) error {
	if err := validateRepositoryConfiguration(cfg); err != nil {
		return err
	}
	lookup, aliases, err := buildIndexes(cfg, true)
	if err != nil {
		return fmt.Errorf("%w: validate configuration indexes: %w", ErrSchemaValidation, err)
	}
	return validateProxyJumpGraph(cfg, lookup, aliases)
}

func wrapConfigDoctorHint(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "xops config doctor") {
		return err
	}
	if errors.Is(err, ErrSchemaValidation) {
		return fmt.Errorf("%w (run 'xops config doctor' to inspect or 'xops config doctor --fix' to repair)", err)
	}
	return err
}

func validateProxyJumpGraph(cfg *Configuration, lookup map[string][]string, aliases map[string]string) error {
	if cfg == nil || cfg.Nodes == nil {
		return nil
	}
	nodeIDs := cfg.Nodes.Keys()
	slices.Sort(nodeIDs)

	adj := make(map[string][]string, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		node, ok := cfg.Nodes.Get(nodeID)
		if !ok {
			continue
		}
		if hasControlOrLineSepChar(node.ProxyJump) {
			return fmt.Errorf("%w: node %q proxy_jump %q invalid: contains control character", ErrSchemaValidation, nodeID, node.ProxyJump)
		}
		if strings.TrimSpace(node.ProxyJump) == "" {
			continue
		}
		ps, err := ssh.ParseProxyJump(node.ProxyJump)
		if err != nil {
			return fmt.Errorf("%w: node %q proxy_jump %q invalid: %w", ErrSchemaValidation, nodeID, node.ProxyJump, err)
		}
		targets, ok := ps.JumpTargets()
		if !ok {
			continue
		}
		edges, err := validateNodeProxyJumpHops(cfg, lookup, aliases, nodeID, node, targets)
		if err != nil {
			return err
		}
		if err := validateSavedNodeProxyJumpGraphCycle(cfg, lookup, aliases, nodeID, node, targets); err != nil {
			return fmt.Errorf("%w: %w", ErrSchemaValidation, err)
		}
		adj[nodeID] = edges
	}
	return detectProxyJumpCycles(nodeIDs, adj)
}

func validateNodeProxyJumpHops(
	cfg *Configuration,
	lookup map[string][]string,
	aliases map[string]string,
	nodeID string,
	node models.Node,
	hops []string,
) ([]string, error) {
	var edges []string
	for _, hop := range hops {
		ref, err := ParseTargetRef(hop)
		if err != nil {
			return nil, fmt.Errorf("%w: node %q proxy_jump hop %q invalid: %w", ErrSchemaValidation, nodeID, hop, err)
		}
		if err := ref.Validate(); err != nil {
			return nil, fmt.Errorf("%w: node %q proxy_jump hop %q invalid: %w", ErrSchemaValidation, nodeID, hop, err)
		}
		if hopReferencesSelf(cfg, nodeID, node, hop, ref) {
			return nil, fmt.Errorf("%w: node %q proxy_jump %q cannot reference itself", ErrSchemaValidation, nodeID, node.ProxyJump)
		}
		if ref.OpenSSH {
			continue
		}
		targets := resolveLocalJumpTargets(cfg, lookup, aliases, hop, ref)
		for _, targetID := range targets {
			if targetID == nodeID {
				return nil, fmt.Errorf("%w: node %q proxy_jump %q cannot reference itself", ErrSchemaValidation, nodeID, node.ProxyJump)
			}
			if !slices.Contains(edges, targetID) {
				edges = append(edges, targetID)
			}
		}
	}
	return edges, nil
}

func hopReferencesSelf(cfg *Configuration, nodeID string, node models.Node, hop string, ref TargetRef) bool {
	if !ref.OpenSSH && hopMatchesSelfName(nodeID, node, hop, ref) {
		return true
	}
	return hopMatchesSelfEndpoint(cfg, node, ref)
}

func hopMatchesSelfName(nodeID string, node models.Node, hop string, ref TargetRef) bool {
	if hop == nodeID {
		return true
	}
	return ref.User == "" && !ref.HasPort && (ref.Host == nodeID || slices.Contains(node.Alias, ref.Host))
}

func hopMatchesSelfEndpoint(cfg *Configuration, node models.Node, ref TargetRef) bool {
	host, hostOK := cfg.Hosts.Get(node.HostRef)
	ident, identOK := cfg.Identities.Get(node.IdentityRef)
	if !hostOK || !identOK {
		return false
	}
	refEp, refErr := ssh.NewEndpoint(ref.Host, int(ref.Port))
	hostEp, hostErr := ssh.NewEndpoint(host.Address, int(host.Port))
	if ref.OpenSSH {
		return refErr == nil && hostErr == nil &&
			refEp.Equal(hostEp) &&
			(ref.User == "" || ref.User == normalizedIdentityUser(ident.User))
	}
	sameHost := refErr == nil && hostErr == nil && refEp.HostEqual(hostEp)
	if !sameHost &&
		!slices.Contains(node.Alias, ref.Host) &&
		!slices.Contains(host.Alias, ref.Host) {
		return false
	}
	if ref.HasPort && normalizedHostPort(ref.Port) != normalizedHostPort(host.Port) {
		return false
	}
	return ref.User == "" || ref.User == normalizedIdentityUser(ident.User)
}

func resolveLocalJumpTargets(
	cfg *Configuration,
	lookup map[string][]string,
	aliases map[string]string,
	hop string,
	ref TargetRef,
) []string {
	if _, ok := cfg.Nodes.Get(hop); ok {
		return []string{hop}
	}
	if nid := aliases[hop]; nid != "" {
		return []string{nid}
	}
	if candidates := lookupBySelector(lookup, hop); len(candidates) > 0 {
		return slices.Clone(candidates)
	}
	hostCandidates := collectHostCandidates(cfg, lookup, aliases, ref.Host)
	if len(hostCandidates) == 0 {
		return nil
	}
	if matched := filterHostCandidates(cfg, hostCandidates, ref.User, ref.Port); len(matched) > 0 {
		return matched
	}
	return nil
}

func detectProxyJumpCycles(nodeIDs []string, adj map[string][]string) error {
	const (
		stateUnvisited = 0
		stateVisiting  = 1
		stateVisited   = 2
	)
	state := make(map[string]uint8, len(nodeIDs))
	var stack []string

	var dfs func(u string) error
	dfs = func(u string) error {
		state[u] = stateVisiting
		stack = append(stack, u)
		for _, v := range adj[u] {
			switch state[v] {
			case stateVisiting:
				start := slices.Index(stack, v)
				cycle := append(slices.Clone(stack[start:]), v)
				return fmt.Errorf("%w: proxy_jump cycle detected: %s", ErrSchemaValidation, strings.Join(cycle, " -> "))
			case stateUnvisited:
				if err := dfs(v); err != nil {
					return err
				}
			}
		}
		stack = stack[:len(stack)-1]
		state[u] = stateVisited
		return nil
	}

	for _, id := range nodeIDs {
		if state[id] == stateUnvisited {
			if err := dfs(id); err != nil {
				return err
			}
		}
	}
	return nil
}
