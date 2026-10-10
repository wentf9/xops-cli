package state

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"

	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
)

type Change struct {
	Affected map[string]struct{}
	Revoke   map[string]struct{}
	Removed  []string
	Retired  []ssh.ConnectionPlan
	Policy   bool
}

func validateSnapshot(view ports.OperationSnapshot) error {
	if view.DomainID == "" || view.Revision == "" {
		return errors.New("publication domain and inventory revision are required")
	}
	if err := guardrail.ValidateConfig(&view.Policy); err != nil {
		return err
	}
	if _, err := view.Digest(); err != nil {
		return err
	}
	for alias, id := range view.Selectors {
		if alias == "" {
			return errors.New("inventory alias cannot be empty")
		}
		if _, ok := view.Targets[id]; !ok {
			return fmt.Errorf("alias %q points outside inventory", alias)
		}
		if _, canonical := view.Targets[alias]; canonical && alias != id {
			return errors.New("alias cannot redirect a canonical node ID")
		}
	}
	seen := make(map[string]ssh.ConnectionConfig)
	for id, target := range view.Targets {
		for _, hop := range target.Plan.Hops {
			identity := endpoint(hop)
			if previous, ok := seen[hop.NodeID]; ok && previous != identity {
				return fmt.Errorf("node %q contains an inconsistent snapshot of shared hop %q", id, hop.NodeID)
			}
			seen[hop.NodeID] = identity
		}
	}
	return nil
}

func endpoint(cfg ssh.ConnectionConfig) ssh.ConnectionConfig {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	cfg.ProxyJump = ""
	cfg.OriginalProxyJump = ""
	cfg.HasOriginalProxyJump = false
	return cfg
}

func calculateChange(old, next ports.OperationSnapshot) (Change, error) {
	change := Change{Affected: make(map[string]struct{}), Revoke: make(map[string]struct{})}
	before, after := policy.Clone(old.Policy), policy.Clone(next.Policy)
	before.AuditLog = ""
	after.AuditLog = ""
	change.Policy = old.PolicyRevision != next.PolicyRevision || !reflect.DeepEqual(before, after)
	for id, target := range old.Targets {
		updated, exists := next.Targets[id]
		if err := change.compareTarget(id, target, updated, exists); err != nil {
			return Change{}, err
		}
	}
	for id := range next.Targets {
		if _, ok := old.Targets[id]; !ok {
			change.Affected[id] = struct{}{}
		}
	}
	connections := maps.Clone(change.Affected)
	aliases := maps.Clone(old.Selectors)
	if aliases == nil {
		aliases = make(map[string]string)
	}
	maps.Copy(aliases, next.Selectors)
	for alias := range aliases {
		if old.Selectors[alias] != next.Selectors[alias] {
			for _, id := range []string{old.Selectors[alias], next.Selectors[alias]} {
				if id != "" {
					change.Affected[id] = struct{}{}
				}
			}
		}
	}
	for id, target := range next.Targets {
		if target.Disabled {
			continue
		}
		for _, hop := range target.Plan.Hops {
			if slices.Contains(change.Removed, hop.NodeID) {
				return Change{}, fmt.Errorf("active node %q still depends on deleted jump %q", id, hop.NodeID)
			}
		}
	}
	// A disabled/shared jump affects all downstream plans even when their own
	// connection fields did not change. Closure is computed without any I/O.
	expandAffected(old, change.Affected)
	expandAffected(next, change.Affected)
	expandAffected(old, change.Revoke)
	expandAffected(next, change.Revoke)
	expandAffected(old, connections)
	expandAffected(next, connections)
	for id, target := range old.Targets {
		if _, affected := connections[id]; affected && !containsPlan(change.Retired, target.Plan) {
			change.Retired = append(change.Retired, target.Plan)
		}
	}
	return change, nil
}

func authenticationChanged(old, next ssh.ConnectionPlan) bool {
	previous := make(map[string]ssh.ConnectionConfig)
	for _, hop := range old.Hops {
		previous[hop.NodeID] = hop
	}
	for _, hop := range next.Hops {
		before, ok := previous[hop.NodeID]
		if !ok {
			continue
		}
		if before.AuthType != hop.AuthType || before.AuthUpdateToken != hop.AuthUpdateToken || before.SudoUpdateToken != hop.SudoUpdateToken || before.KeyRef != hop.KeyRef || before.KeyPath != hop.KeyPath || before.TrustVersion != hop.TrustVersion {
			return true
		}
	}
	return false
}

func expandAffected(view ports.OperationSnapshot, set map[string]struct{}) {
	for changed := true; changed; {
		changed = false
		for id, target := range view.Targets {
			if _, ok := set[id]; ok {
				continue
			}
			for _, hop := range target.Plan.Hops {
				if _, ok := set[hop.NodeID]; ok {
					set[id] = struct{}{}
					changed = true
					break
				}
			}
		}
	}
}

func containsPlan(plans []ssh.ConnectionPlan, plan ssh.ConnectionPlan) bool {
	for _, candidate := range plans {
		if reflect.DeepEqual(candidate, plan) {
			return true
		}
	}
	return false
}

func (change *Change) compareTarget(id string, target, updated ports.Target, exists bool) error {
	if !exists {
		change.Affected[id] = struct{}{}
		change.Revoke[id] = struct{}{}
		change.Removed = append(change.Removed, id)
		change.Retired = append(change.Retired, target.Plan)
		return nil
	}
	oldKey, err := ssh.ConnectionKey(target.Plan)
	if err != nil {
		return err
	}
	newKey, err := ssh.ConnectionKey(updated.Plan)
	if err != nil {
		return err
	}
	if oldKey != newKey || target.Version != updated.Version || target.ExecutionVersion != updated.ExecutionVersion || target.Disabled != updated.Disabled {
		change.Affected[id] = struct{}{}
		change.Retired = append(change.Retired, target.Plan)
	}
	if updated.Disabled || authenticationChanged(target.Plan, updated.Plan) {
		change.Revoke[id] = struct{}{}
	}
	return nil
}
