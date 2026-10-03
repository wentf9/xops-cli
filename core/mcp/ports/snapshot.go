package ports

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/ssh"
)

var (
	ErrStaleBinding = errors.New("operation binding is stale")
	ErrNodeDisabled = errors.New("node is disabled")
	ErrNotFound     = errors.New("node is not in the operation snapshot")
	ErrPurpose      = errors.New("operation permit does not allow this purpose")
)

func cloneNode(info NodeInfo) NodeInfo {
	info.Alias = slices.Clone(info.Alias)
	info.Tags = slices.Clone(info.Tags)
	return info
}

func (s InventorySnapshot) Clone() InventorySnapshot {
	s.Policy = policy.Clone(s.Policy)
	s.Nodes = slices.Clone(s.Nodes)
	for i := range s.Nodes {
		s.Nodes[i] = cloneNode(s.Nodes[i])
	}
	return s
}

func (s OperationSnapshot) Clone() OperationSnapshot {
	s.Policy = policy.Clone(s.Policy)
	s.Targets = maps.Clone(s.Targets)
	s.Selectors = maps.Clone(s.Selectors)
	for id, target := range s.Targets {
		target.Info = cloneNode(target.Info)
		target.Plan.Hops = slices.Clone(target.Plan.Hops)
		s.Targets[id] = target
	}
	return s
}

func (s OperationSnapshot) Resolve(selector string) (string, Target, error) {
	id := selector
	if _, canonical := s.Targets[selector]; !canonical {
		if selected, ok := s.Selectors[selector]; ok {
			id = selected
		}
	}
	target, ok := s.Targets[id]
	if !ok {
		return "", Target{}, fmt.Errorf("resolve %q: %w", selector, ErrNotFound)
	}
	if target.Disabled {
		return "", Target{}, fmt.Errorf("resolve %q: %w", selector, ErrNodeDisabled)
	}
	if target.Info.ID != id || len(target.Plan.Hops) == 0 || target.Plan.Hops[len(target.Plan.Hops)-1].NodeID != id {
		return "", Target{}, errors.New("snapshot node and connection plan identities disagree")
	}
	return id, target, nil
}

// Digest excludes global/display revisions and the legacy audit pathname. It
// binds only the selected plans, relevant versions, resolved selectors and
// policy. Hosts must include tag-dependent policy changes in those versions.
func (s OperationSnapshot) Digest() (string, error) {
	if s.DomainID == "" {
		return "", errors.New("snapshot publication domain is required")
	}
	type targetIdentity struct {
		ConnectionKey, Version string
		Disabled               bool
	}
	targets := make(map[string]targetIdentity, len(s.Targets))
	for id, target := range s.Targets {
		key, err := ssh.ConnectionKey(target.Plan)
		if err != nil {
			return "", fmt.Errorf("bind target %q: %w", id, err)
		}
		if target.Info.ID != id || target.Plan.Hops[len(target.Plan.Hops)-1].NodeID != id {
			return "", errors.New("snapshot node and connection plan identities disagree")
		}
		targets[id] = targetIdentity{key, target.Version, target.Disabled}
	}
	selectors := make(map[string]string, len(s.Selectors))
	maps.Copy(selectors, s.Selectors)
	cfg := policy.Clone(s.Policy)
	cfg.AuditLog = ""
	return digest(struct {
		Domain, PolicyRevision string
		Policy                 policy.Config
		Targets                map[string]targetIdentity
		Selectors              map[string]string
	}{s.DomainID, s.PolicyRevision, cfg, targets, selectors})
}

func Bind(snapshot OperationSnapshot, scope, tool string, input any) (Binding, error) {
	if scope == "" || len(scope) > 256 || tool == "" {
		return Binding{}, errors.New("operation scope and tool are required")
	}
	view, err := snapshot.Digest()
	if err != nil {
		return Binding{}, err
	}
	request, err := digest(input)
	if err != nil {
		return Binding{}, err
	}
	return Binding{snapshot.DomainID, scope, tool, request, view}, nil
}

func (b Binding) Validate(snapshot OperationSnapshot) error {
	current, err := snapshot.Digest()
	if err != nil {
		return err
	}
	digestBytes, decodeErr := hex.DecodeString(b.InputDigest)
	if decodeErr != nil || len(digestBytes) != sha256.Size || b.DomainID != snapshot.DomainID || b.SnapshotDigest != current || b.Scope == "" || b.Tool == "" {
		return ErrStaleBinding
	}
	return nil
}

func (b Binding) Digest() (string, error) { return digest(b) }

func digest(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode operation binding: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
