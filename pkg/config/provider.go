package config

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

// Provider owns one coherent in-memory configuration snapshot. All reads see
// one revision. Repository owns durable mutations and publishes new snapshots.
type Provider struct {
	mu          sync.RWMutex
	cfg         *Configuration
	lookupIndex map[string][]string
	aliasIndex  map[string]string
	openSSH     *OpenSSHParser
}

var _ ConfigProvider = (*Provider)(nil)

// NewProvider creates a provider and loads the local OpenSSH configuration.
func NewProvider(cfg *Configuration) (*Provider, error) {
	openSSH, err := NewOpenSSHParser()
	if err != nil {
		return nil, fmt.Errorf("load openssh config failed: %w", err)
	}
	return newProvider(cfg, openSSH), nil
}

// NewProviderWithoutOpenSSH creates a provider without an OpenSSH fallback.
func NewProviderWithoutOpenSSH(cfg *Configuration) *Provider {
	return newProvider(cfg, &OpenSSHParser{cfg: nil})
}

// NewProviderWithOpenSSHParser creates a provider using parser as its OpenSSH
// fallback. A nil parser disables the fallback.
func NewProviderWithOpenSSHParser(cfg *Configuration, parser *OpenSSHParser) *Provider {
	if parser == nil {
		parser = &OpenSSHParser{cfg: nil}
	}
	return newProvider(cfg, parser)
}

func newProvider(cfg *Configuration, parser *OpenSSHParser) *Provider {
	cloned := cloneConfiguration(cfg)
	lookup, aliases, _ := buildIndexes(cloned, false)
	return &Provider{
		cfg:         cloned,
		lookupIndex: lookup,
		aliasIndex:  aliases,
		openSSH:     parser,
	}
}

// Snapshot returns a deep copy that callers may retain and mutate freely.
func (p *Provider) Snapshot() *Configuration {
	if p == nil {
		return cloneConfiguration(nil)
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return cloneConfiguration(p.cfg)
}

// Find is the legacy no-error selector helper. Ambiguous selectors deliberately
// resolve to an empty string; callers that need diagnostics must use
// ResolveSelector.
func (p *Provider) Find(input string) string {
	nodeID, err := p.ResolveSelector(input)
	if err != nil {
		return ""
	}
	return nodeID
}

func (p *Provider) ResolveSelector(input string) (string, error) {
	if p == nil {
		return "", nil
	}
	p.mu.RLock()
	if _, ok := p.cfg.Nodes.Get(input); ok {
		p.mu.RUnlock()
		return input, nil
	}
	candidates := slices.Clone(p.lookupIndex[input])
	p.mu.RUnlock()

	switch len(candidates) {
	case 1:
		return candidates[0], nil
	case 0:
		if p.openSSH != nil && p.openSSH.cfg != nil {
			if nodeID, ok := p.openSSH.Find(input); ok {
				return nodeID, nil
			}
		}
		return "", nil
	default:
		return "", &AmbiguousNodeError{Selector: input, Candidates: candidates}
	}
}

func (p *Provider) FindAlias(alias string) string {
	if p == nil || alias == "" {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.aliasIndex[alias]
}

func (p *Provider) ResolveProxyJumpChain(jumpChain string) (string, error) {
	if p == nil {
		return "", nil
	}
	return ResolveProxyJumpChainWithConfig(p.Snapshot(), p.openSSH, jumpChain)
}

// Resolve returns one internally consistent, defensive-copy configuration
// triple. OpenSSH virtual nodes remain read-only fallbacks.
func (p *Provider) Resolve(nodeID string) (models.Node, models.Host, models.Identity, error) {
	if p == nil {
		return models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("config provider is nil")
	}
	p.mu.RLock()
	if node, ok := p.cfg.Nodes.Get(nodeID); ok {
		host, hostOK := p.cfg.Hosts.Get(node.HostRef)
		identity, identityOK := p.cfg.Identities.Get(node.IdentityRef)
		p.mu.RUnlock()
		if !hostOK {
			return models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("host ref %q for node %q: %w", node.HostRef, nodeID, ErrHostNotFound)
		}
		if !identityOK {
			return models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("identity ref %q for node %q: %w", node.IdentityRef, nodeID, ErrIdentityNotFound)
		}
		return cloneNode(node), cloneHost(host), identity, nil
	}
	p.mu.RUnlock()

	if strings.HasPrefix(nodeID, OpenSSHNodePrefix) {
		parser := p.openSSH
		if parser == nil {
			parser = &OpenSSHParser{cfg: nil}
		}
		return parser.GetVirtualNode(strings.TrimPrefix(nodeID, OpenSSHNodePrefix))
	}
	return models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("node %q: %w", nodeID, ErrNodeNotFound)
}

// ResolveConnection returns a read-only connection snapshot. Provider does not
// own durable mutations, so discovery values must remain session-local.
func (p *Provider) ResolveConnection(nodeID string) (ConnectionSnapshot, error) {
	node, host, identity, err := p.Resolve(nodeID)
	if err != nil {
		return ConnectionSnapshot{}, err
	}
	return ConnectionSnapshot{Node: node, Host: host, Identity: identity}, nil
}

func (p *Provider) GetNode(nodeID string) (models.Node, bool) {
	if p == nil {
		return models.Node{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	node, ok := p.cfg.Nodes.Get(nodeID)
	return cloneNode(node), ok
}

func (p *Provider) GetHost(nodeID string) (models.Host, bool) {
	if p == nil {
		return models.Host{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	node, ok := p.cfg.Nodes.Get(nodeID)
	if !ok {
		return models.Host{}, false
	}
	host, ok := p.cfg.Hosts.Get(node.HostRef)
	return cloneHost(host), ok
}

func (p *Provider) GetIdentity(nodeID string) (models.Identity, bool) {
	if p == nil {
		return models.Identity{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	node, ok := p.cfg.Nodes.Get(nodeID)
	if !ok {
		return models.Identity{}, false
	}
	identity, ok := p.cfg.Identities.Get(node.IdentityRef)
	return identity, ok
}

func (p *Provider) ListNodes() map[string]models.Node {
	result := make(map[string]models.Node)
	if p == nil {
		return result
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, nodeID := range p.cfg.Nodes.Keys() {
		node, ok := p.cfg.Nodes.Get(nodeID)
		if !ok || isLocalNode(p.cfg, node) {
			continue
		}
		result[nodeID] = cloneNode(node)
	}
	return result
}

func (p *Provider) GetNodesByTag(tag string) map[string]models.Node {
	result := make(map[string]models.Node)
	if p == nil {
		return result
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, nodeID := range p.cfg.Nodes.Keys() {
		node, ok := p.cfg.Nodes.Get(nodeID)
		if !ok || isLocalNode(p.cfg, node) || !slices.Contains(node.Tags, tag) {
			continue
		}
		result[nodeID] = cloneNode(node)
	}
	return result
}

func (p *Provider) ListIdentities() map[string]models.Identity {
	result := make(map[string]models.Identity)
	if p == nil {
		return result
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, identityID := range p.cfg.Identities.Keys() {
		if identity, ok := p.cfg.Identities.Get(identityID); ok {
			result[identityID] = identity
		}
	}
	return result
}

func isLocalNode(cfg *Configuration, node models.Node) bool {
	host, ok := cfg.Hosts.Get(node.HostRef)
	if !ok {
		return false
	}
	address := strings.ToLower(strings.TrimSpace(host.Address))
	return address == "127.0.0.1" || address == "localhost" || address == "::1"
}

func removeNodeAndUnusedRefs(cfg *Configuration, nodeID string) {
	node, ok := cfg.Nodes.Get(nodeID)
	if !ok {
		return
	}
	cfg.Nodes.Remove(nodeID)
	removeUnusedRefs(cfg, node.HostRef, node.IdentityRef)
}

func removeUnusedRefs(cfg *Configuration, hostRef, identityRef string) {
	hostUsed, identityUsed := false, false
	for _, id := range cfg.Nodes.Keys() {
		other, exists := cfg.Nodes.Get(id)
		if !exists {
			continue
		}
		hostUsed = hostUsed || other.HostRef == hostRef
		identityUsed = identityUsed || other.IdentityRef == identityRef
	}
	if !hostUsed && hostRef != "" {
		cfg.Hosts.Remove(hostRef)
	}
	if !identityUsed && identityRef != "" {
		cfg.Identities.Remove(identityRef)
	}
}

func buildIndexes(cfg *Configuration, rejectAliasConflicts bool) (map[string][]string, map[string]string, error) {
	lookup := make(map[string][]string)
	aliases := make(map[string]string)
	for _, nodeID := range cfg.Nodes.Keys() {
		node, ok := cfg.Nodes.Get(nodeID)
		if !ok {
			continue
		}
		for _, alias := range node.Alias {
			if err := addAlias(lookup, aliases, alias, nodeID, rejectAliasConflicts); err != nil {
				return nil, nil, err
			}
		}
		host, hostOK := cfg.Hosts.Get(node.HostRef)
		identity, identityOK := cfg.Identities.Get(node.IdentityRef)
		if !hostOK || !identityOK {
			continue
		}
		addLookup(lookup, host.Address, nodeID)
		for _, alias := range host.Alias {
			if err := addAlias(lookup, aliases, alias, nodeID, rejectAliasConflicts); err != nil {
				return nil, nil, err
			}
		}
		if identity.User == "" {
			continue
		}
		for _, address := range append(slices.Clone(host.Alias), host.Address) {
			if address == "" {
				continue
			}
			addLookup(lookup, fmt.Sprintf("%s@%s", identity.User, address), nodeID)
			addLookup(lookup, fmt.Sprintf("%s@%s:%d", identity.User, address, host.Port), nodeID)
		}
		for _, alias := range node.Alias {
			if alias == "" {
				continue
			}
			addLookup(lookup, fmt.Sprintf("%s@%s", identity.User, alias), nodeID)
			addLookup(lookup, fmt.Sprintf("%s@%s:%d", identity.User, alias, host.Port), nodeID)
		}
	}
	for key := range lookup {
		sort.Strings(lookup[key])
	}
	return lookup, aliases, nil
}

func addAlias(lookup map[string][]string, aliases map[string]string, alias, nodeID string, rejectConflict bool) error {
	if alias == "" {
		return nil
	}
	if existing, ok := aliases[alias]; ok && existing != nodeID {
		if rejectConflict {
			return fmt.Errorf("alias %q is already assigned to node %q", alias, existing)
		}
		delete(aliases, alias)
		addLookup(lookup, alias, nodeID)
		return nil
	}
	aliases[alias] = nodeID
	addLookup(lookup, alias, nodeID)
	return nil
}

func addLookup(lookup map[string][]string, key, nodeID string) {
	if key == "" || slices.Contains(lookup[key], nodeID) {
		return
	}
	lookup[key] = append(lookup[key], nodeID)
}

func cloneConfiguration(cfg *Configuration) *Configuration {
	cloned := &Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	if cfg == nil {
		return cloned
	}
	cloned.PasswordPromptPattern = cfg.PasswordPromptPattern
	cloned.Guardrail = cloneGuardrail(cfg.Guardrail)
	if cfg.Nodes != nil {
		for _, key := range cfg.Nodes.Keys() {
			if node, ok := cfg.Nodes.Get(key); ok {
				cloned.Nodes.Set(key, cloneNode(node))
			}
		}
	}
	if cfg.Hosts != nil {
		for _, key := range cfg.Hosts.Keys() {
			if host, ok := cfg.Hosts.Get(key); ok {
				cloned.Hosts.Set(key, cloneHost(host))
			}
		}
	}
	if cfg.Identities != nil {
		for _, key := range cfg.Identities.Keys() {
			if identity, ok := cfg.Identities.Get(key); ok {
				cloned.Identities.Set(key, identity)
			}
		}
	}
	return cloned
}

func cloneNode(node models.Node) models.Node {
	node.Alias = slices.Clone(node.Alias)
	node.Tags = slices.Clone(node.Tags)
	return node
}

func cloneHost(host models.Host) models.Host {
	host.Alias = slices.Clone(host.Alias)
	return host
}

func cloneGuardrail(cfg *GuardrailConfig) *GuardrailConfig {
	if cfg == nil {
		return nil
	}
	cloned := *cfg
	cloned.BlockedPatterns = slices.Clone(cfg.BlockedPatterns)
	cloned.ProtectedPaths = slices.Clone(cfg.ProtectedPaths)
	cloned.NodeOverrides = make(map[string]NodeGuardrailCfg, len(cfg.NodeOverrides))
	for key, value := range cfg.NodeOverrides {
		cloned.NodeOverrides[key] = value
	}
	return &cloned
}
