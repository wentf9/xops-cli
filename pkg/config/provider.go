package config

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/wentf9/xops-cli/core/concurrent"
	corepolicy "github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

// Provider owns one coherent in-memory configuration snapshot. All reads see
// one revision. Repository owns durable mutations and publishes new snapshots.
type Provider struct {
	mu             sync.RWMutex
	cfg            *Configuration
	lookupIndex    map[string][]string
	aliasIndex     map[string]string
	openSSH        *OpenSSHParser
	openSSHAliases map[string]string
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

// Frozen returns an independent provider with the current configuration and
// parsed OpenSSH fallback. Later repository publications do not affect it.
func (p *Provider) Frozen() ConfigProvider {
	p.mu.RLock()
	defer p.mu.RUnlock()
	frozen := newProvider(p.cfg, p.openSSH)
	if len(p.openSSHAliases) > 0 {
		frozen.openSSHAliases = make(map[string]string, len(p.openSSHAliases))
		for k, v := range p.openSSHAliases {
			frozen.openSSHAliases[k] = v
		}
	}
	return frozen
}

// GetOpenSSHOptions returns supported OpenSSH options from OpenSSH config for an alias.
func (p *Provider) GetOpenSSHOptions(alias string) (*ssh.Options, error) {
	if p == nil || p.openSSH == nil {
		return nil, nil
	}
	return p.openSSH.GetSSHOptions(alias)
}

// GetOpenSSHControl returns multiplexing configuration from OpenSSH config for an alias.
func (p *Provider) GetOpenSSHControl(alias string) (*ssh.ControlConfig, error) {
	if p == nil || p.openSSH == nil {
		return nil, nil
	}
	return p.openSSH.GetControlConfig(alias)
}

// GetOpenSSHParser returns the underlying OpenSSH parser.
func (p *Provider) GetOpenSSHParser() *OpenSSHParser {
	if p == nil {
		return nil
	}
	return p.openSSH
}

// SetNodeOpenSSHAlias records the concrete OpenSSH Host alias from which nodeID
// was derived during the current session without modifying persisted state.
func (p *Provider) SetNodeOpenSSHAlias(nodeID, alias string) {
	if p == nil || nodeID == "" || alias == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.openSSHAliases == nil {
		p.openSSHAliases = make(map[string]string)
	}
	p.openSSHAliases[nodeID] = alias
}

// NodeOpenSSHAlias returns the session-recorded OpenSSH Host alias for nodeID.
func (p *Provider) NodeOpenSSHAlias(nodeID string) string {
	if p == nil || nodeID == "" {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.openSSHAliases[nodeID]
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
		openSSHAlias := p.openSSHAliases[nodeID]
		p.mu.RUnlock()
		if !hostOK {
			return models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("host ref %q for node %q: %w", node.HostRef, nodeID, ErrHostNotFound)
		}
		if !identityOK {
			return models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("identity ref %q for node %q: %w", node.IdentityRef, nodeID, ErrIdentityNotFound)
		}
		clonedNode := cloneNode(node)
		if clonedNode.OpenSSHAlias == "" {
			clonedNode.OpenSSHAlias = openSSHAlias
		}
		return clonedNode, cloneHost(host), cloneIdentity(identity), nil
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
	cloned := cloneNode(node)
	if ok && cloned.OpenSSHAlias == "" {
		cloned.OpenSSHAlias = p.openSSHAliases[nodeID]
	}
	return cloned, ok
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
	return cloneIdentity(identity), ok
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
		if !ok {
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
		if !ok || !slices.Contains(node.Tags, tag) {
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
			result[identityID] = cloneIdentity(identity)
		}
	}
	return result
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
		user := normalizedIdentityUser(identity.User)
		if user == "" {
			continue
		}
		port := normalizedHostPort(host.Port)
		for _, address := range append(slices.Clone(host.Alias), host.Address) {
			if address == "" {
				continue
			}
			addLookup(lookup, fmt.Sprintf("%s@%s", user, address), nodeID)
			addLookup(lookup, fmt.Sprintf("%s@%s:%d", user, address, port), nodeID)
		}
		for _, alias := range node.Alias {
			if alias == "" {
				continue
			}
			addLookup(lookup, fmt.Sprintf("%s@%s", user, alias), nodeID)
			addLookup(lookup, fmt.Sprintf("%s@%s:%d", user, alias, port), nodeID)
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
	if existing, ok := aliases[alias]; ok {
		if existing == nodeID {
			addLookup(lookup, alias, nodeID)
			return nil
		}
		if rejectConflict {
			return fmt.Errorf("alias %q is already assigned to node %q", alias, existing)
		}
		aliases[alias] = ""
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

// Snapshot 返回当前配置的防御性深拷贝副本。
func (c *Configuration) Snapshot() *Configuration {
	return cloneConfiguration(c)
}

func cloneConfiguration(cfg *Configuration) *Configuration {
	cloned := &Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	if cfg == nil {
		cloned.SchemaVersion = 2
		cloned.Credential = DefaultCredentialConfig()
		return cloned
	}
	cloned.SchemaVersion = cfg.SchemaVersion
	cloned.Credential = cfg.Credential.Clone()
	cloned.PasswordPromptPattern = cfg.PasswordPromptPattern
	cloned.Guardrail = cloneGuardrail(cfg.Guardrail)
	cloned.MCP = cfg.MCP.Clone()
	cloned.Execution = cfg.Execution.Clone()
	cloned.SSHOptions = cfg.SSHOptions.Clone()
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
				cloned.Identities.Set(key, cloneIdentity(identity))
			}
		}
	}
	return cloned
}

func cloneNode(node models.Node) models.Node {
	node.Alias = slices.Clone(node.Alias)
	node.Tags = slices.Clone(node.Tags)
	if node.PrivilegePasswordRef != nil {
		node.PrivilegePasswordRef = node.PrivilegePasswordRef.Clone()
	}
	if node.Execution != nil {
		node.Execution = node.Execution.Clone()
	}
	if node.SSHOptions != nil {
		node.SSHOptions = node.SSHOptions.Clone()
	}
	return node
}

func cloneIdentity(identity models.Identity) models.Identity {
	return identity.Clone()
}

func cloneHost(host models.Host) models.Host {
	host.Alias = slices.Clone(host.Alias)
	return host
}

func cloneGuardrail(cfg *corepolicy.Config) *corepolicy.Config {
	if cfg == nil {
		return nil
	}
	cloned := *cfg
	cloned.BlockedPatterns = slices.Clone(cfg.BlockedPatterns)
	cloned.ProtectedPaths = slices.Clone(cfg.ProtectedPaths)
	cloned.NodeOverrides = make(map[string]corepolicy.NodeConfig, len(cfg.NodeOverrides))
	for key, value := range cfg.NodeOverrides {
		cloned.NodeOverrides[key] = value
	}
	return &cloned
}
