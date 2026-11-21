package config

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/wentf9/xops-cli/core/concurrent"
	corepolicy "github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

// OpenSSHOrigin represents the atomic (Alias, CanonicalHost) pair associating a
// node with the OpenSSH Host alias and optional canonicalized hostname from which
// it was resolved during the current session.
type OpenSSHOrigin struct {
	Alias         string
	CanonicalHost string
}

func normalizeOpenSSHOrigin(origin OpenSSHOrigin) OpenSSHOrigin {
	return OpenSSHOrigin{
		Alias:         strings.TrimSpace(origin.Alias),
		CanonicalHost: strings.TrimSpace(origin.CanonicalHost),
	}
}

// IsZero reports whether both Alias and CanonicalHost are empty after trimming.
func (o OpenSSHOrigin) IsZero() bool {
	return strings.TrimSpace(o.Alias) == "" && strings.TrimSpace(o.CanonicalHost) == ""
}

// Equal reports whether o and other represent the same OpenSSH origin pair.
func (o OpenSSHOrigin) Equal(other OpenSSHOrigin) bool {
	a := normalizeOpenSSHOrigin(o)
	b := normalizeOpenSSHOrigin(other)
	return a.Alias == b.Alias && strings.EqualFold(a.CanonicalHost, b.CanonicalHost)
}

// Provider owns one coherent in-memory configuration snapshot. All reads see
// one revision. Repository owns durable mutations and publishes new snapshots.
type Provider struct {
	mu             sync.RWMutex
	cfg            *Configuration
	lookupIndex    map[string][]string
	aliasIndex     map[string]string
	openSSH        *OpenSSHParser
	openSSHOrigins map[string]OpenSSHOrigin
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

// StripHostBrackets removes one surrounding bracket pair from a bracketed IPv6
// address literal (preserving zone IDs). Malformed single brackets and
// non-IPv6 bracketed values are returned trimmed without modification.
func StripHostBrackets(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) >= 2 && trimmed[0] == '[' && trimmed[len(trimmed)-1] == ']' {
		inner := trimmed[1 : len(trimmed)-1]
		if ip, err := netip.ParseAddr(inner); err == nil && ip.Is6() {
			return inner
		}
	}
	return trimmed
}

// NormalizeHostAddress trims whitespace and surrounding IPv6 brackets, returning
// the canonical RFC 5952 representation for IP literals (preserving IPv6 zone IDs
// and keeping IPv4-mapped IPv6 addresses distinct from IPv4) and lowercasing
// non-IP DNS hostnames so equality and index keys share one canonical representative.
func NormalizeHostAddress(raw string) string {
	clean := StripHostBrackets(raw)
	if clean == "" {
		return ""
	}
	if ip, err := netip.ParseAddr(clean); err == nil {
		return ip.String()
	}
	return strings.ToLower(clean)
}

func stripTransientNodeMetadata(cfg *Configuration) {
	if cfg == nil || cfg.Nodes == nil {
		return
	}
	for _, nodeID := range cfg.Nodes.Keys() {
		node, ok := cfg.Nodes.Get(nodeID)
		if !ok || (node.OpenSSHAlias == "" && node.CanonicalHost == "") {
			continue
		}
		node.OpenSSHAlias = ""
		node.CanonicalHost = ""
		cfg.Nodes.Set(nodeID, node)
	}
}

func cloneConfigurationExtractingMetadata(cfg *Configuration) (*Configuration, map[string]OpenSSHOrigin) {
	cloned := cloneConfiguration(cfg)
	if cloned == nil || cloned.Nodes == nil {
		return cloned, nil
	}
	var origins map[string]OpenSSHOrigin
	for _, nodeID := range cloned.Nodes.Keys() {
		node, ok := cloned.Nodes.Get(nodeID)
		if !ok || (node.OpenSSHAlias == "" && node.CanonicalHost == "") {
			continue
		}
		origin := normalizeOpenSSHOrigin(OpenSSHOrigin{
			Alias:         node.OpenSSHAlias,
			CanonicalHost: node.CanonicalHost,
		})
		if !origin.IsZero() {
			if origins == nil {
				origins = make(map[string]OpenSSHOrigin)
			}
			origins[nodeID] = origin
		}
		node.OpenSSHAlias = ""
		node.CanonicalHost = ""
		cloned.Nodes.Set(nodeID, node)
	}
	return cloned, origins
}

func newProvider(cfg *Configuration, parser *OpenSSHParser) *Provider {
	cloned, origins := cloneConfigurationExtractingMetadata(cfg)
	lookup, aliasIdx, _ := buildIndexes(cloned, false)
	return &Provider{
		cfg:            cloned,
		lookupIndex:    lookup,
		aliasIndex:     aliasIdx,
		openSSH:        parser,
		openSSHOrigins: origins,
	}
}

// Frozen returns an independent provider with the current configuration and
// parsed OpenSSH fallback. Later repository publications do not affect it.
func (p *Provider) Frozen() ConfigProvider {
	p.mu.RLock()
	defer p.mu.RUnlock()
	frozen := newProvider(p.cfg, p.openSSH)
	if len(p.openSSHOrigins) > 0 {
		frozen.openSSHOrigins = make(map[string]OpenSSHOrigin, len(p.openSSHOrigins))
		for k, v := range p.openSSHOrigins {
			frozen.openSSHOrigins[k] = v
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

// NodeOpenSSHOrigin returns the atomic session-recorded OpenSSH origin pair for nodeID.
func (p *Provider) NodeOpenSSHOrigin(nodeID string) OpenSSHOrigin {
	if p == nil || nodeID == "" {
		return OpenSSHOrigin{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.openSSHOrigins[nodeID]
}

// SetNodeOpenSSHOrigin atomically replaces the session-recorded OpenSSH origin
// for nodeID without modifying persisted state. A zero origin clears the entry.
func (p *Provider) SetNodeOpenSSHOrigin(nodeID string, origin OpenSSHOrigin) {
	if p == nil || nodeID == "" {
		return
	}
	norm := normalizeOpenSSHOrigin(origin)
	p.mu.Lock()
	defer p.mu.Unlock()
	if norm.IsZero() {
		delete(p.openSSHOrigins, nodeID)
		return
	}
	if p.openSSHOrigins == nil {
		p.openSSHOrigins = make(map[string]OpenSSHOrigin)
	}
	p.openSSHOrigins[nodeID] = norm
}

// ClearNodeOpenSSHOrigin removes the session-recorded OpenSSH origin for nodeID.
func (p *Provider) ClearNodeOpenSSHOrigin(nodeID string) {
	if p == nil || nodeID == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.openSSHOrigins, nodeID)
}

// SetNodeOpenSSHAlias records the concrete OpenSSH Host alias from which nodeID
// was derived during the current session without modifying persisted state.
// Passing an empty alias clears the node's OpenSSH origin; changing the alias
// clears any stale CanonicalHost from a prior alias.
func (p *Provider) SetNodeOpenSSHAlias(nodeID, alias string) {
	if p == nil || nodeID == "" {
		return
	}
	trimmed := strings.TrimSpace(alias)
	p.mu.Lock()
	defer p.mu.Unlock()
	if trimmed == "" {
		delete(p.openSSHOrigins, nodeID)
		return
	}
	if p.openSSHOrigins == nil {
		p.openSSHOrigins = make(map[string]OpenSSHOrigin)
	}
	cur := p.openSSHOrigins[nodeID]
	if cur.Alias != trimmed {
		p.openSSHOrigins[nodeID] = OpenSSHOrigin{Alias: trimmed}
	}
}

// NodeOpenSSHAlias returns the session-recorded OpenSSH Host alias for nodeID.
func (p *Provider) NodeOpenSSHAlias(nodeID string) string {
	return p.NodeOpenSSHOrigin(nodeID).Alias
}

// SetNodeCanonicalHost records the hostname-canonicalized host for nodeID
// during the current session without modifying persisted state.
func (p *Provider) SetNodeCanonicalHost(nodeID, canonicalHost string) {
	if p == nil || nodeID == "" {
		return
	}
	trimmed := strings.TrimSpace(canonicalHost)
	p.mu.Lock()
	defer p.mu.Unlock()
	cur := p.openSSHOrigins[nodeID]
	cur.CanonicalHost = trimmed
	if cur.IsZero() {
		delete(p.openSSHOrigins, nodeID)
		return
	}
	if p.openSSHOrigins == nil {
		p.openSSHOrigins = make(map[string]OpenSSHOrigin)
	}
	p.openSSHOrigins[nodeID] = cur
}

// NodeCanonicalHost returns the session-recorded canonicalized host for nodeID.
func (p *Provider) NodeCanonicalHost(nodeID string) string {
	return p.NodeOpenSSHOrigin(nodeID).CanonicalHost
}

func (p *Provider) setSavedNodeOpenSSHMetadataIfPresent(nodeID, alias, canonicalHost string) {
	origin := normalizeOpenSSHOrigin(OpenSSHOrigin{Alias: alias, CanonicalHost: canonicalHost})
	if p == nil || nodeID == "" || origin.IsZero() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cfg == nil || p.cfg.Nodes == nil {
		return
	}
	if _, ok := p.cfg.Nodes.Get(nodeID); !ok {
		return
	}
	p.setOpenSSHOriginLocked(nodeID, origin)
}

func (p *Provider) setOpenSSHMetadataLocked(nodeID, alias, canonicalHost string) {
	p.setOpenSSHOriginLocked(nodeID, OpenSSHOrigin{Alias: alias, CanonicalHost: canonicalHost})
}

func (p *Provider) setOpenSSHOriginLocked(nodeID string, origin OpenSSHOrigin) {
	norm := normalizeOpenSSHOrigin(origin)
	if norm.IsZero() {
		return
	}
	if p.openSSHOrigins == nil {
		p.openSSHOrigins = make(map[string]OpenSSHOrigin)
	}
	p.openSSHOrigins[nodeID] = norm
}

func (p *Provider) snapshotWithNodeOrigin(nodeID string) (*Configuration, OpenSSHOrigin) {
	if p == nil {
		return cloneConfiguration(nil), OpenSSHOrigin{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return cloneConfiguration(p.cfg), p.openSSHOrigins[nodeID]
}

func (p *Provider) snapshotWithOrigins() (*Configuration, map[string]OpenSSHOrigin) {
	if p == nil {
		return cloneConfiguration(nil), nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	snap := cloneConfiguration(p.cfg)
	if len(p.openSSHOrigins) == 0 {
		return snap, nil
	}
	origins := make(map[string]OpenSSHOrigin, len(p.openSSHOrigins))
	for k, v := range p.openSSHOrigins {
		origins[k] = v
	}
	return snap, origins
}

func resolveConfigNodeHostAddrPort(cfg *Configuration, nodeID string) (string, uint16, bool) {
	if cfg == nil || cfg.Nodes == nil || cfg.Hosts == nil {
		return "", 0, false
	}
	node, ok := cfg.Nodes.Get(nodeID)
	if !ok {
		return "", 0, false
	}
	host, ok := cfg.Hosts.Get(node.HostRef)
	if !ok {
		return "", 0, false
	}
	cleanAddr := StripHostBrackets(host.Address)
	return cleanAddr, normalizedHostPort(host.Port), true
}

func configHasNode(cfg *Configuration, nodeID string) bool {
	if cfg == nil || cfg.Nodes == nil {
		return false
	}
	_, ok := cfg.Nodes.Get(nodeID)
	return ok
}

func (p *Provider) pruneStaleOpenSSHMetadataLocked(oldCfg, updated *Configuration) {
	if p == nil {
		return
	}
	for nodeID := range p.openSSHOrigins {
		oldAddr, oldPort, hadOld := resolveConfigNodeHostAddrPort(oldCfg, nodeID)
		newAddr, newPort, hasNew := resolveConfigNodeHostAddrPort(updated, nodeID)
		stale := false
		if hadOld {
			oldEp, oldErr := ssh.NewEndpoint(oldAddr, int(oldPort))
			newEp, newErr := ssh.NewEndpoint(newAddr, int(newPort))
			stale = !hasNew || oldErr != nil || newErr != nil || !oldEp.Equal(newEp)
		} else if configHasNode(oldCfg, nodeID) || configHasNode(updated, nodeID) {
			stale = true
		}
		if stale {
			delete(p.openSSHOrigins, nodeID)
		}
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
	trimmed := strings.TrimSpace(input)
	p.mu.RLock()
	if nid, ok := p.resolveDirectSelectorLocked(input, trimmed); ok {
		p.mu.RUnlock()
		return nid, nil
	}
	candidates := p.resolveLookupCandidatesLocked(input, trimmed)
	p.mu.RUnlock()

	switch len(candidates) {
	case 1:
		return candidates[0], nil
	case 0:
		if p.openSSH != nil {
			if err := p.openSSH.Err(); err != nil {
				return "", fmt.Errorf("resolve openssh selector %q: %w", input, err)
			}
			if p.openSSH.cfg != nil {
				openSSHQuery := trimmed
				if openSSHQuery == "" {
					openSSHQuery = input
				}
				if nodeID, ok := p.openSSH.Find(openSSHQuery); ok {
					return nodeID, nil
				}
			}
		}
		return "", nil
	default:
		return "", &AmbiguousNodeError{Selector: input, Candidates: candidates}
	}
}

func (p *Provider) resolveDirectSelectorLocked(input, trimmed string) (string, bool) {
	if _, ok := p.cfg.Nodes.Get(input); ok {
		return input, true
	}
	if trimmed != "" && trimmed != input {
		if _, ok := p.cfg.Nodes.Get(trimmed); ok {
			return trimmed, true
		}
	}
	if nid := p.aliasIndex[input]; nid != "" {
		return nid, true
	}
	if trimmed != "" && trimmed != input {
		if nid := p.aliasIndex[trimmed]; nid != "" {
			return nid, true
		}
	}
	return "", false
}

func (p *Provider) resolveLookupCandidatesLocked(input, trimmed string) []string {
	if candidates := slices.Clone(p.lookupIndex[input]); len(candidates) > 0 {
		return candidates
	}
	if trimmed != "" && trimmed != input {
		if candidates := slices.Clone(p.lookupIndex[trimmed]); len(candidates) > 0 {
			return candidates
		}
	}
	if portNorm := normalizeLookupSelectorPreserveHostCase(trimmed); portNorm != "" && portNorm != input && portNorm != trimmed {
		if candidates := slices.Clone(p.lookupIndex[portNorm]); len(candidates) > 0 {
			return candidates
		}
	}
	if norm := normalizeLookupSelector(input); norm != "" && norm != input && norm != trimmed {
		if candidates := slices.Clone(p.lookupIndex[norm]); len(candidates) > 0 {
			return candidates
		}
	}
	return nil
}

func normalizeLookupSelectorPreserveHostCase(trimmed string) string {
	if trimmed == "" {
		return ""
	}
	ref, err := ParseTargetRef(trimmed)
	if err != nil || ref.OpenSSH || ref.Host == "" {
		return ""
	}
	host := StripHostBrackets(ref.Host)
	if host == "" {
		return ""
	}
	if ref.User != "" {
		if ref.HasPort {
			return FormatNodeID(ref.User, host, ref.Port)
		}
		return ref.User + "@" + host
	}
	if ref.HasPort {
		return FormatHostPort(host, ref.Port)
	}
	return host
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
	node, host, identity, _, err := p.resolveWithProvenance(nodeID)
	return node, host, identity, err
}

func (p *Provider) resolveWithProvenance(nodeID string) (models.Node, models.Host, models.Identity, NodeProvenance, error) {
	if p == nil {
		return models.Node{}, models.Host{}, models.Identity{}, ProvenanceUnknown, fmt.Errorf("config provider is nil")
	}
	p.mu.RLock()
	if node, ok := p.cfg.Nodes.Get(nodeID); ok {
		host, hostOK := p.cfg.Hosts.Get(node.HostRef)
		identity, identityOK := p.cfg.Identities.Get(node.IdentityRef)
		origin := p.openSSHOrigins[nodeID]
		p.mu.RUnlock()
		if !hostOK {
			return models.Node{}, models.Host{}, models.Identity{}, ProvenanceUnknown, fmt.Errorf("host ref %q for node %q: %w", node.HostRef, nodeID, ErrHostNotFound)
		}
		if !identityOK {
			return models.Node{}, models.Host{}, models.Identity{}, ProvenanceUnknown, fmt.Errorf("identity ref %q for node %q: %w", node.IdentityRef, nodeID, ErrIdentityNotFound)
		}
		clonedNode := cloneNode(node)
		if clonedNode.OpenSSHAlias == "" && clonedNode.CanonicalHost == "" {
			clonedNode.OpenSSHAlias = origin.Alias
			clonedNode.CanonicalHost = origin.CanonicalHost
		}
		return clonedNode, cloneHost(host), cloneIdentity(identity), ProvenanceSavedManaged, nil
	}
	origin := p.openSSHOrigins[nodeID]
	openSSHAlias := origin.Alias
	canonicalHost := origin.CanonicalHost
	p.mu.RUnlock()

	if IsOpenSSHNodeID(nodeID) {
		parser := p.openSSH
		if parser == nil {
			parser = &OpenSSHParser{cfg: nil}
		}
		spec := strings.TrimPrefix(nodeID, OpenSSHNodePrefix)
		lookupHost, inlineUser, inlinePort, specErr := parseOpenSSHHostSpec(spec)
		if specErr != nil {
			return models.Node{}, models.Host{}, models.Identity{}, ProvenanceUnknown, fmt.Errorf("parse openssh host %q failed: %w", spec, specErr)
		}
		var (
			node     models.Node
			host     models.Host
			identity models.Identity
			err      error
		)
		if openSSHAlias != "" && canonicalHost != "" && !strings.EqualFold(openSSHAlias, canonicalHost) {
			node, host, identity, err = parser.getVirtualNodeWithCanonical(openSSHAlias, canonicalHost, inlineUser, inlinePort, spec)
		} else {
			node, host, identity, err = parser.getVirtualNodeWithCanonical(lookupHost, "", inlineUser, inlinePort, spec)
		}
		if err != nil {
			return models.Node{}, models.Host{}, models.Identity{}, ProvenanceUnknown, err
		}
		if openSSHAlias != "" {
			node.OpenSSHAlias = openSSHAlias
		}
		if canonicalHost != "" {
			node.CanonicalHost = canonicalHost
		}
		return node, host, identity, ProvenanceOpenSSHVirtual, nil
	}
	return models.Node{}, models.Host{}, models.Identity{}, ProvenanceUnknown, fmt.Errorf("node %q: %w", nodeID, ErrNodeNotFound)
}

// ResolveConnection returns a read-only connection snapshot. Provider does not
// own durable mutations, so discovery values must remain session-local.
func (p *Provider) ResolveConnection(nodeID string) (ConnectionSnapshot, error) {
	node, host, identity, prov, err := p.resolveWithProvenance(nodeID)
	if err != nil {
		return ConnectionSnapshot{}, err
	}
	return ConnectionSnapshot{
		Node:       node,
		Host:       host,
		Identity:   identity,
		Provenance: prov,
	}, nil
}

// ResolveConnectionWithOrigin resolves nodeID without reading or mutating
// session-wide OpenSSH alias/canonical metadata maps for virtual OpenSSH targets.
func (p *Provider) ResolveConnectionWithOrigin(nodeID, originalHost string) (ConnectionSnapshot, error) {
	if p == nil {
		return ConnectionSnapshot{}, fmt.Errorf("config provider is nil")
	}
	p.mu.RLock()
	_, savedExists := p.cfg.Nodes.Get(nodeID)
	p.mu.RUnlock()
	if savedExists || !IsOpenSSHNodeID(nodeID) {
		return p.ResolveConnection(nodeID)
	}

	parser := p.openSSH
	if parser == nil {
		parser = &OpenSSHParser{cfg: nil}
	}
	spec := strings.TrimPrefix(nodeID, OpenSSHNodePrefix)
	lookupHost, inlineUser, inlinePort, specErr := parseOpenSSHHostSpec(spec)
	if specErr != nil {
		return ConnectionSnapshot{}, fmt.Errorf("parse openssh host %q failed: %w", spec, specErr)
	}
	orig := normalizeOriginalHost(originalHost)
	var (
		node     models.Node
		host     models.Host
		identity models.Identity
		err      error
	)
	if orig != "" && !strings.EqualFold(orig, lookupHost) {
		node, host, identity, err = parser.getVirtualNodeWithCanonical(orig, lookupHost, inlineUser, inlinePort, spec)
		if err != nil {
			return ConnectionSnapshot{}, err
		}
		node.OpenSSHAlias = orig
		node.CanonicalHost = lookupHost
	} else {
		node, host, identity, err = parser.getVirtualNodeWithCanonical(lookupHost, "", inlineUser, inlinePort, spec)
		if err != nil {
			return ConnectionSnapshot{}, err
		}
		if alias := resolveOpenSSHAliasName(parser, spec); alias != "" {
			node.OpenSSHAlias = alias
		}
		node.CanonicalHost = ""
	}
	return ConnectionSnapshot{
		Node:       node,
		Host:       host,
		Identity:   identity,
		Provenance: ProvenanceOpenSSHVirtual,
	}, nil
}

func (p *Provider) GetNode(nodeID string) (models.Node, bool) {
	if p == nil {
		return models.Node{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	node, ok := p.cfg.Nodes.Get(nodeID)
	cloned := cloneNode(node)
	if ok && cloned.OpenSSHAlias == "" && cloned.CanonicalHost == "" {
		origin := p.openSSHOrigins[nodeID]
		cloned.OpenSSHAlias = origin.Alias
		cloned.CanonicalHost = origin.CanonicalHost
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

func normalizeLookupSelector(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || IsOpenSSHNodeID(trimmed) {
		return ""
	}
	if ref, err := ParseTargetRef(trimmed); err == nil && !ref.OpenSSH && ref.Host != "" {
		normHost := NormalizeHostAddress(ref.Host)
		if normHost != "" {
			norm := TargetRef{
				User:    ref.User,
				Host:    normHost,
				Port:    ref.Port,
				HasPort: ref.HasPort,
			}.NormalizedString()
			if norm != raw {
				return norm
			}
			return ""
		}
	}
	if norm := NormalizeHostAddress(trimmed); norm != "" && norm != raw {
		return norm
	}
	return ""
}

func lookupBySelector(lookup map[string][]string, key string) []string {
	if candidates := lookup[key]; len(candidates) > 0 {
		return candidates
	}
	if norm := normalizeLookupSelector(key); norm != "" && norm != key {
		return lookup[norm]
	}
	return nil
}

func indexAddressLookups(lookup map[string][]string, user, address string, port uint16, nodeID string) {
	cleanAddr := StripHostBrackets(address)
	if cleanAddr == "" {
		return
	}
	canonAddr := NormalizeHostAddress(cleanAddr)
	variants := []string{cleanAddr}
	if canonAddr != "" && canonAddr != cleanAddr {
		variants = append(variants, canonAddr)
	}
	for _, addr := range variants {
		addLookup(lookup, fmt.Sprintf("%s@%s", user, addr), nodeID)
		addLookup(lookup, FormatNodeID(user, addr, port), nodeID)
		if strings.Contains(addr, ":") {
			addLookup(lookup, fmt.Sprintf("[%s]", addr), nodeID)
			addLookup(lookup, fmt.Sprintf("%s@[%s]", user, addr), nodeID)
		}
	}
}

type indexBuildState struct {
	lookup             map[string][]string
	aliases            map[string]string
	hostRefCount       map[string]int
	nodeHostRef        map[string]string
	nodeAliasOwner     map[string]string
	hostAliasHostRef   map[string]string
	hostAliasFirstNode map[string]string
	rejectConflicts    bool
}

func buildIndexes(cfg *Configuration, rejectAliasConflicts bool) (map[string][]string, map[string]string, error) {
	nodeIDs := cfg.Nodes.Keys()
	sort.Strings(nodeIDs)

	state := &indexBuildState{
		lookup:             make(map[string][]string),
		aliases:            make(map[string]string),
		hostRefCount:       make(map[string]int, len(nodeIDs)),
		nodeHostRef:        make(map[string]string, len(nodeIDs)),
		nodeAliasOwner:     make(map[string]string),
		hostAliasHostRef:   make(map[string]string),
		hostAliasFirstNode: make(map[string]string),
		rejectConflicts:    rejectAliasConflicts,
	}

	if err := state.indexNodeAliases(cfg, nodeIDs); err != nil {
		return nil, nil, err
	}
	if err := state.indexNodesHostAndUser(cfg, nodeIDs); err != nil {
		return nil, nil, err
	}
	for key := range state.lookup {
		sort.Strings(state.lookup[key])
	}
	return state.lookup, state.aliases, nil
}

func (s *indexBuildState) indexNodeAliases(cfg *Configuration, nodeIDs []string) error {
	for _, nodeID := range nodeIDs {
		node, ok := cfg.Nodes.Get(nodeID)
		if !ok {
			continue
		}
		s.hostRefCount[node.HostRef]++
		s.nodeHostRef[nodeID] = node.HostRef
		for _, alias := range node.Alias {
			if err := addAlias(s.lookup, s.aliases, alias, nodeID, s.rejectConflicts); err != nil {
				return err
			}
			if alias != "" {
				if _, exists := s.nodeAliasOwner[alias]; !exists {
					s.nodeAliasOwner[alias] = nodeID
				}
			}
		}
	}
	return nil
}

func (s *indexBuildState) indexNodesHostAndUser(cfg *Configuration, nodeIDs []string) error {
	for _, nodeID := range nodeIDs {
		node, ok := cfg.Nodes.Get(nodeID)
		if !ok {
			continue
		}
		host, hostOK := cfg.Hosts.Get(node.HostRef)
		identity, identityOK := cfg.Identities.Get(node.IdentityRef)
		if !hostOK || !identityOK {
			continue
		}
		indexHostAddressKeys(s.lookup, host.Address, nodeID)
		for _, alias := range host.Alias {
			if alias == "" {
				continue
			}
			if err := s.addHostAlias(alias, nodeID, node.HostRef); err != nil {
				return err
			}
			if normAlias := NormalizeHostAddress(alias); normAlias != "" && normAlias != alias {
				addLookup(s.lookup, normAlias, nodeID)
			}
		}
		indexNodeUserLookups(s.lookup, node, host, identity, nodeID)
	}
	return nil
}

func indexHostAddressKeys(lookup map[string][]string, rawAddr, nodeID string) {
	addLookup(lookup, rawAddr, nodeID)
	cleanHost := StripHostBrackets(rawAddr)
	addLookup(lookup, cleanHost, nodeID)
	canonHost := NormalizeHostAddress(cleanHost)
	addLookup(lookup, canonHost, nodeID)
	if strings.Contains(cleanHost, ":") {
		addLookup(lookup, fmt.Sprintf("[%s]", cleanHost), nodeID)
	}
	if canonHost != "" && strings.Contains(canonHost, ":") {
		addLookup(lookup, fmt.Sprintf("[%s]", canonHost), nodeID)
	}
}

func indexNodeUserLookups(lookup map[string][]string, node models.Node, host models.Host, identity models.Identity, nodeID string) {
	user := normalizedIdentityUser(identity.User)
	if user == "" {
		return
	}
	port := normalizedHostPort(host.Port)
	for _, address := range append(slices.Clone(host.Alias), host.Address) {
		if address == "" {
			continue
		}
		indexAddressLookups(lookup, user, address, port, nodeID)
	}
	for _, alias := range node.Alias {
		if alias == "" {
			continue
		}
		addLookup(lookup, fmt.Sprintf("%s@%s", user, alias), nodeID)
		addLookup(lookup, fmt.Sprintf("%s@%s:%d", user, alias, port), nodeID)
	}
}

func (s *indexBuildState) addHostAlias(alias, nodeID, hostRef string) error {
	if ownerNode, ok := s.nodeAliasOwner[alias]; ok && s.nodeHostRef[ownerNode] != hostRef {
		if s.rejectConflicts {
			return fmt.Errorf("alias %q is already assigned to node %q", alias, ownerNode)
		}
		s.aliases[alias] = ""
		addLookup(s.lookup, alias, nodeID)
		return nil
	}
	if existingHostRef, ok := s.hostAliasHostRef[alias]; ok && existingHostRef != hostRef {
		if s.rejectConflicts {
			return fmt.Errorf("alias %q is already assigned to node %q", alias, s.hostAliasFirstNode[alias])
		}
		s.aliases[alias] = ""
		addLookup(s.lookup, alias, nodeID)
		return nil
	}
	if _, ok := s.hostAliasHostRef[alias]; !ok {
		s.hostAliasHostRef[alias] = hostRef
		s.hostAliasFirstNode[alias] = nodeID
	}
	addLookup(s.lookup, alias, nodeID)
	if s.hostRefCount[hostRef] == 1 {
		if _, exists := s.aliases[alias]; !exists {
			s.aliases[alias] = nodeID
		}
	}
	return nil
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
