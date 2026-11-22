package config

import (
	"fmt"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

const maxProxyJumpWalkDepth = 64

// ProxyJumpTarget identifies the destination node or ad-hoc target whose
// resolved ProxyJump chain is being validated for direct self-loops,
// duplicate hops, and transitive multi-hop cycles across Tiers 1, 2, and 4.
type ProxyJumpTarget struct {
	NodeID       string
	Selector     string
	OpenSSHAlias string
	Host         string
	Port         uint16
	User         string
	IsAdHoc      bool
}

type jumpNodeIdentity struct {
	label         string
	canonicalID   string
	aliases       []string
	openSSHAlias  string
	isOpenSSH     bool
	openSSHRef    TargetRef
	hasOpenSSHRef bool
	endpoint      ssh.Endpoint
	hasEndpoint   bool
	user          string
	explicitUser  bool
	isSavedNode   bool
	isDirect      bool
	nextRawJump   string
}

func (id jumpNodeIdentity) hasIdentity() bool {
	return id.canonicalID != "" || id.hasEndpoint || id.openSSHAlias != "" || len(id.aliases) > 0
}

func (id jumpNodeIdentity) effectivePort() uint16 {
	if id.hasEndpoint && id.endpoint.Port() > 0 {
		return id.endpoint.Port()
	}
	if id.hasOpenSSHRef && id.openSSHRef.HasPort && id.openSSHRef.Port > 0 {
		return id.openSSHRef.Port
	}
	return 22
}

// ValidateProxyJumpChainCycle walks resolvedChain transitively against provider
// (covering saved Tier-2 nodes and Tier-4 OpenSSH virtual stanzas) and rejects
// duplicate hops, alias/endpoint self-loops, and multi-hop cycles fail-closed
// with *ssh.ProxyCycleError. Any broken OpenSSHParser, malformed transitive hop,
// or ambiguous/unknown transitive saved jump also fails closed.
func ValidateProxyJumpChainCycle(provider ConfigProvider, dest ProxyJumpTarget, resolvedChain, rawJump string) error {
	var (
		cfg     *Configuration
		openSSH *OpenSSHParser
	)
	if provider != nil {
		var r *Repository
		r, cfg = resolveTargetHelper(provider)
		if r != nil && r.provider != nil {
			openSSH = r.provider.openSSH
		}
	}
	return validateProxyJumpChainCycleWithConfig(cfg, openSSH, dest, resolvedChain, rawJump)
}

func validateProxyJumpChainCycleWithConfig(
	cfg *Configuration,
	openSSH *OpenSSHParser,
	dest ProxyJumpTarget,
	resolvedChain, rawJump string,
) error {
	if hasControlOrLineSepChar(resolvedChain) {
		return fmt.Errorf("%w: invalid proxy_jump %q: contains control character", ssh.ErrSSHOptionsValidation, resolvedChain)
	}
	if strings.TrimSpace(resolvedChain) == "" {
		return nil
	}
	hops, err := splitValidatedJumpHops(resolvedChain)
	if err != nil {
		return err
	}
	if len(hops) == 0 {
		return nil
	}
	destIdent, err := buildDestJumpIdentity(cfg, openSSH, dest)
	if err != nil {
		return err
	}
	var path []jumpNodeIdentity
	if destIdent.hasIdentity() {
		path = []jumpNodeIdentity{destIdent}
	}
	if strings.TrimSpace(rawJump) == "" {
		rawJump = resolvedChain
	}
	return walkJumpChain(cfg, openSSH, path, hops, destIdent.label, rawJump, 0)
}

func splitValidatedJumpHops(chain string) ([]string, error) {
	parts := strings.Split(chain, ",")
	out := make([]string, 0, len(parts))
	for _, rawHop := range parts {
		if hasControlOrLineSepChar(rawHop) {
			return nil, fmt.Errorf("%w: invalid jump host %q: contains control character", ssh.ErrSSHOptionsValidation, rawHop)
		}
		hop := strings.TrimSpace(rawHop)
		if hop == "" {
			return nil, fmt.Errorf("%w: empty ProxyJump hop in %q", ssh.ErrSSHOptionsValidation, chain)
		}
		out = append(out, hop)
	}
	return out, nil
}

func walkJumpChain(
	cfg *Configuration,
	openSSH *OpenSSHParser,
	path []jumpNodeIdentity,
	hops []string,
	rootLabel, rawJump string,
	depth int,
) error {
	if depth > maxProxyJumpWalkDepth {
		return wrapProxyJumpCycleError(rawJump, rootLabel, rootLabel, formatJumpIdentityPath(path))
	}
	hopIdents := make([]jumpNodeIdentity, 0, len(hops))
	for _, hop := range hops {
		ident, err := buildHopJumpIdentity(cfg, openSSH, hop)
		if err != nil {
			return err
		}
		if idx := findMatchingJumpIdentity(path, ident); idx >= 0 {
			cyclePath := append(formatJumpIdentityPath(path[idx:]), ident.label)
			return wrapProxyJumpCycleError(rawJump, rootLabel, ident.label, cyclePath)
		}
		if idx := findMatchingJumpIdentity(hopIdents, ident); idx >= 0 {
			cyclePath := append(formatJumpIdentityPath(path), hopIdents[idx].label, ident.label)
			return wrapProxyJumpCycleError(rawJump, rootLabel, ident.label, cyclePath)
		}
		hopIdents = append(hopIdents, ident)
	}
	for i := len(hopIdents) - 1; i >= 0; i-- {
		ident := hopIdents[i]
		if strings.TrimSpace(ident.nextRawJump) == "" {
			continue
		}
		nextHops, err := resolveUpstreamHopsForIdentity(cfg, openSSH, ident)
		if err != nil {
			return err
		}
		if len(nextHops) == 0 {
			continue
		}
		// Match core/ssh/connector.go chain flattening: hops are pushed right-to-left
		// (innermost hop closest to dest first, outermost hop last), so outer hop[i]
		// jumping back to inner hop[j] (j > i) is a cycle while inner hop[j] using
		// outer hop[i] is not.
		childPath := make([]jumpNodeIdentity, 0, len(path)+len(hopIdents)-i)
		childPath = append(childPath, path...)
		for j := len(hopIdents) - 1; j >= i; j-- {
			childPath = append(childPath, hopIdents[j])
		}
		if err := walkJumpChain(cfg, openSSH, childPath, nextHops, rootLabel, rawJump, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func resolveUpstreamHopsForIdentity(cfg *Configuration, openSSH *OpenSSHParser, ident jumpNodeIdentity) ([]string, error) {
	ps, err := parseOptionalNodeProxyJump(ident.nextRawJump)
	if err != nil {
		return nil, err
	}
	targets, ok := ps.JumpTargets()
	if !ok {
		return nil, nil
	}
	if ident.isSavedNode {
		resolved, rErr := ResolveProxyJumpChainWithConfig(cfg, openSSH, strings.Join(targets, ","))
		if rErr != nil {
			return nil, rErr
		}
		if strings.TrimSpace(resolved) == "" {
			return nil, nil
		}
		return splitValidatedJumpHops(resolved)
	}
	validated, vErr := validateJumpTargetsSyntax(targets)
	if vErr != nil {
		return nil, vErr
	}
	out := make([]string, 0, len(validated))
	for _, hop := range validated {
		if IsOpenSSHNodeID(hop) {
			out = append(out, hop)
			continue
		}
		resolved, rErr := ResolveProxyJumpChainWithConfig(cfg, openSSH, hop)
		if rErr != nil {
			return nil, rErr
		}
		if resolved != "" {
			subHops, sErr := splitValidatedJumpHops(resolved)
			if sErr != nil {
				return nil, sErr
			}
			out = append(out, subHops...)
		}
	}
	return out, nil
}

func buildDestJumpIdentity(cfg *Configuration, openSSH *OpenSSHParser, dest ProxyJumpTarget) (jumpNodeIdentity, error) {
	nodeID := strings.TrimSpace(dest.NodeID)
	selector := strings.TrimSpace(dest.Selector)
	if nodeID == "" {
		nodeID = selector
	}
	if nodeID != "" && !IsOpenSSHNodeID(nodeID) && !dest.IsAdHoc && cfg != nil && cfg.Nodes != nil {
		if savedID, ok := resolveSavedJumpNodeID(cfg, nodeID); ok {
			ident := buildSavedJumpNodeIdentity(cfg, savedID)
			appendUniqueJumpAlias(&ident.aliases, dest.OpenSSHAlias, selector)
			return ident, nil
		}
	}
	if IsOpenSSHNodeID(nodeID) {
		return buildOpenSSHJumpIdentity(openSSH, nodeID, dest)
	}
	return buildDirectDestJumpIdentity(nodeID, selector, dest), nil
}

func resolveSavedJumpNodeID(cfg *Configuration, candidate string) (string, bool) {
	if cfg == nil || cfg.Nodes == nil || candidate == "" {
		return "", false
	}
	if _, ok := cfg.Nodes.Get(candidate); ok {
		return candidate, true
	}
	_, aliases, err := buildIndexes(cfg, false)
	if err != nil {
		return "", false
	}
	if nid := aliases[candidate]; nid != "" {
		if _, ok := cfg.Nodes.Get(nid); ok {
			return nid, true
		}
	}
	return "", false
}

func buildSavedJumpNodeIdentity(cfg *Configuration, nodeID string) jumpNodeIdentity {
	ident := jumpNodeIdentity{
		label:       nodeID,
		canonicalID: nodeID,
		isSavedNode: true,
	}
	if cfg == nil || cfg.Nodes == nil {
		return ident
	}
	node, ok := cfg.Nodes.Get(nodeID)
	if !ok {
		return ident
	}
	ident.nextRawJump = node.ProxyJump
	appendUniqueJumpAlias(&ident.aliases, nodeID)
	appendUniqueJumpAlias(&ident.aliases, node.Alias...)
	appendUniqueJumpAlias(&ident.aliases, node.OpenSSHAlias)
	if cfg.Hosts != nil {
		if host, hOK := cfg.Hosts.Get(node.HostRef); hOK {
			appendUniqueJumpAlias(&ident.aliases, host.Alias...)
			if ep, err := ssh.NewEndpoint(host.Address, int(normalizedHostPort(host.Port))); err == nil {
				ident.endpoint = ep
				ident.hasEndpoint = true
			}
		}
	}
	if cfg.Identities != nil {
		if id, iOK := cfg.Identities.Get(node.IdentityRef); iOK {
			ident.user = normalizedIdentityUser(id.User)
			ident.explicitUser = true
		}
	}
	return ident
}

func buildOpenSSHJumpIdentity(openSSH *OpenSSHParser, rawID string, dest ProxyJumpTarget) (jumpNodeIdentity, error) {
	ref, err := ParseTargetRef(rawID)
	if err != nil {
		return jumpNodeIdentity{}, fmt.Errorf("%w: invalid openssh jump target %q: %w", ssh.ErrSSHOptionsValidation, rawID, err)
	}
	if vErr := ref.Validate(); vErr != nil {
		return jumpNodeIdentity{}, fmt.Errorf("%w: invalid openssh jump target %q: %w", ssh.ErrSSHOptionsValidation, rawID, vErr)
	}
	normID := ref.NormalizedString()
	ident := jumpNodeIdentity{
		label:         normID,
		canonicalID:   normID,
		openSSHAlias:  ref.Host,
		isOpenSSH:     true,
		openSSHRef:    ref,
		hasOpenSSHRef: true,
		user:          ref.User,
		explicitUser:  ref.User != "",
		isDirect:      true,
	}
	if dest.OpenSSHAlias != "" {
		ident.openSSHAlias = strings.TrimSpace(dest.OpenSSHAlias)
	}
	appendUniqueJumpAlias(&ident.aliases, ref.Host, dest.OpenSSHAlias)

	hostAddr := ref.Host
	port := normalizedHostPort(ref.Port)
	if openSSH != nil {
		if pErr := openSSH.Err(); pErr != nil {
			return jumpNodeIdentity{}, fmt.Errorf("resolve openssh jump %q: %w", rawID, pErr)
		}
		if openSSH.cfg != nil {
			if openSSH.HasHost(ref.Host) {
				ident.isDirect = false
			}
			vnode, vhost, vident, vErr := openSSH.GetVirtualNode(ref.formatNormalizedBody())
			if vErr != nil {
				return jumpNodeIdentity{}, fmt.Errorf("resolve openssh jump %q: %w", rawID, vErr)
			}
			hostAddr = StripHostBrackets(vhost.Address)
			port = normalizedHostPort(vhost.Port)
			ident.nextRawJump = vnode.ProxyJump
			if ref.User != "" || strings.TrimSpace(firstSSHConfigKeyValue(openSSH.cfg, ref.Host, "User")) != "" {
				ident.user = strings.TrimSpace(vident.User)
				ident.explicitUser = ident.user != ""
			}
		}
	}
	if strings.TrimSpace(dest.Host) != "" {
		hostAddr = StripHostBrackets(dest.Host)
	}
	if dest.Port > 0 {
		port = dest.Port
	}
	if strings.TrimSpace(dest.User) != "" {
		ident.user = strings.TrimSpace(dest.User)
		ident.explicitUser = true
	}
	if ep, epErr := ssh.NewEndpoint(hostAddr, int(port)); epErr == nil {
		ident.endpoint = ep
		ident.hasEndpoint = true
	}
	return ident, nil
}

func buildDirectDestJumpIdentity(nodeID, selector string, dest ProxyJumpTarget) jumpNodeIdentity {
	ident := jumpNodeIdentity{
		label:        nodeID,
		canonicalID:  nodeID,
		openSSHAlias: strings.TrimSpace(dest.OpenSSHAlias),
		isDirect:     true,
	}
	appendUniqueJumpAlias(&ident.aliases, dest.OpenSSHAlias)
	if selector != "" && !IsOpenSSHNodeID(selector) {
		appendUniqueJumpAlias(&ident.aliases, selector)
		if ref, err := ParseTargetRef(selector); err == nil && !ref.OpenSSH && ref.Host != "" {
			appendUniqueJumpAlias(&ident.aliases, ref.Host)
		}
	}

	hostAddr := strings.TrimSpace(dest.Host)
	port := dest.Port
	user := strings.TrimSpace(dest.User)
	explicitUser := user != ""

	if ref, err := ParseTargetRef(nodeID); err == nil && ref.Host != "" {
		ident.openSSHRef = ref
		ident.hasOpenSSHRef = true
		if hostAddr == "" {
			hostAddr = ref.Host
		}
		if port == 0 && ref.HasPort {
			port = ref.Port
		}
		if user == "" && ref.User != "" {
			user = ref.User
			explicitUser = true
		}
	}
	if hostAddr != "" {
		if ep, epErr := ssh.NewEndpoint(StripHostBrackets(hostAddr), int(normalizedHostPort(port))); epErr == nil {
			ident.endpoint = ep
			ident.hasEndpoint = true
		}
	}
	ident.user = user
	ident.explicitUser = explicitUser
	return ident
}

func buildHopJumpIdentity(cfg *Configuration, openSSH *OpenSSHParser, hop string) (jumpNodeIdentity, error) {
	if hasControlOrLineSepChar(hop) {
		return jumpNodeIdentity{}, fmt.Errorf("%w: invalid jump host %q: contains control character", ssh.ErrSSHOptionsValidation, hop)
	}
	if IsOpenSSHNodeID(hop) {
		return buildOpenSSHJumpIdentity(openSSH, hop, ProxyJumpTarget{})
	}
	if cfg != nil && cfg.Nodes != nil {
		if savedID, ok := resolveSavedJumpNodeID(cfg, hop); ok {
			return buildSavedJumpNodeIdentity(cfg, savedID), nil
		}
	}
	ref, err := ParseTargetRef(hop)
	if err != nil {
		return jumpNodeIdentity{}, fmt.Errorf("%w: invalid jump host %q: %w", ssh.ErrSSHOptionsValidation, hop, err)
	}
	if vErr := ref.Validate(); vErr != nil {
		return jumpNodeIdentity{}, fmt.Errorf("%w: invalid jump host %q: %w", ssh.ErrSSHOptionsValidation, hop, vErr)
	}
	ident := jumpNodeIdentity{
		label:         hop,
		canonicalID:   hop,
		openSSHRef:    ref,
		hasOpenSSHRef: true,
		user:          ref.User,
		explicitUser:  ref.User != "",
		isDirect:      true,
	}
	if ep, epErr := ssh.NewEndpoint(ref.Host, int(normalizedHostPort(ref.Port))); epErr == nil {
		ident.endpoint = ep
		ident.hasEndpoint = true
	}
	return ident, nil
}

func sameJumpNodeIdentity(a, b jumpNodeIdentity) bool {
	if sameCanonicalJumpID(a, b) {
		return true
	}
	if a.isSavedNode && b.isSavedNode {
		return false
	}
	if sameOpenSSHAliasJumpIdentity(a, b) {
		return true
	}
	return sameDirectOrEndpointJumpIdentity(a, b)
}

func sameCanonicalJumpID(a, b jumpNodeIdentity) bool {
	if a.canonicalID == "" || b.canonicalID == "" {
		return false
	}
	if a.canonicalID == b.canonicalID {
		return true
	}
	if !a.isOpenSSH || !b.isOpenSSH || !a.hasOpenSSHRef || !b.hasOpenSSHRef {
		return false
	}
	normA := a.openSSHRef.NormalizedString()
	return normA != "" && normA == b.openSSHRef.NormalizedString()
}

func sameDirectOrEndpointJumpIdentity(a, b jumpNodeIdentity) bool {
	if !a.isDirect && !b.isDirect {
		return false
	}
	if directJumpMatchesAlias(a, b) || directJumpMatchesAlias(b, a) {
		return true
	}
	return a.hasEndpoint && b.hasEndpoint && a.endpoint.Equal(b.endpoint) && jumpUsersCompatible(a, b)
}

func sameOpenSSHAliasJumpIdentity(a, b jumpNodeIdentity) bool {
	aliasA := strings.TrimSpace(a.openSSHAlias)
	aliasB := strings.TrimSpace(b.openSSHAlias)
	if aliasA == "" || aliasB == "" || !strings.EqualFold(aliasA, aliasB) {
		return false
	}
	if a.effectivePort() != b.effectivePort() {
		return false
	}
	return jumpUsersCompatible(a, b)
}

func directJumpMatchesAlias(target, direct jumpNodeIdentity) bool {
	if !direct.isDirect || !direct.hasOpenSSHRef || direct.isSavedNode {
		return false
	}
	if direct.openSSHRef.HasPort && normalizedHostPort(direct.openSSHRef.Port) != target.effectivePort() {
		return false
	}
	if !slices.Contains(target.aliases, direct.openSSHRef.Host) {
		return false
	}
	return jumpUsersCompatible(target, direct)
}

func jumpUsersCompatible(a, b jumpNodeIdentity) bool {
	if !a.explicitUser || !b.explicitUser {
		return true
	}
	return a.user == "" || b.user == "" || a.user == b.user
}

func findMatchingJumpIdentity(list []jumpNodeIdentity, target jumpNodeIdentity) int {
	for i, item := range list {
		if sameJumpNodeIdentity(item, target) {
			return i
		}
	}
	return -1
}

func appendUniqueJumpAlias(dst *[]string, vals ...string) {
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" || slices.Contains(*dst, v) {
			continue
		}
		*dst = append(*dst, v)
	}
}

func formatJumpIdentityPath(path []jumpNodeIdentity) []string {
	out := make([]string, 0, len(path))
	for _, item := range path {
		if item.label != "" {
			out = append(out, item.label)
		}
	}
	return out
}

func wrapProxyJumpCycleError(rawJump, destLabel, cycleNode string, path []string) error {
	if cycleNode == "" {
		cycleNode = destLabel
	}
	cycleErr := &ssh.ProxyCycleError{
		NodeID: cycleNode,
		Path:   path,
	}
	if destLabel != "" {
		return fmt.Errorf("resolve proxy jump %q for node %q failed: %w", rawJump, destLabel, cycleErr)
	}
	return fmt.Errorf("resolve proxy jump %q failed: %w", rawJump, cycleErr)
}

// validateVirtualJumpTargets normalizes a virtual OpenSSH node's base ProxyJump
// targets: non-OpenSSH hops are resolved via provider.ResolveProxyJumpChain,
// while OpenSSH-prefixed hops validate syntax and check any broken OpenSSHParser.
func validateVirtualJumpTargets(provider ConfigProvider, targets []string) (string, error) {
	validated, err := validateJumpTargetsSyntax(targets)
	if err != nil {
		return "", err
	}
	var openSSH *OpenSSHParser
	if provider != nil {
		if r, _ := resolveTargetHelper(provider); r != nil && r.provider != nil {
			openSSH = r.provider.openSSH
		}
	}
	out := make([]string, 0, len(validated))
	for _, hop := range validated {
		if IsOpenSSHNodeID(hop) {
			if pErr := openSSH.Err(); pErr != nil {
				return "", fmt.Errorf("resolve openssh jump %q: %w", hop, pErr)
			}
			out = append(out, hop)
			continue
		}
		if provider == nil {
			out = append(out, hop)
			continue
		}
		resolved, rErr := provider.ResolveProxyJumpChain(hop)
		if rErr != nil {
			return "", rErr
		}
		if resolved != "" {
			out = append(out, resolved)
		}
	}
	return strings.Join(out, ","), nil
}

// buildProxyJumpTargetFromSavedNode constructs a ProxyJumpTarget from a saved
// node triple for shared cycle validation.
func buildProxyJumpTargetFromSavedNode(nodeID, openSSHAlias, selector string, host models.Host, ident models.Identity) ProxyJumpTarget {
	return ProxyJumpTarget{
		NodeID:       nodeID,
		Selector:     selector,
		OpenSSHAlias: openSSHAlias,
		Host:         StripHostBrackets(host.Address),
		Port:         normalizedHostPort(host.Port),
		User:         strings.TrimSpace(ident.User),
	}
}
