package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

// ValidateRawProxyJumpTokens validates raw comma-separated ProxyJump tokens
// BEFORE ssh.ParseProxyJump trims whitespace. Any control/line-separator
// character or any whitespace-padded, malformed, or double-prefixed "openssh:"
// hop fails closed with ssh.ErrSSHOptionsValidation.
func ValidateRawProxyJumpTokens(raw string) error {
	if raw == "" {
		return nil
	}
	if hasControlOrLineSepChar(raw) {
		return fmt.Errorf("%w: invalid proxy_jump %q: contains control character", ssh.ErrSSHOptionsValidation, raw)
	}
	for hop := range strings.SplitSeq(raw, ",") {
		stripped := strings.TrimFunc(hop, func(r rune) bool {
			return unicode.IsSpace(r) || unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
		})
		if !hasOpenSSHPrefix(hop) && !hasOpenSSHPrefix(stripped) {
			continue
		}
		if stripped != hop || hasControlOrLineSepChar(hop) || hasAnyWhitespace(hop) {
			return fmt.Errorf("%w: invalid openssh jump host %q: contains whitespace or control characters", ssh.ErrSSHOptionsValidation, hop)
		}
		ref, err := ParseTargetRef(hop)
		if err != nil {
			return fmt.Errorf("%w: invalid openssh jump host %q: %w", ssh.ErrSSHOptionsValidation, hop, err)
		}
		if err := ref.Validate(); err != nil {
			return fmt.Errorf("%w: invalid openssh jump host %q: %w", ssh.ErrSSHOptionsValidation, hop, err)
		}
	}
	return nil
}

// ValidateRawProxyJumpOption validates a raw OpenSSH -o ProxyJump directive
// string before ssh.SplitOptionKeyValue / ssh.ParseProxyJump trims leading or
// trailing whitespace in Key=Value syntax.
func ValidateRawProxyJumpOption(opt, val string) error {
	rawVal := val
	trimmed := strings.Trim(opt, " \t")
	eqIdx := strings.IndexByte(trimmed, '=')
	wsIdx := strings.IndexAny(trimmed, " \t")
	if eqIdx >= 0 && (wsIdx == -1 || eqIdx < wsIdx) {
		rawVal = opt[strings.IndexByte(opt, '=')+1:]
	}
	if err := ValidateRawProxyJumpTokens(rawVal); err != nil {
		return err
	}
	if rawVal != val {
		return ValidateRawProxyJumpTokens(val)
	}
	return nil
}

const maxProxyJumpWalkDepth = 64

// ProxyJumpTarget identifies the destination node or ad-hoc target whose
// resolved ProxyJump chain is being validated for direct self-loops,
// duplicate hops, and transitive multi-hop cycles across Tiers 1, 2, and 4.
type ProxyJumpTarget struct {
	NodeID        string
	Selector      string
	OpenSSHAlias  string
	CanonicalHost string
	Host          string
	Port          uint16
	User          string
	IsAdHoc       bool
}

type jumpNodeIdentity struct {
	label          string
	canonicalID    string
	aliases        []string
	openSSHAliases []string
	openSSHAlias   string
	isOpenSSH      bool
	openSSHRef     TargetRef
	hasOpenSSHRef  bool
	endpoint       ssh.Endpoint
	hasEndpoint    bool
	user           string
	explicitUser   bool
	isSavedNode    bool
	isDirect       bool
	nextRawJump    string
}

func (id jumpNodeIdentity) hasIdentity() bool {
	return id.canonicalID != "" || id.hasEndpoint || id.openSSHAlias != "" || len(id.aliases) > 0 || len(id.openSSHAliases) > 0
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

type jumpWalkOptions struct {
	graphMode bool
	lookup    map[string][]string
	aliases   map[string]string
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
	return walkJumpChain(cfg, openSSH, jumpWalkOptions{}, path, hops, destIdent.label, rawJump, 0)
}

func validateSavedNodeProxyJumpGraphCycle(
	cfg *Configuration,
	lookup map[string][]string,
	aliases map[string]string,
	nodeID string,
	node models.Node,
	targets []string,
) error {
	if cfg == nil || len(targets) == 0 {
		return nil
	}
	destIdent := buildSavedJumpNodeIdentity(cfg, nodeID)
	var path []jumpNodeIdentity
	if destIdent.hasIdentity() {
		path = []jumpNodeIdentity{destIdent}
	}
	opts := jumpWalkOptions{
		graphMode: true,
		lookup:    lookup,
		aliases:   aliases,
	}
	return walkJumpChain(cfg, nil, opts, path, targets, destIdent.label, node.ProxyJump, 0)
}

// ValidateSavedNodeJumpCycleWithOpenSSH validates the saved node nodeID (and
// any saved nodes in cfg whose resolved ProxyJump graph across Tier-2 saved
// nodes and Tier-4 OpenSSH stanzas can reach nodeID) for direct self-loops,
// duplicate hops, and transitive multi-hop ProxyJump cycles.
func ValidateSavedNodeJumpCycleWithOpenSSH(cfg *Configuration, openSSH *OpenSSHParser, nodeID string) error {
	if cfg == nil || cfg.Nodes == nil || strings.TrimSpace(nodeID) == "" {
		return nil
	}
	lookup, aliases, err := buildIndexes(cfg, false)
	if err != nil {
		return fmt.Errorf("build configuration indexes for jump cycle validation: %w", err)
	}
	affected := collectSavedNodesReachingNode(cfg, openSSH, lookup, aliases, nodeID)
	for _, nid := range affected {
		node, ok := cfg.Nodes.Get(nid)
		if !ok || strings.TrimSpace(node.ProxyJump) == "" {
			continue
		}
		host, hOK := cfg.Hosts.Get(node.HostRef)
		ident, iOK := cfg.Identities.Get(node.IdentityRef)
		if !hOK || !iOK {
			continue
		}
		ps, pErr := parseOptionalNodeProxyJump(node.ProxyJump)
		if pErr != nil {
			return pErr
		}
		targets, ok := ps.JumpTargets()
		if !ok {
			continue
		}
		dest := buildProxyJumpTargetFromSavedNode(nid, node.OpenSSHAlias, node.CanonicalHost, nid, host, ident)
		resolvedJump, rErr := resolveBaseTargetJumpWithConfig(cfg, openSSH, dest, targets)
		if rErr != nil {
			return rErr
		}
		if err := validateProxyJumpChainCycleWithConfig(cfg, openSSH, dest, resolvedJump, node.ProxyJump); err != nil {
			return err
		}
	}
	return nil
}

func collectSavedNodesReachingNode(
	cfg *Configuration,
	openSSH *OpenSSHParser,
	lookup map[string][]string,
	aliases map[string]string,
	targetNodeID string,
) []string {
	targetIdent := buildSavedJumpNodeIdentity(cfg, targetNodeID)
	var upstream []string
	for _, nid := range cfg.Nodes.Keys() {
		if nid == targetNodeID {
			continue
		}
		node, ok := cfg.Nodes.Get(nid)
		if !ok || strings.TrimSpace(node.ProxyJump) == "" {
			continue
		}
		if savedNodeReachesTarget(cfg, openSSH, lookup, aliases, nid, targetNodeID, targetIdent) {
			upstream = append(upstream, nid)
		}
	}
	slices.Sort(upstream)
	return append([]string{targetNodeID}, upstream...)
}

type jumpReachabilityState struct {
	cfg          *Configuration
	openSSH      *OpenSSHParser
	lookup       map[string][]string
	aliases      map[string]string
	targetNodeID string
	targetIdent  jumpNodeIdentity
	visited      map[string]struct{}
	queue        []jumpReachHop
}

type jumpReachHop struct {
	hop   string
	depth int
}

func (s *jumpReachabilityState) enqueueRawJump(raw string, depth int) {
	if depth > maxProxyJumpWalkDepth || strings.TrimSpace(raw) == "" {
		return
	}
	ps, err := parseOptionalNodeProxyJump(raw)
	if err != nil {
		return
	}
	targets, ok := ps.JumpTargets()
	if !ok {
		return
	}
	for _, hop := range targets {
		s.queue = append(s.queue, jumpReachHop{hop: hop, depth: depth})
	}
}

func (s *jumpReachabilityState) visitSavedTarget(dst string, nextDepth int) bool {
	if dst == s.targetNodeID {
		return true
	}
	key := "saved:" + dst
	if _, seen := s.visited[key]; seen {
		return false
	}
	s.visited[key] = struct{}{}
	if dstNode, ok := s.cfg.Nodes.Get(dst); ok {
		s.enqueueRawJump(dstNode.ProxyJump, nextDepth)
	}
	return false
}

func (s *jumpReachabilityState) stepHop(cur jumpReachHop) bool {
	if cur.depth > maxProxyJumpWalkDepth {
		return false
	}
	if !hasOpenSSHPrefix(cur.hop) {
		if ref, rErr := ParseTargetRef(cur.hop); rErr == nil && !ref.OpenSSH {
			if localTargets := resolveLocalJumpTargets(s.cfg, s.lookup, s.aliases, cur.hop, ref); len(localTargets) > 0 {
				for _, dst := range localTargets {
					if s.visitSavedTarget(dst, cur.depth+1) {
						return true
					}
				}
				return false
			}
		}
	}
	resolved, rErr := resolveSingleJumpHopWithConfig(s.cfg, s.openSSH, cur.hop)
	if rErr != nil || resolved == "" {
		return false
	}
	if _, isSaved := s.cfg.Nodes.Get(resolved); isSaved && !IsOpenSSHNodeID(resolved) {
		return s.visitSavedTarget(resolved, cur.depth+1)
	}
	if !IsOpenSSHNodeID(resolved) {
		return false
	}
	hopIdent, hErr := buildOpenSSHJumpIdentity(s.openSSH, resolved, ProxyJumpTarget{})
	if hErr != nil {
		return false
	}
	if sameJumpNodeIdentity(s.targetIdent, hopIdent) {
		return true
	}
	key := "openssh:" + hopIdent.canonicalID
	if _, seen := s.visited[key]; seen {
		return false
	}
	s.visited[key] = struct{}{}
	s.enqueueRawJump(hopIdent.nextRawJump, cur.depth+1)
	return false
}

func savedNodeReachesTarget(
	cfg *Configuration,
	openSSH *OpenSSHParser,
	lookup map[string][]string,
	aliases map[string]string,
	startNodeID, targetNodeID string,
	targetIdent jumpNodeIdentity,
) bool {
	st := &jumpReachabilityState{
		cfg:          cfg,
		openSSH:      openSSH,
		lookup:       lookup,
		aliases:      aliases,
		targetNodeID: targetNodeID,
		targetIdent:  targetIdent,
		visited:      map[string]struct{}{"saved:" + startNodeID: {}},
		queue:        make([]jumpReachHop, 0, 8),
	}
	if startNode, ok := cfg.Nodes.Get(startNodeID); ok {
		st.enqueueRawJump(startNode.ProxyJump, 0)
	}
	for len(st.queue) > 0 {
		cur := st.queue[0]
		st.queue = st.queue[1:]
		if st.stepHop(cur) {
			return true
		}
	}
	return false
}

func findNodeProxyJumpCycleHop(
	cfg *Configuration,
	lookup map[string][]string,
	aliases map[string]string,
	nodeID string,
	node models.Node,
) (string, []string, bool) {
	if cfg == nil || strings.TrimSpace(node.ProxyJump) == "" {
		return "", nil, false
	}
	ps, err := parseOptionalNodeProxyJump(node.ProxyJump)
	if err != nil {
		return "", nil, false
	}
	targets, ok := ps.JumpTargets()
	if !ok || len(targets) == 0 {
		return "", nil, false
	}
	opts := jumpWalkOptions{
		graphMode: true,
		lookup:    lookup,
		aliases:   aliases,
	}
	destIdent := buildSavedJumpNodeIdentity(cfg, nodeID)
	var basePath []jumpNodeIdentity
	if destIdent.hasIdentity() {
		basePath = []jumpNodeIdentity{destIdent}
	}
	hopIdents := make([]jumpNodeIdentity, 0, len(targets))
	for i, hop := range targets {
		ident, hErr := buildHopJumpIdentityWithOpts(cfg, nil, opts, hop)
		if hErr != nil {
			return "", nil, false
		}
		if idx := findMatchingJumpIdentity(basePath, ident); idx >= 0 {
			cyclePath := append(formatJumpIdentityPath(basePath[idx:]), ident.label)
			return targets[i], cyclePath, true
		}
		if idx := findMatchingJumpIdentity(hopIdents, ident); idx >= 0 {
			cyclePath := append(formatJumpIdentityPath(basePath), hopIdents[idx].label, ident.label)
			return targets[i], cyclePath, true
		}
		hopIdents = append(hopIdents, ident)
	}
	for i := len(hopIdents) - 1; i >= 0; i-- {
		ident := hopIdents[i]
		if strings.TrimSpace(ident.nextRawJump) == "" {
			continue
		}
		nextHops, nErr := resolveUpstreamHopsForIdentityWithOpts(cfg, nil, opts, ident)
		if nErr != nil || len(nextHops) == 0 {
			continue
		}
		childPath := make([]jumpNodeIdentity, 0, len(basePath)+len(hopIdents)-i)
		childPath = append(childPath, basePath...)
		for j := len(hopIdents) - 1; j >= i; j-- {
			childPath = append(childPath, hopIdents[j])
		}
		wErr := walkJumpChain(cfg, nil, opts, childPath, nextHops, destIdent.label, node.ProxyJump, 1)
		var cycleErr *ssh.ProxyCycleError
		if errors.As(wErr, &cycleErr) {
			return targets[i], cycleErr.Path, true
		}
	}
	return "", nil, false
}

func splitValidatedJumpHops(chain string) ([]string, error) {
	if err := ValidateRawProxyJumpTokens(chain); err != nil {
		return nil, err
	}
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
	opts jumpWalkOptions,
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
		ident, err := buildHopJumpIdentityWithOpts(cfg, openSSH, opts, hop)
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
		nextHops, err := resolveUpstreamHopsForIdentityWithOpts(cfg, openSSH, opts, ident)
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
		if err := walkJumpChain(cfg, openSSH, opts, childPath, nextHops, rootLabel, rawJump, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func resolveUpstreamHopsForIdentityWithOpts(cfg *Configuration, openSSH *OpenSSHParser, opts jumpWalkOptions, ident jumpNodeIdentity) ([]string, error) {
	ps, err := parseOptionalNodeProxyJump(ident.nextRawJump)
	if err != nil {
		return nil, err
	}
	targets, ok := ps.JumpTargets()
	if !ok {
		return nil, nil
	}
	if opts.graphMode {
		return validateJumpTargetsSyntax(targets)
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
			if ident.openSSHAlias == "" && strings.TrimSpace(dest.OpenSSHAlias) != "" {
				ident.openSSHAlias = strings.TrimSpace(dest.OpenSSHAlias)
			}
			appendUniqueJumpAlias(&ident.aliases, dest.OpenSSHAlias, dest.CanonicalHost, selector)
			appendUniqueJumpAlias(&ident.openSSHAliases, dest.OpenSSHAlias, dest.CanonicalHost)
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
	ident.openSSHAlias = strings.TrimSpace(node.OpenSSHAlias)
	appendUniqueJumpAlias(&ident.aliases, nodeID)
	appendUniqueJumpAlias(&ident.aliases, node.Alias...)
	appendUniqueJumpAlias(&ident.aliases, node.OpenSSHAlias, node.CanonicalHost)
	appendUniqueJumpAlias(&ident.openSSHAliases, node.OpenSSHAlias, node.CanonicalHost)
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
	appendUniqueJumpAlias(&ident.aliases, ref.Host, dest.OpenSSHAlias, dest.CanonicalHost)
	appendUniqueJumpAlias(&ident.openSSHAliases, ref.Host, dest.OpenSSHAlias, dest.CanonicalHost)

	hostAddr := ref.Host
	port := normalizedHostPort(ref.Port)
	if openSSH != nil {
		var pErr error
		hostAddr, port, pErr = populateOpenSSHJumpIdentityFromParser(openSSH, rawID, ref, dest, hostAddr, port, &ident)
		if pErr != nil {
			return jumpNodeIdentity{}, pErr
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

func populateOpenSSHJumpIdentityFromParser(
	openSSH *OpenSSHParser,
	rawID string,
	ref TargetRef,
	dest ProxyJumpTarget,
	hostAddr string,
	port uint16,
	ident *jumpNodeIdentity,
) (string, uint16, error) {
	if pErr := openSSH.Err(); pErr != nil {
		return "", 0, fmt.Errorf("resolve openssh jump %q: %w", rawID, pErr)
	}
	if openSSH.cfg == nil {
		return hostAddr, port, nil
	}
	var (
		vnode  models.Node
		vhost  models.Host
		vident models.Identity
		vErr   error
	)
	if orig := strings.TrimSpace(dest.OpenSSHAlias); orig != "" && !strings.EqualFold(orig, ref.Host) {
		vnode, vhost, vident, vErr = openSSH.getVirtualNodeWithCanonical(orig, ref.Host, ref.User, ref.Port, ref.formatNormalizedBody())
	} else {
		vnode, vhost, vident, vErr = openSSH.GetVirtualNode(ref.formatNormalizedBody())
	}
	if vErr != nil {
		return "", 0, fmt.Errorf("resolve openssh jump %q: %w", rawID, vErr)
	}
	hostAddr = StripHostBrackets(vhost.Address)
	port = normalizedHostPort(vhost.Port)
	concrete, cErr := isOpenSSHJumpConcrete(openSSH, ref, dest, hostAddr)
	if cErr != nil {
		return "", 0, fmt.Errorf("resolve openssh jump %q: %w", rawID, cErr)
	}
	if concrete {
		ident.isDirect = false
	}
	ident.nextRawJump = vnode.ProxyJump
	if u := strings.TrimSpace(vident.User); u != "" {
		ident.user = u
		ident.explicitUser = true
	}
	return hostAddr, port, nil
}

func isOpenSSHJumpConcrete(openSSH *OpenSSHParser, ref TargetRef, dest ProxyJumpTarget, hostAddr string) (bool, error) {
	if openSSH.HasHost(ref.Host) || (dest.OpenSSHAlias != "" && openSSH.HasHost(dest.OpenSSHAlias)) {
		return true, nil
	}
	if hostAddr == "" {
		return false, nil
	}
	if !strings.EqualFold(hostAddr, StripHostBrackets(ref.Host)) {
		return true, nil
	}
	_, explicit, hErr := openSSH.ResolveExplicitHostName(ref.Host)
	if hErr != nil {
		return false, hErr
	}
	return explicit, nil
}

func buildDirectDestJumpIdentity(nodeID, selector string, dest ProxyJumpTarget) jumpNodeIdentity {
	ident := jumpNodeIdentity{
		label:        nodeID,
		canonicalID:  nodeID,
		openSSHAlias: strings.TrimSpace(dest.OpenSSHAlias),
		isDirect:     true,
	}
	appendUniqueJumpAlias(&ident.aliases, dest.OpenSSHAlias, dest.CanonicalHost)
	appendUniqueJumpAlias(&ident.openSSHAliases, dest.OpenSSHAlias, dest.CanonicalHost)
	if selector != "" && !IsOpenSSHNodeID(selector) {
		appendUniqueJumpAlias(&ident.aliases, selector)
		if ref, err := ParseTargetRef(selector); err == nil && !ref.OpenSSH && ref.Host != "" {
			appendUniqueJumpAlias(&ident.aliases, ref.Host)
			if ident.openSSHAlias != "" {
				appendUniqueJumpAlias(&ident.openSSHAliases, ref.Host)
			}
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
		} else if port > 0 {
			ident.openSSHRef.Port = port
			ident.openSSHRef.HasPort = true
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

func buildGraphHopJumpIdentity(cfg *Configuration, lookup map[string][]string, aliases map[string]string, hop string) (jumpNodeIdentity, error) {
	return buildHopJumpIdentityWithOpts(cfg, nil, jumpWalkOptions{
		graphMode: true,
		lookup:    lookup,
		aliases:   aliases,
	}, hop)
}

func buildHopJumpIdentityWithOpts(cfg *Configuration, openSSH *OpenSSHParser, opts jumpWalkOptions, hop string) (jumpNodeIdentity, error) {
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
		if opts.graphMode {
			if ref, err := ParseTargetRef(hop); err == nil && !ref.OpenSSH {
				if localTargets := resolveLocalJumpTargets(cfg, opts.lookup, opts.aliases, hop, ref); len(localTargets) == 1 {
					return buildSavedJumpNodeIdentity(cfg, localTargets[0]), nil
				}
			}
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
	if (a.isDirect || b.isDirect) && (directJumpMatchesAlias(a, b) || directJumpMatchesAlias(b, a)) {
		return true
	}
	if !a.isDirect && !b.isDirect && a.isOpenSSH && b.isOpenSSH {
		return false
	}
	return a.hasEndpoint && b.hasEndpoint && a.endpoint.Equal(b.endpoint) && jumpUsersCompatible(a, b)
}

func sameOpenSSHAliasJumpIdentity(a, b jumpNodeIdentity) bool {
	if len(a.openSSHAliases) == 0 || len(b.openSSHAliases) == 0 {
		return false
	}
	if a.effectivePort() != b.effectivePort() {
		return false
	}
	if !jumpUsersCompatible(a, b) {
		return false
	}
	for _, aliasA := range a.openSSHAliases {
		for _, aliasB := range b.openSSHAliases {
			if strings.EqualFold(aliasA, aliasB) {
				return true
			}
		}
	}
	return false
}

func directJumpMatchesAlias(target, direct jumpNodeIdentity) bool {
	if !direct.isDirect || !direct.hasOpenSSHRef || direct.isSavedNode {
		return false
	}
	if direct.isOpenSSH && target.isSavedNode {
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

// validateVirtualJumpTargetsWithConfig normalizes a virtual OpenSSH node's base
// ProxyJump targets: non-OpenSSH hops are resolved via ResolveProxyJumpChainWithConfig,
// while OpenSSH-prefixed hops validate syntax and check any broken OpenSSHParser.
func validateVirtualJumpTargetsWithConfig(cfg *Configuration, openSSH *OpenSSHParser, targets []string) (string, error) {
	validated, err := validateJumpTargetsSyntax(targets)
	if err != nil {
		return "", err
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
		if cfg == nil {
			out = append(out, hop)
			continue
		}
		resolved, rErr := ResolveProxyJumpChainWithConfig(cfg, openSSH, hop)
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
func buildProxyJumpTargetFromSavedNode(nodeID, openSSHAlias, canonicalHost, selector string, host models.Host, ident models.Identity) ProxyJumpTarget {
	return ProxyJumpTarget{
		NodeID:        nodeID,
		Selector:      selector,
		OpenSSHAlias:  openSSHAlias,
		CanonicalHost: canonicalHost,
		Host:          StripHostBrackets(host.Address),
		Port:          normalizedHostPort(host.Port),
		User:          strings.TrimSpace(ident.User),
	}
}
