package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/user"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/models"
	fileutils "github.com/wentf9/xops-cli/pkg/utils/file"
)

// ConnectionTarget represents the user's connection intent, preserving whether
// user, port, and jump host were explicitly specified.
type ConnectionTarget struct {
	Selector     string
	User         string
	HasUser      bool
	Port         uint16
	HasPort      bool
	ProxyJump    string
	HasProxyJump bool
}

// EnsureNodeOptions carries connection intent and optional creation attributes.
type EnsureNodeOptions struct {
	Target       ConnectionTarget
	DefaultUser  string
	Password     string
	IdentityFile string
	Passphrase   string
	Alias        string
	Tags         []string
	SudoMode     models.SudoMode
	SuPwd        string
}

// EnsureNodeResult contains the resolved or created node ID and mutation details.
type EnsureNodeResult struct {
	NodeID   string
	Created  bool
	Mutation NodeMutation
}

type canonicalTargetInfo struct {
	Address              string
	Port                 uint16
	IdentityFile         string
	ProxyJump            string
	DefaultUser          string
	AmbiguousDefaultUser bool
	AmbiguousCandidates  []string
}

// FormatHostPort formats host and port, enclosing IPv6 addresses in brackets.
func FormatHostPort(address string, port uint16) string {
	cleaned := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(address), "]"), "[")
	if strings.Contains(cleaned, ":") {
		return fmt.Sprintf("[%s]:%d", cleaned, port)
	}
	return fmt.Sprintf("%s:%d", cleaned, port)
}

// FormatNodeID formats node ID using user@host:port (with IPv6 bracketed if necessary).
func FormatNodeID(user, address string, port uint16) string {
	return fmt.Sprintf("%s@%s", user, FormatHostPort(address, port))
}

// EnsureNodeContext ensures a node matching the target intent exists. If not, it
// atomically creates the required Host, Identity, and Node within a single
// configuration transaction.
//
//nolint:gocyclo
func (r *Repository) EnsureNodeContext(ctx context.Context, opts EnsureNodeOptions) (EnsureNodeResult, error) {
	if r == nil {
		return EnsureNodeResult{}, fmt.Errorf("configuration repository is nil")
	}
	target := opts.Target
	selector := strings.TrimSpace(target.Selector)
	if selector == "" {
		return EnsureNodeResult{}, fmt.Errorf("target selector is empty")
	}

	explicitDefaultUser := strings.TrimSpace(opts.DefaultUser)

	// 1. Read-only fast-path check
	if existingID, isAmbiguous, err := r.findExistingNodeFast(target, explicitDefaultUser); err != nil {
		return EnsureNodeResult{}, err
	} else if isAmbiguous {
		return EnsureNodeResult{}, err
	} else if existingID != "" {
		return EnsureNodeResult{NodeID: existingID, Created: false}, nil
	}

	// 2. Perform atomic ensure in mutation transaction.
	var finalNodeID string
	var createdNode bool

	result, commitErr := r.commitResultContext(ctx, anyRevision, func(cfg *Configuration) error {
		lookup, aliases, err := buildIndexes(cfg, false)
		if err != nil {
			return fmt.Errorf("build configuration indexes failed: %w", err)
		}

		if !target.HasUser && !target.HasPort {
			return r.ensureBareTargetInTransaction(cfg, opts, lookup, aliases, selector, explicitDefaultUser, &finalNodeID, &createdNode)
		}

		return r.ensureExplicitTargetInTransaction(cfg, opts, lookup, aliases, selector, explicitDefaultUser, &finalNodeID, &createdNode)
	})

	mutation := NodeMutation{
		Outcome: MutationOutcome{Applied: result.Applied, Durable: result.Durable},
	}
	if !result.Applied {
		return EnsureNodeResult{}, commitErr
	}

	if createdNode {
		version, versionErr := nodeEntityVersion(result.Snapshot.Configuration, finalNodeID)
		if versionErr != nil {
			return EnsureNodeResult{
				NodeID:   finalNodeID,
				Created:  createdNode,
				Mutation: mutation,
			}, errors.Join(commitErr, fmt.Errorf("resolve applied node %q version: %w", finalNodeID, versionErr))
		}
		mutation.Ref = NodeRef{ID: finalNodeID, Version: version}
	}

	return EnsureNodeResult{
		NodeID:   finalNodeID,
		Created:  createdNode,
		Mutation: mutation,
	}, commitErr
}

func (r *Repository) ensureBareTargetInTransaction(
	cfg *Configuration,
	opts EnsureNodeOptions,
	lookup map[string][]string,
	aliases map[string]string,
	selector, explicitDefaultUser string,
	finalNodeID *string,
	createdNode *bool,
) error {
	if _, exists := cfg.Nodes.Get(selector); exists {
		*finalNodeID = selector
		*createdNode = false
		return nil
	}
	if nid, ok := aliases[selector]; ok && nid != "" {
		*finalNodeID = nid
		*createdNode = false
		return nil
	}
	candidates := lookup[selector]
	switch len(candidates) {
	case 1:
		*finalNodeID = candidates[0]
		*createdNode = false
		return nil
	case 0:
		if r.provider != nil && r.provider.openSSH != nil && r.provider.openSSH.cfg != nil {
			if nid, ok := r.provider.openSSH.Find(selector); ok {
				*finalNodeID = nid
				*createdNode = false
				return nil
			}
		}
		canonicalInfo, resolveErr := r.resolveCanonicalTargetInfo(cfg, lookup, aliases, selector, opts.Target)
		if resolveErr != nil {
			return resolveErr
		}
		effectiveUser, userErr := resolveEffectiveUser(opts.Target, explicitDefaultUser, canonicalInfo.DefaultUser)
		if userErr != nil {
			return userErr
		}
		return r.createNodeInTransaction(cfg, opts, canonicalInfo, effectiveUser, 22, finalNodeID, createdNode)
	default:
		return &AmbiguousNodeError{Selector: selector, Candidates: slices.Clone(candidates)}
	}
}

func (r *Repository) ensureExplicitTargetInTransaction(
	cfg *Configuration,
	opts EnsureNodeOptions,
	lookup map[string][]string,
	aliases map[string]string,
	selector, explicitDefaultUser string,
	finalNodeID *string,
	createdNode *bool,
) error {
	target := opts.Target
	canonicalInfo, resolveErr := r.resolveCanonicalTargetInfo(cfg, lookup, aliases, selector, target)
	if resolveErr != nil {
		return resolveErr
	}
	if !target.HasUser && canonicalInfo.AmbiguousDefaultUser {
		return &AmbiguousNodeError{Selector: selector, Candidates: canonicalInfo.AmbiguousCandidates}
	}

	effectivePort := canonicalInfo.Port
	if target.HasPort {
		effectivePort = target.Port
	} else if effectivePort == 0 {
		effectivePort = 22
	}

	effectiveUser, userErr := resolveEffectiveUser(target, explicitDefaultUser, canonicalInfo.DefaultUser)
	if userErr != nil {
		return userErr
	}

	matches := findMatchingNodes(cfg, effectiveUser, canonicalInfo.Address, effectivePort)
	switch len(matches) {
	case 1:
		*finalNodeID = matches[0]
		*createdNode = false
		return nil
	case 0:
		return r.createNodeInTransaction(cfg, opts, canonicalInfo, effectiveUser, effectivePort, finalNodeID, createdNode)
	default:
		return &AmbiguousNodeError{Selector: selector, Candidates: matches}
	}
}

func resolveEffectiveUser(target ConnectionTarget, explicitDefaultUser, canonicalDefaultUser string) (string, error) {
	if target.HasUser && strings.TrimSpace(target.User) != "" {
		return strings.TrimSpace(target.User), nil
	}
	if strings.TrimSpace(canonicalDefaultUser) != "" {
		return strings.TrimSpace(canonicalDefaultUser), nil
	}
	if strings.TrimSpace(explicitDefaultUser) != "" {
		return strings.TrimSpace(explicitDefaultUser), nil
	}
	curr, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("get default user failed: %w", err)
	}
	return curr.Username, nil
}

// findExistingNodeFast checks in the current snapshot if the node already exists.
func (r *Repository) findExistingNodeFast(target ConnectionTarget, explicitDefaultUser string) (string, bool, error) {
	selector := strings.TrimSpace(target.Selector)
	snapshot := r.provider.Snapshot()
	lookup, aliases, err := buildIndexes(snapshot, false)
	if err != nil {
		return "", false, err
	}

	if !target.HasUser && !target.HasPort {
		return r.findBareNodeFast(snapshot, lookup, aliases, selector)
	}

	canonicalInfo, err := r.resolveCanonicalTargetInfo(snapshot, lookup, aliases, selector, target)
	if err != nil {
		return "", true, err
	}
	if !target.HasUser && canonicalInfo.AmbiguousDefaultUser {
		return "", true, &AmbiguousNodeError{Selector: selector, Candidates: canonicalInfo.AmbiguousCandidates}
	}

	effectivePort := canonicalInfo.Port
	if target.HasPort {
		effectivePort = target.Port
	} else if effectivePort == 0 {
		effectivePort = 22
	}

	effectiveUser, userErr := resolveEffectiveUser(target, explicitDefaultUser, canonicalInfo.DefaultUser)
	if userErr != nil {
		return "", true, userErr
	}

	matches := findMatchingNodes(snapshot, effectiveUser, canonicalInfo.Address, effectivePort)
	switch len(matches) {
	case 1:
		return matches[0], false, nil
	case 0:
		return "", false, nil
	default:
		return "", true, &AmbiguousNodeError{Selector: selector, Candidates: matches}
	}
}

func (r *Repository) findBareNodeFast(snapshot *Configuration, lookup map[string][]string, aliases map[string]string, selector string) (string, bool, error) {
	if _, exists := snapshot.Nodes.Get(selector); exists {
		return selector, false, nil
	}
	if nid, ok := aliases[selector]; ok && nid != "" {
		return nid, false, nil
	}
	candidates := lookup[selector]
	switch len(candidates) {
	case 1:
		return candidates[0], false, nil
	case 0:
		if r.provider != nil && r.provider.openSSH != nil && r.provider.openSSH.cfg != nil {
			if nid, ok := r.provider.openSSH.Find(selector); ok {
				return nid, false, nil
			}
		}
		return "", false, nil
	default:
		return "", true, &AmbiguousNodeError{Selector: selector, Candidates: slices.Clone(candidates)}
	}
}

func findMatchingNodes(snapshot *Configuration, user, addr string, port uint16) []string {
	var matches []string
	for _, nid := range snapshot.Nodes.Keys() {
		n, ok := snapshot.Nodes.Get(nid)
		if !ok {
			continue
		}
		h, hok := snapshot.Hosts.Get(n.HostRef)
		ident, iok := snapshot.Identities.Get(n.IdentityRef)
		if hok && iok {
			cleanHostAddr := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(h.Address), "]"), "[")
			if cleanHostAddr == addr && h.Port == port && ident.User == user {
				matches = append(matches, nid)
			}
		}
	}
	slices.Sort(matches)
	return matches
}

// resolveCanonicalTargetInfo extracts canonical address, port, identity and proxy details.
func (r *Repository) resolveCanonicalTargetInfo(cfg *Configuration, lookup map[string][]string, aliases map[string]string, selector string, target ConnectionTarget) (canonicalTargetInfo, error) {
	// 1. Direct Node ID match
	if node, exists := cfg.Nodes.Get(selector); exists {
		if host, hostExists := cfg.Hosts.Get(node.HostRef); hostExists {
			clean := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(host.Address), "]"), "[")
			var defUser string
			if ident, identExists := cfg.Identities.Get(node.IdentityRef); identExists {
				defUser = ident.User
			}
			return canonicalTargetInfo{Address: clean, Port: host.Port, DefaultUser: defUser}, nil
		}
	}

	// 2. Alias match
	if nid, exists := aliases[selector]; exists && nid != "" {
		if node, ok := cfg.Nodes.Get(nid); ok {
			if host, hostExists := cfg.Hosts.Get(node.HostRef); hostExists {
				clean := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(host.Address), "]"), "[")
				var defUser string
				if ident, identExists := cfg.Identities.Get(node.IdentityRef); identExists {
					defUser = ident.User
				}
				return canonicalTargetInfo{Address: clean, Port: host.Port, DefaultUser: defUser}, nil
			}
		}
	}

	// 3. Lookup match
	if candidates := lookup[selector]; len(candidates) > 0 {
		return resolveLookupCandidates(cfg, selector, candidates, target)
	}

	// 4. OpenSSH configuration match
	if r != nil && r.provider != nil && r.provider.openSSH != nil && r.provider.openSSH.cfg != nil {
		clean := strings.TrimPrefix(selector, OpenSSHNodePrefix)
		if r.provider.openSSH.HasHost(clean) {
			vnode, vhost, vident, err := r.provider.openSSH.GetVirtualNode(clean)
			if err != nil {
				return canonicalTargetInfo{}, fmt.Errorf("resolve openssh host %q: %w", clean, err)
			}
			return canonicalTargetInfo{
				Address:      strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(vhost.Address), "]"), "["),
				Port:         vhost.Port,
				IdentityFile: vident.KeyPath,
				ProxyJump:    vnode.ProxyJump,
				DefaultUser:  vident.User,
			}, nil
		}
	}

	// 5. Raw address/hostname fallback
	clean := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(selector), "]"), "[")
	return canonicalTargetInfo{Address: clean, Port: 22}, nil
}

func filterCandidatesByExplicitTarget(cfg *Configuration, candidates []string, target ConnectionTarget) []string {
	if !target.HasPort && !target.HasUser {
		return slices.Clone(candidates)
	}
	filtered := make([]string, 0, len(candidates))
	for _, cid := range candidates {
		node, ok := cfg.Nodes.Get(cid)
		if !ok {
			continue
		}
		host, hostExists := cfg.Hosts.Get(node.HostRef)
		if !hostExists {
			continue
		}
		var user string
		if ident, identExists := cfg.Identities.Get(node.IdentityRef); identExists {
			user = ident.User
		}
		if target.HasPort && host.Port != target.Port {
			continue
		}
		if target.HasUser && user != target.User {
			continue
		}
		filtered = append(filtered, cid)
	}
	return filtered
}

func resolveCandidateNodeInfo(cfg *Configuration, candidateID string) (canonicalTargetInfo, bool) {
	node, ok := cfg.Nodes.Get(candidateID)
	if !ok {
		return canonicalTargetInfo{}, false
	}
	host, hostExists := cfg.Hosts.Get(node.HostRef)
	if !hostExists {
		return canonicalTargetInfo{}, false
	}
	clean := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(host.Address), "]"), "[")
	var defUser string
	if ident, identExists := cfg.Identities.Get(node.IdentityRef); identExists {
		defUser = ident.User
	}
	return canonicalTargetInfo{Address: clean, Port: host.Port, DefaultUser: defUser}, true
}

func resolveConsistentCandidates(cfg *Configuration, selector string, candidates []string) (canonicalTargetInfo, error) {
	var firstAddr string
	var firstPort uint16
	var firstUser string
	initialized := false
	addrPortConsistent := true
	userConsistent := true

	for _, cid := range candidates {
		node, ok := cfg.Nodes.Get(cid)
		if !ok {
			continue
		}
		host, hostExists := cfg.Hosts.Get(node.HostRef)
		if !hostExists {
			continue
		}
		var user string
		if ident, identExists := cfg.Identities.Get(node.IdentityRef); identExists {
			user = ident.User
		}
		clean := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(host.Address), "]"), "[")
		if !initialized {
			firstAddr = clean
			firstPort = host.Port
			firstUser = user
			initialized = true
		} else {
			if firstAddr != clean || firstPort != host.Port {
				addrPortConsistent = false
				break
			}
			if firstUser != user {
				userConsistent = false
			}
		}
	}
	if initialized && addrPortConsistent {
		var defUser string
		if userConsistent {
			defUser = firstUser
		}
		return canonicalTargetInfo{
			Address:              firstAddr,
			Port:                 firstPort,
			DefaultUser:          defUser,
			AmbiguousDefaultUser: !userConsistent,
			AmbiguousCandidates:  slices.Clone(candidates),
		}, nil
	}
	return canonicalTargetInfo{}, &AmbiguousNodeError{Selector: selector, Candidates: slices.Clone(candidates)}
}

func resolveCandidateAddressFallback(cfg *Configuration, selector string, candidates []string, target ConnectionTarget) (canonicalTargetInfo, error) {
	var firstAddr string
	var firstPort uint16
	var firstUser string
	initialized := false
	addrConsistent := true
	portConsistent := true
	userConsistent := true

	for _, cid := range candidates {
		node, ok := cfg.Nodes.Get(cid)
		if !ok {
			continue
		}
		host, hostExists := cfg.Hosts.Get(node.HostRef)
		if !hostExists {
			continue
		}
		var user string
		if ident, identExists := cfg.Identities.Get(node.IdentityRef); identExists {
			user = ident.User
		}
		clean := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(host.Address), "]"), "[")
		if !initialized {
			firstAddr = clean
			firstPort = host.Port
			firstUser = user
			initialized = true
		} else {
			if firstAddr != clean {
				addrConsistent = false
				break
			}
			if firstPort != host.Port {
				portConsistent = false
			}
			if firstUser != user {
				userConsistent = false
			}
		}
	}

	if !initialized || !addrConsistent {
		return canonicalTargetInfo{}, &AmbiguousNodeError{Selector: selector, Candidates: slices.Clone(candidates)}
	}

	effectivePort := target.Port
	if !target.HasPort {
		if !portConsistent {
			return canonicalTargetInfo{}, &AmbiguousNodeError{Selector: selector, Candidates: slices.Clone(candidates)}
		}
		effectivePort = firstPort
		if effectivePort == 0 {
			effectivePort = 22
		}
	}

	var defUser string
	if target.HasUser {
		defUser = target.User
	} else if userConsistent {
		defUser = firstUser
	}

	return canonicalTargetInfo{
		Address:              firstAddr,
		Port:                 effectivePort,
		DefaultUser:          defUser,
		AmbiguousDefaultUser: !target.HasUser && !userConsistent,
		AmbiguousCandidates:  slices.Clone(candidates),
	}, nil
}

func resolveLookupCandidates(cfg *Configuration, selector string, candidates []string, target ConnectionTarget) (canonicalTargetInfo, error) {
	filtered := filterCandidatesByExplicitTarget(cfg, candidates, target)
	if len(filtered) == 1 {
		if info, ok := resolveCandidateNodeInfo(cfg, filtered[0]); ok {
			return info, nil
		}
	}
	if len(filtered) > 1 {
		return resolveConsistentCandidates(cfg, selector, filtered)
	}
	return resolveCandidateAddressFallback(cfg, selector, candidates, target)
}

// createNodeInTransaction performs the atomic creation of Host, Identity, and Node.
func (r *Repository) createNodeInTransaction(
	cfg *Configuration,
	opts EnsureNodeOptions,
	canonicalInfo canonicalTargetInfo,
	effectiveUser string,
	effectivePort uint16,
	finalNodeID *string,
	createdNode *bool,
) error {
	canonicalAddr := canonicalInfo.Address
	targetNodeID := FormatNodeID(effectiveUser, canonicalAddr, effectivePort)
	if _, exists := cfg.Nodes.Get(targetNodeID); exists {
		*finalNodeID = targetNodeID
		*createdNode = false
		return nil
	}

	// 1. Host resolution / reuse
	hostRef, hostErr := ensureMatchingHost(cfg, canonicalAddr, effectivePort, targetNodeID)
	if hostErr != nil {
		return hostErr
	}

	// 2. ProxyJump resolution / inheritance
	finalJump, jumpErr := r.resolveJumpForNode(cfg, opts, canonicalInfo, canonicalAddr, effectivePort)
	if jumpErr != nil {
		return jumpErr
	}

	// 3. Identity creation and strict isolation
	identityRef := r.createIdentityForNode(cfg, opts, canonicalInfo, effectiveUser, canonicalAddr, targetNodeID)

	// 4. Node creation
	sudoMode := models.SudoModeAuto
	if opts.SudoMode != "" {
		sudoMode = opts.SudoMode
	}
	newNode := models.Node{
		HostRef:     hostRef,
		IdentityRef: identityRef,
		ProxyJump:   finalJump,
		SudoMode:    sudoMode,
		SuPwd:       opts.SuPwd,
	}
	if opts.Alias != "" {
		trimmedAlias := strings.TrimSpace(opts.Alias)
		if existingNode := findAliasInConfig(cfg, trimmedAlias); existingNode != "" && existingNode != targetNodeID {
			return fmt.Errorf("%s", i18n.Tf("alias_err_exists", map[string]any{"Alias": trimmedAlias, "Node": existingNode}))
		}
		newNode.Alias = []string{trimmedAlias}
	}
	if len(opts.Tags) > 0 {
		newNode.Tags = slices.Clone(opts.Tags)
	}

	cfg.Nodes.Set(targetNodeID, newNode)
	*finalNodeID = targetNodeID
	*createdNode = true
	return nil
}

func ensureMatchingHost(cfg *Configuration, canonicalAddr string, port uint16, targetNodeID string) (string, error) {
	var matchingHostRefs []string
	for _, href := range cfg.Hosts.Keys() {
		h, ok := cfg.Hosts.Get(href)
		if !ok {
			continue
		}
		clean := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(h.Address), "]"), "[")
		if clean == canonicalAddr && h.Port == port {
			matchingHostRefs = append(matchingHostRefs, href)
		}
	}

	switch len(matchingHostRefs) {
	case 0:
		candidateRef := FormatHostPort(canonicalAddr, port)
		hostRef := candidateRef
		if existing, exists := cfg.Hosts.Get(candidateRef); exists {
			clean := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(existing.Address), "]"), "[")
			if clean != canonicalAddr || existing.Port != port {
				hostRef = privateHostReference(cfg, targetNodeID)
			}
		}
		cfg.Hosts.Set(hostRef, models.Host{
			Address: canonicalAddr,
			Port:    port,
		})
		return hostRef, nil
	case 1:
		return matchingHostRefs[0], nil
	default:
		return "", fmt.Errorf("ambiguous host configuration: multiple host references found for %s: %v",
			FormatHostPort(canonicalAddr, port), matchingHostRefs)
	}
}

func (r *Repository) resolveJumpForNode(
	cfg *Configuration,
	opts EnsureNodeOptions,
	canonicalInfo canonicalTargetInfo,
	canonicalAddr string,
	port uint16,
) (string, error) {
	if opts.Target.HasProxyJump {
		finalJump := opts.Target.ProxyJump
		if finalJump != "" {
			return r.resolveProxyJumpChain(cfg, finalJump)
		}
		return "", nil
	}

	jumpSet := make(map[string]struct{})
	for _, nid := range cfg.Nodes.Keys() {
		n, ok := cfg.Nodes.Get(nid)
		if !ok {
			continue
		}
		h, hok := cfg.Hosts.Get(n.HostRef)
		if !hok {
			continue
		}
		clean := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(h.Address), "]"), "[")
		if clean == canonicalAddr && h.Port == port {
			trimmedJump := strings.TrimSpace(n.ProxyJump)
			jumpSet[trimmedJump] = struct{}{}
		}
	}

	switch len(jumpSet) {
	case 0:
		if canonicalInfo.ProxyJump != "" {
			return r.resolveProxyJumpChain(cfg, canonicalInfo.ProxyJump)
		}
		return "", nil
	case 1:
		for j := range jumpSet {
			return j, nil
		}
		return "", nil
	default:
		return "", fmt.Errorf("ambiguous proxy jump: multiple nodes for host %s have conflicting proxy jumps",
			FormatHostPort(canonicalAddr, port))
	}
}

func (r *Repository) createIdentityForNode(
	cfg *Configuration,
	opts EnsureNodeOptions,
	canonicalInfo canonicalTargetInfo,
	effectiveUser, canonicalAddr, targetNodeID string,
) string {
	identity := models.Identity{
		User: effectiveUser,
	}
	effectiveKeyPath := opts.IdentityFile
	if effectiveKeyPath == "" && canonicalInfo.IdentityFile != "" {
		effectiveKeyPath = canonicalInfo.IdentityFile
	}

	if opts.Password == "" && effectiveKeyPath == "" {
		identity.AuthType = "auto"
	} else if opts.Password != "" {
		identity.Password = opts.Password
		identity.AuthType = "password"
	} else if effectiveKeyPath != "" {
		identity.KeyPath = fileutils.ToAbsolutePath(effectiveKeyPath)
		identity.Passphrase = opts.Passphrase
		identity.AuthType = "key"
	}

	preferredIdentRef := fmt.Sprintf("%s@%s", effectiveUser, canonicalAddr)
	var identityRef string
	if _, exists := cfg.Identities.Get(preferredIdentRef); exists {
		identityRef = privateIdentityReference(cfg, targetNodeID)
	} else {
		identityRef = preferredIdentRef
	}
	cfg.Identities.Set(identityRef, identity)
	return identityRef
}

// ResolveProxyJumpChain validates and resolves a comma-separated jump host chain against the current configuration.
func (r *Repository) ResolveProxyJumpChain(jumpChain string) (string, error) {
	var openSSH *OpenSSHParser
	if r != nil && r.provider != nil {
		openSSH = r.provider.openSSH
	}
	return ResolveProxyJumpChainWithConfig(r.provider.Snapshot(), openSSH, jumpChain)
}

func (r *Repository) resolveProxyJumpChain(cfg *Configuration, jumpChain string) (string, error) {
	var openSSH *OpenSSHParser
	if r != nil && r.provider != nil {
		openSSH = r.provider.openSSH
	}
	return ResolveProxyJumpChainWithConfig(cfg, openSSH, jumpChain)
}

// ResolveProxyJumpChainWithConfig validates and normalizes a comma-separated jump host chain.
func ResolveProxyJumpChainWithConfig(cfg *Configuration, openSSH *OpenSSHParser, jumpChain string) (string, error) {
	trimmed := strings.TrimSpace(jumpChain)
	if trimmed == "" {
		return "", nil
	}
	rawHops := strings.Split(trimmed, ",")
	resolvedHops := make([]string, 0, len(rawHops))
	for _, rawHop := range rawHops {
		hop := strings.TrimSpace(rawHop)
		if hop == "" {
			continue
		}
		resolved, err := resolveSingleJumpHopWithConfig(cfg, openSSH, hop)
		if err != nil {
			return "", err
		}
		resolvedHops = append(resolvedHops, resolved)
	}
	return strings.Join(resolvedHops, ","), nil
}

// resolveHopExactNodeMatch checks whether hop directly matches a node ID, alias, or unique lookup candidate.
func resolveHopExactNodeMatch(cfg *Configuration, lookup map[string][]string, aliases map[string]string, hop string) (string, bool, error) {
	if _, ok := cfg.Nodes.Get(hop); ok {
		return hop, true, nil
	}
	if nid, ok := aliases[hop]; ok && nid != "" {
		return nid, true, nil
	}
	if candidates := lookup[hop]; len(candidates) == 1 {
		return candidates[0], true, nil
	} else if len(candidates) > 1 {
		return "", true, &AmbiguousNodeError{Selector: hop, Candidates: slices.Clone(candidates)}
	}
	return "", false, nil
}

func collectHostCandidates(cfg *Configuration, lookup map[string][]string, aliases map[string]string, host string) []string {
	if nid, ok := aliases[host]; ok && nid != "" {
		return []string{nid}
	}
	if cands := lookup[host]; len(cands) > 0 {
		return slices.Clone(cands)
	}
	if _, ok := cfg.Nodes.Get(host); ok {
		return []string{host}
	}
	return nil
}

func filterHostCandidates(cfg *Configuration, candidates []string, hopUser string, hopPort uint16) []string {
	var matched []string
	for _, cid := range candidates {
		node, ok := cfg.Nodes.Get(cid)
		if !ok {
			continue
		}
		h, hok := cfg.Hosts.Get(node.HostRef)
		ident, iok := cfg.Identities.Get(node.IdentityRef)
		if !hok || !iok {
			continue
		}
		if hopPort != 0 && h.Port != hopPort {
			continue
		}
		if hopUser != "" && ident.User != hopUser {
			continue
		}
		matched = append(matched, cid)
	}
	return matched
}

func resolveHopAddressFromCandidates(cfg *Configuration, hostCandidates []string) (string, bool) {
	var firstAddr string
	for _, cid := range hostCandidates {
		node, ok := cfg.Nodes.Get(cid)
		if !ok {
			continue
		}
		h, hok := cfg.Hosts.Get(node.HostRef)
		if !hok {
			continue
		}
		clean := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(h.Address), "]"), "[")
		if firstAddr == "" {
			firstAddr = clean
		} else if firstAddr != clean {
			return "", false
		}
	}
	return firstAddr, true
}

func resolveHopPortFromCandidates(cfg *Configuration, hostCandidates []string) (uint16, bool) {
	var firstPort uint16
	for _, cid := range hostCandidates {
		node, ok := cfg.Nodes.Get(cid)
		if !ok {
			continue
		}
		h, hok := cfg.Hosts.Get(node.HostRef)
		if !hok {
			continue
		}
		if firstPort == 0 {
			firstPort = h.Port
		} else if firstPort != h.Port {
			return 0, false
		}
	}
	return firstPort, true
}

func resolveHopAddressFallback(cfg *Configuration, hop, hopUser string, hopPort uint16, hostCandidates []string) (string, error) {
	firstAddr, consistent := resolveHopAddressFromCandidates(cfg, hostCandidates)
	if !consistent {
		return "", &AmbiguousNodeError{Selector: hop, Candidates: slices.Clone(hostCandidates)}
	}
	if firstAddr == "" {
		return "", errors.New(i18n.Tf("ssh_err_jump_not_found", map[string]any{"Host": hop}))
	}
	effectivePort := hopPort
	if effectivePort == 0 {
		candPort, portConsistent := resolveHopPortFromCandidates(cfg, hostCandidates)
		if !portConsistent {
			return "", &AmbiguousNodeError{Selector: hop, Candidates: slices.Clone(hostCandidates)}
		}
		if candPort != 0 {
			effectivePort = candPort
		} else {
			effectivePort = 22
		}
	}
	var matchingNodes []string
	for _, nid := range cfg.Nodes.Keys() {
		n, ok := cfg.Nodes.Get(nid)
		if !ok {
			continue
		}
		h, hok := cfg.Hosts.Get(n.HostRef)
		ident, iok := cfg.Identities.Get(n.IdentityRef)
		if hok && iok {
			cleanHostAddr := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(h.Address), "]"), "[")
			if cleanHostAddr == firstAddr && h.Port == effectivePort {
				if hopUser == "" || ident.User == hopUser {
					matchingNodes = append(matchingNodes, nid)
				}
			}
		}
	}
	slices.Sort(matchingNodes)
	switch len(matchingNodes) {
	case 1:
		return matchingNodes[0], nil
	case 0:
		var resolvedSpec string
		if hopUser != "" {
			resolvedSpec = FormatNodeID(hopUser, firstAddr, effectivePort)
		} else {
			resolvedSpec = FormatHostPort(firstAddr, effectivePort)
		}
		if isDirectJumpTarget(resolvedSpec) {
			return OpenSSHNodePrefix + resolvedSpec, nil
		}
		return "", errors.New(i18n.Tf("ssh_err_jump_not_found", map[string]any{"Host": hop}))
	default:
		return "", &AmbiguousNodeError{Selector: hop, Candidates: matchingNodes}
	}
}

func resolveHopFromHostCandidates(cfg *Configuration, hop, hopUser string, hopPort uint16, hostCandidates []string) (string, error) {
	matched := filterHostCandidates(cfg, hostCandidates, hopUser, hopPort)
	switch len(matched) {
	case 1:
		return matched[0], nil
	case 0:
		return resolveHopAddressFallback(cfg, hop, hopUser, hopPort, hostCandidates)
	default:
		return "", &AmbiguousNodeError{Selector: hop, Candidates: slices.Clone(matched)}
	}
}

// resolveOpenSSHJumpHop handles jump targets that are explicitly prefixed with OpenSSHNodePrefix.
func resolveOpenSSHJumpHop(openSSH *OpenSSHParser, hop string) (string, error) {
	cleanHop := strings.TrimPrefix(hop, OpenSSHNodePrefix)
	if openSSH != nil && openSSH.cfg != nil && openSSH.HasHost(cleanHop) {
		if _, _, _, vErr := openSSH.GetVirtualNode(cleanHop); vErr != nil {
			return "", fmt.Errorf("resolve openssh jump %q: %w", cleanHop, vErr)
		}
		return OpenSSHNodePrefix + cleanHop, nil
	}

	if isDirectJumpTarget(cleanHop) {
		if _, _, _, parseErr := parseOpenSSHHostSpec(cleanHop); parseErr != nil {
			return "", fmt.Errorf("invalid jump host address %q: %w", cleanHop, parseErr)
		}
		return OpenSSHNodePrefix + cleanHop, nil
	}

	return "", errors.New(i18n.Tf("ssh_err_jump_not_found", map[string]any{"Host": hop}))
}

// resolveLocalOrDirectJumpHop handles jump targets with unspecified origin (local first, then OpenSSH, then direct).
func resolveLocalOrDirectJumpHop(cfg *Configuration, openSSH *OpenSSHParser, hop string) (string, error) {
	lookup, aliases, err := buildIndexes(cfg, false)
	if err != nil {
		return "", fmt.Errorf("build indexes for jump resolution failed: %w", err)
	}
	if exact, matched, matchErr := resolveHopExactNodeMatch(cfg, lookup, aliases, hop); matched {
		return exact, matchErr
	}

	hopHost, hopUser, hopPort, parseErr := parseOpenSSHHostSpec(hop)
	if parseErr == nil && hopHost != "" {
		hostCandidates := collectHostCandidates(cfg, lookup, aliases, hopHost)
		if len(hostCandidates) > 0 {
			return resolveHopFromHostCandidates(cfg, hop, hopUser, hopPort, hostCandidates)
		}
	}

	if openSSH != nil && openSSH.cfg != nil && openSSH.HasHost(hop) {
		if _, _, _, vErr := openSSH.GetVirtualNode(hop); vErr != nil {
			return "", fmt.Errorf("resolve openssh jump %q: %w", hop, vErr)
		}
		return OpenSSHNodePrefix + hop, nil
	}

	if isDirectJumpTarget(hop) {
		if parseErr != nil {
			return "", fmt.Errorf("invalid jump host address %q: %w", hop, parseErr)
		}
		return OpenSSHNodePrefix + hop, nil
	}

	return "", errors.New(i18n.Tf("ssh_err_jump_not_found", map[string]any{"Host": hop}))
}

// resolveSingleJumpHopWithConfig resolves a single jump hop selector to a canonical node ID or OpenSSH node.
// Resolution strategy:
//  1. Explicit OpenSSH targets (prefixed with OpenSSHNodePrefix): OpenSSH config host or direct jump target only.
//  2. Unspecified origin:
//     a. Existing Node ID
//     b. Existing Alias
//     c. Existing Host address/selector lookup
//     d. OpenSSH Host defined in ~/.ssh/config
//     e. Direct jump target: explicitly requires Node/Alias, FQDN (contains '.'), IP, or [user@]host:port.
//
// Single-label hostnames without port/user cannot be used as direct jumps to avoid silent misconnections on alias typos.
func resolveSingleJumpHopWithConfig(cfg *Configuration, openSSH *OpenSSHParser, hop string) (string, error) {
	if strings.HasPrefix(hop, OpenSSHNodePrefix) {
		return resolveOpenSSHJumpHop(openSSH, hop)
	}
	return resolveLocalOrDirectJumpHop(cfg, openSSH, hop)
}

func isDirectJumpTarget(cleanHop string) bool {
	lookupAlias, _, _, err := parseOpenSSHHostSpec(cleanHop)
	if err != nil {
		return false
	}
	if strings.Contains(cleanHop, "@") || strings.Contains(cleanHop, ":") {
		return true
	}
	if net.ParseIP(lookupAlias) != nil {
		return true
	}
	if isDNSHostname(lookupAlias) {
		return true
	}
	return false
}

func isDNSHostname(host string) bool {
	if !strings.Contains(host, ".") {
		return false
	}
	if len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	parts := strings.Split(host, ".")
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
		for _, ch := range part {
			if !isValidDNSChar(ch) {
				return false
			}
		}
	}
	return true
}

func isValidDNSChar(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-'
}

// findAliasInConfig checks if an alias is used by any node or host.
func findAliasInConfig(cfg *Configuration, alias string) string {
	if cfg == nil || alias == "" {
		return ""
	}
	for _, nodeID := range cfg.Nodes.Keys() {
		node, ok := cfg.Nodes.Get(nodeID)
		if ok && slices.Contains(node.Alias, alias) {
			return nodeID
		}
	}
	for _, hostID := range cfg.Hosts.Keys() {
		host, ok := cfg.Hosts.Get(hostID)
		if ok && slices.Contains(host.Alias, alias) {
			for _, nodeID := range cfg.Nodes.Keys() {
				node, ok := cfg.Nodes.Get(nodeID)
				if ok && node.HostRef == hostID {
					return nodeID
				}
			}
		}
	}
	return ""
}
