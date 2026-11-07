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
	RawSelector  string
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

// ResolvedTarget describes the effective connection parameters resolved from
// a ConnectionTarget without mutating configuration or creating pending nodes.
type ResolvedTarget struct {
	// NodeID is the matched saved/virtual node ID, or the derived canonical
	// FormatNodeID(User, Host, Port) when no existing node matches the effective target.
	NodeID string
	// MatchedNodeID is non-empty only when the effective (User, Host, Port)
	// matched an existing saved node or unmodified OpenSSH virtual node.
	MatchedNodeID string
	// BaseNodeID is the saved or OpenSSH virtual node ID matched by Selector
	// before applying user/port overrides, if any.
	BaseNodeID   string
	Host         string
	Port         uint16
	User         string
	ProxyJump    string
	KeyPath      string
	OpenSSHAlias string
	Created      bool
}

type canonicalTargetInfo struct {
	BaseNodeID           string
	Address              string
	Port                 uint16
	IdentityFile         string
	ProxyJump            string
	DefaultUser          string
	OpenSSHAlias         string
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

type openSSHParserSource interface {
	GetOpenSSHParser() *OpenSSHParser
}

type openSSHAliasStore interface {
	SetNodeOpenSSHAlias(nodeID, alias string)
	NodeOpenSSHAlias(nodeID string) string
}

func resolveTargetHelper(provider ConfigProvider) (*Repository, *Configuration) {
	if provider == nil {
		return nil, nil
	}
	if repo, ok := provider.(*Repository); ok && repo != nil {
		return repo, repo.Snapshot()
	}
	if p, ok := provider.(*Provider); ok && p != nil {
		return &Repository{provider: p}, p.Snapshot()
	}
	if fr, ok := provider.(*frozenRepository); ok && fr != nil {
		return resolveTargetHelper(fr.ConfigProvider)
	}
	snap := provider.Snapshot()
	lookup, aliases, _ := buildIndexes(snap, false)
	var parser *OpenSSHParser
	if src, ok := provider.(openSSHParserSource); ok {
		parser = src.GetOpenSSHParser()
	}
	if parser == nil {
		parser = &OpenSSHParser{cfg: nil}
	}
	p := &Provider{
		cfg:         snap,
		lookupIndex: lookup,
		aliasIndex:  aliases,
		openSSH:     parser,
	}
	return &Repository{provider: p}, snap
}

func recordResolvedOpenSSHAlias(r *Repository, provider ConfigProvider, nodeID, alias string) {
	if nodeID == "" || alias == "" {
		return
	}
	if r != nil {
		r.SetNodeOpenSSHAlias(nodeID, alias)
	}
	if store, ok := provider.(openSSHAliasStore); ok {
		store.SetNodeOpenSSHAlias(nodeID, alias)
	}
}

func normalizeTargetSelector(cfg *Configuration, lookup map[string][]string, aliases map[string]string, target ConnectionTarget) (ConnectionTarget, string) {
	selector := strings.TrimSpace(target.Selector)
	if isDirectOrIndexedSelector(cfg, lookup, aliases, selector) {
		return target, selector
	}
	parsedHost, parsedUser, parsedPort, err := parseOpenSSHHostSpec(selector)
	if err != nil || parsedHost == "" {
		return target, selector
	}
	cleanHost := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(parsedHost), "]"), "[")
	if cleanHost == "" || isAlreadySplitCompositeTarget(target, selector, parsedUser, parsedPort) {
		return target, selector
	}
	if cleanHost == selector && parsedUser == "" && parsedPort == 0 {
		return target, selector
	}
	if strings.TrimSpace(target.RawSelector) == "" {
		target.RawSelector = selector
	}
	target.Selector = cleanHost
	if !target.HasUser && parsedUser != "" {
		target.User = parsedUser
		target.HasUser = true
	}
	if !target.HasPort && parsedPort != 0 {
		target.Port = parsedPort
		target.HasPort = true
	}
	return target, cleanHost
}

func isDirectOrIndexedSelector(cfg *Configuration, lookup map[string][]string, aliases map[string]string, selector string) bool {
	if selector == "" || strings.HasPrefix(selector, OpenSSHNodePrefix) {
		return true
	}
	if cfg != nil && cfg.Nodes != nil {
		if _, exists := cfg.Nodes.Get(selector); exists {
			return true
		}
	}
	if nid, ok := aliases[selector]; ok && nid != "" {
		return true
	}
	return len(lookup[selector]) > 0
}

func isAlreadySplitCompositeTarget(target ConnectionTarget, selector, parsedUser string, parsedPort uint16) bool {
	if strings.TrimSpace(target.RawSelector) != selector {
		return false
	}
	if parsedUser == "" && parsedPort == 0 {
		return false
	}
	return (parsedUser == "" || target.HasUser) && (parsedPort == 0 || target.HasPort)
}

type targetDecision struct {
	NormalizedTarget ConnectionTarget
	Selector         string
	MatchedNodeID    string
	BaseNodeID       string
	OpenSSHAlias     string
	Canonical        canonicalTargetInfo
	EffectiveUser    string
	EffectivePort    uint16
	NeedsCreation    bool
}

// ResolveTarget resolves a ConnectionTarget against a read-only ConfigProvider
// using the exact same resolution rules as PrepareNodeContext / EnsureNodeContext,
// without mutating persisted state or creating pending nodes.
func ResolveTarget(provider ConfigProvider, target ConnectionTarget) (ResolvedTarget, error) {
	if provider == nil {
		return ResolvedTarget{}, fmt.Errorf("configuration provider is nil")
	}
	r, cfg := resolveTargetHelper(provider)
	if r == nil || cfg == nil {
		return ResolvedTarget{}, fmt.Errorf("configuration snapshot is nil")
	}
	lookup, aliases, err := buildIndexes(cfg, false)
	if err != nil {
		return ResolvedTarget{}, fmt.Errorf("build configuration indexes failed: %w", err)
	}
	decision, err := r.evaluateTargetDecision(cfg, lookup, aliases, target, "")
	if err != nil {
		return ResolvedTarget{}, err
	}
	if !decision.NeedsCreation {
		return r.buildMatchedResolvedTarget(provider, decision.MatchedNodeID, decision.BaseNodeID, decision.OpenSSHAlias, decision.NormalizedTarget)
	}
	return r.buildCreatedResolvedTargetWithUserPort(provider, cfg, decision.Canonical, decision.EffectiveUser, decision.EffectivePort, decision.NormalizedTarget)
}

// ResolveTarget resolves target against the repository's current view.
func (r *Repository) ResolveTarget(target ConnectionTarget) (ResolvedTarget, error) {
	if r == nil {
		return ResolvedTarget{}, fmt.Errorf("configuration repository is nil")
	}
	return ResolveTarget(r, target)
}

// ResolveTarget resolves target against the provider's configuration snapshot.
func (p *Provider) ResolveTarget(target ConnectionTarget) (ResolvedTarget, error) {
	if p == nil {
		return ResolvedTarget{}, fmt.Errorf("configuration provider is nil")
	}
	return ResolveTarget(p, target)
}

func (r *Repository) evaluateTargetDecision(
	cfg *Configuration,
	lookup map[string][]string,
	aliases map[string]string,
	target ConnectionTarget,
	explicitDefaultUser string,
) (targetDecision, error) {
	normTarget, selector := normalizeTargetSelector(cfg, lookup, aliases, target)
	if selector == "" {
		return targetDecision{}, fmt.Errorf("target selector is empty")
	}
	var decision targetDecision
	var err error
	if !normTarget.HasUser && !normTarget.HasPort {
		decision, err = r.evaluateBareTargetDecision(cfg, lookup, aliases, selector, normTarget, explicitDefaultUser)
	} else {
		decision, err = r.evaluateExplicitTargetDecision(cfg, lookup, aliases, selector, normTarget, explicitDefaultUser)
	}
	if err != nil {
		return targetDecision{}, err
	}
	if decision.NeedsCreation {
		targetNodeID := FormatNodeID(decision.EffectiveUser, decision.Canonical.Address, decision.EffectivePort)
		if _, exists := cfg.Nodes.Get(targetNodeID); exists {
			if decision.BaseNodeID == "" {
				decision.BaseNodeID = targetNodeID
			}
			decision.MatchedNodeID = targetNodeID
			decision.NeedsCreation = false
		}
	}
	return decision, nil
}

func (r *Repository) evaluateBareTargetDecision(
	cfg *Configuration,
	lookup map[string][]string,
	aliases map[string]string,
	selector string,
	target ConnectionTarget,
	explicitDefaultUser string,
) (targetDecision, error) {
	if _, exists := cfg.Nodes.Get(selector); exists {
		return targetDecision{
			NormalizedTarget: target,
			Selector:         selector,
			MatchedNodeID:    selector,
			BaseNodeID:       selector,
		}, nil
	}
	if nid, ok := aliases[selector]; ok && nid != "" {
		return targetDecision{
			NormalizedTarget: target,
			Selector:         selector,
			MatchedNodeID:    nid,
			BaseNodeID:       nid,
		}, nil
	}
	candidates := lookup[selector]
	switch len(candidates) {
	case 1:
		return targetDecision{
			NormalizedTarget: target,
			Selector:         selector,
			MatchedNodeID:    candidates[0],
			BaseNodeID:       candidates[0],
		}, nil
	case 0:
		if nid, alias, ok := r.matchBareOpenSSHSelector(selector); ok {
			return targetDecision{
				NormalizedTarget: target,
				Selector:         selector,
				MatchedNodeID:    nid,
				BaseNodeID:       nid,
				OpenSSHAlias:     alias,
			}, nil
		}
		canonicalInfo, err := r.resolveCanonicalTargetInfo(cfg, lookup, aliases, selector, target)
		if err != nil {
			return targetDecision{}, err
		}
		effectiveUser, err := resolveEffectiveUser(target, explicitDefaultUser, canonicalInfo.DefaultUser)
		if err != nil {
			return targetDecision{}, err
		}
		effectivePort := canonicalInfo.Port
		if effectivePort == 0 {
			effectivePort = 22
		}
		return targetDecision{
			NormalizedTarget: target,
			Selector:         selector,
			BaseNodeID:       canonicalInfo.BaseNodeID,
			OpenSSHAlias:     canonicalInfo.OpenSSHAlias,
			Canonical:        canonicalInfo,
			EffectiveUser:    effectiveUser,
			EffectivePort:    effectivePort,
			NeedsCreation:    true,
		}, nil
	default:
		return targetDecision{}, &AmbiguousNodeError{Selector: selector, Candidates: slices.Clone(candidates)}
	}
}

func (r *Repository) evaluateExplicitTargetDecision(
	cfg *Configuration,
	lookup map[string][]string,
	aliases map[string]string,
	selector string,
	target ConnectionTarget,
	explicitDefaultUser string,
) (targetDecision, error) {
	canonicalInfo, err := r.resolveCanonicalTargetInfo(cfg, lookup, aliases, selector, target)
	if err != nil {
		return targetDecision{}, err
	}
	if !target.HasUser && canonicalInfo.AmbiguousDefaultUser {
		return targetDecision{}, &AmbiguousNodeError{Selector: selector, Candidates: canonicalInfo.AmbiguousCandidates}
	}

	effectivePort := canonicalInfo.Port
	if target.HasPort {
		effectivePort = target.Port
	} else if effectivePort == 0 {
		effectivePort = 22
	}

	effectiveUser, userErr := resolveEffectiveUser(target, explicitDefaultUser, canonicalInfo.DefaultUser)
	if userErr != nil {
		return targetDecision{}, userErr
	}

	matches := narrowMatchingNodesBySelector(
		findMatchingNodes(cfg, effectiveUser, canonicalInfo.Address, effectivePort),
		aliases,
		selector,
		strings.TrimSpace(target.RawSelector),
	)
	switch len(matches) {
	case 1:
		baseID := canonicalInfo.BaseNodeID
		if baseID == "" {
			baseID = matches[0]
		}
		return targetDecision{
			NormalizedTarget: target,
			Selector:         selector,
			MatchedNodeID:    matches[0],
			BaseNodeID:       baseID,
			OpenSSHAlias:     canonicalInfo.OpenSSHAlias,
			Canonical:        canonicalInfo,
			EffectiveUser:    effectiveUser,
			EffectivePort:    effectivePort,
		}, nil
	case 0:
		if nid, alias := r.matchOpenSSHVirtualNode(selector, effectiveUser, effectivePort); nid != "" {
			return targetDecision{
				NormalizedTarget: target,
				Selector:         selector,
				MatchedNodeID:    nid,
				BaseNodeID:       nid,
				OpenSSHAlias:     alias,
				Canonical:        canonicalInfo,
				EffectiveUser:    effectiveUser,
				EffectivePort:    effectivePort,
			}, nil
		}
		return targetDecision{
			NormalizedTarget: target,
			Selector:         selector,
			BaseNodeID:       canonicalInfo.BaseNodeID,
			OpenSSHAlias:     canonicalInfo.OpenSSHAlias,
			Canonical:        canonicalInfo,
			EffectiveUser:    effectiveUser,
			EffectivePort:    effectivePort,
			NeedsCreation:    true,
		}, nil
	default:
		return targetDecision{}, &AmbiguousNodeError{Selector: selector, Candidates: matches}
	}
}

func (r *Repository) buildMatchedResolvedTarget(
	provider ConfigProvider,
	matchedID, baseID, openSSHAlias string,
	target ConnectionTarget,
) (ResolvedTarget, error) {
	if openSSHAlias != "" {
		recordResolvedOpenSSHAlias(r, provider, matchedID, openSSHAlias)
	}
	node, host, ident, err := provider.Resolve(matchedID)
	if err != nil {
		return ResolvedTarget{}, err
	}
	cleanAddr := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(host.Address), "]"), "[")
	port := host.Port
	if port == 0 {
		port = 22
	}
	user := ident.User
	if user == "" {
		if defUser, uErr := resolveEffectiveUser(target, "", ""); uErr == nil {
			user = defUser
		}
	}
	jump := node.ProxyJump
	if target.HasProxyJump {
		jump = strings.TrimSpace(target.ProxyJump)
		if jump != "" {
			if resolvedJump, jErr := provider.ResolveProxyJumpChain(jump); jErr == nil {
				jump = resolvedJump
			}
		}
	}
	alias := openSSHAlias
	if alias == "" {
		alias = r.effectiveNodeOpenSSHAlias(matchedID, node)
	}
	if alias == "" && strings.HasPrefix(matchedID, OpenSSHNodePrefix) {
		if r.provider != nil && r.provider.openSSH != nil {
			alias = resolveOpenSSHAliasName(r.provider.openSSH, matchedID)
		}
	}
	return ResolvedTarget{
		NodeID:        matchedID,
		MatchedNodeID: matchedID,
		BaseNodeID:    baseID,
		Host:          cleanAddr,
		Port:          port,
		User:          user,
		ProxyJump:     jump,
		KeyPath:       ident.KeyPath,
		OpenSSHAlias:  alias,
		Created:       false,
	}, nil
}

func (r *Repository) buildCreatedResolvedTargetWithUserPort(
	provider ConfigProvider,
	cfg *Configuration,
	canonicalInfo canonicalTargetInfo,
	effectiveUser string,
	effectivePort uint16,
	target ConnectionTarget,
) (ResolvedTarget, error) {
	targetNodeID := FormatNodeID(effectiveUser, canonicalInfo.Address, effectivePort)
	if _, exists := cfg.Nodes.Get(targetNodeID); exists {
		baseID := canonicalInfo.BaseNodeID
		if baseID == "" {
			baseID = targetNodeID
		}
		return r.buildMatchedResolvedTarget(provider, targetNodeID, baseID, canonicalInfo.OpenSSHAlias, target)
	}
	jump, err := r.resolveJumpForNode(cfg, EnsureNodeOptions{Target: target}, canonicalInfo, canonicalInfo.Address, effectivePort)
	if err != nil {
		if target.HasProxyJump {
			jump = strings.TrimSpace(target.ProxyJump)
			if strings.EqualFold(jump, "none") {
				jump = ""
			}
		} else {
			jump = ""
		}
	}
	openSSHAlias := canonicalInfo.OpenSSHAlias
	keyPath := ""
	if canonicalInfo.IdentityFile != "" {
		keyPath = fileutils.ToAbsolutePath(canonicalInfo.IdentityFile)
	}
	if pNode, _, pIdent, ok := r.resolvePendingNode(targetNodeID); ok {
		if !target.HasProxyJump && jump == "" && pNode.ProxyJump != "" {
			jump = pNode.ProxyJump
		}
		if keyPath == "" && pIdent.KeyPath != "" {
			keyPath = pIdent.KeyPath
		}
		if openSSHAlias == "" && pNode.OpenSSHAlias != "" {
			openSSHAlias = pNode.OpenSSHAlias
		}
	}
	if openSSHAlias != "" {
		recordResolvedOpenSSHAlias(r, provider, targetNodeID, openSSHAlias)
	}
	return ResolvedTarget{
		NodeID:        targetNodeID,
		MatchedNodeID: "",
		BaseNodeID:    canonicalInfo.BaseNodeID,
		Host:          canonicalInfo.Address,
		Port:          effectivePort,
		User:          effectiveUser,
		ProxyJump:     jump,
		KeyPath:       keyPath,
		OpenSSHAlias:  openSSHAlias,
		Created:       true,
	}, nil
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
		return r.ensureTargetInTransaction(cfg, opts, explicitDefaultUser, &finalNodeID, &createdNode)
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

func (r *Repository) ensureTargetInTransaction(
	cfg *Configuration,
	opts EnsureNodeOptions,
	explicitDefaultUser string,
	finalNodeID *string,
	createdNode *bool,
) error {
	lookup, aliases, err := buildIndexes(cfg, false)
	if err != nil {
		return fmt.Errorf("build configuration indexes failed: %w", err)
	}
	decision, err := r.evaluateTargetDecision(cfg, lookup, aliases, opts.Target, explicitDefaultUser)
	if err != nil {
		return err
	}
	if !decision.NeedsCreation {
		if decision.OpenSSHAlias != "" {
			r.SetNodeOpenSSHAlias(decision.MatchedNodeID, decision.OpenSSHAlias)
		}
		*finalNodeID = decision.MatchedNodeID
		*createdNode = false
		return nil
	}
	txOpts := opts
	txOpts.Target = decision.NormalizedTarget
	return r.createNodeInTransaction(cfg, txOpts, decision.Canonical, decision.EffectiveUser, decision.EffectivePort, finalNodeID, createdNode)
}

func narrowMatchingNodesBySelector(matches []string, aliases map[string]string, selectors ...string) []string {
	if len(matches) <= 1 {
		return matches
	}
	for _, selector := range selectors {
		if selector == "" {
			continue
		}
		if slices.Contains(matches, selector) {
			return []string{selector}
		}
		if nid, ok := aliases[selector]; ok && nid != "" && slices.Contains(matches, nid) {
			return []string{nid}
		}
	}
	return matches
}

func (r *Repository) openSSHParserOrEmpty() *OpenSSHParser {
	if r != nil && r.provider != nil && r.provider.openSSH != nil {
		return r.provider.openSSH
	}
	return &OpenSSHParser{cfg: nil}
}

func resolveOpenSSHAliasName(parser *OpenSSHParser, spec string) string {
	if parser == nil || parser.cfg == nil {
		return ""
	}
	clean := strings.TrimSpace(strings.TrimPrefix(spec, OpenSSHNodePrefix))
	if clean == "" {
		return ""
	}
	lookupHost, _, _, err := parseOpenSSHHostSpec(clean)
	if err != nil || lookupHost == "" {
		return ""
	}
	if parser.HasHost(lookupHost) {
		return lookupHost
	}
	return ""
}

func (r *Repository) matchBareOpenSSHSelector(selector string) (string, string, bool) {
	if strings.HasPrefix(selector, OpenSSHNodePrefix) {
		clean := strings.TrimSpace(strings.TrimPrefix(selector, OpenSSHNodePrefix))
		if clean == "" {
			return "", "", false
		}
		parser := r.openSSHParserOrEmpty()
		if _, _, _, err := parser.GetVirtualNode(clean); err != nil {
			return "", "", false
		}
		return OpenSSHNodePrefix + clean, resolveOpenSSHAliasName(parser, clean), true
	}
	if r != nil && r.provider != nil && r.provider.openSSH != nil && r.provider.openSSH.cfg != nil {
		if nid, ok := r.provider.openSSH.Find(selector); ok {
			return nid, resolveOpenSSHAliasName(r.provider.openSSH, nid), true
		}
	}
	return "", "", false
}

func (r *Repository) matchOpenSSHVirtualNode(selector, effectiveUser string, effectivePort uint16) (string, string) {
	if strings.HasPrefix(selector, OpenSSHNodePrefix) {
		clean := strings.TrimSpace(strings.TrimPrefix(selector, OpenSSHNodePrefix))
		if clean == "" {
			return "", ""
		}
		parser := r.openSSHParserOrEmpty()
		_, vhost, vident, err := parser.GetVirtualNode(clean)
		if err != nil {
			return "", ""
		}
		vport := vhost.Port
		if vport == 0 {
			vport = 22
		}
		if vident.User == effectiveUser && vport == effectivePort {
			return OpenSSHNodePrefix + clean, resolveOpenSSHAliasName(parser, clean)
		}
		return "", ""
	}
	if r == nil || r.provider == nil || r.provider.openSSH == nil || r.provider.openSSH.cfg == nil {
		return "", ""
	}
	if selector == "" || strings.Contains(selector, "@") || strings.Contains(selector, ":") {
		return "", ""
	}
	if !r.provider.openSSH.HasHost(selector) {
		return "", ""
	}
	_, vhost, vident, err := r.provider.openSSH.GetVirtualNode(selector)
	if err != nil {
		return "", ""
	}
	vport := vhost.Port
	if vport == 0 {
		vport = 22
	}
	if vident.User == effectiveUser && vport == effectivePort {
		return OpenSSHNodePrefix + selector, selector
	}
	return "", ""
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
	snapshot := r.provider.Snapshot()
	lookup, aliases, err := buildIndexes(snapshot, false)
	if err != nil {
		return "", false, err
	}
	decision, err := r.evaluateTargetDecision(snapshot, lookup, aliases, target, explicitDefaultUser)
	if err != nil {
		return "", true, err
	}
	if !decision.NeedsCreation {
		if decision.OpenSSHAlias != "" {
			r.SetNodeOpenSSHAlias(decision.MatchedNodeID, decision.OpenSSHAlias)
		}
		return decision.MatchedNodeID, false, nil
	}
	return "", false, nil
}

func normalizedHostPort(port uint16) uint16 {
	if port == 0 {
		return 22
	}
	return port
}

func normalizedIdentityUser(rawUser string) string {
	if u := strings.TrimSpace(rawUser); u != "" {
		return u
	}
	fallbackUser, _ := resolveEffectiveUser(ConnectionTarget{}, "", "")
	return fallbackUser
}

func findMatchingNodes(snapshot *Configuration, user, addr string, port uint16) []string {
	var matches []string
	targetPort := normalizedHostPort(port)
	for _, nid := range snapshot.Nodes.Keys() {
		n, ok := snapshot.Nodes.Get(nid)
		if !ok {
			continue
		}
		h, hok := snapshot.Hosts.Get(n.HostRef)
		ident, iok := snapshot.Identities.Get(n.IdentityRef)
		if hok && iok {
			cleanHostAddr := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(h.Address), "]"), "[")
			nodeUser := normalizedIdentityUser(ident.User)
			if cleanHostAddr == addr && normalizedHostPort(h.Port) == targetPort && nodeUser == user {
				matches = append(matches, nid)
			}
		}
	}
	slices.Sort(matches)
	return matches
}

// resolveCanonicalTargetInfo extracts canonical address, port, identity and proxy details.
//
//nolint:gocyclo // canonical target resolution sequentially evaluates direct, alias, lookup, OpenSSH, and raw fallback tiers
func (r *Repository) resolveCanonicalTargetInfo(cfg *Configuration, lookup map[string][]string, aliases map[string]string, selector string, target ConnectionTarget) (canonicalTargetInfo, error) {
	// 1 & 2. Direct Node ID or Alias match (checking RawSelector first when split from user@host:port)
	if info, ok := r.resolveDirectOrAliasTargetInfo(cfg, aliases, strings.TrimSpace(target.RawSelector), selector); ok {
		return info, nil
	}

	// 3. Lookup match
	if candidates := lookup[selector]; len(candidates) > 0 {
		return r.resolveLookupCandidates(cfg, selector, candidates, target)
	}
	if raw := strings.TrimSpace(target.RawSelector); raw != "" && raw != selector {
		if candidates := lookup[raw]; len(candidates) > 0 {
			return r.resolveLookupCandidates(cfg, raw, candidates, target)
		}
	}
	if strings.TrimSpace(target.RawSelector) == "" && target.HasUser && target.HasPort && strings.TrimSpace(target.User) != "" && target.Port > 0 {
		composite := FormatNodeID(strings.TrimSpace(target.User), selector, target.Port)
		if info, ok := r.resolveDirectOrAliasTargetInfo(cfg, aliases, composite); ok {
			return info, nil
		}
	}

	// 4. OpenSSH configuration match
	if r != nil && r.provider != nil && r.provider.openSSH != nil && r.provider.openSSH.cfg != nil {
		clean := strings.TrimSpace(strings.TrimPrefix(selector, OpenSSHNodePrefix))
		allowSpec := strings.HasPrefix(selector, OpenSSHNodePrefix) || (!strings.Contains(clean, "@") && !strings.Contains(clean, ":"))
		if clean != "" && allowSpec && r.provider.openSSH.HasHost(clean) {
			vnode, vhost, vident, err := r.provider.openSSH.GetVirtualNode(clean)
			if err != nil {
				return canonicalTargetInfo{}, fmt.Errorf("resolve openssh host %q: %w", clean, err)
			}
			return canonicalTargetInfo{
				BaseNodeID:   OpenSSHNodePrefix + clean,
				Address:      strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(vhost.Address), "]"), "["),
				Port:         vhost.Port,
				IdentityFile: vident.KeyPath,
				ProxyJump:    vnode.ProxyJump,
				DefaultUser:  vident.User,
				OpenSSHAlias: resolveOpenSSHAliasName(r.provider.openSSH, clean),
			}, nil
		}
	}

	// 5. Raw address/hostname fallback (including openssh: virtual selectors or
	// unconfirmed user@host:port node IDs passed across process boundaries).
	clean := strings.TrimPrefix(strings.TrimSpace(selector), OpenSSHNodePrefix)
	if parsedHost, parsedUser, parsedPort, err := parseOpenSSHHostSpec(clean); err == nil && parsedHost != "" {
		port := parsedPort
		if port == 0 {
			port = 22
		}
		return canonicalTargetInfo{
			Address:     strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(parsedHost), "]"), "["),
			Port:        port,
			DefaultUser: parsedUser,
		}, nil
	}
	clean = strings.TrimPrefix(strings.TrimSuffix(clean, "]"), "[")
	return canonicalTargetInfo{Address: clean, Port: 22}, nil
}

func (r *Repository) resolveDirectOrAliasTargetInfo(cfg *Configuration, aliases map[string]string, keys ...string) (canonicalTargetInfo, bool) {
	for _, key := range keys {
		if key == "" {
			continue
		}
		if info, ok := r.resolveCandidateNodeInfo(cfg, key); ok {
			return info, true
		}
		if nid, exists := aliases[key]; exists && nid != "" {
			if info, ok := r.resolveCandidateNodeInfo(cfg, nid); ok {
				return info, true
			}
		}
	}
	return canonicalTargetInfo{}, false
}

func (r *Repository) effectiveNodeOpenSSHAlias(nodeID string, node models.Node) string {
	if node.OpenSSHAlias != "" {
		return node.OpenSSHAlias
	}
	return r.NodeOpenSSHAlias(nodeID)
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
			user = normalizedIdentityUser(ident.User)
		}
		if target.HasPort && normalizedHostPort(host.Port) != normalizedHostPort(target.Port) {
			continue
		}
		if target.HasUser && user != target.User {
			continue
		}
		filtered = append(filtered, cid)
	}
	return filtered
}

func (r *Repository) resolveCandidateNodeInfo(cfg *Configuration, candidateID string) (canonicalTargetInfo, bool) {
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
	var keyPath string
	if ident, identExists := cfg.Identities.Get(node.IdentityRef); identExists {
		defUser = normalizedIdentityUser(ident.User)
		keyPath = ident.KeyPath
	}
	return canonicalTargetInfo{
		BaseNodeID:   candidateID,
		Address:      clean,
		Port:         normalizedHostPort(host.Port),
		IdentityFile: keyPath,
		DefaultUser:  defUser,
		OpenSSHAlias: r.effectiveNodeOpenSSHAlias(candidateID, node),
	}, true
}

func (r *Repository) consistentCandidateOpenSSHAlias(cfg *Configuration, candidates []string) string {
	var alias string
	for _, cid := range candidates {
		node, ok := cfg.Nodes.Get(cid)
		if !ok {
			continue
		}
		nodeAlias := r.effectiveNodeOpenSSHAlias(cid, node)
		if nodeAlias == "" {
			continue
		}
		if alias == "" {
			alias = nodeAlias
		} else if alias != nodeAlias {
			return ""
		}
	}
	return alias
}

func (r *Repository) resolveConsistentCandidates(cfg *Configuration, selector string, candidates []string) (canonicalTargetInfo, error) {
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
			user = normalizedIdentityUser(ident.User)
		}
		clean := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(host.Address), "]"), "[")
		port := normalizedHostPort(host.Port)
		if !initialized {
			firstAddr = clean
			firstPort = port
			firstUser = user
			initialized = true
		} else {
			if firstAddr != clean || firstPort != port {
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
			OpenSSHAlias:         r.consistentCandidateOpenSSHAlias(cfg, candidates),
			AmbiguousDefaultUser: !userConsistent,
			AmbiguousCandidates:  slices.Clone(candidates),
		}, nil
	}
	return canonicalTargetInfo{}, &AmbiguousNodeError{Selector: selector, Candidates: slices.Clone(candidates)}
}

func (r *Repository) resolveCandidateAddressFallback(cfg *Configuration, selector string, candidates []string, target ConnectionTarget) (canonicalTargetInfo, error) {
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
			user = normalizedIdentityUser(ident.User)
		}
		clean := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(host.Address), "]"), "[")
		port := normalizedHostPort(host.Port)
		if !initialized {
			firstAddr = clean
			firstPort = port
			firstUser = user
			initialized = true
		} else {
			if firstAddr != clean {
				addrConsistent = false
				break
			}
			if firstPort != port {
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
		OpenSSHAlias:         r.consistentCandidateOpenSSHAlias(cfg, candidates),
		AmbiguousDefaultUser: !target.HasUser && !userConsistent,
		AmbiguousCandidates:  slices.Clone(candidates),
	}, nil
}

func (r *Repository) resolveLookupCandidates(cfg *Configuration, selector string, candidates []string, target ConnectionTarget) (canonicalTargetInfo, error) {
	filtered := filterCandidatesByExplicitTarget(cfg, candidates, target)
	if len(filtered) == 1 {
		if info, ok := r.resolveCandidateNodeInfo(cfg, filtered[0]); ok {
			return info, nil
		}
	}
	if len(filtered) > 1 {
		return r.resolveConsistentCandidates(cfg, selector, filtered)
	}
	return r.resolveCandidateAddressFallback(cfg, selector, candidates, target)
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
		if canonicalInfo.OpenSSHAlias != "" {
			r.SetNodeOpenSSHAlias(targetNodeID, canonicalInfo.OpenSSHAlias)
		}
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
		HostRef:      hostRef,
		IdentityRef:  identityRef,
		ProxyJump:    finalJump,
		SudoMode:     sudoMode,
		SuPwd:        opts.SuPwd,
		OpenSSHAlias: canonicalInfo.OpenSSHAlias,
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
	if canonicalInfo.OpenSSHAlias != "" {
		r.SetNodeOpenSSHAlias(targetNodeID, canonicalInfo.OpenSSHAlias)
	}
	*finalNodeID = targetNodeID
	*createdNode = true
	return nil
}

func ensureMatchingHost(cfg *Configuration, canonicalAddr string, port uint16, targetNodeID string) (string, error) {
	var matchingHostRefs []string
	var unaliasedHostRef string
	targetPort := normalizedHostPort(port)
	for _, href := range cfg.Hosts.Keys() {
		h, ok := cfg.Hosts.Get(href)
		if !ok {
			continue
		}
		clean := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(h.Address), "]"), "[")
		if clean == canonicalAddr && normalizedHostPort(h.Port) == targetPort {
			matchingHostRefs = append(matchingHostRefs, href)
			if len(h.Alias) == 0 && unaliasedHostRef == "" {
				unaliasedHostRef = href
			}
		}
	}

	createHost := func() string {
		candidateRef := FormatHostPort(canonicalAddr, targetPort)
		hostRef := candidateRef
		if existing, exists := cfg.Hosts.Get(candidateRef); exists {
			clean := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(existing.Address), "]"), "[")
			if clean != canonicalAddr || normalizedHostPort(existing.Port) != targetPort || len(existing.Alias) > 0 {
				hostRef = privateHostReference(cfg, targetNodeID)
			}
		}
		cfg.Hosts.Set(hostRef, models.Host{
			Address: canonicalAddr,
			Port:    targetPort,
		})
		return hostRef
	}

	switch len(matchingHostRefs) {
	case 0:
		return createHost(), nil
	case 1:
		if existing, ok := cfg.Hosts.Get(matchingHostRefs[0]); ok && len(existing.Alias) > 0 {
			if countNodeReferences(cfg, func(candidate models.Node) bool {
				return candidate.HostRef == matchingHostRefs[0] && candidate.HostRef != ""
			}) > 0 {
				return createHost(), nil
			}
		}
		return matchingHostRefs[0], nil
	default:
		if unaliasedHostRef != "" {
			return unaliasedHostRef, nil
		}
		return "", fmt.Errorf("ambiguous host configuration: multiple host references found for %s: %v",
			FormatHostPort(canonicalAddr, targetPort), matchingHostRefs)
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

	targetPort := normalizedHostPort(port)
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
		if clean == canonicalAddr && normalizedHostPort(h.Port) == targetPort {
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
			FormatHostPort(canonicalAddr, targetPort))
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
	if trimmed == "" || strings.EqualFold(trimmed, "none") {
		return "", nil
	}
	rawHops := strings.Split(trimmed, ",")
	resolvedHops := make([]string, 0, len(rawHops))
	for _, rawHop := range rawHops {
		hop := strings.TrimSpace(rawHop)
		if hop == "" || strings.EqualFold(hop, "none") {
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
		if hopPort != 0 && normalizedHostPort(h.Port) != normalizedHostPort(hopPort) {
			continue
		}
		if hopUser != "" && normalizedIdentityUser(ident.User) != hopUser {
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
		port := normalizedHostPort(h.Port)
		if firstPort == 0 {
			firstPort = port
		} else if firstPort != port {
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
			if cleanHostAddr == firstAddr && normalizedHostPort(h.Port) == normalizedHostPort(effectivePort) {
				if hopUser == "" || normalizedIdentityUser(ident.User) == hopUser {
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
