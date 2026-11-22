package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/verdict"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/models"
	fileutils "github.com/wentf9/xops-cli/pkg/utils/file"
)

// ConnectionTarget represents the user's connection intent, preserving whether
// user, port, and jump host were explicitly specified.
type ConnectionTarget struct {
	Selector     string
	RawSelector  string
	OriginalHost string
	User         string
	HasUser      bool
	Port         uint16
	HasPort      bool
	ProxyJump    string
	HasProxyJump bool
}

// PendingNodeUpdate describes optional CLI mutations to stage against an
// existing saved node during WithPendingNode. Staged updates are validated
// against the full configuration graph before dialing, are visible through
// Resolve and ResolveConnection for the scoped session, and are persisted to
// disk only when PendingLease.Confirm succeeds.
type PendingNodeUpdate struct {
	Enabled      bool
	JumpHost     string
	Alias        string
	Tags         []string
	SudoMode     models.SudoMode
	RememberAuth bool
	HasPassword  bool
	IdentityFile string
}

// EnsureNodeOptions carries connection intent and optional creation or staged
// saved-node update attributes.
type EnsureNodeOptions struct {
	Target         ConnectionTarget
	DefaultUser    string
	Password       string
	IdentityFile   string
	Passphrase     string
	Alias          string
	Tags           []string
	SudoMode       models.SudoMode
	SuPwd          string
	ExistingUpdate PendingNodeUpdate
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
	BaseNodeID    string
	Host          string
	Port          uint16
	User          string
	ProxyJump     string
	KeyPath       string
	OpenSSHAlias  string
	CanonicalHost string
	Provenance    NodeProvenance
	Created       bool
}

type canonicalTargetInfo struct {
	BaseNodeID           string
	Address              string
	Port                 uint16
	IdentityFile         string
	ProxyJump            string
	DefaultUser          string
	OpenSSHAlias         string
	CanonicalHost        string
	AmbiguousDefaultUser bool
	AmbiguousCandidates  []string
}

// FormatHostPort formats host and port, enclosing IPv6 addresses in brackets.
func FormatHostPort(address string, port uint16) string {
	cleaned := StripHostBrackets(address)
	return net.JoinHostPort(cleaned, strconv.Itoa(int(port)))
}

// FormatNodeID formats node ID using user@host:port (with IPv6 bracketed if necessary).
func FormatNodeID(user, address string, port uint16) string {
	return fmt.Sprintf("%s@%s", user, FormatHostPort(address, port))
}

// ValidatePersistableIdentityPath verifies that raw is a concrete identity key
// path suitable for persisting into Identity.KeyPath (excluding "none", OpenSSH
// % tokens, ${ENV} placeholders, invalid control/token syntax, and unresolved
// ~user prefixes).
func ValidatePersistableIdentityPath(raw string) error {
	setting, err := ssh.ParseIdentityPathSetting(raw, true)
	if err != nil {
		return err
	}
	if !setting.Persistable() {
		return fmt.Errorf("identity path %q is not persistable", raw)
	}
	expanded := fileutils.ToAbsolutePath(setting.Raw)
	if expanded == "" || strings.HasPrefix(expanded, "~") {
		return fmt.Errorf("identity path %q cannot be resolved to an absolute local path", raw)
	}
	return nil
}

// NormalizePersistableIdentityPath converts a persistable identity key path into an
// absolute path, returning "" for non-persistable syntaxes ("none", %tokens, ${ENV},
// or unresolved ~user).
func NormalizePersistableIdentityPath(raw string) string {
	if err := ValidatePersistableIdentityPath(raw); err != nil {
		return ""
	}
	return fileutils.ToAbsolutePath(strings.TrimSpace(raw))
}

// ValidateNodeID ensures a persisted node identifier is non-empty, free of
// control or line-separator characters, and does not collide with the reserved
// "openssh" virtual namespace (case-insensitive).
func ValidateNodeID(nodeID string) error {
	if hasControlOrLineSepChar(nodeID) {
		return fmt.Errorf("invalid node ID %q: contains invalid control character", nodeID)
	}
	trimmed := strings.TrimSpace(nodeID)
	if trimmed == "" {
		return fmt.Errorf("node ID cannot be empty")
	}
	if strings.EqualFold(trimmed, "openssh") || hasOpenSSHPrefix(trimmed) {
		return fmt.Errorf("node ID %q is reserved for OpenSSH virtual targets", trimmed)
	}
	return nil
}

// ValidateNodeAlias enforces the single strict node/host alias rule across CLI,
// TUI, and configuration persistence: rejects control/line-separator characters,
// whitespace-only values, '@' and ':' delimiters, the reserved "openssh" virtual
// namespace (case-insensitive), and values that cannot round-trip as a TargetRef.
func ValidateNodeAlias(alias string) error {
	if alias == "" {
		return nil
	}
	if hasControlOrLineSepChar(alias) {
		return fmt.Errorf("invalid alias %q: contains invalid control character", alias)
	}
	trimmed := strings.TrimSpace(alias)
	if trimmed == "" {
		return fmt.Errorf("invalid alias %q: cannot be whitespace-only", alias)
	}
	if strings.ContainsAny(trimmed, "@:") {
		return fmt.Errorf("invalid alias %q: cannot contain '@' or ':'", trimmed)
	}
	if strings.EqualFold(trimmed, "openssh") || hasOpenSSHPrefix(trimmed) {
		return fmt.Errorf("alias %q is reserved for OpenSSH virtual targets", trimmed)
	}
	ref, err := ParseTargetRef(trimmed)
	if err != nil {
		return fmt.Errorf("invalid alias %q: %w", trimmed, err)
	}
	if ref.OpenSSH {
		return fmt.Errorf("alias %q is reserved for OpenSSH virtual targets", trimmed)
	}
	if err := ref.Validate(); err != nil {
		return fmt.Errorf("invalid alias %q: %w", trimmed, err)
	}
	return nil
}

// ValidateNodeAliases ensures every custom alias in aliases satisfies ValidateNodeAlias.
func ValidateNodeAliases(aliases []string) error {
	for _, alias := range aliases {
		if err := ValidateNodeAlias(alias); err != nil {
			return err
		}
	}
	return nil
}

// ValidateConcreteHostAddress ensures raw is a concrete host address or hostname
// suitable for persisted inventory host records, rejecting empty values, control
// or line-separator characters, internal whitespace, malformed brackets, and
// the reserved "openssh:" virtual namespace prefix (case-insensitive).
func ValidateConcreteHostAddress(raw string) error {
	if hasControlOrLineSepChar(raw) {
		return fmt.Errorf("invalid host address %q: contains invalid control character", raw)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("host address cannot be empty")
	}
	if hasOpenSSHPrefix(trimmed) {
		return fmt.Errorf("invalid host address %q: openssh selector cannot be used as a concrete host address", raw)
	}
	for _, r := range trimmed {
		if unicode.IsSpace(r) {
			return fmt.Errorf("invalid host address %q: contains whitespace", raw)
		}
	}
	if strings.ContainsAny(trimmed, "[]") && StripHostBrackets(trimmed) == trimmed {
		return fmt.Errorf("invalid host address %q: malformed brackets", raw)
	}
	return nil
}

type openSSHParserSource interface {
	GetOpenSSHParser() *OpenSSHParser
}

// HasOpenSSHConfig reports whether provider has an active loaded OpenSSH config
// (false when provider is nil, -F none was specified, or ~/.ssh/config is absent).
func HasOpenSSHConfig(provider ConfigProvider) bool {
	if provider == nil {
		return false
	}
	r, _ := resolveTargetHelper(provider)
	return r != nil && r.provider != nil && r.provider.openSSH != nil && r.provider.openSSH.cfg != nil
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
	if ov, ok := provider.(*openSSHOverrideProvider); ok && ov != nil && ov.repo != nil {
		return ov.repo, ov.repo.Snapshot()
	}
	if fr, ok := provider.(*frozenRepository); ok && fr != nil {
		return resolveTargetHelper(fr.ConfigProvider)
	}
	var (
		snap    *Configuration
		origins map[string]OpenSSHOrigin
	)
	if src, ok := provider.(interface {
		snapshotWithOrigins() (*Configuration, map[string]OpenSSHOrigin)
	}); ok {
		snap, origins = src.snapshotWithOrigins()
	} else {
		snap = provider.Snapshot()
	}
	var parser *OpenSSHParser
	if src, ok := provider.(openSSHParserSource); ok {
		parser = src.GetOpenSSHParser()
	}
	if parser == nil {
		parser = &OpenSSHParser{cfg: nil}
	}
	p := newProvider(snap, parser)
	populateProviderOriginsFromBase(p, snap, provider, origins)
	return &Repository{provider: p}, snap
}

func populateProviderOriginsFromBase(p *Provider, snap *Configuration, provider ConfigProvider, origins map[string]OpenSSHOrigin) {
	if p == nil || snap == nil || snap.Nodes == nil {
		return
	}
	if origins != nil {
		for nodeID, origin := range origins {
			if _, exists := snap.Nodes.Get(nodeID); exists && !origin.IsZero() {
				p.SetNodeOpenSSHOrigin(nodeID, origin)
			}
		}
		return
	}
	if origSrc, ok := provider.(interface{ NodeOpenSSHOrigin(string) OpenSSHOrigin }); ok {
		for _, nodeID := range snap.Nodes.Keys() {
			if origin := origSrc.NodeOpenSSHOrigin(nodeID); !origin.IsZero() {
				p.SetNodeOpenSSHOrigin(nodeID, origin)
			}
		}
		return
	}
	for _, nodeID := range snap.Nodes.Keys() {
		if n, ok := provider.GetNode(nodeID); ok && (n.OpenSSHAlias != "" || n.CanonicalHost != "") {
			p.SetNodeOpenSSHOrigin(nodeID, OpenSSHOrigin{Alias: n.OpenSSHAlias, CanonicalHost: n.CanonicalHost})
		}
	}
}

func normalizeOriginalHost(raw string) string {
	orig := strings.TrimSpace(UnwrapOpenSSHSelector(raw))
	if orig == "" {
		return ""
	}
	if parsedHost, _, _, err := parseOpenSSHHostSpec(orig); err == nil && parsedHost != "" {
		orig = parsedHost
	}
	return StripHostBrackets(orig)
}

func canonicalOriginalAlias(parser *OpenSSHParser, rawOrig, lookupHost string) string {
	orig := normalizeOriginalHost(rawOrig)
	cleanLookup := StripHostBrackets(lookupHost)
	if orig != "" && !strings.EqualFold(orig, cleanLookup) {
		return orig
	}
	return resolveOpenSSHAliasName(parser, lookupHost)
}

func backfillCanonicalTargetMetadata(target ConnectionTarget, candidateHost string, openSSHAlias, canonicalHost *string) {
	canon := canonicalTargetHost(target, candidateHost)
	if canonicalHost != nil && *canonicalHost == "" && canon != "" {
		*canonicalHost = canon
	}
	if openSSHAlias != nil && *openSSHAlias == "" && canon != "" {
		if orig := normalizeOriginalHost(target.OriginalHost); orig != "" {
			*openSSHAlias = orig
		}
	}
}

func resolveVirtualNodeForTarget(parser *OpenSSHParser, lookupHost string, target ConnectionTarget) (models.Node, models.Host, models.Identity, error) {
	if parser == nil {
		parser = &OpenSSHParser{}
	}
	cleanHost, inlineUser, inlinePort, err := parseOpenSSHHostSpec(lookupHost)
	if err != nil {
		cleanHost = lookupHost
	}
	if orig := normalizeOriginalHost(target.OriginalHost); orig != "" && !strings.EqualFold(orig, cleanHost) {
		return parser.getVirtualNodeWithCanonical(orig, cleanHost, inlineUser, inlinePort, lookupHost)
	}
	return parser.GetVirtualNode(lookupHost)
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
	cleanHost := StripHostBrackets(parsedHost)
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
	if selector == "" || hasOpenSSHPrefix(selector) {
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
	return len(lookupBySelector(lookup, selector)) > 0
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
	CanonicalHost    string
	Canonical        canonicalTargetInfo
	EffectiveUser    string
	EffectivePort    uint16
	NeedsCreation    bool
}

// ResolveTarget resolves a ConnectionTarget against a read-only ConfigProvider
// using the exact same resolution rules as WithPendingNode / EnsureNodeContext,
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
		return r.buildMatchedResolvedTarget(provider, decision.MatchedNodeID, decision.BaseNodeID, decision.OpenSSHAlias, decision.CanonicalHost, decision.NormalizedTarget)
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
		matches := narrowMatchingNodesBySelector(
			findMatchingNodes(cfg, decision.EffectiveUser, decision.Canonical.Address, decision.EffectivePort),
			aliases,
			decision.Selector,
			strings.TrimSpace(decision.NormalizedTarget.RawSelector),
		)
		switch len(matches) {
		case 1:
			matchedID := matches[0]
			node, _ := cfg.Nodes.Get(matchedID)
			if decision.BaseNodeID == "" {
				decision.BaseNodeID = matchedID
			}
			decision.OpenSSHAlias, decision.CanonicalHost = r.resolveSavedNodeDecisionMetadata(
				matchedID, node, decision.NormalizedTarget, decision.Selector, decision.OpenSSHAlias, decision.CanonicalHost,
			)
			decision.MatchedNodeID = matchedID
			decision.NeedsCreation = false
		case 0:
			// Keep NeedsCreation = true when no saved node matches the semantic
			// endpoint even if FormatNodeID(...) is held by an unrelated node.
		default:
			return targetDecision{}, &AmbiguousNodeError{Selector: decision.Selector, Candidates: matches}
		}
	}
	return decision, nil
}

func validateExplicitOpenSSHTargetSelector(selector string, target ConnectionTarget) (clean, lookupHost, inlineUser string, inlinePort uint16, err error) {
	rawSelector := target.Selector
	if rawSelector == "" {
		rawSelector = selector
	}
	if !hasOpenSSHPrefix(rawSelector) || hasControlOrLineSepChar(rawSelector) || hasAnyWhitespace(rawSelector) {
		return "", "", "", 0, fmt.Errorf("parse openssh host %q failed: invalid openssh selector", rawSelector)
	}
	return parseExplicitOpenSSHSelector(rawSelector)
}

func (r *Repository) resolveExplicitOpenSSHVirtualTarget(
	selector string,
	target ConnectionTarget,
	explicitDefaultUser string,
) (targetDecision, bool, error) {
	if _, ok := cutOpenSSHPrefix(selector); !ok {
		return targetDecision{}, false, nil
	}
	clean, lookupHost, inlineUser, inlinePort, err := validateExplicitOpenSSHTargetSelector(selector, target)
	if err != nil {
		return targetDecision{}, true, err
	}
	parser := r.openSSHParserOrEmpty()
	vnode, vhost, vident, err := resolveVirtualNodeForTarget(parser, lookupHost, target)
	if err != nil {
		return targetDecision{}, true, fmt.Errorf("resolve openssh host %q: %w", clean, err)
	}
	basePort := normalizedHostPort(vhost.Port)
	baseUser := strings.TrimSpace(vident.User)

	effectiveUser := inlineUser
	if target.HasUser && strings.TrimSpace(target.User) != "" {
		effectiveUser = strings.TrimSpace(target.User)
	}
	if effectiveUser == "" {
		effectiveUser, err = resolveEffectiveUser(target, explicitDefaultUser, baseUser)
		if err != nil {
			return targetDecision{}, true, err
		}
	}

	effectivePort := basePort
	if inlinePort != 0 {
		effectivePort = inlinePort
	}
	if target.HasPort && target.Port != 0 {
		effectivePort = target.Port
	}

	matchedID := OpenSSHNodePrefix + FormatNodeID(effectiveUser, lookupHost, effectivePort)
	if !target.HasUser && !target.HasPort {
		matchedID = OpenSSHNodePrefix + clean
	} else if inlineUser == "" && inlinePort == 0 && effectiveUser == baseUser && effectivePort == basePort {
		matchedID = OpenSSHNodePrefix + lookupHost
	}

	openSSHAlias := canonicalOriginalAlias(parser, target.OriginalHost, lookupHost)
	canonicalHost := canonicalTargetHost(target, lookupHost)
	canonicalInfo := canonicalTargetInfo{
		BaseNodeID:    OpenSSHNodePrefix + lookupHost,
		Address:       StripHostBrackets(vhost.Address),
		Port:          basePort,
		IdentityFile:  vident.KeyPath,
		ProxyJump:     vnode.ProxyJump,
		DefaultUser:   baseUser,
		OpenSSHAlias:  openSSHAlias,
		CanonicalHost: canonicalHost,
	}
	return targetDecision{
		NormalizedTarget: target,
		Selector:         selector,
		MatchedNodeID:    matchedID,
		BaseNodeID:       canonicalInfo.BaseNodeID,
		OpenSSHAlias:     canonicalInfo.OpenSSHAlias,
		CanonicalHost:    canonicalInfo.CanonicalHost,
		Canonical:        canonicalInfo,
		EffectiveUser:    effectiveUser,
		EffectivePort:    effectivePort,
	}, true, nil
}

func (r *Repository) resolveSavedNodeDecisionMetadata(
	matchedID string,
	node models.Node,
	target ConnectionTarget,
	selector, openSSHAlias, canonHost string,
) (string, string) {
	backfillCanonicalTargetMetadata(target, selector, &openSSHAlias, &canonHost)
	if openSSHAlias == "" && canonHost == "" {
		openSSHAlias, canonHost = r.effectiveNodeMetadata(matchedID, node)
	}
	return openSSHAlias, canonHost
}

func (r *Repository) savedNodeDecision(
	cfg *Configuration,
	target ConnectionTarget,
	selector, matchedID, baseID, openSSHAlias, canonHost string,
) targetDecision {
	node, _ := cfg.Nodes.Get(matchedID)
	openSSHAlias, canonHost = r.resolveSavedNodeDecisionMetadata(matchedID, node, target, selector, openSSHAlias, canonHost)
	if baseID == "" {
		baseID = matchedID
	}
	return targetDecision{
		NormalizedTarget: target,
		Selector:         selector,
		MatchedNodeID:    matchedID,
		BaseNodeID:       baseID,
		OpenSSHAlias:     openSSHAlias,
		CanonicalHost:    canonHost,
	}
}

func (r *Repository) evaluateBareTargetDecision(
	cfg *Configuration,
	lookup map[string][]string,
	aliases map[string]string,
	selector string,
	target ConnectionTarget,
	explicitDefaultUser string,
) (targetDecision, error) {
	if decision, handled, err := r.resolveExplicitOpenSSHVirtualTarget(selector, target, explicitDefaultUser); handled {
		return decision, err
	}
	if _, exists := cfg.Nodes.Get(selector); exists {
		return r.savedNodeDecision(cfg, target, selector, selector, selector, "", ""), nil
	}
	if nid, ok := aliases[selector]; ok && nid != "" {
		return r.savedNodeDecision(cfg, target, selector, nid, nid, "", ""), nil
	}
	candidates := lookupBySelector(lookup, selector)
	switch len(candidates) {
	case 1:
		return r.savedNodeDecision(cfg, target, selector, candidates[0], candidates[0], "", ""), nil
	case 0:
		nid, alias, vErr := r.matchBareOpenSSHSelector(selector, target)
		if vErr != nil {
			return targetDecision{}, vErr
		}
		if nid != "" {
			canonHost := canonicalTargetHost(target, selector)
			backfillCanonicalTargetMetadata(target, selector, &alias, &canonHost)
			return targetDecision{
				NormalizedTarget: target,
				Selector:         selector,
				MatchedNodeID:    nid,
				BaseNodeID:       nid,
				OpenSSHAlias:     alias,
				CanonicalHost:    canonHost,
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
			CanonicalHost:    canonicalInfo.CanonicalHost,
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
	if decision, handled, err := r.resolveExplicitOpenSSHVirtualTarget(selector, target, explicitDefaultUser); handled {
		return decision, err
	}
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
		decision := r.savedNodeDecision(cfg, target, selector, matches[0], baseID, canonicalInfo.OpenSSHAlias, canonicalInfo.CanonicalHost)
		decision.Canonical = canonicalInfo
		decision.EffectiveUser = effectiveUser
		decision.EffectivePort = effectivePort
		return decision, nil
	case 0:
		if canonicalInfo.BaseNodeID == "" || IsOpenSSHNodeID(canonicalInfo.BaseNodeID) {
			nid, alias, vErr := r.matchOpenSSHVirtualNode(selector, effectiveUser, effectivePort, canonicalInfo.Address, target)
			if vErr != nil {
				return targetDecision{}, vErr
			}
			if nid != "" {
				canonHost := canonicalTargetHost(target, selector)
				backfillCanonicalTargetMetadata(target, selector, &alias, &canonHost)
				return targetDecision{
					NormalizedTarget: target,
					Selector:         selector,
					MatchedNodeID:    nid,
					BaseNodeID:       nid,
					OpenSSHAlias:     alias,
					CanonicalHost:    canonHost,
					Canonical:        canonicalInfo,
					EffectiveUser:    effectiveUser,
					EffectivePort:    effectivePort,
				}, nil
			}
		}
		return targetDecision{
			NormalizedTarget: target,
			Selector:         selector,
			BaseNodeID:       canonicalInfo.BaseNodeID,
			OpenSSHAlias:     canonicalInfo.OpenSSHAlias,
			CanonicalHost:    canonicalInfo.CanonicalHost,
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
	matchedID, baseID, openSSHAlias, canonicalHost string,
	target ConnectionTarget,
) (ResolvedTarget, error) {
	if IsOpenSSHNodeID(matchedID) {
		return r.buildMatchedOpenSSHResolvedTarget(provider, matchedID, baseID, openSSHAlias, canonicalHost, target)
	}
	node, host, ident, err := provider.Resolve(matchedID)
	if err != nil {
		return ResolvedTarget{}, err
	}
	cleanAddr := StripHostBrackets(host.Address)
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
	jump, err := normalizeTargetJump(provider, node.ProxyJump, target)
	if err != nil {
		return ResolvedTarget{}, err
	}
	alias, canon := r.resolveSavedNodeDecisionMetadata(matchedID, node, target, target.Selector, openSSHAlias, canonicalHost)
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
		CanonicalHost: canon,
		Provenance:    ProvenanceSavedManaged,
		Created:       false,
	}, nil
}

func (r *Repository) buildMatchedOpenSSHResolvedTarget(
	provider ConfigProvider,
	matchedID, baseID, openSSHAlias, canonicalHost string,
	target ConnectionTarget,
) (ResolvedTarget, error) {
	cleanMatched, _ := cutOpenSSHPrefix(matchedID)
	lookupHost, inlineUser, inlinePort, parseErr := parseOpenSSHHostSpec(cleanMatched)
	if parseErr != nil {
		return ResolvedTarget{}, fmt.Errorf("parse openssh host %q failed: %w", cleanMatched, parseErr)
	}
	parser := r.openSSHParserOrEmpty()
	node, host, ident, err := resolveVirtualNodeForTarget(parser, lookupHost, target)
	if err != nil {
		return ResolvedTarget{}, err
	}
	cleanAddr := StripHostBrackets(host.Address)
	port := host.Port
	if target.HasPort && target.Port > 0 {
		port = target.Port
	} else if inlinePort != 0 {
		port = inlinePort
	}
	if port == 0 {
		port = 22
	}
	user := ident.User
	if target.HasUser && strings.TrimSpace(target.User) != "" {
		user = strings.TrimSpace(target.User)
	} else if inlineUser != "" {
		user = inlineUser
	}
	if user == "" {
		if defUser, uErr := resolveEffectiveUser(target, "", ""); uErr == nil {
			user = defUser
		}
	}
	jump, err := normalizeTargetJump(provider, node.ProxyJump, target)
	if err != nil {
		return ResolvedTarget{}, err
	}
	alias := openSSHAlias
	if alias == "" {
		alias = canonicalOriginalAlias(parser, target.OriginalHost, lookupHost)
	}
	backfillCanonicalTargetMetadata(target, lookupHost, &alias, &canonicalHost)
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
		CanonicalHost: canonicalHost,
		Provenance:    ProvenanceOpenSSHVirtual,
		Created:       false,
	}, nil
}

func isProxyJumpHardValidationError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ssh.ErrSSHOptionsValidation) {
		return true
	}
	var cycleErr *ssh.ProxyCycleError
	return errors.As(err, &cycleErr)
}

func parseOptionalNodeProxyJump(raw string) (ssh.ProxySetting, error) {
	if hasControlOrLineSepChar(raw) {
		return ssh.UnsetProxySetting(), fmt.Errorf("invalid node ProxyJump %q: %w", raw, ssh.ErrSSHOptionsValidation)
	}
	if strings.TrimSpace(raw) == "" {
		return ssh.UnsetProxySetting(), nil
	}
	ps, err := ssh.ParseProxyJump(raw)
	if err != nil {
		return ssh.UnsetProxySetting(), fmt.Errorf("invalid node ProxyJump %q: %w", raw, err)
	}
	return ps, nil
}

func normalizeTargetJump(provider ConfigProvider, baseJump string, target ConnectionTarget) (string, error) {
	basePS, err := parseOptionalNodeProxyJump(baseJump)
	if err != nil {
		return "", err
	}
	if target.HasProxyJump || target.ProxyJump != "" {
		ps, pErr := ssh.ParseProxyJump(target.ProxyJump)
		if pErr != nil {
			return "", fmt.Errorf("invalid target ProxyJump %q: %w", target.ProxyJump, pErr)
		}
		if ps.Kind() != ssh.ProxyJump {
			return "", nil
		}
		jump := strings.TrimSpace(target.ProxyJump)
		if provider != nil {
			resolvedJump, jErr := provider.ResolveProxyJumpChain(jump)
			if jErr == nil {
				return resolvedJump, nil
			}
			if isProxyJumpHardValidationError(jErr) {
				return "", jErr
			}
		}
		targets, _ := ps.JumpTargets()
		return strings.Join(targets, ","), nil
	}
	if basePS.Kind() != ssh.ProxyJump {
		return "", nil
	}
	targets, _ := basePS.JumpTargets()
	return strings.Join(targets, ","), nil
}

func (r *Repository) resolveCreatedTargetJump(
	cfg *Configuration,
	canonicalInfo canonicalTargetInfo,
	effectivePort uint16,
	target ConnectionTarget,
) (string, error) {
	jump, err := r.resolveJumpForNode(cfg, EnsureNodeOptions{Target: target}, canonicalInfo, canonicalInfo.Address, effectivePort)
	if err != nil {
		if isProxyJumpHardValidationError(err) {
			return "", err
		}
		if target.HasProxyJump || target.ProxyJump != "" {
			jump = target.ProxyJump
		} else {
			jump = ""
		}
	}
	if target.HasProxyJump || target.ProxyJump != "" {
		if _, pErr := ssh.ParseProxyJump(target.ProxyJump); pErr != nil {
			return "", fmt.Errorf("invalid target ProxyJump %q: %w", target.ProxyJump, pErr)
		}
	}
	if jump == "" {
		return "", nil
	}
	ps, pErr := parseOptionalNodeProxyJump(jump)
	if pErr != nil {
		return "", pErr
	}
	if targets, ok := ps.JumpTargets(); ok {
		return strings.Join(targets, ","), nil
	}
	return "", nil
}

func (r *Repository) applyPendingCreatedTargetMetadata(
	targetNodeID string,
	target ConnectionTarget,
	jump, keyPath, openSSHAlias, canonHost *string,
) error {
	pNode, _, pIdent, ok := r.resolvePendingNode(targetNodeID)
	if !ok {
		return nil
	}
	if !target.HasProxyJump && target.ProxyJump == "" && *jump == "" && pNode.ProxyJump != "" {
		ps, pErr := parseOptionalNodeProxyJump(pNode.ProxyJump)
		if pErr != nil {
			return pErr
		}
		if targets, ok := ps.JumpTargets(); ok {
			*jump = strings.Join(targets, ",")
		}
	}
	if *keyPath == "" && pIdent.KeyPath != "" {
		*keyPath = pIdent.KeyPath
	}
	if *openSSHAlias == "" && *canonHost == "" {
		*openSSHAlias = pNode.OpenSSHAlias
		*canonHost = pNode.CanonicalHost
	}
	return nil
}

func (r *Repository) buildCreatedResolvedTargetWithUserPort(
	provider ConfigProvider,
	cfg *Configuration,
	canonicalInfo canonicalTargetInfo,
	effectiveUser string,
	effectivePort uint16,
	target ConnectionTarget,
) (ResolvedTarget, error) {
	if matches := findMatchingNodes(cfg, effectiveUser, canonicalInfo.Address, effectivePort); len(matches) == 1 {
		matchedID := matches[0]
		baseID := canonicalInfo.BaseNodeID
		if baseID == "" {
			baseID = matchedID
		}
		return r.buildMatchedResolvedTarget(provider, matchedID, baseID, canonicalInfo.OpenSSHAlias, canonicalInfo.CanonicalHost, target)
	} else if len(matches) > 1 {
		return ResolvedTarget{}, &AmbiguousNodeError{Selector: target.Selector, Candidates: matches}
	}
	targetNodeID := allocateAvailableNodeID(cfg, FormatNodeID(effectiveUser, canonicalInfo.Address, effectivePort))
	jump, err := r.resolveCreatedTargetJump(cfg, canonicalInfo, effectivePort, target)
	if err != nil {
		return ResolvedTarget{}, err
	}
	openSSHAlias := canonicalInfo.OpenSSHAlias
	canonHost := canonicalInfo.CanonicalHost
	keyPath := NormalizePersistableIdentityPath(canonicalInfo.IdentityFile)
	if err := r.applyPendingCreatedTargetMetadata(targetNodeID, target, &jump, &keyPath, &openSSHAlias, &canonHost); err != nil {
		return ResolvedTarget{}, err
	}
	prov := ProvenanceAdHocPending
	if openSSHAlias != "" {
		prov = ProvenanceOpenSSHDerived
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
		CanonicalHost: canonHost,
		Provenance:    prov,
		Created:       true,
	}, nil
}

type ensureTransactionOutcome struct {
	nodeID        string
	created       bool
	openSSHAlias  string
	canonicalHost string
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

	// 1. Fast-path check: inspect read-only first, then sync session metadata under pendingMu.
	r.pendingMu.Lock()
	decision, fastErr := r.findExistingNodeDecision(target, explicitDefaultUser)
	if fastErr != nil {
		r.pendingMu.Unlock()
		return EnsureNodeResult{}, fastErr
	}
	if !decision.NeedsCreation && decision.MatchedNodeID != "" {
		r.syncPreparedExistingMetadataLocked(decision)
		r.pendingMu.Unlock()
		return EnsureNodeResult{NodeID: decision.MatchedNodeID, Created: false}, nil
	}
	r.pendingMu.Unlock()

	// 2. Perform atomic ensure in mutation transaction.
	var outcome ensureTransactionOutcome
	action := &publishAction{
		applyProviderLocked: func(p *Provider, updated *Configuration) {
			if p == nil || updated == nil || updated.Nodes == nil {
				return
			}
			if _, exists := updated.Nodes.Get(outcome.nodeID); !exists {
				return
			}
			p.setOpenSSHMetadataLocked(outcome.nodeID, outcome.openSSHAlias, outcome.canonicalHost)
		},
	}

	result, commitErr := r.commitResultWithPublishAction(ctx, anyRevision, func(cfg *Configuration) error {
		return r.ensureTargetInTransaction(cfg, opts, explicitDefaultUser, &outcome)
	}, action)
	finalNodeID := outcome.nodeID
	createdNode := outcome.created

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
	outcome *ensureTransactionOutcome,
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
		*outcome = ensureTransactionOutcome{
			nodeID:        decision.MatchedNodeID,
			created:       false,
			openSSHAlias:  decision.OpenSSHAlias,
			canonicalHost: decision.CanonicalHost,
		}
		return nil
	}
	txOpts := opts
	txOpts.Target = decision.NormalizedTarget
	return r.createNodeInTransaction(cfg, txOpts, decision.Canonical, decision.EffectiveUser, decision.EffectivePort, outcome)
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
	clean, _ := cutOpenSSHPrefix(spec)
	clean = strings.TrimSpace(clean)
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

func (r *Repository) matchBareOpenSSHSelector(selector string, target ConnectionTarget) (string, string, error) {
	parser := r.openSSHParserOrEmpty()
	if err := parser.Err(); err != nil {
		return "", "", fmt.Errorf("resolve openssh host %q: %w", selector, err)
	}
	if hasOpenSSHPrefix(selector) {
		clean, lookupHost, _, _, err := parseExplicitOpenSSHSelector(selector)
		if err != nil {
			return "", "", nil
		}
		if _, _, _, err := resolveVirtualNodeForTarget(parser, clean, target); err != nil {
			return "", "", nil
		}
		alias := resolveOpenSSHAliasName(parser, clean)
		if orig := normalizeOriginalHost(target.OriginalHost); orig != "" && !strings.EqualFold(orig, lookupHost) {
			alias = orig
		}
		return OpenSSHNodePrefix + clean, alias, nil
	}
	orig := normalizeOriginalHost(target.OriginalHost)
	hasCanonicalAlias := orig != "" && !strings.EqualFold(orig, selector)
	if hasCanonicalAlias {
		if !canonicalVirtualMatchesSinglePass(parser, orig, selector) {
			return "", "", nil
		}
	}
	if parser != nil && parser.cfg != nil {
		if nid, ok := parser.Find(selector); ok {
			alias := resolveOpenSSHAliasName(parser, nid)
			if hasCanonicalAlias {
				alias = orig
			}
			return nid, alias, nil
		}
	}
	return "", "", nil
}

func (r *Repository) matchOpenSSHVirtualNode(selector, effectiveUser string, effectivePort uint16, expectedAddr string, target ConnectionTarget) (string, string, error) {
	parser := r.openSSHParserOrEmpty()
	if err := parser.Err(); err != nil {
		return "", "", fmt.Errorf("resolve openssh host %q: %w", selector, err)
	}
	if hasOpenSSHPrefix(selector) {
		return matchExplicitOpenSSHVirtualNode(parser, selector, effectiveUser, effectivePort, target)
	}
	orig := normalizeOriginalHost(target.OriginalHost)
	hasCanonicalAlias := orig != "" && !strings.EqualFold(orig, selector)
	if hasCanonicalAlias {
		if !canonicalVirtualMatchesSinglePass(parser, orig, selector) {
			return "", "", nil
		}
	}
	if parser == nil || parser.cfg == nil {
		return "", "", nil
	}
	if !IsPlainOpenSSHHostSelector(selector) || !parser.HasHost(selector) {
		return "", "", nil
	}
	cleanSelector := StripHostBrackets(selector)
	_, vhost, vident, err := parser.GetVirtualNode(cleanSelector)
	if err != nil {
		return "", "", nil
	}
	vhostEp, vErr := ssh.NewEndpoint(vhost.Address, int(vhost.Port))
	if cleanExpected := StripHostBrackets(expectedAddr); cleanExpected != "" {
		expEp, eErr := ssh.NewEndpoint(cleanExpected, int(effectivePort))
		if vErr != nil || eErr != nil || !expEp.Equal(vhostEp) {
			return "", "", nil
		}
	} else if normalizedHostPort(vhost.Port) != effectivePort {
		return "", "", nil
	}
	if vident.User == effectiveUser {
		alias := cleanSelector
		if hasCanonicalAlias {
			alias = orig
		}
		return OpenSSHNodePrefix + cleanSelector, alias, nil
	}
	return "", "", nil
}

func matchExplicitOpenSSHVirtualNode(parser *OpenSSHParser, selector, effectiveUser string, effectivePort uint16, target ConnectionTarget) (string, string, error) {
	clean, _, _, _, err := parseExplicitOpenSSHSelector(selector)
	if err != nil {
		return "", "", nil
	}
	_, vhost, vident, err := resolveVirtualNodeForTarget(parser, clean, target)
	if err != nil {
		return "", "", nil
	}
	if vident.User != effectiveUser || normalizedHostPort(vhost.Port) != effectivePort {
		return "", "", nil
	}
	alias := canonicalOriginalAlias(parser, target.OriginalHost, clean)
	return OpenSSHNodePrefix + clean, alias, nil
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

// findExistingNodeDecision performs a read-only check in the current snapshot to determine
// whether target already resolves to a saved or OpenSSH virtual node.
func (r *Repository) findExistingNodeDecision(target ConnectionTarget, explicitDefaultUser string) (targetDecision, error) {
	snapshot := r.provider.Snapshot()
	lookup, aliases, err := buildIndexes(snapshot, false)
	if err != nil {
		return targetDecision{}, err
	}
	return r.evaluateTargetDecision(snapshot, lookup, aliases, target, explicitDefaultUser)
}

// syncPreparedExistingMetadataLocked synchronizes per-node session metadata under r.pendingMu.Lock().
func (r *Repository) syncPreparedExistingMetadataLocked(decision targetDecision) {
	id := decision.MatchedNodeID
	if id == "" || decision.NeedsCreation || IsOpenSSHNodeID(id) {
		return
	}
	if r.provider != nil {
		r.provider.setSavedNodeOpenSSHMetadataIfPresent(id, decision.OpenSSHAlias, decision.CanonicalHost)
	}
}

func normalizedHostPort(port uint16) uint16 {
	if port == 0 {
		return 22
	}
	return port
}

func canonicalVirtualMatchesSinglePass(parser *OpenSSHParser, orig, selector string) bool {
	if parser == nil || parser.cfg == nil {
		return false
	}
	v1, h1, i1, err1 := parser.GetVirtualNodeWithCanonical(orig, selector)
	v2, h2, i2, err2 := parser.GetVirtualNode(selector)
	if err1 != nil || err2 != nil {
		return false
	}
	return h1.Address == h2.Address &&
		normalizedHostPort(h1.Port) == normalizedHostPort(h2.Port) &&
		i1.User == i2.User &&
		i1.KeyPath == i2.KeyPath &&
		v1.ProxyJump == v2.ProxyJump &&
		v1.SSHOptions.Equal(v2.SSHOptions)
}

func normalizedIdentityUser(rawUser string) string {
	if u := strings.TrimSpace(rawUser); u != "" {
		return u
	}
	fallbackUser, _ := resolveEffectiveUser(ConnectionTarget{}, "", "")
	return fallbackUser
}

func nodeMatchesEndpoint(cfg *Configuration, nodeID, user, addr string, port uint16) bool {
	if cfg == nil || cfg.Nodes == nil || cfg.Hosts == nil || cfg.Identities == nil || nodeID == "" {
		return false
	}
	node, ok := cfg.Nodes.Get(nodeID)
	if !ok {
		return false
	}
	host, hok := cfg.Hosts.Get(node.HostRef)
	ident, iok := cfg.Identities.Get(node.IdentityRef)
	if !hok || !iok {
		return false
	}
	hostEp, hErr := ssh.NewEndpoint(host.Address, int(host.Port))
	targetEp, tErr := ssh.NewEndpoint(addr, int(port))
	return hErr == nil && tErr == nil &&
		hostEp.Equal(targetEp) &&
		normalizedIdentityUser(ident.User) == user
}

func allocateAvailableNodeID(cfg *Configuration, baseID string) string {
	if cfg == nil || cfg.Nodes == nil || baseID == "" {
		return baseID
	}
	if _, exists := cfg.Nodes.Get(baseID); !exists {
		return baseID
	}
	for suffix := 2; ; suffix++ {
		candidate := fmt.Sprintf("%s-%d", baseID, suffix)
		if _, exists := cfg.Nodes.Get(candidate); !exists {
			return candidate
		}
	}
}

func findMatchingNodes(snapshot *Configuration, user, addr string, port uint16) []string {
	var matches []string
	targetEp, tErr := ssh.NewEndpoint(addr, int(port))
	if tErr != nil {
		return nil
	}
	for _, nid := range snapshot.Nodes.Keys() {
		n, ok := snapshot.Nodes.Get(nid)
		if !ok {
			continue
		}
		h, hok := snapshot.Hosts.Get(n.HostRef)
		ident, iok := snapshot.Identities.Get(n.IdentityRef)
		if hok && iok {
			nodeUser := normalizedIdentityUser(ident.User)
			hostEp, hErr := ssh.NewEndpoint(h.Address, int(h.Port))
			if hErr == nil && hostEp.Equal(targetEp) && nodeUser == user {
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
	if hasOpenSSHPrefix(selector) {
		clean, lookupHost, _, _, err := parseExplicitOpenSSHSelector(selector)
		if err != nil {
			return canonicalTargetInfo{}, err
		}
		parser := r.openSSHParserOrEmpty()
		vnode, vhost, vident, err := resolveVirtualNodeForTarget(parser, clean, target)
		if err != nil {
			return canonicalTargetInfo{}, fmt.Errorf("resolve openssh host %q: %w", clean, err)
		}
		alias := canonicalOriginalAlias(parser, target.OriginalHost, lookupHost)
		canonicalHost := canonicalTargetHost(target, lookupHost)
		backfillCanonicalTargetMetadata(target, lookupHost, &alias, &canonicalHost)
		return canonicalTargetInfo{
			BaseNodeID:    OpenSSHNodePrefix + lookupHost,
			Address:       NormalizeHostAddress(vhost.Address),
			Port:          normalizedHostPort(vhost.Port),
			IdentityFile:  vident.KeyPath,
			ProxyJump:     vnode.ProxyJump,
			DefaultUser:   vident.User,
			OpenSSHAlias:  alias,
			CanonicalHost: canonicalHost,
		}, nil
	}

	// 1 & 2. Direct Node ID or Alias match (checking RawSelector first when split from user@host:port)
	if info, ok := r.resolveDirectOrAliasTargetInfo(cfg, aliases, strings.TrimSpace(target.RawSelector), selector); ok {
		backfillCanonicalTargetMetadata(target, selector, &info.OpenSSHAlias, &info.CanonicalHost)
		return info, nil
	}

	// 3. Lookup match
	if candidates := lookupBySelector(lookup, selector); len(candidates) > 0 {
		return r.resolveLookupCandidates(cfg, selector, candidates, target)
	}
	if raw := strings.TrimSpace(target.RawSelector); raw != "" && raw != selector {
		if candidates := lookupBySelector(lookup, raw); len(candidates) > 0 {
			return r.resolveLookupCandidates(cfg, raw, candidates, target)
		}
	}
	if strings.TrimSpace(target.RawSelector) == "" && target.HasUser && target.HasPort && strings.TrimSpace(target.User) != "" && target.Port > 0 {
		targetUser := strings.TrimSpace(target.User)
		composite := FormatNodeID(targetUser, selector, target.Port)
		if nodeMatchesEndpoint(cfg, composite, targetUser, selector, target.Port) {
			if info, ok := r.resolveDirectOrAliasTargetInfo(cfg, aliases, composite); ok {
				backfillCanonicalTargetMetadata(target, selector, &info.OpenSSHAlias, &info.CanonicalHost)
				return info, nil
			}
		}
		if matches := findMatchingNodes(cfg, targetUser, selector, target.Port); len(matches) == 1 {
			if info, ok := r.resolveDirectOrAliasTargetInfo(cfg, aliases, matches[0]); ok {
				backfillCanonicalTargetMetadata(target, selector, &info.OpenSSHAlias, &info.CanonicalHost)
				return info, nil
			}
		}
	}

	// 4. OpenSSH configuration match
	parser := r.openSSHParserOrEmpty()
	if err := parser.Err(); err != nil {
		return canonicalTargetInfo{}, fmt.Errorf("resolve openssh host %q: %w", selector, err)
	}
	if parser.cfg != nil {
		clean, isPrefixed := cutOpenSSHPrefix(selector)
		clean = strings.TrimSpace(clean)
		allowSpec := isPrefixed || IsPlainOpenSSHHostSelector(clean)
		orig := normalizeOriginalHost(target.OriginalHost)
		if clean != "" && allowSpec && ((orig != "" && !strings.EqualFold(orig, clean)) || parser.HasHost(clean)) {
			vnode, vhost, vident, err := resolveVirtualNodeForTarget(parser, clean, target)
			if err != nil {
				return canonicalTargetInfo{}, fmt.Errorf("resolve openssh host %q: %w", clean, err)
			}
			cleanHost := StripHostBrackets(clean)
			alias := resolveOpenSSHAliasName(parser, clean)
			if orig != "" && !strings.EqualFold(orig, cleanHost) {
				alias = orig
			}
			canonHost := canonicalTargetHost(target, cleanHost)
			backfillCanonicalTargetMetadata(target, cleanHost, &alias, &canonHost)
			return canonicalTargetInfo{
				BaseNodeID:    OpenSSHNodePrefix + cleanHost,
				Address:       NormalizeHostAddress(vhost.Address),
				Port:          vhost.Port,
				IdentityFile:  vident.KeyPath,
				ProxyJump:     vnode.ProxyJump,
				DefaultUser:   vident.User,
				OpenSSHAlias:  alias,
				CanonicalHost: canonHost,
			}, nil
		}
	}

	// 5. Raw address/hostname fallback (including openssh: virtual selectors or
	// unconfirmed user@host:port node IDs passed across process boundaries).
	clean, _ := cutOpenSSHPrefix(strings.TrimSpace(selector))
	if parsedHost, parsedUser, parsedPort, err := parseOpenSSHHostSpec(clean); err == nil && parsedHost != "" {
		port := parsedPort
		if port == 0 {
			port = 22
		}
		cleanHost := NormalizeHostAddress(parsedHost)
		var rawAlias string
		canonHost := canonicalTargetHost(target, cleanHost)
		backfillCanonicalTargetMetadata(target, cleanHost, &rawAlias, &canonHost)
		return canonicalTargetInfo{
			Address:       cleanHost,
			Port:          port,
			DefaultUser:   parsedUser,
			OpenSSHAlias:  rawAlias,
			CanonicalHost: canonHost,
		}, nil
	}
	clean = NormalizeHostAddress(clean)
	var rawAlias string
	canonHost := canonicalTargetHost(target, clean)
	backfillCanonicalTargetMetadata(target, clean, &rawAlias, &canonHost)
	return canonicalTargetInfo{Address: clean, Port: 22, OpenSSHAlias: rawAlias, CanonicalHost: canonHost}, nil
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

func (r *Repository) effectiveNodeOpenSSHOrigin(nodeID string, node models.Node) OpenSSHOrigin {
	origin := normalizeOpenSSHOrigin(OpenSSHOrigin{
		Alias:         node.OpenSSHAlias,
		CanonicalHost: node.CanonicalHost,
	})
	if !origin.IsZero() {
		return origin
	}
	if r != nil && r.provider != nil {
		return r.provider.NodeOpenSSHOrigin(nodeID)
	}
	return OpenSSHOrigin{}
}

func (r *Repository) effectiveNodeMetadata(nodeID string, node models.Node) (alias, canon string) {
	origin := r.effectiveNodeOpenSSHOrigin(nodeID, node)
	return origin.Alias, origin.CanonicalHost
}

func canonicalTargetHost(target ConnectionTarget, candidateHost string) string {
	cleanOrig := normalizeOriginalHost(target.OriginalHost)
	if cleanOrig == "" {
		return ""
	}
	cleanCandidate := normalizeOriginalHost(candidateHost)
	if cleanCandidate == "" || strings.EqualFold(cleanOrig, cleanCandidate) {
		return ""
	}
	return cleanCandidate
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
	clean := NormalizeHostAddress(host.Address)
	var defUser string
	var keyPath string
	if ident, identExists := cfg.Identities.Get(node.IdentityRef); identExists {
		defUser = normalizedIdentityUser(ident.User)
		keyPath = ident.KeyPath
	}
	origin := r.effectiveNodeOpenSSHOrigin(candidateID, node)
	return canonicalTargetInfo{
		BaseNodeID:    candidateID,
		Address:       clean,
		Port:          normalizedHostPort(host.Port),
		IdentityFile:  keyPath,
		DefaultUser:   defUser,
		OpenSSHAlias:  origin.Alias,
		CanonicalHost: origin.CanonicalHost,
	}, true
}

func (r *Repository) consistentCandidateOpenSSHOrigin(cfg *Configuration, candidates []string) OpenSSHOrigin {
	var first OpenSSHOrigin
	for _, cid := range candidates {
		node, ok := cfg.Nodes.Get(cid)
		if !ok {
			continue
		}
		origin := r.effectiveNodeOpenSSHOrigin(cid, node)
		if origin.IsZero() {
			continue
		}
		if first.IsZero() {
			first = origin
		} else if !first.Equal(origin) {
			return OpenSSHOrigin{}
		}
	}
	return first
}

func (r *Repository) resolveConsistentCandidates(cfg *Configuration, selector string, candidates []string) (canonicalTargetInfo, error) {
	var firstBaseID string
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
		clean := NormalizeHostAddress(host.Address)
		port := normalizedHostPort(host.Port)
		if !initialized {
			firstBaseID = cid
			firstAddr = clean
			firstPort = port
			firstUser = user
			initialized = true
		} else {
			firstEp, fErr := ssh.NewEndpoint(firstAddr, int(firstPort))
			curEp, cErr := ssh.NewEndpoint(clean, int(port))
			if fErr != nil || cErr != nil || !firstEp.Equal(curEp) {
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
		if firstBaseID == "" && len(candidates) > 0 {
			firstBaseID = candidates[0]
		}
		origin := r.consistentCandidateOpenSSHOrigin(cfg, candidates)
		return canonicalTargetInfo{
			BaseNodeID:           firstBaseID,
			Address:              firstAddr,
			Port:                 firstPort,
			DefaultUser:          defUser,
			OpenSSHAlias:         origin.Alias,
			CanonicalHost:        origin.CanonicalHost,
			AmbiguousDefaultUser: !userConsistent,
			AmbiguousCandidates:  slices.Clone(candidates),
		}, nil
	}
	return canonicalTargetInfo{}, &AmbiguousNodeError{Selector: selector, Candidates: slices.Clone(candidates)}
}

func (r *Repository) resolveCandidateAddressFallback(cfg *Configuration, selector string, candidates []string, target ConnectionTarget) (canonicalTargetInfo, error) {
	var firstBaseID string
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
		clean := NormalizeHostAddress(host.Address)
		port := normalizedHostPort(host.Port)
		if !initialized {
			firstBaseID = cid
			firstAddr = clean
			firstPort = port
			firstUser = user
			initialized = true
		} else {
			if !endpointHostsMatch(firstAddr, firstPort, clean, port) {
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
	if firstBaseID == "" && len(candidates) > 0 {
		firstBaseID = candidates[0]
	}
	origin := r.consistentCandidateOpenSSHOrigin(cfg, candidates)

	return canonicalTargetInfo{
		BaseNodeID:           firstBaseID,
		Address:              firstAddr,
		Port:                 effectivePort,
		DefaultUser:          defUser,
		OpenSSHAlias:         origin.Alias,
		CanonicalHost:        origin.CanonicalHost,
		AmbiguousDefaultUser: !target.HasUser && !userConsistent,
		AmbiguousCandidates:  slices.Clone(candidates),
	}, nil
}

func endpointHostsMatch(addrA string, portA uint16, addrB string, portB uint16) bool {
	epA, errA := ssh.NewEndpoint(addrA, int(portA))
	epB, errB := ssh.NewEndpoint(addrB, int(portB))
	return errA == nil && errB == nil && epA.HostEqual(epB)
}

func (r *Repository) resolveLookupCandidates(cfg *Configuration, selector string, candidates []string, target ConnectionTarget) (canonicalTargetInfo, error) {
	var (
		info canonicalTargetInfo
		err  error
	)
	filtered := filterCandidatesByExplicitTarget(cfg, candidates, target)
	if len(filtered) == 1 {
		if resolvedInfo, ok := r.resolveCandidateNodeInfo(cfg, filtered[0]); ok {
			info = resolvedInfo
			goto backfill
		}
	}
	if len(filtered) > 1 {
		info, err = r.resolveConsistentCandidates(cfg, selector, filtered)
	} else {
		info, err = r.resolveCandidateAddressFallback(cfg, selector, candidates, target)
	}
	if err != nil {
		return canonicalTargetInfo{}, err
	}
backfill:
	backfillCanonicalTargetMetadata(target, selector, &info.OpenSSHAlias, &info.CanonicalHost)
	return info, nil
}

// createNodeInTransaction performs the atomic creation of Host, Identity, and Node.
func (r *Repository) createNodeInTransaction(
	cfg *Configuration,
	opts EnsureNodeOptions,
	canonicalInfo canonicalTargetInfo,
	effectiveUser string,
	effectivePort uint16,
	outcome *ensureTransactionOutcome,
) error {
	canonicalAddr := canonicalInfo.Address
	if err := ValidateConcreteHostAddress(canonicalAddr); err != nil {
		return err
	}
	defaultNodeID := FormatNodeID(effectiveUser, canonicalAddr, effectivePort)
	if matches := findMatchingNodes(cfg, effectiveUser, canonicalAddr, effectivePort); len(matches) == 1 {
		*outcome = ensureTransactionOutcome{
			nodeID:        matches[0],
			created:       false,
			openSSHAlias:  canonicalInfo.OpenSSHAlias,
			canonicalHost: canonicalInfo.CanonicalHost,
		}
		return nil
	} else if len(matches) > 1 {
		return &AmbiguousNodeError{Selector: opts.Target.Selector, Candidates: matches}
	}
	targetNodeID := allocateAvailableNodeID(cfg, defaultNodeID)

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
		if err := ValidateNodeAlias(trimmedAlias); err != nil {
			return err
		}
		if existingNode := findAliasInConfig(cfg, trimmedAlias); existingNode != "" && existingNode != targetNodeID {
			return fmt.Errorf("%s", i18n.Tf("alias_err_exists", map[string]any{"Alias": trimmedAlias, "Node": existingNode}))
		}
		newNode.Alias = []string{trimmedAlias}
	}
	if len(opts.Tags) > 0 {
		newNode.Tags = slices.Clone(opts.Tags)
	}

	cfg.Nodes.Set(targetNodeID, newNode)
	*outcome = ensureTransactionOutcome{
		nodeID:        targetNodeID,
		created:       true,
		openSSHAlias:  canonicalInfo.OpenSSHAlias,
		canonicalHost: canonicalInfo.CanonicalHost,
	}
	return nil
}

func ensureMatchingHost(cfg *Configuration, canonicalAddr string, port uint16, targetNodeID string) (string, error) {
	var matchingHostRefs []string
	var unaliasedHostRef string
	targetPort := normalizedHostPort(port)
	targetEp, tErr := ssh.NewEndpoint(canonicalAddr, int(targetPort))
	for _, href := range cfg.Hosts.Keys() {
		h, ok := cfg.Hosts.Get(href)
		if !ok {
			continue
		}
		hostEp, hErr := ssh.NewEndpoint(h.Address, int(h.Port))
		if tErr == nil && hErr == nil && hostEp.Equal(targetEp) {
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
			existEp, eErr := ssh.NewEndpoint(existing.Address, int(existing.Port))
			if tErr != nil || eErr != nil || !existEp.Equal(targetEp) || len(existing.Alias) > 0 {
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
	if opts.Target.HasProxyJump || opts.Target.ProxyJump != "" {
		if _, err := ssh.ParseProxyJump(opts.Target.ProxyJump); err != nil {
			return "", fmt.Errorf("invalid target ProxyJump %q: %w", opts.Target.ProxyJump, err)
		}
		return r.resolveProxyJumpChain(cfg, opts.Target.ProxyJump)
	}

	targetPort := normalizedHostPort(port)
	targetEp, tErr := ssh.NewEndpoint(canonicalAddr, int(targetPort))
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
		hostEp, hErr := ssh.NewEndpoint(h.Address, int(h.Port))
		if tErr == nil && hErr == nil && hostEp.Equal(targetEp) {
			ps, pErr := parseOptionalNodeProxyJump(n.ProxyJump)
			if pErr != nil {
				return "", pErr
			}
			var trimmedJump string
			if targets, ok := ps.JumpTargets(); ok {
				trimmedJump = strings.Join(targets, ",")
			}
			jumpSet[trimmedJump] = struct{}{}
		}
	}

	switch len(jumpSet) {
	case 0:
		ps, pErr := parseOptionalNodeProxyJump(canonicalInfo.ProxyJump)
		if pErr != nil {
			return "", pErr
		}
		if targets, ok := ps.JumpTargets(); ok {
			return r.resolveProxyJumpChain(cfg, strings.Join(targets, ","))
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
	cliKeyPath := NormalizePersistableIdentityPath(opts.IdentityFile)
	configKeyPath := NormalizePersistableIdentityPath(canonicalInfo.IdentityFile)

	switch {
	case opts.Password != "":
		identity.Password = opts.Password
		identity.AuthType = "password"
	case cliKeyPath != "":
		identity.KeyPath = cliKeyPath
		identity.Passphrase = opts.Passphrase
		identity.AuthType = "key"
	case configKeyPath != "":
		identity.KeyPath = configKeyPath
		identity.Passphrase = opts.Passphrase
		identity.AuthType = "auto"
	default:
		identity.AuthType = "auto"
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
	if hasControlOrLineSepChar(jumpChain) {
		return "", fmt.Errorf("%w: invalid proxy_jump %q: contains control character", ssh.ErrSSHOptionsValidation, jumpChain)
	}
	if strings.TrimSpace(jumpChain) == "" {
		return "", nil
	}
	ps, err := ssh.ParseProxyJump(jumpChain)
	if err != nil {
		return "", err
	}
	targets, ok := ps.JumpTargets()
	if !ok {
		return "", nil
	}
	resolvedHops := make([]string, 0, len(targets))
	for _, hop := range targets {
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
	if candidates := lookupBySelector(lookup, hop); len(candidates) == 1 {
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
	if cands := lookupBySelector(lookup, host); len(cands) > 0 {
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
	var firstEp ssh.Endpoint
	for _, cid := range hostCandidates {
		node, ok := cfg.Nodes.Get(cid)
		if !ok {
			continue
		}
		h, hok := cfg.Hosts.Get(node.HostRef)
		if !hok {
			continue
		}
		clean := StripHostBrackets(h.Address)
		curEp, err := ssh.NewEndpoint(clean, int(h.Port))
		if err != nil {
			return "", false
		}
		if firstAddr == "" {
			firstAddr = clean
			firstEp = curEp
		} else if !firstEp.HostEqual(curEp) {
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
	targetEp, tErr := ssh.NewEndpoint(firstAddr, int(effectivePort))
	var matchingNodes []string
	for _, nid := range cfg.Nodes.Keys() {
		n, ok := cfg.Nodes.Get(nid)
		if !ok {
			continue
		}
		h, hok := cfg.Hosts.Get(n.HostRef)
		ident, iok := cfg.Identities.Get(n.IdentityRef)
		if hok && iok {
			hostEp, hErr := ssh.NewEndpoint(h.Address, int(h.Port))
			if tErr == nil && hErr == nil && hostEp.Equal(targetEp) {
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
		candidateRef := TargetRef{
			OpenSSH: true,
			User:    hopUser,
			Host:    firstAddr,
			Port:    effectivePort,
			HasPort: effectivePort > 0,
		}
		if err := candidateRef.Validate(); err != nil {
			return "", fmt.Errorf("invalid jump host %q: %w", hop, err)
		}
		if isDirectJumpTargetRef(candidateRef) {
			return candidateRef.NormalizedString(), nil
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

func isResolvedOpenSSHJumpHost(openSSH *OpenSSHParser, hop string) (bool, error) {
	if openSSH == nil || openSSH.cfg == nil {
		return false, nil
	}
	if openSSH.HasHost(hop) {
		return true, nil
	}
	cleanHop, _ := cutOpenSSHPrefix(hop)
	cleanHop = strings.TrimSpace(cleanHop)
	if cleanHop == "" {
		return false, nil
	}
	lookupAlias, _, _, parseErr := parseOpenSSHHostSpec(cleanHop)
	if parseErr != nil || lookupAlias == "" {
		return false, nil
	}
	hostName, explicit, err := openSSH.ResolveExplicitHostName(lookupAlias)
	if err != nil {
		return false, err
	}
	if !explicit || ValidateConcreteHostAddress(hostName) != nil {
		return false, nil
	}
	if v, vErr := isDirectJumpTarget(hostName); vErr == nil && v.Allowed() {
		return true, nil
	}
	return !strings.EqualFold(StripHostBrackets(hostName), StripHostBrackets(lookupAlias)), nil
}

// resolveOpenSSHJumpHop handles jump targets that are explicitly prefixed with
// the reserved "openssh:" namespace. It requires a pre-validated TargetRef so
// double-prefixed or non-round-trippable selectors cannot enter this path.
func resolveOpenSSHJumpHop(openSSH *OpenSSHParser, ref TargetRef) (string, error) {
	if !ref.OpenSSH {
		return "", fmt.Errorf("resolve openssh jump %q: missing openssh prefix", ref.NormalizedString())
	}
	if err := ref.Validate(); err != nil {
		return "", fmt.Errorf("invalid openssh jump %q: %w", ref.NormalizedString(), err)
	}
	cleanHop := ref.formatNormalizedBody()
	if err := openSSH.Err(); err != nil {
		return "", fmt.Errorf("resolve openssh jump %q: %w", cleanHop, err)
	}
	matched, matchErr := isResolvedOpenSSHJumpHost(openSSH, cleanHop)
	if matchErr != nil {
		return "", fmt.Errorf("resolve openssh jump %q: %w", cleanHop, matchErr)
	}
	if matched {
		if _, _, _, vErr := openSSH.GetVirtualNode(cleanHop); vErr != nil {
			return "", fmt.Errorf("resolve openssh jump %q: %w", cleanHop, vErr)
		}
		return ref.NormalizedString(), nil
	}

	if isDirectJumpTargetRef(ref) {
		return ref.NormalizedString(), nil
	}

	return "", errors.New(i18n.Tf("ssh_err_jump_not_found", map[string]any{"Host": ref.NormalizedString()}))
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

	if err := openSSH.Err(); err != nil {
		return "", fmt.Errorf("resolve openssh jump %q: %w", hop, err)
	}
	matched, matchErr := isResolvedOpenSSHJumpHost(openSSH, hop)
	if matchErr != nil {
		return "", fmt.Errorf("resolve openssh jump %q: %w", hop, matchErr)
	}
	if matched {
		ref, refErr := ParseTargetRef(hop)
		if refErr != nil {
			return "", fmt.Errorf("invalid jump host address %q: %w", hop, refErr)
		}
		outRef := ref
		outRef.OpenSSH = true
		if err := outRef.Validate(); err != nil {
			return "", fmt.Errorf("invalid jump host address %q: %w", hop, err)
		}
		if _, _, _, vErr := openSSH.GetVirtualNode(outRef.formatNormalizedBody()); vErr != nil {
			return "", fmt.Errorf("resolve openssh jump %q: %w", hop, vErr)
		}
		return outRef.NormalizedString(), nil
	}

	ref, refErr := ParseTargetRef(hop)
	if refErr == nil && isDirectJumpTargetRef(ref) {
		outRef := ref
		outRef.OpenSSH = true
		if err := outRef.Validate(); err != nil {
			return "", fmt.Errorf("invalid jump host address %q: %w", hop, err)
		}
		return outRef.NormalizedString(), nil
	}
	if v, vErr := isDirectJumpTarget(hop); vErr == nil && v.Allowed() && parseErr != nil {
		return "", fmt.Errorf("invalid jump host address %q: %w", hop, parseErr)
	}

	return "", errors.New(i18n.Tf("ssh_err_jump_not_found", map[string]any{"Host": hop}))
}

// resolveSingleJumpHopWithConfig resolves a single jump hop selector to a canonical node ID or OpenSSH node.
// Resolution strategy:
//  1. Explicit OpenSSH targets (prefixed with case-insensitive "openssh:"): OpenSSH config host or direct jump target only.
//  2. Unspecified origin:
//     a. Existing Node ID
//     b. Existing Alias
//     c. Existing Host address/selector lookup
//     d. OpenSSH Host defined in ~/.ssh/config
//     e. Direct jump target: explicitly requires Node/Alias, FQDN (contains '.'), IP, or [user@]host:port.
//
// Single-label hostnames without port/user cannot be used as direct jumps to avoid silent misconnections on alias typos.
func resolveSingleJumpHopWithConfig(cfg *Configuration, openSSH *OpenSSHParser, hop string) (string, error) {
	if hasOpenSSHPrefix(hop) {
		ref, err := ParseTargetRef(hop)
		if err != nil {
			return "", fmt.Errorf("invalid jump host %q: %w", hop, err)
		}
		return resolveOpenSSHJumpHop(openSSH, ref)
	}
	return resolveLocalOrDirectJumpHop(cfg, openSSH, hop)
}

func isDirectJumpTargetRef(ref TargetRef) bool {
	if ref.Host == "" {
		return false
	}
	if ref.User != "" || ref.HasPort {
		return true
	}
	if _, err := netip.ParseAddr(ref.Host); err == nil {
		return true
	}
	return isDNSHostname(ref.Host)
}

func isDirectJumpTarget(cleanHop string) (verdict.Verdict, error) {
	lookupAlias, _, _, err := parseOpenSSHHostSpec(cleanHop)
	if err != nil {
		return verdict.Deny, err
	}
	if strings.Contains(cleanHop, "@") || strings.Contains(cleanHop, ":") {
		return verdict.Allow, nil
	}
	if net.ParseIP(lookupAlias) != nil {
		return verdict.Allow, nil
	}
	if isDNSHostname(lookupAlias) {
		return verdict.Allow, nil
	}
	return verdict.Deny, nil
}

func isDNSHostname(host string) bool {
	if strings.HasPrefix(host, ".") {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	if !strings.Contains(host, ".") || len(host) > 253 || strings.HasSuffix(host, ".") {
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
