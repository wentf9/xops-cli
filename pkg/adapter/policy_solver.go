package adapter

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
)

type policySolveMode struct {
	requireSnapshot bool
	resolveOptions  bool
	resolveControl  bool
	resolveProxy    bool
}

type effectivePolicy struct {
	snapshot             config.ConnectionSnapshot
	hasSnapshot          bool
	globalCfg            *config.Configuration
	tier1Auth            SessionAuth
	hasTier1Auth         bool
	tier1Jump            proxyDirectiveKind
	tier1ActiveJump      bool
	hasResolvedTier1Jump bool
	resolvedTier1Jump    string
	higherTierCmdWins    bool
	effectiveOpts        *ssh.Options
	effectiveCtrl        *ssh.ControlConfig
	originalHost         string
	canonicalHost        string
}

func isTargetMissingError(err error) bool {
	return errors.Is(err, config.ErrNodeNotFound)
}

func (a *SSHAdapter) solvePolicy(nodeName string, sessionOpts SessionControlOptions, mode policySolveMode) (effectivePolicy, error) {
	if a == nil || a.cfgProvider == nil {
		return effectivePolicy{}, fmt.Errorf("configuration provider is nil")
	}
	tier1Auth, hasTier1Auth := a.getSessionOverride(nodeName)
	var (
		snapshot config.ConnectionSnapshot
		snapErr  error
	)
	if config.IsOpenSSHNodeID(nodeName) && hasTier1Auth && strings.TrimSpace(tier1Auth.OriginalHost) != "" {
		if origProvider, ok := a.cfgProvider.(interface {
			ResolveConnectionWithOrigin(string, string) (config.ConnectionSnapshot, error)
		}); ok {
			snapshot, snapErr = origProvider.ResolveConnectionWithOrigin(nodeName, tier1Auth.OriginalHost)
		} else {
			snapshot, snapErr = a.cfgProvider.ResolveConnection(nodeName)
		}
	} else {
		snapshot, snapErr = a.cfgProvider.ResolveConnection(nodeName)
	}
	if snapErr != nil && (!isTargetMissingError(snapErr) || mode.requireSnapshot) {
		return effectivePolicy{}, snapErr
	}
	globalCfg := a.cfgProvider.Snapshot()
	var tier3Global *ssh.Options
	if globalCfg != nil {
		tier3Global = globalCfg.SSHOptions
	}
	tier1Jump, resolvedTier1Jump, err := a.resolveTier1JumpChain(nodeName, hasTier1Auth, tier1Auth, mode.resolveProxy)
	if err != nil {
		return effectivePolicy{}, err
	}
	canonHost := strings.TrimSpace(snapshot.Node.CanonicalHost)
	if canonHost == "" {
		canonHost = strings.TrimSpace(a.lookupNodeCanonicalHost(nodeName))
	}
	pol := effectivePolicy{
		snapshot:             snapshot,
		hasSnapshot:          snapErr == nil,
		globalCfg:            globalCfg,
		tier1Auth:            tier1Auth,
		hasTier1Auth:         hasTier1Auth,
		tier1Jump:            tier1Jump,
		tier1ActiveJump:      tier1Jump == proxyActive,
		hasResolvedTier1Jump: mode.resolveProxy && tier1Jump == proxyActive,
		resolvedTier1Jump:    resolvedTier1Jump,
		originalHost:         openSSHSnapshotOriginalHost(nodeName, snapshot),
		canonicalHost:        canonHost,
	}
	if !mode.resolveOptions && !mode.resolveControl && !mode.resolveProxy {
		return pol, nil
	}
	t2, t3, t4, tierErr := a.resolvePolicyTiers(nodeName, snapshot, snapErr, tier3Global, pol.tier1Auth.OriginalHost)
	if tierErr != nil {
		return pol, tierErr
	}

	tier1Opts := sessionOpts.ToSSHOptions()
	maskedT2, maskedT3, maskedT4, higherCmdWins := solveProxyPrecedence(
		pol.tier1Jump, tier1Opts, snapshot, pol.hasSnapshot, t2, t3, t4,
	)
	pol.higherTierCmdWins = higherCmdWins

	if err := a.applyPolicyMergeModes(&pol, nodeName, sessionOpts, tier1Opts, maskedT2, maskedT3, maskedT4, t2, t3, t4, mode); err != nil {
		return pol, err
	}
	return pol, nil
}

func (a *SSHAdapter) resolveTier1JumpChain(nodeName string, hasTier1Auth bool, tier1Auth SessionAuth, resolveProxy bool) (proxyDirectiveKind, string, error) {
	tier1Jump := proxyUnset
	if hasTier1Auth {
		tier1Jump = classifyProxyJump(tier1Auth.ProxyJump)
	}
	if !resolveProxy || tier1Jump != proxyActive {
		return tier1Jump, "", nil
	}
	resolved, err := a.cfgProvider.ResolveProxyJumpChain(tier1Auth.ProxyJump)
	if err != nil {
		return tier1Jump, "", fmt.Errorf("resolve proxy jump %q for node %q failed: %w", tier1Auth.ProxyJump, nodeName, err)
	}
	return tier1Jump, resolved, nil
}

func (a *SSHAdapter) applyPolicyMergeModes(
	pol *effectivePolicy,
	nodeName string,
	sessionOpts SessionControlOptions,
	tier1Opts, maskedT2, maskedT3, maskedT4, t2, t3, t4 *ssh.Options,
	mode policySolveMode,
) error {
	if mode.resolveOptions {
		merged, err := a.finalizeEffectiveOptions(tier1Opts, maskedT2, maskedT3, maskedT4, pol.tier1ActiveJump)
		if err != nil {
			return err
		}
		merged = a.applyBatchModeLatch(nodeName, merged, tier1Opts, maskedT2, maskedT3)
		pol.effectiveOpts = merged
	}
	if mode.resolveControl && !a.disableControl {
		merged := mergeControlFields(sessionOpts, t2.ControlConfig(), t3.ControlConfig(), t4.ControlConfig())
		if merged != nil {
			if err := validateMergedControl(merged); err != nil {
				return err
			}
			pol.effectiveCtrl = merged
		}
	}
	return nil
}

func (a *SSHAdapter) latchBatchMode(nodeID string) {
	if a == nil || nodeID == "" {
		return
	}
	a.batchModeMu.Lock()
	if a.batchModeLatched == nil {
		a.batchModeLatched = make(map[string]bool)
	}
	a.batchModeLatched[nodeID] = true
	a.batchModeMu.Unlock()
}

func (a *SSHAdapter) isBatchModeLatched(nodeID string) bool {
	if a == nil || nodeID == "" {
		return false
	}
	a.batchModeMu.RLock()
	latched := a.batchModeLatched[nodeID]
	a.batchModeMu.RUnlock()
	return latched
}

func (a *SSHAdapter) applyBatchModeLatch(nodeID string, merged, tier1Opts, t2, t3 *ssh.Options) *ssh.Options {
	if merged != nil && merged.BatchMode() {
		a.latchBatchMode(nodeID)
		return merged
	}
	tier1To3Explicit := (tier1Opts != nil && tier1Opts.Get(ssh.OptionBatchMode) != "") ||
		(t2 != nil && t2.Get(ssh.OptionBatchMode) != "") ||
		(t3 != nil && t3.Get(ssh.OptionBatchMode) != "")
	if !tier1To3Explicit && a.isBatchModeLatched(nodeID) {
		var out *ssh.Options
		if merged != nil {
			out = merged.Clone()
		} else {
			out = &ssh.Options{}
		}
		_ = out.Set(ssh.OptionBatchMode, "yes")
		return out
	}
	return merged
}

type proxyDirectiveKind uint8

const (
	proxyUnset    proxyDirectiveKind = iota
	proxyDisabled                    // explicit "none"
	proxyActive                      // explicit non-empty command or jump host
)

func classifyProxyJump(raw string) proxyDirectiveKind {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return proxyUnset
	}
	if ssh.IsDisabledProxyJump(trimmed) {
		return proxyDisabled
	}
	return proxyActive
}

func classifyProxyValue(raw string) proxyDirectiveKind {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return proxyUnset
	}
	if strings.EqualFold(trimmed, "none") {
		return proxyDisabled
	}
	return proxyActive
}

func classifyProxyCommand(opts *ssh.Options) proxyDirectiveKind {
	if opts == nil {
		return proxyUnset
	}
	return classifyProxyValue(opts.Get(ssh.OptionProxyCommand))
}

// solveProxyPrecedence applies both halves of the 4-tier ProxyJump vs ProxyCommand
// precedence rule:
//   - An active higher-tier ProxyJump masks ProxyCommand from lower tiers.
//   - A disabled higher-tier ProxyJump ("none") cancels lower ProxyJump without masking lower ProxyCommand.
//   - A higher-tier ProxyCommand overrides a lower-tier ProxyJump only when active; explicit "none" stops search.
func solveProxyPrecedence(
	tier1Jump proxyDirectiveKind,
	tier1Opts *ssh.Options,
	snapshot config.ConnectionSnapshot,
	hasSnapshot bool,
	t2, t3, t4 *ssh.Options,
) (maskedT2, maskedT3, maskedT4 *ssh.Options, higherTierProxyCommandWins bool) {
	maskedT2, maskedT3, maskedT4 = t2, t3, t4
	if tier1Jump == proxyActive {
		return cloneWithoutProxyCommand(t2), cloneWithoutProxyCommand(t3), cloneWithoutProxyCommand(t4), false
	}
	if tier1Jump == proxyDisabled {
		return maskedT2, maskedT3, maskedT4, false
	}
	if !hasSnapshot || !isActiveProxyJumpValue(snapshot.Node.ProxyJump) {
		return maskedT2, maskedT3, maskedT4, false
	}
	if !snapshot.Provenance.IsUnpersistedOpenSSH() {
		maskedT3 = cloneWithoutProxyCommand(t3)
		maskedT4 = cloneWithoutProxyCommand(t4)
		return maskedT2, maskedT3, maskedT4, classifyProxyCommand(tier1Opts) == proxyActive
	}
	for _, cmdKind := range []proxyDirectiveKind{
		classifyProxyCommand(tier1Opts),
		classifyProxyCommand(t2),
		classifyProxyCommand(t3),
	} {
		switch cmdKind {
		case proxyActive:
			return maskedT2, maskedT3, maskedT4, true
		case proxyDisabled:
			return maskedT2, maskedT3, maskedT4, false
		}
	}
	return maskedT2, maskedT3, maskedT4, false
}

func (a *SSHAdapter) finalizeEffectiveOptions(
	tier1Opts, maskedT2, maskedT3, maskedT4 *ssh.Options,
	tier1ActiveJump bool,
) (*ssh.Options, error) {
	merged, err := ssh.EffectiveOptions(tier1Opts, maskedT2, maskedT3, maskedT4)
	if err != nil {
		return nil, err
	}
	if tier1ActiveJump && merged != nil {
		merged.Delete(ssh.OptionProxyCommand)
	}
	if merged.IsEmpty() {
		return nil, nil
	}
	a.applyOptionRestrictions(merged)
	if a.controlProxyMode {
		merged.Delete(ssh.OptionProxyCommand)
	}
	if !a.localExecEnabled() {
		merged.Delete(ssh.OptionLocalCommand)
		merged.Delete(ssh.OptionPermitLocalCommand)
		if key := firstLocalExecOption(merged); key != "" {
			return nil, fmt.Errorf("%w: %s", ErrLocalExecutionDisabled, key)
		}
	}
	if merged.IsEmpty() {
		return nil, nil
	}
	return merged, nil
}

func (a *SSHAdapter) applyOptionRestrictions(merged *ssh.Options) {
	if a.disableControl {
		merged.StripClasses(ssh.OptionClassMux)
	}
	if a.disableHostTrust {
		merged.StripClasses(ssh.OptionClassTrust)
	}
	if a.disableForward {
		merged.StripClasses(ssh.OptionClassForward)
	}
	if a.disableSession {
		merged.StripClasses(ssh.OptionClassSession)
	}
	if a.disableSessionAndForward {
		merged.StripClasses(ssh.OptionClassForward, ssh.OptionClassSession)
	}
	if a.nonInteractive {
		merged.Delete(ssh.OptionForwardAgent)
	}
}

func (p effectivePolicy) controlTargetContext(nodeID string) ssh.TargetContext {
	origHost := nodeID
	if p.originalHost != "" {
		origHost = p.originalHost
	}
	if p.hasTier1Auth && strings.TrimSpace(p.tier1Auth.OriginalHost) != "" {
		origHost = strings.TrimSpace(p.tier1Auth.OriginalHost)
		if cleanOrig, ok := config.OpenSSHOriginalHost(origHost); ok {
			origHost = cleanOrig
		}
	}
	host := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(p.snapshot.Host.Address), "]"), "[")
	if p.hasTier1Auth && strings.TrimSpace(p.tier1Auth.HostName) != "" {
		host = strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(p.tier1Auth.HostName), "]"), "[")
	}
	jumpHost := strings.TrimSpace(p.snapshot.Node.ProxyJump)
	if ssh.IsDisabledProxyJump(jumpHost) {
		jumpHost = ""
	}
	if p.hasTier1Auth {
		switch classifyProxyJump(p.tier1Auth.ProxyJump) {
		case proxyDisabled:
			jumpHost = ""
		case proxyActive:
			if p.hasResolvedTier1Jump {
				jumpHost = p.resolvedTier1Jump
			} else {
				jumpHost = strings.TrimSpace(p.tier1Auth.ProxyJump)
			}
		}
	}
	if p.higherTierCmdWins {
		jumpHost = ""
	}
	return ssh.TargetContext{
		Host:          host,
		Port:          effectiveSnapshotPort(p.snapshot.Host.Port),
		User:          effectiveSnapshotUser(p.snapshot.Identity.User),
		OriginalHost:  origHost,
		CanonicalHost: p.canonicalHost,
		JumpHost:      jumpHost,
	}
}

func (a *SSHAdapter) resolvePolicyTiers(
	nodeName string,
	snapshot config.ConnectionSnapshot,
	snapErr error,
	tier3Global *ssh.Options,
	tier1OriginalHost string,
) (tier2Node, tier3Out, tier4OpenSSH *ssh.Options, err error) {
	tier3Out = tier3Global
	if snapErr == nil {
		switch snapshot.Provenance {
		case config.ProvenanceOpenSSHDerived:
			var rawT4 *ssh.Options
			rawT4, err = a.resolveTier4OpenSSHOptions(nodeName, snapErr, snapshot, tier1OriginalHost)
			if err != nil {
				return nil, nil, nil, err
			}
			tier4OpenSSH = rawT4.Clone()
		case config.ProvenanceOpenSSHVirtual:
			tier4OpenSSH = snapshot.Node.SSHOptions.Clone()
		default:
			tier2Node = snapshot.Node.SSHOptions
			var rawT4 *ssh.Options
			rawT4, err = a.resolveTier4OpenSSHOptions(nodeName, snapErr, snapshot, tier1OriginalHost)
			if err != nil {
				return nil, nil, nil, err
			}
			tier4OpenSSH = filterNonVirtualTier4Options(rawT4)
		}
	} else if !config.IsOpenSSHNodeID(nodeName) {
		var rawT4 *ssh.Options
		rawT4, err = a.resolveTier4OpenSSHOptions(nodeName, snapErr, snapshot, tier1OriginalHost)
		if err != nil {
			return nil, nil, nil, err
		}
		tier4OpenSSH = filterNonVirtualTier4Options(rawT4)
	}

	if tier4OpenSSH != nil && tier4OpenSSH.ControlConfig() != nil {
		tier4OpenSSH.ImplicitTier4 = true
	}
	return tier2Node, tier3Out, tier4OpenSSH, nil
}

func filterNonVirtualTier4Options(rawTier4 *ssh.Options) *ssh.Options {
	if rawTier4 == nil {
		return nil
	}
	filtered := rawTier4.FilterByClasses(
		ssh.OptionClassMux,
		ssh.OptionClassTransport,
	)
	if strings.EqualFold(strings.TrimSpace(rawTier4.Get(ssh.OptionHashKnownHosts)), "yes") {
		if filtered == nil {
			filtered = &ssh.Options{}
		}
		_ = filtered.Set(ssh.OptionHashKnownHosts, "yes")
	}
	return filtered
}

func (a *SSHAdapter) resolveTier4OpenSSHOptions(nodeName string, snapErr error, snapshot config.ConnectionSnapshot, tier1OriginalHost string) (*ssh.Options, error) {
	parser := a.getOpenSSHParser()
	if snapErr == nil {
		switch snapshot.Provenance {
		case config.ProvenanceOpenSSHDerived:
			return a.resolveTier4DerivedOpenSSHOptions(parser, nodeName, snapshot)
		case config.ProvenanceOpenSSHVirtual:
			return nil, nil
		}
	}
	if config.IsOpenSSHNodeID(nodeName) || parser == nil {
		return nil, nil
	}
	if err := parser.Err(); err != nil {
		// Pure saved-node operations continue when ~/.ssh/config has parse errors;
		// only unmatched fallback / OpenSSH-backed lookups fail closed here.
		if snapErr == nil && snapshot.Provenance == config.ProvenanceSavedManaged {
			return nil, nil
		}
		return nil, err
	}
	lookupKeys := a.buildTier4OpenSSHLookupKeys(parser, nodeName, snapErr, snapshot, tier1OriginalHost)
	_, canonicalHost := a.resolveOpenSSHAliasAndCanonical(nodeName, snapshot)
	openSSHAlias := a.resolveEffectiveOpenSSHAlias(parser, nodeName, snapErr, snapshot, tier1OriginalHost)
	isTwoPassCanon := openSSHAlias != "" && canonicalHost != "" && !strings.EqualFold(openSSHAlias, canonicalHost)
	if isTwoPassCanon {
		opts, err := parser.GetSSHOptionsWithCanonical(openSSHAlias, canonicalHost)
		if err != nil || opts.IsEmpty() {
			return nil, err
		}
		return opts, nil
	}
	lookupOpts := func(key string) (*ssh.Options, error) {
		return parser.GetSSHOptions(key)
	}
	isConcreteKey := func(key string) bool {
		return parser.HasHost(key)
	}

	// 1. First pass: prioritize concrete host matches (defined without wildcards like Host *).
	layers, err := collectTier4OpenSSHOptLayers(lookupKeys, isConcreteKey, nil, lookupOpts, true)
	if err != nil {
		return nil, err
	}
	if len(layers) == 0 {
		// 2. Second pass: fallback to generic wildcard / pattern matches (e.g. Host *).
		layers, err = collectTier4OpenSSHOptLayers(lookupKeys, isConcreteKey, nil, lookupOpts, false)
		if err != nil {
			return nil, err
		}
	}
	return ssh.MergeOptionLayers(layers...), nil
}

func (a *SSHAdapter) resolveOpenSSHAliasAndCanonical(nodeName string, snapshot config.ConnectionSnapshot) (string, string) {
	alias := strings.TrimSpace(snapshot.Node.OpenSSHAlias)
	if alias == "" {
		alias = strings.TrimSpace(a.lookupNodeOpenSSHAlias(nodeName))
	}
	canonicalHost := strings.TrimSpace(snapshot.Node.CanonicalHost)
	if canonicalHost == "" {
		canonicalHost = strings.TrimSpace(a.lookupNodeCanonicalHost(nodeName))
	}
	return alias, canonicalHost
}

func (a *SSHAdapter) resolveTier4DerivedOpenSSHOptions(parser *config.OpenSSHParser, nodeName string, snapshot config.ConnectionSnapshot) (*ssh.Options, error) {
	if parser == nil {
		return nil, nil
	}
	if err := parser.Err(); err != nil {
		return nil, err
	}
	alias, canonicalHost := a.resolveOpenSSHAliasAndCanonical(nodeName, snapshot)
	if alias == "" {
		alias = nodeName
	}
	var (
		opts *ssh.Options
		err  error
	)
	if canonicalHost != "" && !strings.EqualFold(alias, canonicalHost) {
		opts, err = parser.GetSSHOptionsWithCanonical(alias, canonicalHost)
	} else {
		opts, err = parser.GetSSHOptions(alias)
	}
	if err != nil || opts.IsEmpty() {
		return nil, err
	}
	return opts, nil
}

func collectTier4OpenSSHOptLayers(
	keys []string,
	isConcrete func(string) bool,
	shouldSkip func(string) bool,
	lookupOpts func(string) (*ssh.Options, error),
	concreteOnly bool,
) ([]*ssh.Options, error) {
	var layers []*ssh.Options
	for _, key := range keys {
		if shouldSkip != nil && shouldSkip(key) {
			continue
		}
		if concreteOnly && !isConcrete(key) {
			continue
		}
		opts, err := lookupOpts(key)
		if err != nil {
			return nil, err
		}
		if !opts.IsEmpty() {
			layers = append(layers, opts)
		}
	}
	return layers, nil
}

func resolveScopedSavedOpenSSHAlias(
	parser *config.OpenSSHParser,
	nodeName string,
	snapshot config.ConnectionSnapshot,
	tier1OriginalHost string,
) string {
	if parser == nil || snapshot.Provenance != config.ProvenanceSavedManaged {
		return ""
	}
	orig := strings.TrimSpace(config.UnwrapOpenSSHSelector(tier1OriginalHost))
	if orig == "" || strings.EqualFold(orig, nodeName) || strings.ContainsAny(orig, "@:") || !parser.HasHost(orig) {
		return ""
	}
	_, vhost, _, err := parser.GetVirtualNode(orig)
	if err != nil {
		return ""
	}
	cleanVHost := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(vhost.Address), "]"), "[")
	cleanSnapAddr := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(snapshot.Host.Address), "]"), "[")
	if cleanVHost == "" || cleanSnapAddr == "" || !strings.EqualFold(cleanVHost, cleanSnapAddr) {
		return ""
	}
	return orig
}

func (a *SSHAdapter) resolveEffectiveOpenSSHAlias(
	parser *config.OpenSSHParser,
	nodeName string,
	snapErr error,
	snapshot config.ConnectionSnapshot,
	tier1OriginalHost string,
) string {
	openSSHAlias := snapshot.Node.OpenSSHAlias
	if openSSHAlias == "" {
		openSSHAlias = a.lookupNodeOpenSSHAlias(nodeName)
	}
	if openSSHAlias == "" && snapErr == nil {
		openSSHAlias = resolveScopedSavedOpenSSHAlias(parser, nodeName, snapshot, tier1OriginalHost)
	}
	return openSSHAlias
}

func (a *SSHAdapter) buildTier4OpenSSHLookupKeys(parser *config.OpenSSHParser, nodeName string, snapErr error, snapshot config.ConnectionSnapshot, tier1OriginalHost string) []string {
	var lookupKeys []string
	appendUnique := func(keys ...string) {
		for _, k := range keys {
			k = strings.TrimSpace(k)
			if k != "" && !slices.Contains(lookupKeys, k) {
				lookupKeys = append(lookupKeys, k)
			}
		}
	}

	openSSHAlias := a.resolveEffectiveOpenSSHAlias(parser, nodeName, snapErr, snapshot, tier1OriginalHost)
	if openSSHAlias != "" {
		appendUnique(openSSHAlias)
	}
	canonicalHost := snapshot.Node.CanonicalHost
	if canonicalHost == "" {
		canonicalHost = a.lookupNodeCanonicalHost(nodeName)
	}
	if canonicalHost != "" {
		appendUnique(canonicalHost)
	}
	if snapErr != nil {
		if !strings.Contains(nodeName, "@") && !strings.Contains(nodeName, ":") {
			appendUnique(nodeName)
		}
		if addr, port, ok := parseFallbackNodeIDAddressPort(nodeName); ok {
			if openSSHAlias == "" {
				appendUnique(parser.FindConcreteHostsByAddress(addr, port)...)
			}
			if addr != nodeName {
				appendUnique(addr)
			}
		} else {
			appendUnique(nodeName)
		}
		return lookupKeys
	}

	appendUnique(snapshot.Node.Alias...)
	appendUnique(snapshot.Host.Alias...)
	if !strings.Contains(nodeName, "@") && !strings.Contains(nodeName, ":") {
		appendUnique(nodeName)
	}
	if snapshot.Host.Address != "" {
		if openSSHAlias == "" {
			appendUnique(parser.FindConcreteHostsByAddress(snapshot.Host.Address, uint16(effectiveSnapshotPort(snapshot.Host.Port)))...)
		}
		if snapshot.Host.Address != nodeName {
			appendUnique(snapshot.Host.Address)
		}
	}
	appendUnique(nodeName)
	return lookupKeys
}

func (a *SSHAdapter) lookupNodeOpenSSHAlias(nodeName string) string {
	if a == nil || a.cfgProvider == nil || nodeName == "" {
		return ""
	}
	if p, ok := a.cfgProvider.(interface{ NodeOpenSSHAlias(string) string }); ok {
		return p.NodeOpenSSHAlias(nodeName)
	}
	return ""
}

func (a *SSHAdapter) lookupNodeCanonicalHost(nodeName string) string {
	if a == nil || a.cfgProvider == nil || nodeName == "" {
		return ""
	}
	if p, ok := a.cfgProvider.(interface{ NodeCanonicalHost(string) string }); ok {
		return p.NodeCanonicalHost(nodeName)
	}
	return ""
}

func parseFallbackNodeIDAddressPort(nodeName string) (string, uint16, bool) {
	spec := strings.TrimSpace(nodeName)
	if at := strings.LastIndex(spec, "@"); at >= 0 {
		spec = strings.TrimSpace(spec[at+1:])
	}
	host, portText, err := net.SplitHostPort(spec)
	if err != nil {
		return "", 0, false
	}
	host = strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(host), "]"), "[")
	parsedPort, parseErr := strconv.ParseUint(strings.TrimSpace(portText), 10, 16)
	if host == "" || parseErr != nil || parsedPort == 0 {
		return "", 0, false
	}
	return host, uint16(parsedPort), true
}
