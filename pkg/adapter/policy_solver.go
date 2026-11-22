package adapter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/verdict"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/config"
)

// ResolveRequest carries caller inputs for the single canonical policy
// resolution entry point (*SSHAdapter).Resolve.
type ResolveRequest struct {
	NodeID          string
	SessionControl  *SessionControlOptions
	RequireSnapshot bool
	ResolveProxy    bool
	AllowBatchLatch bool
}

// EffectivePolicy is an immutable, fully validated SSH policy snapshot
// constructed exclusively by (*SSHAdapter).Resolve. All intra-layer and
// cross-layer option, proxy, and multiplexing invariants are enforced at
// construction time.
type EffectivePolicy struct {
	nodeID            string
	snapshot          config.ConnectionSnapshot
	hasSnapshot       bool
	globalCfg         *config.Configuration
	tier1Auth         SessionAuth
	hasTier1Auth      bool
	sessionCtrlOpts   SessionControlOptions
	proxySetting      ssh.ProxySetting
	resolvedJumpChain string
	effectiveOpts     *ssh.Options
	controlSetting    ssh.ControlSetting
	effectiveCtrl     *ssh.ControlConfig
	originalHost      string
	canonicalHost     string
}

// Options returns a defensive clone of the validated effective *ssh.Options,
// or nil when no SSH options are configured.
func (p EffectivePolicy) Options() *ssh.Options {
	if p.effectiveOpts.IsEmpty() {
		return nil
	}
	return p.effectiveOpts.Clone()
}

// Control returns a defensive clone of the validated effective *ssh.ControlConfig,
// or nil when control multiplexing is disabled/unset.
func (p EffectivePolicy) Control() *ssh.ControlConfig {
	if p.effectiveCtrl == nil {
		return nil
	}
	cp := *p.effectiveCtrl
	return &cp
}

// ControlSetting returns the typed, immutable ssh.ControlSetting for this policy.
func (p EffectivePolicy) ControlSetting() ssh.ControlSetting {
	return p.controlSetting
}

// Proxy returns the resolved, mutually exclusive ssh.ProxySetting for this policy.
func (p EffectivePolicy) Proxy() ssh.ProxySetting {
	return p.proxySetting
}

// EffectiveJump returns the resolved active ProxyJump chain when
// Proxy().Kind() == ssh.ProxyJump, or "" when ProxyJump is unset, disabled,
// or superseded by ProxyCommand.
func (p EffectivePolicy) EffectiveJump() string {
	if p.proxySetting.Kind() != ssh.ProxyJump {
		return ""
	}
	if p.resolvedJumpChain != "" {
		return p.resolvedJumpChain
	}
	if targets, ok := p.proxySetting.JumpTargets(); ok {
		return strings.Join(targets, ",")
	}
	return ""
}

// OriginalHost returns the original OpenSSH selector host for token expansion (%n).
func (p EffectivePolicy) OriginalHost() string {
	return p.originalHost
}

// CanonicalHost returns the canonicalized host name (if canonicalization occurred).
func (p EffectivePolicy) CanonicalHost() string {
	return p.canonicalHost
}

// TargetContext builds the canonical control-plane ssh.TargetContext using the
// discovered local environment.
func (p EffectivePolicy) TargetContext() ssh.TargetContext {
	return p.controlTargetContext(p.nodeID)
}

func isTargetMissingError(err error) bool {
	return errors.Is(err, config.ErrNodeNotFound)
}

func (a *SSHAdapter) resolveConnectionSnapshot(nodeID string) (config.ConnectionSnapshot, SessionAuth, bool, error) {
	tier1Auth, hasTier1Auth := a.getSessionOverride(nodeID)
	if config.IsOpenSSHNodeID(nodeID) && hasTier1Auth && strings.TrimSpace(tier1Auth.OriginalHost) != "" {
		if origProvider, ok := a.cfgProvider.(interface {
			ResolveConnectionWithOrigin(string, string) (config.ConnectionSnapshot, error)
		}); ok {
			snap, err := origProvider.ResolveConnectionWithOrigin(nodeID, tier1Auth.OriginalHost)
			return snap, tier1Auth, hasTier1Auth, err
		}
	}
	snap, err := a.cfgProvider.ResolveConnection(nodeID)
	return snap, tier1Auth, hasTier1Auth, err
}

// Resolve is the single canonical policy resolver for SSHAdapter. It merges the
// 4-tier hierarchy (Tier 1 CLI > Tier 2 Node > Tier 3 Global > Tier 4 ~/.ssh/config),
// resolves ProxyJump/ProxyCommand precedence via ssh.ProxySetting, enforces all
// intra-layer and cross-layer option/control validation invariants, and returns
// an immutable EffectivePolicy.
func (a *SSHAdapter) Resolve(ctx context.Context, req ResolveRequest) (EffectivePolicy, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return EffectivePolicy{}, err
		}
	}
	if a == nil || a.cfgProvider == nil {
		return EffectivePolicy{}, fmt.Errorf("configuration provider is nil")
	}
	if err := validateOpenSSHControlSelector("node ID", req.NodeID); err != nil {
		return EffectivePolicy{}, err
	}

	var sessionOpts SessionControlOptions
	if req.SessionControl != nil {
		sessionOpts = cloneSessionControlOptions(*req.SessionControl)
	} else {
		sessionOpts, _ = a.getSessionControlOverride(req.NodeID)
	}

	snapshot, tier1Auth, hasTier1Auth, snapErr := a.resolveConnectionSnapshot(req.NodeID)
	if snapErr != nil && (!isTargetMissingError(snapErr) || req.RequireSnapshot) {
		return EffectivePolicy{}, snapErr
	}
	globalCfg := a.cfgProvider.Snapshot()
	var tier3Global *ssh.Options
	if globalCfg != nil {
		tier3Global = globalCfg.SSHOptions
	}

	parser := a.getOpenSSHParser()
	_, canonHost := a.resolveSessionOpenSSHMetadata(parser, req.NodeID, snapErr, snapshot, tier1Auth)
	pol := EffectivePolicy{
		nodeID:          req.NodeID,
		snapshot:        snapshot,
		hasSnapshot:     snapErr == nil,
		globalCfg:       globalCfg,
		tier1Auth:       tier1Auth,
		hasTier1Auth:    hasTier1Auth,
		sessionCtrlOpts: sessionOpts,
		originalHost:    openSSHSnapshotOriginalHost(req.NodeID, snapshot),
		canonicalHost:   canonHost,
	}

	t2, t3, t4, t4ParserProxy, tierErr := a.resolvePolicyTiers(req.NodeID, snapshot, snapErr, tier3Global, pol.tier1Auth)
	if tierErr != nil {
		return pol, tierErr
	}

	tier1Opts := sessionOpts.ToSSHOptions()
	effectiveProxy, tier1JumpWon, proxyErr := resolveFourTierProxySetting(
		hasTier1Auth, tier1Auth, sessionOpts.proxySetting, tier1Opts, snapshot, pol.hasSnapshot, t2, t3, t4, t4ParserProxy,
	)
	if proxyErr != nil {
		return pol, proxyErr
	}
	pol.proxySetting = effectiveProxy

	if effectiveProxy.Kind() == ssh.ProxyJump {
		resolvedJump, err := a.resolveEffectiveJumpChain(req.NodeID, req.ResolveProxy, tier1JumpWon, tier1Auth, effectiveProxy, snapshot, pol.hasSnapshot)
		if err != nil {
			return pol, err
		}
		pol.resolvedJumpChain = resolvedJump
	}

	merged, ctrlSetting, ctrl, err := a.finalizePolicyOptions(
		req.NodeID, pol, sessionOpts, tier1Opts, t2, t3, t4, effectiveProxy, req.AllowBatchLatch,
	)
	if err != nil {
		return pol, err
	}
	pol.effectiveOpts = merged
	pol.controlSetting = ctrlSetting
	pol.effectiveCtrl = ctrl
	return pol, nil
}

func hasControlOrLineSepChar(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return true
		}
	}
	return false
}

func hasAnyWhitespace(s string) bool {
	for _, r := range s {
		if unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

func trimControlAndSpace(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
	})
}

func proxySettingFromJumpString(raw string) (ssh.ProxySetting, error) {
	if hasControlOrLineSepChar(raw) {
		return ssh.UnsetProxySetting(), fmt.Errorf("%w: invalid ProxyJump %q: contains control character", ssh.ErrSSHOptionsValidation, raw)
	}
	if strings.TrimSpace(raw) == "" {
		return ssh.UnsetProxySetting(), nil
	}
	return ssh.ParseProxyJump(raw)
}

func proxyCommandSetting(opts *ssh.Options) ssh.ProxySetting {
	if opts == nil {
		return ssh.UnsetProxySetting()
	}
	return opts.ProxyCommandSetting()
}

// resolveFourTierProxySetting folds ProxyJump and ProxyCommand across the 4-tier
// hierarchy (Tier 1 CLI > Tier 2 Saved Node > Tier 3 Global > Tier 4 OpenSSH)
// using the associative ssh.ProxySetting monoid.
func resolveFourTierProxySetting(
	hasTier1Auth bool,
	tier1Auth SessionAuth,
	tier1SessionProxy ssh.ProxySetting,
	tier1Opts *ssh.Options,
	snapshot config.ConnectionSnapshot,
	hasSnapshot bool,
	t2, t3, t4 *ssh.Options,
	t4ParserProxy ssh.ProxySetting,
) (effective ssh.ProxySetting, tier1JumpWon bool, err error) {
	t1Jump := ssh.UnsetProxySetting()
	if hasTier1Auth && tier1Auth.ProxyJump != "" {
		t1Jump, err = ssh.ParseProxyJump(tier1Auth.ProxyJump)
		if err != nil {
			return ssh.UnsetProxySetting(), false, fmt.Errorf("invalid session ProxyJump %q: %w", tier1Auth.ProxyJump, err)
		}
	}
	t1Proxy := ssh.MergeProxySettings(t1Jump, tier1SessionProxy, proxyCommandSetting(tier1Opts))

	t2Jump := ssh.UnsetProxySetting()
	if hasSnapshot && !snapshot.Provenance.IsUnpersistedOpenSSH() {
		t2Jump, err = proxySettingFromJumpString(snapshot.Node.ProxyJump)
		if err != nil {
			return ssh.UnsetProxySetting(), false, fmt.Errorf("invalid node ProxyJump %q: %w", snapshot.Node.ProxyJump, err)
		}
	}
	t2Proxy := t2Jump.Merge(proxyCommandSetting(t2))

	t3Proxy := proxyCommandSetting(t3)

	t4Jump := ssh.UnsetProxySetting()
	if hasSnapshot && snapshot.Provenance.IsUnpersistedOpenSSH() {
		t4Jump, err = proxySettingFromJumpString(snapshot.Node.ProxyJump)
		if err != nil {
			return ssh.UnsetProxySetting(), false, fmt.Errorf("invalid OpenSSH ProxyJump %q: %w", snapshot.Node.ProxyJump, err)
		}
	}
	t4Proxy := ssh.MergeProxySettings(t4Jump, t4ParserProxy, proxyCommandSetting(t4))

	effective = ssh.MergeProxySettings(t1Proxy, t2Proxy, t3Proxy, t4Proxy)
	tier1JumpWon = t1Proxy.Kind() == ssh.ProxyJump && effective.Kind() == ssh.ProxyJump
	return effective, tier1JumpWon, nil
}

func (a *SSHAdapter) resolveEffectiveJumpChain(
	nodeID string,
	resolveProxy bool,
	tier1JumpWon bool,
	tier1Auth SessionAuth,
	effectiveProxy ssh.ProxySetting,
	snapshot config.ConnectionSnapshot,
	hasSnapshot bool,
) (string, error) {
	var rawJump string
	if tier1JumpWon {
		rawJump = strings.TrimSpace(tier1Auth.ProxyJump)
	}
	if rawJump == "" {
		if targets, ok := effectiveProxy.JumpTargets(); ok {
			rawJump = strings.Join(targets, ",")
		}
	}
	if rawJump == "" {
		rawJump = strings.TrimSpace(snapshot.Node.ProxyJump)
	}
	if !resolveProxy || rawJump == "" {
		return rawJump, nil
	}
	var (
		resolved string
		err      error
	)
	if !tier1JumpWon && hasSnapshot && snapshot.Provenance.IsUnpersistedOpenSSH() {
		resolved, err = resolveUnpersistedOpenSSHJumpChain(a.cfgProvider, rawJump)
	} else {
		resolved, err = a.cfgProvider.ResolveProxyJumpChain(rawJump)
	}
	if err != nil {
		return "", fmt.Errorf("resolve proxy jump %q for node %q failed: %w", rawJump, nodeID, err)
	}
	dest := buildPolicyProxyJumpTarget(nodeID, snapshot, hasSnapshot)
	if err := config.ValidateProxyJumpChainCycle(a.cfgProvider, dest, resolved, rawJump); err != nil {
		return "", err
	}
	return resolved, nil
}

func buildPolicyProxyJumpTarget(nodeID string, snapshot config.ConnectionSnapshot, hasSnapshot bool) config.ProxyJumpTarget {
	dest := config.ProxyJumpTarget{
		NodeID:   strings.TrimSpace(nodeID),
		Selector: strings.TrimSpace(nodeID),
	}
	if !hasSnapshot {
		return dest
	}
	dest.OpenSSHAlias = strings.TrimSpace(snapshot.Node.OpenSSHAlias)
	dest.Host = strings.TrimSpace(snapshot.Host.Address)
	dest.Port = snapshot.Host.Port
	if snapshot.Provenance != config.ProvenanceOpenSSHVirtual {
		dest.User = strings.TrimSpace(snapshot.Identity.User)
	}
	dest.IsAdHoc = snapshot.Provenance == config.ProvenanceAdHocPending
	return dest
}

// resolveUnpersistedOpenSSHJumpChain resolves non-OpenSSH hops (such as saved
// xops inventory node IDs or aliases inherited onto ProvenanceOpenSSHDerived
// nodes) through provider.ResolveProxyJumpChain while validating and normalizing
// OpenSSH-origin "openssh:..." hops via config.ParseTargetRef so unconfigured
// single-label OpenSSH jumps are not rejected by local inventory rules while
// casing drift ("OPENSSH:..."), broken OpenSSHParser, and malformed tokens fail closed.
func resolveUnpersistedOpenSSHJumpChain(provider config.ConfigProvider, rawJump string) (string, error) {
	ps, err := proxySettingFromJumpString(rawJump)
	if err != nil {
		return "", err
	}
	targets, ok := ps.JumpTargets()
	if !ok {
		return "", nil
	}
	var parser *config.OpenSSHParser
	if src, ok := provider.(interface{ GetOpenSSHParser() *config.OpenSSHParser }); ok && src != nil {
		parser = src.GetOpenSSHParser()
	}
	out := make([]string, 0, len(targets))
	for _, rawHop := range targets {
		hop := strings.TrimSpace(rawHop)
		if hop == "" {
			continue
		}
		if config.IsOpenSSHNodeID(hop) {
			if hasControlOrLineSepChar(rawHop) || hasAnyWhitespace(hop) {
				return "", fmt.Errorf("%w: invalid openssh jump host %q", ssh.ErrSSHOptionsValidation, rawHop)
			}
			ref, refErr := config.ParseTargetRef(hop)
			if refErr != nil {
				return "", fmt.Errorf("%w: invalid openssh jump host %q: %w", ssh.ErrSSHOptionsValidation, hop, refErr)
			}
			if vErr := ref.Validate(); vErr != nil {
				return "", fmt.Errorf("%w: invalid openssh jump host %q: %w", ssh.ErrSSHOptionsValidation, hop, vErr)
			}
			if parser != nil {
				if pErr := parser.Err(); pErr != nil {
					return "", fmt.Errorf("resolve openssh jump %q: %w", hop, pErr)
				}
			}
			out = append(out, ref.NormalizedString())
			continue
		}
		if provider == nil {
			ref, refErr := config.ParseTargetRef(hop)
			if refErr != nil {
				return "", fmt.Errorf("%w: invalid jump host %q: %w", ssh.ErrSSHOptionsValidation, hop, refErr)
			}
			if vErr := ref.Validate(); vErr != nil {
				return "", fmt.Errorf("%w: invalid jump host %q: %w", ssh.ErrSSHOptionsValidation, hop, vErr)
			}
			out = append(out, hop)
			continue
		}
		resolvedHop, err := provider.ResolveProxyJumpChain(hop)
		if err != nil {
			return "", err
		}
		if resolvedHop != "" {
			out = append(out, resolvedHop)
		}
	}
	return strings.Join(out, ","), nil
}

// prefixTier4OpenSSHProxySetting prefixes unprefixed Tier-4 OpenSSH parser
// ProxyJump hops with "openssh:" at the parser source while preserving any
// shadowed ProxyCommand / ProxyCommand=none fallback slot carried by ps.
// Raw ssh_config hops that already carry an "openssh:" prefix or fail
// ParseTargetRef("openssh:" + hop) (including interior whitespace) fail closed.
func prefixTier4OpenSSHProxySetting(ps ssh.ProxySetting) (ssh.ProxySetting, error) {
	targets, ok := ps.JumpTargets()
	if !ok {
		return ps, nil
	}
	prefixed := make([]string, len(targets))
	for i, rawHop := range targets {
		hop := strings.TrimSpace(rawHop)
		if hop == "" || hasControlOrLineSepChar(rawHop) || hasAnyWhitespace(hop) {
			return ssh.UnsetProxySetting(), fmt.Errorf("%w: invalid OpenSSH ProxyJump hop %q", ssh.ErrSSHOptionsValidation, rawHop)
		}
		if config.IsOpenSSHNodeID(hop) {
			return ssh.UnsetProxySetting(), fmt.Errorf("%w: invalid OpenSSH ProxyJump hop %q: reserved %q prefix is not allowed in ssh_config", ssh.ErrSSHOptionsValidation, hop, config.OpenSSHNodePrefix)
		}
		ref, err := config.ParseTargetRef(config.OpenSSHNodePrefix + hop)
		if err != nil {
			return ssh.UnsetProxySetting(), fmt.Errorf("%w: invalid OpenSSH ProxyJump hop %q: %w", ssh.ErrSSHOptionsValidation, hop, err)
		}
		if err := ref.Validate(); err != nil {
			return ssh.UnsetProxySetting(), fmt.Errorf("%w: invalid OpenSSH ProxyJump hop %q: %w", ssh.ErrSSHOptionsValidation, hop, err)
		}
		prefixed[i] = ref.NormalizedString()
	}
	prefixedJump, err := ssh.NewProxyJump(prefixed...)
	if err != nil {
		return ssh.UnsetProxySetting(), err
	}
	return prefixedJump.Merge(ps), nil
}

func resolvePrefixedTier4OpenSSHProxySetting(parser *config.OpenSSHParser, alias, canonicalHost string) (ssh.ProxySetting, error) {
	if parser == nil {
		return ssh.UnsetProxySetting(), nil
	}
	ps, err := parser.ResolveProxySettingWithCanonical(alias, canonicalHost)
	if err != nil {
		return ssh.UnsetProxySetting(), err
	}
	return prefixTier4OpenSSHProxySetting(ps)
}

func cloneStrippingMux(opts *ssh.Options) *ssh.Options {
	if opts == nil {
		return nil
	}
	cloned := opts.Clone()
	cloned.StripClasses(ssh.OptionClassMux)
	if cloned.IsEmpty() {
		return nil
	}
	return cloned
}

func (a *SSHAdapter) finalizePolicyOptions(
	nodeID string,
	pol EffectivePolicy,
	sessionOpts SessionControlOptions,
	tier1Opts, t2, t3, t4 *ssh.Options,
	effectiveProxy ssh.ProxySetting,
	allowBatchLatch bool,
) (*ssh.Options, ssh.ControlSetting, *ssh.ControlConfig, error) {
	l1, l2, l3, l4 := tier1Opts, t2, t3, t4
	if a.disableControl {
		l1 = cloneStrippingMux(tier1Opts)
		l2 = cloneStrippingMux(t2)
		l3 = cloneStrippingMux(t3)
		l4 = cloneStrippingMux(t4)
	}

	merged, err := ssh.MergeEffectiveOptions(l1, l2, l3, l4)
	if err != nil {
		return nil, ssh.UnsetControlSetting(), nil, err
	}

	merged, err = applyEffectiveProxyToOptions(merged, effectiveProxy)
	if err != nil {
		return nil, ssh.UnsetControlSetting(), nil, err
	}

	if err := a.enforceMergedOptionPolicy(merged); err != nil {
		return nil, ssh.UnsetControlSetting(), nil, err
	}

	ctrlSetting, ctrl, err := a.resolvePolicyControlConfig(merged, sessionOpts)
	if err != nil {
		return nil, ssh.UnsetControlSetting(), nil, err
	}

	merged = a.applyBatchModeLatch(nodeID, pol, merged, tier1Opts, t2, t3, t4, allowBatchLatch)
	if merged.IsEmpty() {
		merged = nil
	}
	return merged, ctrlSetting, ctrl, nil
}

func applyEffectiveProxyToOptions(merged *ssh.Options, effectiveProxy ssh.ProxySetting) (*ssh.Options, error) {
	switch effectiveProxy.Kind() {
	case ssh.ProxyJump:
		if merged != nil {
			merged.Delete(ssh.OptionProxyCommand)
		}
	case ssh.ProxyCommand:
		if cmd, ok := effectiveProxy.Command(); ok {
			if merged == nil {
				merged = &ssh.Options{}
			}
			if err := merged.Set(ssh.OptionProxyCommand, cmd); err != nil {
				return nil, err
			}
		}
	case ssh.ProxyDisabled:
		if effectiveProxy.Equal(ssh.DisabledProxySetting()) {
			if merged != nil && merged.ActiveProxyCommand() != "" {
				if err := merged.Set(ssh.OptionProxyCommand, "none"); err != nil {
					return nil, err
				}
			}
		} else if merged != nil && merged.ActiveProxyCommand() != "" {
			merged.Delete(ssh.OptionProxyCommand)
		}
	}
	return merged, nil
}

func (a *SSHAdapter) enforceMergedOptionPolicy(merged *ssh.Options) error {
	if merged == nil {
		return nil
	}
	a.applyOptionRestrictions(merged)
	if a.controlProxyMode {
		merged.Delete(ssh.OptionProxyCommand)
	}
	if !a.localExecEnabled() {
		merged.Delete(ssh.OptionLocalCommand)
		merged.Delete(ssh.OptionPermitLocalCommand)
		if key := firstLocalExecOption(merged); key != "" {
			return fmt.Errorf("%w: %s", ErrLocalExecutionDisabled, key)
		}
	}
	return nil
}

func (a *SSHAdapter) resolvePolicyControlConfig(merged *ssh.Options, sessionOpts SessionControlOptions) (ssh.ControlSetting, *ssh.ControlConfig, error) {
	if a.disableControl || merged == nil {
		return ssh.UnsetControlSetting(), nil, nil
	}
	ctrl, err := merged.ValidatedControlConfig()
	if err != nil {
		return ssh.UnsetControlSetting(), nil, err
	}
	ctrlSetting, err := ssh.ControlSettingFromOptions(merged)
	if err != nil {
		return ssh.UnsetControlSetting(), nil, err
	}
	if ctrl != nil {
		ctrl.AllowReuse = sessionOpts.AllowReuse && !sessionOpts.HasExplicitMaster() && ctrl.IsEnabled()
	}
	return ctrlSetting, ctrl, nil
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

func (a *SSHAdapter) applyBatchModeLatch(
	nodeID string,
	pol EffectivePolicy,
	merged, tier1Opts, t2, t3, t4 *ssh.Options,
	allowLatch bool,
) *ssh.Options {
	if allowLatch && pol.hasSnapshot && pol.snapshot.Provenance == config.ProvenanceOpenSSHDerived &&
		t4 != nil && t4.BatchMode() && merged != nil && merged.BatchMode() {
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

func (p EffectivePolicy) controlTargetContext(nodeID string) ssh.TargetContext {
	return p.controlTargetContextWithEnv(nodeID, sshenv.Discover())
}

func (p EffectivePolicy) controlTargetContextWithEnv(nodeID string, env ssh.Environment) ssh.TargetContext {
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
	host := effectiveSnapshotHost(p.snapshot, p.hasTier1Auth, p.tier1Auth)
	jumpHost := p.EffectiveJump()
	return ssh.NormalizeTargetContext(ssh.TargetContext{
		Host:          host,
		Port:          effectiveSnapshotPort(p.snapshot.Host.Port),
		User:          strings.TrimSpace(p.snapshot.Identity.User),
		OriginalHost:  origHost,
		CanonicalHost: p.canonicalHost,
		JumpHost:      jumpHost,
	}, env)
}

func (a *SSHAdapter) resolvePolicyTiers(
	nodeName string,
	snapshot config.ConnectionSnapshot,
	snapErr error,
	tier3Global *ssh.Options,
	tier1Auth SessionAuth,
) (tier2Node, tier3Out, tier4OpenSSH *ssh.Options, tier4Proxy ssh.ProxySetting, err error) {
	tier3Out = tier3Global
	if snapErr == nil {
		switch snapshot.Provenance {
		case config.ProvenanceOpenSSHDerived:
			var rawT4 *ssh.Options
			rawT4, err = a.resolveTier4OpenSSHOptions(nodeName, snapErr, snapshot, tier1Auth)
			if err != nil {
				return nil, nil, nil, ssh.UnsetProxySetting(), err
			}
			tier4OpenSSH = rawT4.Clone()
			tier4Proxy, err = a.resolveTier4OpenSSHProxySetting(a.getOpenSSHParser(), nodeName, snapErr, snapshot)
			if err != nil {
				return nil, nil, nil, ssh.UnsetProxySetting(), err
			}
		case config.ProvenanceOpenSSHVirtual:
			tier4OpenSSH = snapshot.Node.SSHOptions.Clone()
			tier4Proxy, err = a.resolveTier4OpenSSHProxySetting(a.getOpenSSHParser(), nodeName, snapErr, snapshot)
			if err != nil {
				return nil, nil, nil, ssh.UnsetProxySetting(), err
			}
		default:
			tier2Node = snapshot.Node.SSHOptions
			var rawT4 *ssh.Options
			rawT4, err = a.resolveTier4OpenSSHOptions(nodeName, snapErr, snapshot, tier1Auth)
			if err != nil {
				return nil, nil, nil, ssh.UnsetProxySetting(), err
			}
			tier4OpenSSH = filterNonVirtualTier4Options(rawT4)
		}
	} else if !config.IsOpenSSHNodeID(nodeName) {
		var rawT4 *ssh.Options
		rawT4, err = a.resolveTier4OpenSSHOptions(nodeName, snapErr, snapshot, tier1Auth)
		if err != nil {
			return nil, nil, nil, ssh.UnsetProxySetting(), err
		}
		tier4OpenSSH = filterNonVirtualTier4Options(rawT4)
	}

	if tier4OpenSSH != nil && !tier4OpenSSH.FilterByClasses(ssh.OptionClassMux).IsEmpty() {
		tier4OpenSSH.ImplicitTier4 = true
	}
	return tier2Node, tier3Out, tier4OpenSSH, tier4Proxy, nil
}

func (a *SSHAdapter) resolveTier4OpenSSHProxySetting(
	parser *config.OpenSSHParser,
	nodeName string,
	snapErr error,
	snapshot config.ConnectionSnapshot,
) (ssh.ProxySetting, error) {
	if parser == nil || snapErr != nil {
		return ssh.UnsetProxySetting(), nil
	}
	switch snapshot.Provenance {
	case config.ProvenanceOpenSSHDerived:
		if err := parser.Err(); err != nil {
			return ssh.UnsetProxySetting(), err
		}
		alias := strings.TrimSpace(snapshot.Node.OpenSSHAlias)
		canonicalHost := strings.TrimSpace(snapshot.Node.CanonicalHost)
		if alias == "" {
			alias = nodeName
		}
		return resolvePrefixedTier4OpenSSHProxySetting(parser, alias, canonicalHost)
	case config.ProvenanceOpenSSHVirtual:
		if err := parser.Err(); err != nil {
			return ssh.UnsetProxySetting(), err
		}
		alias := strings.TrimSpace(snapshot.Node.OpenSSHAlias)
		canonicalHost := strings.TrimSpace(snapshot.Node.CanonicalHost)
		if alias == "" {
			if orig, ok := config.OpenSSHOriginalHost(nodeName); ok {
				alias = orig
			} else {
				alias = config.UnwrapOpenSSHSelector(nodeName)
			}
		}
		return resolvePrefixedTier4OpenSSHProxySetting(parser, alias, canonicalHost)
	default:
		// Saved managed nodes and ad-hoc pending nodes block Tier-4 ProxyJump
		// and OptionClassLocalExec (ProxyCommand) per Tier-4 trust policy.
		return ssh.UnsetProxySetting(), nil
	}
}

func filterNonVirtualTier4Options(rawTier4 *ssh.Options) *ssh.Options {
	if rawTier4 == nil {
		return nil
	}
	filtered := rawTier4.FilterByClasses(
		ssh.OptionClassMux,
		ssh.OptionClassTransport,
	)
	for _, spec := range ssh.RegisteredOptionSpecs() {
		if spec.Tier4Policy != ssh.OptionTier4OneWayYes {
			continue
		}
		trimmed := strings.TrimSpace(rawTier4.Get(spec.CanonicalKey))
		if strings.EqualFold(trimmed, "yes") || strings.EqualFold(trimmed, "true") {
			if filtered == nil {
				filtered = &ssh.Options{}
			}
			_ = filtered.Set(spec.CanonicalKey, "yes")
		} else if filtered != nil {
			filtered.Delete(spec.CanonicalKey)
		}
	}
	if filtered.IsEmpty() {
		return nil
	}
	return filtered
}

func (a *SSHAdapter) resolveTier4OpenSSHOptions(nodeName string, snapErr error, snapshot config.ConnectionSnapshot, tier1Auth SessionAuth) (*ssh.Options, error) {
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
	openSSHAlias, canonicalHost := a.resolveSessionOpenSSHMetadata(parser, nodeName, snapErr, snapshot, tier1Auth)
	lookupKeys := a.buildTier4OpenSSHLookupKeys(parser, nodeName, snapErr, snapshot, openSSHAlias, canonicalHost)
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
	return ssh.MergeOptions(layers...), nil
}

func (a *SSHAdapter) resolveTier4DerivedOpenSSHOptions(parser *config.OpenSSHParser, nodeName string, snapshot config.ConnectionSnapshot) (*ssh.Options, error) {
	if parser == nil {
		return nil, nil
	}
	if err := parser.Err(); err != nil {
		return nil, err
	}
	alias := strings.TrimSpace(snapshot.Node.OpenSSHAlias)
	canonicalHost := strings.TrimSpace(snapshot.Node.CanonicalHost)
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

func savedNodeMatchesVirtualEndpoint(snapshot config.ConnectionSnapshot, vhostEp ssh.Endpoint, canon string) bool {
	nodeEp, err := ssh.NewEndpoint(snapshot.Host.Address, effectiveSnapshotPort(snapshot.Host.Port))
	if err != nil {
		return false
	}
	if nodeEp.Equal(vhostEp) {
		return true
	}
	// When Pass-2 ssh_config omits HostName (DNS resolved canon -> snapshot.Host.Address),
	// accept an alias/FQDN match on the saved node's own aliases only when Port matches.
	if canon == "" {
		return false
	}
	canonEp, err := ssh.NewEndpoint(canon, int(nodeEp.Port()))
	if err != nil || !vhostEp.Equal(canonEp) {
		return false
	}
	for _, alias := range snapshot.Host.Alias {
		if aliasEp, err := ssh.NewEndpoint(alias, int(nodeEp.Port())); err == nil && aliasEp.Equal(canonEp) {
			return true
		}
	}
	for _, alias := range snapshot.Node.Alias {
		if aliasEp, err := ssh.NewEndpoint(alias, int(nodeEp.Port())); err == nil && aliasEp.Equal(canonEp) {
			return true
		}
	}
	return false
}

func resolveScopedSavedOpenSSHAlias(
	parser *config.OpenSSHParser,
	snapshot config.ConnectionSnapshot,
	tier1OriginalHost string,
	tier1CanonicalHost string,
) (string, string, bool) {
	if parser == nil || snapshot.Provenance != config.ProvenanceSavedManaged {
		return "", "", false
	}
	orig := strings.TrimSpace(config.UnwrapOpenSSHSelector(tier1OriginalHost))
	if !config.IsPlainOpenSSHHostSelector(orig) {
		return "", "", false
	}
	canon := strings.TrimSpace(config.UnwrapOpenSSHSelector(tier1CanonicalHost))
	if canon != "" && !strings.EqualFold(orig, canon) {
		_, vhost, _, err := parser.GetVirtualNodeWithCanonical(orig, canon)
		if err != nil {
			return "", "", false
		}
		vhostEp, err := ssh.NewEndpoint(vhost.Address, effectiveSnapshotPort(vhost.Port))
		if err != nil || !savedNodeMatchesVirtualEndpoint(snapshot, vhostEp, canon) {
			return "", "", false
		}
		return orig, canon, true
	}
	if !parser.HasHost(orig) {
		return "", "", false
	}
	_, vhost, _, err := parser.GetVirtualNode(orig)
	if err != nil {
		return "", "", false
	}
	vhostEp, err := ssh.NewEndpoint(vhost.Address, effectiveSnapshotPort(vhost.Port))
	nodeEp, nodeErr := ssh.NewEndpoint(snapshot.Host.Address, effectiveSnapshotPort(snapshot.Host.Port))
	if err != nil || nodeErr != nil || !nodeEp.Equal(vhostEp) {
		return "", "", false
	}
	return orig, "", true
}

func (a *SSHAdapter) resolveSessionOpenSSHMetadata(
	parser *config.OpenSSHParser,
	nodeName string,
	snapErr error,
	snapshot config.ConnectionSnapshot,
	tier1Auth SessionAuth,
) (string, string) {
	t1Orig := strings.TrimSpace(config.UnwrapOpenSSHSelector(tier1Auth.OriginalHost))
	t1Canon := strings.TrimSpace(config.UnwrapOpenSSHSelector(tier1Auth.CanonicalHost))
	if snapErr == nil {
		if snapshot.Provenance != config.ProvenanceSavedManaged {
			return strings.TrimSpace(snapshot.Node.OpenSSHAlias), strings.TrimSpace(snapshot.Node.CanonicalHost)
		}
		snapOrigin := config.OpenSSHOrigin{
			Alias:         strings.TrimSpace(snapshot.Node.OpenSSHAlias),
			CanonicalHost: strings.TrimSpace(snapshot.Node.CanonicalHost),
		}
		if t1Orig != "" || t1Canon != "" {
			if alias, canon, ok := resolveScopedSavedOpenSSHAlias(parser, snapshot, t1Orig, t1Canon); ok {
				return alias, canon
			}
			// Allow matching the saved node's own origin only when the session echoes
			// both the same Alias and the same CanonicalHost (case-insensitive) and
			// re-verification confirms it still targets this saved node's Endpoint.
			if !snapOrigin.IsZero() && t1Orig != "" && t1Orig == snapOrigin.Alias &&
				strings.EqualFold(t1Canon, snapOrigin.CanonicalHost) {
				if alias, canon, ok := resolveScopedSavedOpenSSHAlias(parser, snapshot, snapOrigin.Alias, snapOrigin.CanonicalHost); ok {
					return alias, canon
				}
			}
			return "", ""
		}
		if !snapOrigin.IsZero() {
			if alias, canon, ok := resolveScopedSavedOpenSSHAlias(parser, snapshot, snapOrigin.Alias, snapOrigin.CanonicalHost); ok {
				return alias, canon
			}
		}
		if alias, canon, ok := resolveScopedSavedOpenSSHAlias(parser, snapshot, nodeName, ""); ok {
			return alias, canon
		}
		return "", ""
	}
	if t1Orig != "" || t1Canon != "" {
		return t1Orig, t1Canon
	}
	origin := a.lookupNodeOpenSSHOrigin(nodeName)
	return origin.Alias, origin.CanonicalHost
}

func savedNodeTier4KeyVerdict(parser *config.OpenSSHParser, snapshot config.ConnectionSnapshot, key string) (verdict.Verdict, error) {
	if parser == nil {
		return verdict.Allow, nil
	}
	nodeEp, err := ssh.NewEndpoint(snapshot.Host.Address, effectiveSnapshotPort(snapshot.Host.Port))
	if err != nil {
		return verdict.Deny, err
	}
	if parser.HasHost(key) {
		stanzaEp, err := parser.ResolveEndpoint(key)
		if err != nil {
			return verdict.Deny, err
		}
		if stanzaEp.Equal(nodeEp) {
			return verdict.Allow, nil
		}
		return verdict.Deny, nil
	}
	_, explicitHost, hostErr := parser.ResolveExplicitHostName(key)
	if hostErr != nil {
		return verdict.Deny, hostErr
	}
	_, explicitPort, portErr := parser.ResolveExplicitPort(key)
	if portErr != nil {
		return verdict.Deny, portErr
	}
	if explicitHost || explicitPort {
		resolvedEp, err := parser.ResolveEndpoint(key)
		if err != nil {
			return verdict.Deny, err
		}
		if resolvedEp.Equal(nodeEp) {
			return verdict.Allow, nil
		}
		return verdict.Deny, nil
	}
	keyEp, err := ssh.NewEndpoint(key, int(nodeEp.Port()))
	if err != nil {
		return verdict.Deny, err
	}
	if keyEp.Equal(nodeEp) {
		return verdict.Allow, nil
	}
	return verdict.Deny, nil
}

func savedNodeAllowsTier4Key(parser *config.OpenSSHParser, snapshot config.ConnectionSnapshot, key string) bool {
	return verdict.Decide(func() (verdict.Verdict, error) {
		return savedNodeTier4KeyVerdict(parser, snapshot, key)
	}).Allowed()
}

func (a *SSHAdapter) buildTier4FallbackLookupKeys(parser *config.OpenSSHParser, nodeName, openSSHAlias string, lookupKeys []string) []string {
	appendUnique := func(keys ...string) {
		for _, k := range keys {
			k = strings.TrimSpace(k)
			if k != "" && !slices.Contains(lookupKeys, k) {
				lookupKeys = append(lookupKeys, k)
			}
		}
	}
	if config.IsPlainOpenSSHHostSelector(nodeName) {
		appendUnique(nodeName)
	}
	if addr, port, ok := parseFallbackNodeIDAddressPort(nodeName); ok {
		if openSSHAlias == "" {
			if ep, err := ssh.NewEndpoint(addr, int(port)); err == nil {
				appendUnique(parser.FindConcreteHostsByAddress(ep)...)
			}
		}
		if addr != nodeName {
			appendUnique(addr)
		}
	} else {
		appendUnique(nodeName)
	}
	return lookupKeys
}

func (a *SSHAdapter) buildTier4OpenSSHLookupKeys(parser *config.OpenSSHParser, nodeName string, snapErr error, snapshot config.ConnectionSnapshot, openSSHAlias, canonicalHost string) []string {
	var lookupKeys []string
	savedManaged := snapErr == nil && snapshot.Provenance == config.ProvenanceSavedManaged
	appendKeys := func(checkScope bool, keys ...string) {
		for _, k := range keys {
			k = strings.TrimSpace(k)
			if k == "" || slices.Contains(lookupKeys, k) {
				continue
			}
			if checkScope && savedManaged && !savedNodeAllowsTier4Key(parser, snapshot, k) {
				continue
			}
			lookupKeys = append(lookupKeys, k)
		}
	}

	if openSSHAlias != "" {
		appendKeys(canonicalHost == "", openSSHAlias)
	}
	if canonicalHost != "" {
		appendKeys(false, canonicalHost)
	}
	if snapErr != nil {
		return a.buildTier4FallbackLookupKeys(parser, nodeName, openSSHAlias, lookupKeys)
	}

	appendKeys(true, snapshot.Node.Alias...)
	appendKeys(true, snapshot.Host.Alias...)
	if config.IsPlainOpenSSHHostSelector(nodeName) {
		appendKeys(true, nodeName)
	}
	if snapshot.Host.Address != "" {
		if openSSHAlias == "" {
			if ep, err := ssh.NewEndpoint(snapshot.Host.Address, effectiveSnapshotPort(snapshot.Host.Port)); err == nil {
				appendKeys(false, parser.FindConcreteHostsByAddress(ep)...)
			}
		}
		if snapshot.Host.Address != nodeName {
			appendKeys(true, snapshot.Host.Address)
		}
	}
	appendKeys(true, nodeName)
	return lookupKeys
}

func (a *SSHAdapter) lookupNodeOpenSSHOrigin(nodeName string) config.OpenSSHOrigin {
	if a == nil || a.cfgProvider == nil || nodeName == "" {
		return config.OpenSSHOrigin{}
	}
	if p, ok := a.cfgProvider.(interface {
		NodeOpenSSHOrigin(string) config.OpenSSHOrigin
	}); ok {
		return p.NodeOpenSSHOrigin(nodeName)
	}
	return config.OpenSSHOrigin{
		Alias:         strings.TrimSpace(a.lookupNodeOpenSSHAlias(nodeName)),
		CanonicalHost: strings.TrimSpace(a.lookupNodeCanonicalHost(nodeName)),
	}
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
	host = config.StripHostBrackets(host)
	portPart := strings.TrimSpace(portText)
	if base, suffix, hasDash := strings.Cut(portPart, "-"); hasDash && base != "" && suffix != "" {
		allDigits := true
		for i := 0; i < len(suffix); i++ {
			if suffix[i] < '0' || suffix[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			portPart = base
		}
	}
	parsedPort, parseErr := strconv.ParseUint(portPart, 10, 16)
	if host == "" || parseErr != nil || parsedPort == 0 {
		return "", 0, false
	}
	return host, uint16(parsedPort), true
}
