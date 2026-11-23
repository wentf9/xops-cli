package adapter

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/config"
)

// ControlTargetRequest carries the read-only caller inputs used to resolve the
// authoritative control-plane TargetContext, adapter lookup key, and
// SessionAuth metadata without mutating configuration state or creating pending
// nodes.
type ControlTargetRequest struct {
	Provider                 config.ConfigProvider
	NodeID                   string
	Target                   config.ConnectionTarget
	FallbackHost             string
	FallbackPort             uint16
	FallbackUser             string
	OverrideOriginalHost     string
	OverrideExpandedHost     string
	ApplyTargetNodeOverrides bool
	CanonicalOriginalHost    string
	CanonicalHost            string
	SessionControl           SessionControlOptions
	Environment              *ssh.Environment
}

// ControlTargetResolution holds the canonicalized control-plane TargetContext
// along with the adapter lookup key and SessionAuth metadata needed to resolve
// multiplexing and SSH options without mutating provider state.
type ControlTargetResolution struct {
	Target      ssh.TargetContext
	LookupKey   string
	SessionAuth SessionAuth
}

func validateOpenSSHControlSelector(field, raw string) error {
	if raw == "" {
		return nil
	}
	stripped := trimControlAndSpace(raw)
	if !config.IsOpenSSHNodeID(raw) && !config.IsOpenSSHNodeID(stripped) {
		return nil
	}
	if stripped != raw || hasControlOrLineSepChar(raw) || hasAnyWhitespace(raw) {
		return fmt.Errorf("%w: invalid openssh %s %q: contains whitespace or control characters", ssh.ErrSSHOptionsValidation, field, raw)
	}
	if _, err := config.ParseTargetRef(raw); err != nil {
		return fmt.Errorf("%w: invalid openssh %s %q: %w", ssh.ErrSSHOptionsValidation, field, raw, err)
	}
	return nil
}

func validateOpenSSHControlProxyJump(field, raw string) error {
	if raw == "" {
		return nil
	}
	if hasControlOrLineSepChar(raw) {
		return fmt.Errorf("%w: invalid %s %q: contains control characters", ssh.ErrSSHOptionsValidation, field, raw)
	}
	for hop := range strings.SplitSeq(raw, ",") {
		if err := validateOpenSSHControlSelector(field, hop); err != nil {
			return err
		}
	}
	return nil
}

func validateSessionAuthOpenSSHSelectors(auth SessionAuth) error {
	if err := validateOpenSSHControlSelector("session original host", auth.OriginalHost); err != nil {
		return err
	}
	if err := validateOpenSSHControlSelector("session canonical host", auth.CanonicalHost); err != nil {
		return err
	}
	return validateOpenSSHControlProxyJump("session proxy jump", auth.ProxyJump)
}

func validateControlTargetRequest(req ControlTargetRequest) error {
	for _, field := range []struct {
		name string
		val  string
	}{
		{"node ID", req.NodeID},
		{"target selector", req.Target.Selector},
		{"target raw selector", req.Target.RawSelector},
		{"target original host", req.Target.OriginalHost},
		{"fallback host", req.FallbackHost},
		{"override original host", req.OverrideOriginalHost},
		{"override expanded host", req.OverrideExpandedHost},
		{"canonical original host", req.CanonicalOriginalHost},
		{"canonical host", req.CanonicalHost},
	} {
		if err := validateOpenSSHControlSelector(field.name, field.val); err != nil {
			return err
		}
	}
	return validateOpenSSHControlProxyJump("target proxy jump", req.Target.ProxyJump)
}

func trimNonPaddedOpenSSH(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed != raw && config.IsOpenSSHNodeID(trimmed) {
		return raw
	}
	return trimmed
}

// ResolveControlTarget computes the canonical control-plane TargetContext,
// adapter lookup key, and SessionAuth metadata purely from caller inputs and
// read-only provider lookups (zero config mutation, zero pending-node creation).
func ResolveControlTarget(req ControlTargetRequest) (ControlTargetResolution, error) {
	if err := validateControlTargetRequest(req); err != nil {
		return ControlTargetResolution{}, err
	}
	if _, err := parseControlTier1ProxyJump(req.Target); err != nil {
		return ControlTargetResolution{}, err
	}
	env := resolveControlEnvironment(req.Environment)
	connTarget := prepareControlConnectionTarget(req)
	target, hasResolved, err := resolveControlTargetContext(req, connTarget, env)
	if err != nil {
		return ControlTargetResolution{}, err
	}
	lookupKey, sessionAuth := resolveControlSessionLookup(req, connTarget, target, hasResolved)
	return ControlTargetResolution{
		Target:      target,
		LookupKey:   lookupKey,
		SessionAuth: sessionAuth,
	}, nil
}

func savedHostMatchesSelector(addr string, aliases []string, selector, normSel string) bool {
	if addr == selector || (normSel != "" && config.NormalizeHostAddress(addr) == normSel) {
		return true
	}
	for _, alias := range aliases {
		if alias == selector || strings.EqualFold(alias, selector) ||
			(normSel != "" && config.NormalizeHostAddress(alias) == normSel) {
			return true
		}
	}
	return false
}

func isSavedControlNodeID(provider config.ConfigProvider, selector string) bool {
	if provider == nil || selector == "" || config.IsOpenSSHNodeID(selector) {
		return false
	}
	if _, ok := provider.GetNode(selector); ok {
		return true
	}
	if aliasID := provider.FindAlias(selector); aliasID != "" {
		return true
	}
	snap := provider.Snapshot()
	if snap == nil || snap.Nodes == nil {
		return false
	}
	normSel := config.NormalizeHostAddress(selector)
	for _, nid := range snap.Nodes.Keys() {
		n, ok := snap.Nodes.Get(nid)
		if !ok {
			continue
		}
		if slices.Contains(n.Alias, selector) {
			return true
		}
		if snap.Hosts == nil {
			continue
		}
		if h, hOK := snap.Hosts.Get(n.HostRef); hOK && savedHostMatchesSelector(h.Address, h.Alias, selector, normSel) {
			return true
		}
	}
	return false
}

func controlSelectorHost(sel string) string {
	ref, err := config.ParseTargetRef(sel)
	if err != nil || ref.OpenSSH || ref.Host == "" {
		return sel
	}
	return ref.Host
}

func shouldPropagateControlCanonicalOrigin(provider config.ConfigProvider, sel, canonOrig, canonHost string) bool {
	if sel == "" || config.IsOpenSSHNodeID(sel) {
		return true
	}
	if canonHost != "" && isSavedControlNodeID(provider, sel) &&
		!strings.EqualFold(sel, canonOrig) && !strings.EqualFold(sel, canonHost) {
		return false
	}
	host := controlSelectorHost(sel)
	if host != sel && canonHost != "" && isSavedControlNodeID(provider, host) &&
		!strings.EqualFold(host, canonOrig) && !strings.EqualFold(host, canonHost) {
		return false
	}
	return true
}

func rewriteOpenSSHLookupKeyHost(lookupKey, canonHost string) string {
	canonHost = strings.TrimSpace(canonHost)
	if canonHost == "" {
		return lookupKey
	}
	if ref, err := config.ParseTargetRef(lookupKey); err == nil && ref.OpenSSH {
		ref.Host = canonHost
		if norm := ref.NormalizedString(); norm != "" {
			return norm
		}
	}
	return config.OpenSSHNodePrefix + canonHost
}

func prepareControlConnectionTarget(req ControlTargetRequest) config.ConnectionTarget {
	connTarget := req.Target
	if strings.TrimSpace(connTarget.Selector) == "" && strings.TrimSpace(req.NodeID) != "" {
		connTarget.Selector = trimNonPaddedOpenSSH(req.NodeID)
	}
	if !connTarget.HasProxyJump && connTarget.ProxyJump == "" {
		if jump, hasJump := EffectiveTier1ProxyJumpOverride(req.SessionControl, ""); hasJump {
			connTarget.ProxyJump = jump
			connTarget.HasProxyJump = true
		}
	}
	canonOrig := strings.TrimSpace(req.CanonicalOriginalHost)
	canonHost := strings.TrimSpace(req.CanonicalHost)
	if canonOrig == "" && canonHost == "" {
		return connTarget
	}
	sel := trimNonPaddedOpenSSH(connTarget.Selector)
	if strings.TrimSpace(connTarget.OriginalHost) == "" && canonOrig != "" &&
		shouldPropagateControlCanonicalOrigin(req.Provider, sel, canonOrig, canonHost) {
		connTarget.OriginalHost = canonOrig
	}
	if canonHost != "" && sel != "" {
		applyCanonicalHostToControlSelector(req.Provider, &connTarget, sel, canonOrig, canonHost)
	}
	return connTarget
}

func applyCanonicalHostToControlSelector(
	provider config.ConfigProvider,
	connTarget *config.ConnectionTarget,
	sel, canonOrig, canonHost string,
) {
	if config.IsOpenSSHNodeID(sel) {
		applyCanonicalHostToOpenSSHSelector(connTarget, canonOrig, canonHost)
		return
	}
	applyCanonicalHostToPlainSelector(provider, connTarget, sel, canonOrig, canonHost)
}

func applyCanonicalHostToOpenSSHSelector(connTarget *config.ConnectionTarget, canonOrig, canonHost string) {
	ref, err := config.ParseTargetRef(connTarget.Selector)
	if err != nil || !ref.OpenSSH || strings.EqualFold(ref.Host, canonHost) {
		return
	}
	if canonOrig != "" && !strings.EqualFold(ref.Host, canonOrig) {
		return
	}
	if strings.TrimSpace(connTarget.OriginalHost) == "" {
		connTarget.OriginalHost = ref.Host
	}
	ref.Host = canonHost
	if norm := ref.NormalizedString(); norm != "" {
		connTarget.Selector = norm
	}
}

func applyCanonicalHostToPlainSelector(
	provider config.ConfigProvider,
	connTarget *config.ConnectionTarget,
	sel, canonOrig, canonHost string,
) {
	if isSavedControlNodeID(provider, sel) || strings.EqualFold(sel, canonHost) {
		return
	}
	if ref, err := config.ParseTargetRef(sel); err == nil && !ref.OpenSSH && ref.Host != "" {
		if isSavedControlNodeID(provider, ref.Host) || strings.EqualFold(ref.Host, canonHost) {
			return
		}
		if canonOrig != "" && !strings.EqualFold(ref.Host, canonOrig) {
			return
		}
		if strings.TrimSpace(connTarget.OriginalHost) == "" {
			connTarget.OriginalHost = ref.Host
		}
		ref.Host = canonHost
		if norm := ref.NormalizedString(); norm != "" {
			connTarget.Selector = norm
			return
		}
	}
	if canonOrig != "" && !strings.EqualFold(sel, canonOrig) {
		return
	}
	if strings.TrimSpace(connTarget.OriginalHost) == "" {
		connTarget.OriginalHost = sel
	}
	connTarget.Selector = canonHost
}

func controlTargetResolved(req ControlTargetRequest, connTarget config.ConnectionTarget) bool {
	if strings.TrimSpace(connTarget.Selector) == "" {
		return false
	}
	effectiveProvider := req.Provider
	if effectiveProvider == nil {
		effectiveProvider = config.NewProviderWithoutOpenSSH(nil)
	}
	lookupTarget := connTarget
	if req.Provider == nil || (req.ApplyTargetNodeOverrides && strings.TrimSpace(req.OverrideExpandedHost) != "") {
		lookupTarget.ProxyJump = "none"
		lookupTarget.HasProxyJump = true
	}
	_, err := config.ResolveTarget(effectiveProvider, lookupTarget)
	return err == nil
}

// ResolveControlSessionLookup computes the effective adapter lookup key and
// SessionAuth metadata for an already-resolved TargetContext purely from caller
// inputs and read-only provider lookups without mutating provider state.
func ResolveControlSessionLookup(req ControlTargetRequest, target ssh.TargetContext) (string, SessionAuth) {
	connTarget := prepareControlConnectionTarget(req)
	return resolveControlSessionLookup(req, connTarget, target, controlTargetResolved(req, connTarget))
}

func validateControlConfigSelectors(lookupKey, selector string, sessionAuth SessionAuth) error {
	for _, field := range []struct {
		name string
		val  string
	}{
		{"lookup key", lookupKey},
		{"selector", selector},
	} {
		if err := validateOpenSSHControlSelector(field.name, field.val); err != nil {
			return err
		}
	}
	return validateSessionAuthOpenSSHSelectors(sessionAuth)
}

// EffectiveTier1ProxyJumpOverride computes the effective Tier-1 ConnectionTarget
// ProxyJump override from an already-parsed SessionControlOptions and optional
// explicit jump override. Per core/ssh.ProxySetting precedence, Tier-1
// ProxyDisabled (ProxyJump=none / ProxyCommand=none) or active ProxyCommand
// maps to ("none", true) so lower-tier ProxyJump validation is canceled.
func EffectiveTier1ProxyJumpOverride(sessionOpts SessionControlOptions, explicitJump string) (string, bool) {
	return effectiveControlConfigJumpOverride(SessionAuth{ProxyJump: explicitJump}, sessionOpts)
}

// EffectiveCLIProxyJumpOverride parses rawCLIOptions and explicit cliProxyJump
// through ParseSessionOptions and computes the effective Tier-1 ConnectionTarget
// ProxyJump override. When Tier-1 resolves to ProxyDisabled or ProxyCommand, it
// returns ("none", true, nil) so lower-tier ProxyJump validation is canceled.
func EffectiveCLIProxyJumpOverride(rawCLIOptions []string, cliProxyJump string) (string, bool, error) {
	if len(rawCLIOptions) == 0 && cliProxyJump == "" {
		return "", false, nil
	}
	sessionOpts, err := ParseSessionOptions(rawCLIOptions, cliProxyJump)
	if err != nil {
		return "", false, err
	}
	jump, hasJump := EffectiveTier1ProxyJumpOverride(sessionOpts, "")
	return jump, hasJump, nil
}

func effectiveControlConfigJumpOverride(sessionAuth SessionAuth, sessionOpts SessionControlOptions) (string, bool) {
	if sessionAuth.ProxyJump != "" {
		return sessionAuth.ProxyJump, true
	}
	ps := ssh.MergeProxySettings(sessionOpts.ProxySetting(), proxyCommandSetting(sessionOpts.Options))
	switch {
	case ps.Kind() == ssh.ProxyJump:
		if targets, ok := ps.JumpTargets(); ok {
			return strings.Join(targets, ","), true
		}
	case ps.Kind() == ssh.ProxyDisabled || ps.Kind() == ssh.ProxyCommand:
		return "none", true
	}
	return "", false
}

func isDerivedOpenSSHResolvedTarget(resolved config.ResolvedTarget) bool {
	if resolved.Provenance == config.ProvenanceOpenSSHDerived {
		return true
	}
	return resolved.Provenance == config.ProvenanceUnknown && config.IsOpenSSHNodeID(resolved.BaseNodeID)
}

func derivedOpenSSHLookupKey(resolved config.ResolvedTarget) string {
	if canon := strings.TrimSpace(resolved.CanonicalHost); canon != "" {
		return config.OpenSSHNodePrefix + canon
	}
	if config.IsOpenSSHNodeID(resolved.BaseNodeID) {
		return resolved.BaseNodeID
	}
	if alias := strings.TrimSpace(resolved.OpenSSHAlias); alias != "" {
		return config.OpenSSHNodePrefix + alias
	}
	return resolved.NodeID
}

func applyResolvedOpenSSHOriginToSessionAuth(resolved config.ResolvedTarget, auth SessionAuth) SessionAuth {
	if strings.TrimSpace(auth.OriginalHost) == "" && strings.TrimSpace(resolved.OpenSSHAlias) != "" {
		auth.OriginalHost = strings.TrimSpace(resolved.OpenSSHAlias)
	}
	if strings.TrimSpace(auth.CanonicalHost) == "" && strings.TrimSpace(resolved.CanonicalHost) != "" {
		auth.CanonicalHost = strings.TrimSpace(resolved.CanonicalHost)
	}
	return auth
}

func resolveControlConfigLookupFromResolvedTarget(resolved config.ResolvedTarget, sessionAuth SessionAuth) (string, SessionAuth, bool) {
	if resolved.MatchedNodeID != "" {
		if config.IsOpenSSHNodeID(resolved.MatchedNodeID) {
			sessionAuth = applyResolvedOpenSSHOriginToSessionAuth(resolved, sessionAuth)
		}
		return resolved.MatchedNodeID, sessionAuth, true
	}
	if isDerivedOpenSSHResolvedTarget(resolved) {
		return derivedOpenSSHLookupKey(resolved), applyResolvedOpenSSHOriginToSessionAuth(resolved, sessionAuth), true
	}
	if resolved.NodeID != "" {
		return resolved.NodeID, sessionAuth, true
	}
	return "", sessionAuth, false
}

func resolveControlConfigLookupKey(
	provider config.ConfigProvider,
	lookupKey, selector string,
	sessionAuth SessionAuth,
	sessionOpts SessionControlOptions,
) (string, SessionAuth, error) {
	if lookupKey == "" {
		if provider != nil && strings.TrimSpace(selector) != "" {
			jump, hasJump := effectiveControlConfigJumpOverride(sessionAuth, sessionOpts)
			hadTier1Jump := hasJump
			overrideHost := strings.TrimSpace(sessionAuth.HostName)
			if overrideHost != "" {
				jump = "none"
				hasJump = true
			}
			sessUser := strings.TrimSpace(sessionAuth.User)
			origHost := strings.TrimSpace(sessionAuth.OriginalHost)
			canonHost := strings.TrimSpace(sessionAuth.CanonicalHost)
			connTarget := config.ConnectionTarget{
				Selector:     selector,
				OriginalHost: origHost,
				User:         sessUser,
				HasUser:      sessUser != "",
				Port:         sessionAuth.Port,
				HasPort:      sessionAuth.Port > 0,
				ProxyJump:    jump,
				HasProxyJump: hasJump,
			}
			trimmedSel := trimNonPaddedOpenSSH(selector)
			if canonHost != "" && shouldPropagateControlCanonicalOrigin(provider, trimmedSel, origHost, canonHost) {
				applyCanonicalHostToControlSelector(provider, &connTarget, trimmedSel, origHost, canonHost)
			}
			resolved, err := config.ResolveTarget(provider, connTarget)
			if err != nil {
				if !isTargetMissingError(err) {
					return "", sessionAuth, err
				}
			} else {
				if overrideHost != "" && !hadTier1Jump && resolved.MatchedNodeID == "" {
					baseTarget := connTarget
					baseTarget.ProxyJump = ""
					baseTarget.HasProxyJump = false
					syntheticReq := ControlTargetRequest{
						Provider:                 provider,
						Target:                   baseTarget,
						OverrideExpandedHost:     overrideHost,
						ApplyTargetNodeOverrides: true,
						SessionControl:           sessionOpts,
					}
					if _, jumpErr := resolveControlEffectiveJumpHost(syntheticReq, baseTarget, true, resolved); jumpErr != nil {
						return "", sessionAuth, jumpErr
					}
				}
				if resolvedKey, updatedAuth, ok := resolveControlConfigLookupFromResolvedTarget(resolved, sessionAuth); ok {
					return resolvedKey, updatedAuth, nil
				}
			}
		}
		// Resolve treats an unknown selector as "no node layer" and falls
		// back to session > global > OpenSSH, which is the ad-hoc case.
		lookupKey = selector
	}
	if provider != nil && lookupKey != "" && !config.IsOpenSSHNodeID(lookupKey) {
		if _, ok := provider.GetNode(lookupKey); !ok {
			if aliasID := provider.FindAlias(lookupKey); aliasID != "" {
				return aliasID, sessionAuth, nil
			}
		}
	}
	return lookupKey, sessionAuth, nil
}

// ResolveControlConfig resolves the effective multiplexing ControlConfig for
// lookupKey with the given session overrides via the single SSHAdapter.Resolve
// entry point. When the selector matches no inventory node, SSHAdapter.Resolve
// still merges session, global, and OpenSSH layers so ad-hoc hosts are
// validated identically to managed ones.
func ResolveControlConfig(
	provider config.ConfigProvider,
	lookupKey, selector string,
	sessionAuth SessionAuth,
	sessionOpts SessionControlOptions,
) (*ssh.ControlConfig, error) {
	if err := validateControlConfigSelectors(lookupKey, selector, sessionAuth); err != nil {
		return nil, err
	}
	var sessionJumpPS ssh.ProxySetting
	if sessionAuth.ProxyJump != "" {
		ps, err := ssh.ParseProxyJump(sessionAuth.ProxyJump)
		if err != nil {
			return nil, fmt.Errorf("invalid session ProxyJump %q: %w", sessionAuth.ProxyJump, err)
		}
		sessionJumpPS = ps
	}
	var err error
	lookupKey, sessionAuth, err = resolveControlConfigLookupKey(provider, lookupKey, selector, sessionAuth, sessionOpts)
	if err != nil {
		return nil, err
	}
	nilProvider := provider == nil
	if nilProvider {
		if err := validateNilProviderControlJump(lookupKey, selector, sessionAuth, sessionJumpPS, sessionOpts); err != nil {
			return nil, err
		}
		if sessionOpts.IsEmpty() {
			return nil, nil
		}
		provider = config.NewProviderWithoutOpenSSH(nil)
	} else if lookupKey == "" && sessionJumpPS.Kind() == ssh.ProxyJump {
		if err := validateEmptyLookupKeyControlJump(provider, selector, sessionAuth); err != nil {
			return nil, err
		}
	}
	adpOpts := []Option{WithControlProxyMode(true)}
	if lookupKey != "" && hasControlSessionAuthOverrides(sessionAuth) {
		adpOpts = append(adpOpts, WithSessionAuthOverride(lookupKey, sessionAuth))
	}
	pol, err := NewSSHAdapter(provider, adpOpts...).Resolve(context.Background(), ResolveRequest{
		NodeID:         lookupKey,
		SessionControl: &sessionOpts,
		ResolveProxy:   !nilProvider,
	})
	if err != nil {
		return nil, err
	}
	return pol.Control(), nil
}

func hasControlSessionAuthOverrides(auth SessionAuth) bool {
	return auth.OriginalHost != "" || auth.CanonicalHost != "" || auth.ProxyJump != "" ||
		auth.HostName != "" || auth.User != "" || auth.Port > 0
}

func validateNilProviderControlJump(
	lookupKey, selector string,
	sessionAuth SessionAuth,
	sessionJumpPS ssh.ProxySetting,
	sessionOpts SessionControlOptions,
) error {
	t1Proxy := ssh.MergeProxySettings(sessionJumpPS, sessionOpts.ProxySetting(), proxyCommandSetting(sessionOpts.Options))
	rawJump := sessionAuth.ProxyJump
	if rawJump == "" {
		if targets, ok := t1Proxy.JumpTargets(); ok {
			rawJump = strings.Join(targets, ",")
		}
	}
	return validateNilProviderSessionJump(lookupKey, selector, sessionAuth, t1Proxy, rawJump)
}

func validateEmptyLookupKeyControlJump(provider config.ConfigProvider, selector string, sessionAuth SessionAuth) error {
	resolvedJump, jErr := provider.ResolveProxyJumpChain(strings.TrimSpace(sessionAuth.ProxyJump))
	if jErr != nil {
		return fmt.Errorf("resolve session proxy jump %q failed: %w", sessionAuth.ProxyJump, jErr)
	}
	var parser *config.OpenSSHParser
	if src, ok := provider.(interface{ GetOpenSSHParser() *config.OpenSSHParser }); ok && src != nil {
		parser = src.GetOpenSSHParser()
	}
	dest := buildNoSnapshotPolicyProxyJumpTarget(provider, parser, config.ProxyJumpTarget{
		NodeID:        strings.TrimSpace(selector),
		Selector:      strings.TrimSpace(selector),
		OpenSSHAlias:  strings.TrimSpace(config.UnwrapOpenSSHSelector(sessionAuth.OriginalHost)),
		CanonicalHost: strings.TrimSpace(config.UnwrapOpenSSHSelector(sessionAuth.CanonicalHost)),
		IsAdHoc:       true,
	}, sessionAuth, true)
	return config.ValidateProxyJumpChainCycle(provider, dest, resolvedJump, sessionAuth.ProxyJump)
}

func validateNilProviderSessionJump(lookupKey, selector string, sessionAuth SessionAuth, ps ssh.ProxySetting, rawJump string) error {
	targets, ok := ps.JumpTargets()
	if !ok {
		return nil
	}
	validated, err := validateNoProviderJumpChain(targets)
	if err != nil {
		return err
	}
	destID := strings.TrimSpace(lookupKey)
	if destID == "" {
		destID = strings.TrimSpace(selector)
	}
	dest := buildNoSnapshotPolicyProxyJumpTarget(nil, nil, config.ProxyJumpTarget{
		NodeID:        destID,
		Selector:      strings.TrimSpace(selector),
		OpenSSHAlias:  strings.TrimSpace(config.UnwrapOpenSSHSelector(sessionAuth.OriginalHost)),
		CanonicalHost: strings.TrimSpace(config.UnwrapOpenSSHSelector(sessionAuth.CanonicalHost)),
		IsAdHoc:       true,
	}, sessionAuth, true)
	return config.ValidateProxyJumpChainCycle(nil, dest, validated, rawJump)
}

// ResolveControlSocketPath resolves the control-plane target, lookup metadata,
// and effective ControlConfig, then expands the resulting control socket path.
// It returns ("", resolution, nil) when control multiplexing is disabled/unset.
func ResolveControlSocketPath(req ControlTargetRequest) (string, ControlTargetResolution, error) {
	if err := validateControlTargetRequest(req); err != nil {
		return "", ControlTargetResolution{}, err
	}
	env := resolveControlEnvironment(req.Environment)
	res, err := ResolveControlTarget(req)
	if err != nil {
		return "", ControlTargetResolution{}, err
	}
	selector := trimNonPaddedOpenSSH(req.Target.Selector)
	if selector == "" {
		selector = trimNonPaddedOpenSSH(req.NodeID)
	}
	ctrl, err := ResolveControlConfig(req.Provider, res.LookupKey, selector, res.SessionAuth, req.SessionControl)
	if err != nil {
		return "", res, err
	}
	if !ctrl.IsEnabled() {
		return "", res, nil
	}
	expanded, err := ctrl.ResolvePath(env, res.Target)
	if err != nil {
		return "", res, err
	}
	if strings.TrimSpace(expanded) == "" || ssh.IsNoneValue(expanded) {
		return "", res, nil
	}
	return expanded, res, nil
}

func resolveControlEnvironment(env *ssh.Environment) ssh.Environment {
	if env != nil {
		return *env
	}
	return sshenv.Discover()
}

func resolveControlTargetContext(req ControlTargetRequest, connTarget config.ConnectionTarget, env ssh.Environment) (ssh.TargetContext, bool, error) {
	var (
		target         ssh.TargetContext
		resolvedTarget config.ResolvedTarget
		hasResolved    bool
	)
	if strings.TrimSpace(connTarget.Selector) != "" {
		effectiveProvider := req.Provider
		if effectiveProvider == nil {
			effectiveProvider = config.NewProviderWithoutOpenSSH(nil)
		}
		lookupTarget := connTarget
		if req.Provider == nil || (req.ApplyTargetNodeOverrides && strings.TrimSpace(req.OverrideExpandedHost) != "") {
			lookupTarget.ProxyJump = "none"
			lookupTarget.HasProxyJump = true
		}
		resolved, err := config.ResolveTarget(effectiveProvider, lookupTarget)
		if err != nil {
			if !isTargetMissingError(err) {
				return ssh.TargetContext{}, false, err
			}
		} else {
			resolvedTarget = resolved
			hasResolved = true
			target = TargetContextFromResolvedTarget(resolved, env)
			applyTargetNodeOverrides(req, &target)
		}
	}
	if !hasResolved {
		orig := connTarget.Selector
		if cleanOrig, ok := config.OpenSSHOriginalHost(orig); ok {
			orig = cleanOrig
		}
		target = ssh.TargetContext{
			Host:          req.FallbackHost,
			Port:          int(req.FallbackPort),
			User:          req.FallbackUser,
			OriginalHost:  orig,
			CanonicalHost: req.CanonicalHost,
			JumpHost:      strings.TrimSpace(connTarget.ProxyJump),
		}
		applyTargetNodeOverrides(req, &target)
		if connTarget.HasUser && connTarget.User != "" {
			target.User = connTarget.User
		}
		if connTarget.HasPort && connTarget.Port > 0 {
			target.Port = int(connTarget.Port)
		}
	}
	jumpHost, err := resolveControlEffectiveJumpHost(req, connTarget, hasResolved, resolvedTarget)
	if err != nil {
		return ssh.TargetContext{}, false, err
	}
	target.JumpHost = jumpHost
	return ssh.NormalizeTargetContext(target, env), hasResolved, nil
}

func applyTargetNodeOverrides(req ControlTargetRequest, target *ssh.TargetContext) {
	if target == nil || !req.ApplyTargetNodeOverrides {
		return
	}
	if orig := strings.TrimSpace(req.OverrideOriginalHost); orig != "" {
		if cleanOrig, ok := config.OpenSSHOriginalHost(orig); ok {
			orig = cleanOrig
		}
		target.OriginalHost = orig
	}
	if expandedHost := strings.TrimSpace(req.OverrideExpandedHost); expandedHost != "" {
		target.Host = expandedHost
	}
}

func parseControlTier1ProxyJump(connTarget config.ConnectionTarget) (ssh.ProxySetting, error) {
	if !connTarget.HasProxyJump && connTarget.ProxyJump == "" {
		return ssh.UnsetProxySetting(), nil
	}
	ps, err := ssh.ParseProxyJump(connTarget.ProxyJump)
	if err != nil {
		return ssh.UnsetProxySetting(), fmt.Errorf("invalid target ProxyJump %q: %w", connTarget.ProxyJump, err)
	}
	return ps, nil
}

func resolveControlTier1ProxySetting(connTarget config.ConnectionTarget, sessionCtrl SessionControlOptions) (ssh.ProxySetting, error) {
	t1Jump, err := parseControlTier1ProxyJump(connTarget)
	if err != nil {
		return ssh.UnsetProxySetting(), err
	}
	return ssh.MergeProxySettings(
		t1Jump,
		sessionCtrl.ProxySetting(),
		proxyCommandSetting(sessionCtrl.Options),
	), nil
}

func collectMatchingHostProxyJumps(snap *config.Configuration, targetEp ssh.Endpoint) (map[string]struct{}, error) {
	jumpSet := make(map[string]struct{})
	for _, nid := range snap.Nodes.Keys() {
		n, ok := snap.Nodes.Get(nid)
		if !ok {
			continue
		}
		h, hOK := snap.Hosts.Get(n.HostRef)
		if !hOK {
			continue
		}
		hostPort := h.Port
		if hostPort == 0 {
			hostPort = 22
		}
		hostEp, hErr := ssh.NewEndpoint(h.Address, int(hostPort))
		if hErr != nil || !hostEp.Equal(targetEp) {
			continue
		}
		ps, pErr := proxySettingFromJumpString(n.ProxyJump)
		if pErr != nil {
			return nil, fmt.Errorf("invalid node ProxyJump %q: %w", n.ProxyJump, pErr)
		}
		var trimmedJump string
		if targets, ok := ps.JumpTargets(); ok {
			validated, vErr := validateNoProviderJumpChain(targets)
			if vErr != nil {
				return nil, vErr
			}
			trimmedJump = validated
		}
		jumpSet[trimmedJump] = struct{}{}
	}
	return jumpSet, nil
}

// resolveInheritedHostProxyJump mirrors pkg/config/target.go:resolveJumpForNode's
// saved-node host scan when ResolveTarget had ProxyJump="none" injected to defer
// cycle validation until after -o HostName overrides are applied.
func resolveInheritedHostProxyJump(provider config.ConfigProvider, host string, port uint16) (ssh.ProxySetting, bool, error) {
	if provider == nil {
		return ssh.UnsetProxySetting(), false, nil
	}
	snap := provider.Snapshot()
	if snap == nil || snap.Nodes == nil || snap.Hosts == nil {
		return ssh.UnsetProxySetting(), false, nil
	}
	cleanHost := config.NormalizeHostAddress(host)
	if cleanHost == "" {
		return ssh.UnsetProxySetting(), false, nil
	}
	targetPort := port
	if targetPort == 0 {
		targetPort = 22
	}
	targetEp, tErr := ssh.NewEndpoint(cleanHost, int(targetPort))
	if tErr != nil {
		return ssh.UnsetProxySetting(), false, nil
	}
	jumpSet, err := collectMatchingHostProxyJumps(snap, targetEp)
	if err != nil {
		return ssh.UnsetProxySetting(), false, err
	}
	switch len(jumpSet) {
	case 0:
		return ssh.UnsetProxySetting(), false, nil
	case 1:
		for j := range jumpSet {
			if j == "" {
				return ssh.UnsetProxySetting(), true, nil
			}
			ps, err := proxySettingFromJumpString(j)
			if err != nil {
				return ssh.UnsetProxySetting(), false, fmt.Errorf("invalid node ProxyJump %q: %w", j, err)
			}
			return ps, true, nil
		}
		return ssh.UnsetProxySetting(), true, nil
	default:
		return ssh.UnsetProxySetting(), false, fmt.Errorf("ambiguous proxy jump: multiple nodes for host %s have conflicting proxy jumps",
			config.FormatHostPort(cleanHost, targetPort))
	}
}

func resolveControlTier2ProxySetting(
	provider config.ConfigProvider,
	connTarget config.ConnectionTarget,
	hasResolved bool,
	resolved config.ResolvedTarget,
) (ssh.ProxySetting, error) {
	return resolveControlTier2ProxySettingWithHostOverride(provider, connTarget, hasResolved, resolved, false)
}

func resolveControlTier2ProxySettingWithHostOverride(
	provider config.ConfigProvider,
	connTarget config.ConnectionTarget,
	hasResolved bool,
	resolved config.ResolvedTarget,
	hostNameSuppressedJump bool,
) (ssh.ProxySetting, error) {
	if !hasResolved || resolved.Provenance.IsUnpersistedOpenSSH() {
		return ssh.UnsetProxySetting(), nil
	}
	var t2Jump, t2Cmd ssh.ProxySetting
	if provider != nil && resolved.MatchedNodeID != "" && !config.IsOpenSSHNodeID(resolved.MatchedNodeID) {
		if node, ok := provider.GetNode(resolved.MatchedNodeID); ok {
			ps, err := proxySettingFromJumpString(node.ProxyJump)
			if err != nil {
				return ssh.UnsetProxySetting(), fmt.Errorf("invalid node ProxyJump %q: %w", node.ProxyJump, err)
			}
			t2Jump = ps
			t2Cmd = proxyCommandSetting(node.SSHOptions)
			return t2Jump.Merge(t2Cmd), nil
		}
	}
	if !connTarget.HasProxyJump && connTarget.ProxyJump == "" {
		if resolved.ProxyJump != "" {
			ps, err := proxySettingFromJumpString(resolved.ProxyJump)
			if err != nil {
				return ssh.UnsetProxySetting(), fmt.Errorf("invalid node ProxyJump %q: %w", resolved.ProxyJump, err)
			}
			t2Jump = ps
		} else if hostNameSuppressedJump {
			ps, _, err := resolveInheritedHostProxyJump(provider, resolved.Host, resolved.Port)
			if err != nil {
				return ssh.UnsetProxySetting(), err
			}
			t2Jump = ps
		}
	}
	return t2Jump, nil
}

func resolveControlTier3ProxySetting(provider config.ConfigProvider) ssh.ProxySetting {
	if provider == nil {
		return ssh.UnsetProxySetting()
	}
	if snap := provider.Snapshot(); snap != nil {
		return proxyCommandSetting(snap.SSHOptions)
	}
	return ssh.UnsetProxySetting()
}

func resolveControlTier4ProxySetting(
	provider config.ConfigProvider,
	connTarget config.ConnectionTarget,
	hasResolved bool,
	resolved config.ResolvedTarget,
) (ssh.ProxySetting, error) {
	return resolveControlTier4ProxySettingWithHostOverride(provider, connTarget, hasResolved, resolved, false)
}

func resolveControlTier4ProxySettingWithHostOverride(
	provider config.ConfigProvider,
	connTarget config.ConnectionTarget,
	hasResolved bool,
	resolved config.ResolvedTarget,
	hostNameSuppressedJump bool,
) (ssh.ProxySetting, error) {
	if !hasResolved || !resolved.Provenance.IsUnpersistedOpenSSH() {
		return ssh.UnsetProxySetting(), nil
	}
	var t4Jump, t4Parser ssh.ProxySetting
	if !connTarget.HasProxyJump && connTarget.ProxyJump == "" {
		if resolved.ProxyJump != "" {
			ps, err := proxySettingFromJumpString(resolved.ProxyJump)
			if err != nil {
				return ssh.UnsetProxySetting(), fmt.Errorf("invalid OpenSSH ProxyJump %q: %w", resolved.ProxyJump, err)
			}
			t4Jump = ps
		} else if hostNameSuppressedJump && resolved.MatchedNodeID == "" {
			ps, _, err := resolveInheritedHostProxyJump(provider, resolved.Host, resolved.Port)
			if err != nil {
				return ssh.UnsetProxySetting(), err
			}
			t4Jump = ps
		}
	}
	if parserSrc, ok := provider.(interface{ GetOpenSSHParser() *config.OpenSSHParser }); ok && parserSrc != nil {
		if parser := parserSrc.GetOpenSSHParser(); parser != nil {
			if err := parser.Err(); err != nil {
				return ssh.UnsetProxySetting(), err
			}
			alias := strings.TrimSpace(resolved.OpenSSHAlias)
			if alias == "" {
				alias = strings.TrimSpace(config.UnwrapOpenSSHSelector(resolved.NodeID))
			}
			canon := strings.TrimSpace(resolved.CanonicalHost)
			if alias == "" {
				alias = canon
			}
			if alias != "" || canon != "" {
				ps, err := resolvePrefixedTier4OpenSSHProxySetting(parser, alias, canon)
				if err != nil {
					return ssh.UnsetProxySetting(), err
				}
				t4Parser = ps
			}
		}
	}
	return t4Jump.Merge(t4Parser), nil
}

func validateNoProviderJumpChain(targets []string) (string, error) {
	out := make([]string, 0, len(targets))
	for _, rawHop := range targets {
		hop := strings.TrimSpace(rawHop)
		if hop == "" {
			return "", fmt.Errorf("%w: empty ProxyJump hop", ssh.ErrSSHOptionsValidation)
		}
		if hasControlOrLineSepChar(rawHop) || (config.IsOpenSSHNodeID(hop) && hasAnyWhitespace(hop)) {
			return "", fmt.Errorf("%w: invalid jump host %q", ssh.ErrSSHOptionsValidation, rawHop)
		}
		ref, err := config.ParseTargetRef(hop)
		if err != nil {
			return "", fmt.Errorf("%w: invalid jump host %q: %w", ssh.ErrSSHOptionsValidation, hop, err)
		}
		if err := ref.Validate(); err != nil {
			return "", fmt.Errorf("%w: invalid jump host %q: %w", ssh.ErrSSHOptionsValidation, hop, err)
		}
		if ref.OpenSSH {
			out = append(out, ref.NormalizedString())
		} else {
			out = append(out, hop)
		}
	}
	return strings.Join(out, ","), nil
}

func resolveControlDestinationNodeID(
	req ControlTargetRequest,
	connTarget config.ConnectionTarget,
	hasResolved bool,
	resolved config.ResolvedTarget,
) string {
	if hasResolved {
		if resolved.MatchedNodeID != "" {
			return resolved.MatchedNodeID
		}
		if resolved.NodeID != "" {
			return resolved.NodeID
		}
	}
	if id := strings.TrimSpace(req.NodeID); id != "" {
		return id
	}
	return strings.TrimSpace(connTarget.Selector)
}

func buildControlProxyJumpTarget(
	req ControlTargetRequest,
	connTarget config.ConnectionTarget,
	hasResolved bool,
	resolved config.ResolvedTarget,
) config.ProxyJumpTarget {
	destID := resolveControlDestinationNodeID(req, connTarget, hasResolved, resolved)
	var dest config.ProxyJumpTarget
	if hasResolved {
		user := strings.TrimSpace(resolved.User)
		if connTarget.HasUser && strings.TrimSpace(connTarget.User) != "" {
			user = strings.TrimSpace(connTarget.User)
		}
		port := resolved.Port
		if connTarget.HasPort && connTarget.Port > 0 {
			port = connTarget.Port
		}
		dest = config.ProxyJumpTarget{
			NodeID:        destID,
			Selector:      strings.TrimSpace(connTarget.Selector),
			OpenSSHAlias:  strings.TrimSpace(resolved.OpenSSHAlias),
			CanonicalHost: strings.TrimSpace(resolved.CanonicalHost),
			Host:          strings.TrimSpace(resolved.Host),
			Port:          port,
			User:          user,
			IsAdHoc:       resolved.Provenance == config.ProvenanceAdHocPending || (resolved.Provenance == config.ProvenanceUnknown && resolved.Created && resolved.OpenSSHAlias == ""),
		}
	} else {
		user := strings.TrimSpace(req.FallbackUser)
		if connTarget.HasUser && strings.TrimSpace(connTarget.User) != "" {
			user = strings.TrimSpace(connTarget.User)
		}
		port := req.FallbackPort
		if connTarget.HasPort && connTarget.Port > 0 {
			port = connTarget.Port
		}
		dest = config.ProxyJumpTarget{
			NodeID:   destID,
			Selector: strings.TrimSpace(connTarget.Selector),
			Host:     strings.TrimSpace(req.FallbackHost),
			Port:     port,
			User:     user,
			IsAdHoc:  true,
		}
	}
	if req.ApplyTargetNodeOverrides {
		if overrideHost := config.StripHostBrackets(req.OverrideExpandedHost); overrideHost != "" {
			baseHost := config.StripHostBrackets(dest.Host)
			if baseHost == "" || !hostAddressesEqual(overrideHost, baseHost) {
				dest.Host = overrideHost
				dest.OpenSSHAlias = ""
				dest.CanonicalHost = ""
				dest.IsAdHoc = true
				if formatted := formatDirectOverriddenNodeID(dest.User, dest.Host, dest.Port); formatted != "" {
					dest.NodeID = formatted
					dest.Selector = formatted
				}
			}
		}
	}
	return dest
}

// resolveControlEffectiveJumpHost folds ProxyJump and ProxyCommand across all
// 4 tiers using the same ssh.ProxySetting monoid as resolveFourTierProxySetting
// so %j / %C ControlPath expansion and CanonicalTargetIdentity stay aligned
// with SSHAdapter.GetConfig.
func resolveControlEffectiveJumpHost(
	req ControlTargetRequest,
	connTarget config.ConnectionTarget,
	hasResolved bool,
	resolved config.ResolvedTarget,
) (string, error) {
	t1Proxy, err := resolveControlTier1ProxySetting(req.Target, req.SessionControl)
	if err != nil {
		return "", err
	}
	tier1HasProxy := connTarget.HasProxyJump || connTarget.ProxyJump != "" || !t1Proxy.IsUnset()
	hostNameSuppressedJump := req.Provider != nil &&
		req.ApplyTargetNodeOverrides &&
		strings.TrimSpace(req.OverrideExpandedHost) != "" &&
		!tier1HasProxy
	t2Proxy, err := resolveControlTier2ProxySettingWithHostOverride(req.Provider, connTarget, hasResolved, resolved, hostNameSuppressedJump)
	if err != nil {
		return "", err
	}
	t3Proxy := resolveControlTier3ProxySetting(req.Provider)
	t4Proxy, err := resolveControlTier4ProxySettingWithHostOverride(req.Provider, connTarget, hasResolved, resolved, hostNameSuppressedJump)
	if err != nil {
		return "", err
	}

	effective := ssh.MergeProxySettings(t1Proxy, t2Proxy, t3Proxy, t4Proxy)
	if effective.Kind() != ssh.ProxyJump {
		return "", nil
	}
	targets, ok := effective.JumpTargets()
	if !ok {
		return "", nil
	}
	tier1Won := t1Proxy.Kind() == ssh.ProxyJump
	rawJump := strings.Join(targets, ",")
	var (
		resolvedJump string
		jErr         error
	)
	if req.Provider != nil {
		if !tier1Won && hasResolved && resolved.Provenance.IsUnpersistedOpenSSH() {
			resolvedJump, jErr = resolveUnpersistedOpenSSHJumpChain(req.Provider, rawJump)
		} else {
			resolvedJump, jErr = req.Provider.ResolveProxyJumpChain(rawJump)
		}
		if jErr != nil {
			return "", jErr
		}
	} else {
		resolvedJump, jErr = validateNoProviderJumpChain(targets)
		if jErr != nil {
			return "", jErr
		}
	}
	dest := buildControlProxyJumpTarget(req, connTarget, hasResolved, resolved)
	if cErr := config.ValidateProxyJumpChainCycle(req.Provider, dest, resolvedJump, rawJump); cErr != nil {
		return "", cErr
	}
	return resolvedJump, nil
}

func isResolvedSavedNode(r config.ResolvedTarget) bool {
	if strings.TrimSpace(r.Host) == "" {
		return false
	}
	return (r.MatchedNodeID != "" && !config.IsOpenSSHNodeID(r.MatchedNodeID)) ||
		(r.BaseNodeID != "" && !config.IsOpenSSHNodeID(r.BaseNodeID))
}

// TargetContextFromResolvedTarget converts a read-only config.ResolvedTarget
// into a canonical ssh.TargetContext normalized against env.
func TargetContextFromResolvedTarget(resolved config.ResolvedTarget, env ssh.Environment) ssh.TargetContext {
	user := resolved.User
	if user == "" {
		user = env.LocalUser
	}
	port := int(resolved.Port)
	if port <= 0 {
		port = 22
	}
	orig := resolved.NodeID
	if !isResolvedSavedNode(resolved) && resolved.OpenSSHAlias != "" &&
		(resolved.CanonicalHost != "" || !config.IsOpenSSHNodeID(orig)) {
		orig = resolved.OpenSSHAlias
	} else if cleanOrig, ok := config.OpenSSHOriginalHost(orig); ok {
		orig = cleanOrig
	}
	if orig == "" && resolved.Host != "" && user != "" && port > 0 {
		orig = config.FormatNodeID(user, resolved.Host, uint16(port))
	}
	return ssh.NormalizeTargetContext(ssh.TargetContext{
		Host:          resolved.Host,
		Port:          port,
		User:          user,
		OriginalHost:  orig,
		CanonicalHost: resolved.CanonicalHost,
		JumpHost:      resolved.ProxyJump,
		KeyPath:       resolved.KeyPath,
	}, env)
}

func firstNonEmptySessionValue(vals ...string) string {
	for _, v := range vals {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func extractOpenSSHHost(nodeID string) string {
	alias := strings.TrimSpace(config.UnwrapOpenSSHSelector(nodeID))
	if alias == "" {
		return ""
	}
	if ref, err := config.ParseTargetRef(alias); err == nil && ref.Selector() != "" {
		return ref.Selector()
	}
	return alias
}

func resolveSavedControlLookupByKey(
	provider config.ConfigProvider,
	lookupKey string,
	connTarget config.ConnectionTarget,
	origHost, canonHost, targetOrig, proxyJump string,
) (auth SessionAuth, handled bool, resolvedVirtual bool) {
	auth.ProxyJump = proxyJump
	if lookupKey == "" {
		return auth, false, false
	}
	snap, err := provider.ResolveConnection(lookupKey)
	if err != nil {
		return auth, false, false
	}
	if config.IsOpenSSHNodeID(lookupKey) && snap.Provenance == config.ProvenanceOpenSSHVirtual {
		return auth, false, config.HasOpenSSHConfig(provider)
	}
	resolvedAlias := snap.Node.OpenSSHAlias
	resolvedCanon := snap.Node.CanonicalHost
	if origHost != "" || canonHost != "" {
		resolvedCanon = ""
	}
	if origHost == "" && strings.TrimSpace(connTarget.Selector) != "" {
		if resolved, rErr := config.ResolveTarget(provider, connTarget); rErr == nil && resolved.MatchedNodeID == lookupKey {
			resolvedAlias = resolved.OpenSSHAlias
			if canonHost == "" {
				resolvedCanon = resolved.CanonicalHost
			}
		}
	}
	auth.OriginalHost = firstNonEmptySessionValue(origHost, resolvedAlias, targetOrig)
	auth.CanonicalHost = firstNonEmptySessionValue(canonHost, resolvedCanon)
	return auth, true, false
}

func applyResolvedControlSessionOrigin(
	auth SessionAuth,
	origHost, canonHost, resolvedAlias, resolvedCanon string,
	fallbackOrigs ...string,
) SessionAuth {
	candidates := append([]string{origHost, resolvedAlias}, fallbackOrigs...)
	auth.OriginalHost = firstNonEmptySessionValue(candidates...)
	if origHost == "" && canonHost == "" {
		auth.CanonicalHost = resolvedCanon
	} else {
		auth.CanonicalHost = canonHost
	}
	return auth
}

func resolveTargetControlSessionLookup(
	provider config.ConfigProvider,
	lookupKey, nodeID string,
	resolved config.ResolvedTarget,
	origHost, canonHost, targetOrig string,
	auth SessionAuth,
	resolvedVirtual bool,
) (string, SessionAuth, bool, bool) {
	if resolved.MatchedNodeID != "" {
		if !config.IsOpenSSHNodeID(resolved.MatchedNodeID) {
			auth = applyResolvedControlSessionOrigin(auth, origHost, canonHost, resolved.OpenSSHAlias, resolved.CanonicalHost, extractOpenSSHHost(nodeID), targetOrig)
			return resolved.MatchedNodeID, auth, true, resolvedVirtual
		}
		if lookupKey == "" || (!config.IsOpenSSHNodeID(lookupKey) && !isSavedControlNodeID(provider, lookupKey)) {
			auth = applyResolvedControlSessionOrigin(auth, origHost, canonHost, resolved.OpenSSHAlias, resolved.CanonicalHost, targetOrig)
			return resolved.MatchedNodeID, auth, false, config.HasOpenSSHConfig(provider)
		}
		return "", auth, false, resolvedVirtual
	}
	if isDerivedOpenSSHResolvedTarget(resolved) {
		if lookupKey == "" || lookupKey == resolved.NodeID || (!config.IsOpenSSHNodeID(lookupKey) && !isSavedControlNodeID(provider, lookupKey)) {
			auth = applyResolvedControlSessionOrigin(auth, origHost, canonHost, resolved.OpenSSHAlias, resolved.CanonicalHost, targetOrig)
			return derivedOpenSSHLookupKey(resolved), auth, false, config.HasOpenSSHConfig(provider)
		}
		return "", auth, false, resolvedVirtual
	}
	if resolved.NodeID != "" && lookupKey == "" {
		auth = applyResolvedControlSessionOrigin(auth, origHost, canonHost, resolved.OpenSSHAlias, resolved.CanonicalHost, targetOrig)
		return resolved.NodeID, auth, false, resolvedVirtual
	}
	return "", auth, false, resolvedVirtual
}

func resolveSavedControlSessionLookup(
	provider config.ConfigProvider,
	lookupKey, nodeID string,
	connTarget config.ConnectionTarget,
	origHost, canonHost, targetOrig, proxyJump string,
) (key string, auth SessionAuth, handled bool, resolvedVirtual bool) {
	auth.ProxyJump = proxyJump
	if provider == nil {
		return "", auth, false, false
	}
	if keyAuth, ok, isVirtual := resolveSavedControlLookupByKey(provider, lookupKey, connTarget, origHost, canonHost, targetOrig, proxyJump); ok {
		return lookupKey, keyAuth, true, false
	} else {
		resolvedVirtual = isVirtual
	}
	if strings.TrimSpace(connTarget.Selector) != "" {
		if resolved, err := config.ResolveTarget(provider, connTarget); err == nil {
			return resolveTargetControlSessionLookup(
				provider, lookupKey, nodeID, resolved, origHost, canonHost, targetOrig, auth, resolvedVirtual,
			)
		}
	}
	return "", auth, false, resolvedVirtual
}

func effectiveControlSessionProxyJump(connTarget config.ConnectionTarget, sessionCtrl SessionControlOptions) string {
	if connTarget.ProxyJump != "" {
		return connTarget.ProxyJump
	}
	ps := sessionCtrl.ProxySetting()
	switch {
	case ps.Kind() == ssh.ProxyJump:
		if targets, ok := ps.JumpTargets(); ok {
			return strings.Join(targets, ",")
		}
	case ps.IsJumpDisabledOnly():
		return "none"
	}
	return ""
}

func parseExplicitSelectorUserPort(provider config.ConfigProvider, selectors []string) (user string, port uint16) {
	for _, rawSel := range selectors {
		sel := strings.TrimSpace(rawSel)
		if sel == "" {
			continue
		}
		if provider != nil && !config.IsOpenSSHNodeID(sel) {
			if _, ok := provider.GetNode(sel); ok {
				continue
			}
		}
		ref, err := config.ParseTargetRef(sel)
		if err != nil {
			continue
		}
		if user == "" && ref.User != "" {
			user = ref.User
		}
		if port == 0 && ref.HasPort && ref.Port > 0 {
			port = ref.Port
		}
	}
	return user, port
}

func explicitControlSessionUserPort(req ControlTargetRequest, connTarget config.ConnectionTarget, hasResolved bool) (user string, port uint16) {
	user, port = parseExplicitSelectorUserPort(req.Provider, []string{
		connTarget.RawSelector, connTarget.Selector, req.Target.RawSelector, req.Target.Selector,
	})
	if connTarget.HasUser && strings.TrimSpace(connTarget.User) != "" {
		user = strings.TrimSpace(connTarget.User)
	}
	if connTarget.HasPort && connTarget.Port > 0 {
		port = connTarget.Port
	}
	if !hasResolved {
		if user == "" && strings.TrimSpace(req.FallbackUser) != "" {
			user = strings.TrimSpace(req.FallbackUser)
		}
		if port == 0 && req.FallbackPort > 0 {
			port = req.FallbackPort
		}
	}
	return user, port
}

func controlOverrideLookupTarget(req ControlTargetRequest, connTarget config.ConnectionTarget) (string, config.ConnectionTarget) {
	if !req.ApplyTargetNodeOverrides {
		return "", connTarget
	}
	overrideHostName := config.StripHostBrackets(req.OverrideExpandedHost)
	if overrideHostName == "" {
		return "", connTarget
	}
	lookupTarget := connTarget
	lookupTarget.ProxyJump = "none"
	lookupTarget.HasProxyJump = true
	return overrideHostName, lookupTarget
}

func finalizeControlSessionLookup(
	lookupKey string,
	connTarget config.ConnectionTarget,
	origHost, canonHost, targetOrig string,
	resolvedVirtual bool,
	auth SessionAuth,
) (string, SessionAuth) {
	if canonHost != "" {
		if lookupKey == "" {
			lookupKey = config.OpenSSHNodePrefix + canonHost
		} else if config.IsOpenSSHNodeID(lookupKey) {
			if unwrapped := extractOpenSSHHost(lookupKey); unwrapped != "" && !strings.EqualFold(unwrapped, canonHost) {
				lookupKey = rewriteOpenSSHLookupKeyHost(lookupKey, canonHost)
			}
		}
		auth.OriginalHost = firstNonEmptySessionValue(origHost, targetOrig)
		auth.CanonicalHost = canonHost
		return lookupKey, auth
	}
	if config.IsOpenSSHNodeID(lookupKey) {
		openSSHHost := extractOpenSSHHost(lookupKey)
		if !resolvedVirtual {
			if cleanOrig, ok := config.OpenSSHOriginalHost(lookupKey); ok && targetOrig != "" && targetOrig != cleanOrig && targetOrig != openSSHHost {
				lookupKey = targetOrig
			}
		}
		auth.OriginalHost = firstNonEmptySessionValue(origHost, openSSHHost, targetOrig)
		auth.CanonicalHost = canonHost
		return lookupKey, auth
	}
	if lookupKey == "" {
		lookupKey = firstNonEmptySessionValue(targetOrig, connTarget.Selector)
	}
	auth.OriginalHost = firstNonEmptySessionValue(origHost, targetOrig)
	auth.CanonicalHost = canonHost
	return lookupKey, auth
}

func resolveControlSessionLookup(
	req ControlTargetRequest,
	connTarget config.ConnectionTarget,
	target ssh.TargetContext,
	hasResolved bool,
) (string, SessionAuth) {
	lookupKey := trimNonPaddedOpenSSH(req.NodeID)
	sel := trimNonPaddedOpenSSH(connTarget.Selector)
	if sel == "" {
		sel = lookupKey
	}
	origHost := strings.TrimSpace(req.CanonicalOriginalHost)
	canonHost := strings.TrimSpace(req.CanonicalHost)
	if !shouldPropagateControlCanonicalOrigin(req.Provider, sel, origHost, canonHost) {
		origHost = ""
		canonHost = ""
	}
	targetOrig := strings.TrimSpace(target.OriginalHost)
	proxyJump := effectiveControlSessionProxyJump(req.Target, req.SessionControl)
	overrideHostName, lookupTarget := controlOverrideLookupTarget(req, connTarget)
	key, savedAuth, handled, resolvedVirtual := resolveSavedControlSessionLookup(
		req.Provider, lookupKey, req.NodeID, lookupTarget, origHost, canonHost, targetOrig, proxyJump,
	)
	sessUser, sessPort := explicitControlSessionUserPort(req, connTarget, hasResolved || handled || resolvedVirtual)
	if handled {
		savedAuth.User = sessUser
		savedAuth.Port = sessPort
		savedAuth.HostName = overrideHostName
		return key, savedAuth
	}
	if key != "" && (lookupKey == "" || (config.IsOpenSSHNodeID(key) && !config.IsOpenSSHNodeID(lookupKey))) {
		lookupKey = key
	}
	if origHost == "" && savedAuth.OriginalHost != "" {
		origHost = savedAuth.OriginalHost
	}
	if canonHost == "" {
		canonHost = firstNonEmptySessionValue(savedAuth.CanonicalHost, target.CanonicalHost)
	}
	auth := SessionAuth{
		User:      sessUser,
		Port:      sessPort,
		HostName:  overrideHostName,
		ProxyJump: proxyJump,
	}
	return finalizeControlSessionLookup(lookupKey, connTarget, origHost, canonHost, targetOrig, resolvedVirtual, auth)
}
