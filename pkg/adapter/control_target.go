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
	target, err := resolveControlTargetContext(req, connTarget, env)
	if err != nil {
		return ControlTargetResolution{}, err
	}
	lookupKey, sessionAuth := resolveControlSessionLookup(req, connTarget, target)
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

// ResolveControlSessionLookup computes the effective adapter lookup key and
// SessionAuth metadata for an already-resolved TargetContext purely from caller
// inputs and read-only provider lookups without mutating provider state.
func ResolveControlSessionLookup(req ControlTargetRequest, target ssh.TargetContext) (string, SessionAuth) {
	connTarget := prepareControlConnectionTarget(req)
	return resolveControlSessionLookup(req, connTarget, target)
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

func resolveControlConfigLookupKey(
	provider config.ConfigProvider,
	lookupKey, selector string,
	sessionAuth SessionAuth,
	sessionOpts SessionControlOptions,
) (string, error) {
	if lookupKey == "" {
		if provider != nil && strings.TrimSpace(selector) != "" {
			jump, hasJump := effectiveControlConfigJumpOverride(sessionAuth, sessionOpts)
			resolved, err := config.ResolveTarget(provider, config.ConnectionTarget{
				Selector:     selector,
				OriginalHost: strings.TrimSpace(sessionAuth.OriginalHost),
				ProxyJump:    jump,
				HasProxyJump: hasJump,
			})
			if err != nil {
				if !isTargetMissingError(err) {
					return "", err
				}
			} else if resolved.MatchedNodeID != "" {
				return resolved.MatchedNodeID, nil
			}
		}
		// Resolve treats an unknown selector as "no node layer" and falls
		// back to session > global > OpenSSH, which is the ad-hoc case.
		lookupKey = selector
	}
	if provider != nil && lookupKey != "" && !config.IsOpenSSHNodeID(lookupKey) {
		if _, ok := provider.GetNode(lookupKey); !ok {
			if aliasID := provider.FindAlias(lookupKey); aliasID != "" {
				return aliasID, nil
			}
		}
	}
	return lookupKey, nil
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
	lookupKey, err = resolveControlConfigLookupKey(provider, lookupKey, selector, sessionAuth, sessionOpts)
	if err != nil {
		return nil, err
	}
	if provider == nil {
		if err := validateNilProviderSessionJump(lookupKey, sessionAuth.ProxyJump, sessionJumpPS); err != nil {
			return nil, err
		}
		if sessionOpts.IsEmpty() {
			return nil, nil
		}
		provider = config.NewProviderWithoutOpenSSH(nil)
	} else if lookupKey == "" && sessionJumpPS.Kind() == ssh.ProxyJump {
		resolvedJump, jErr := provider.ResolveProxyJumpChain(strings.TrimSpace(sessionAuth.ProxyJump))
		if jErr != nil {
			return nil, fmt.Errorf("resolve session proxy jump %q failed: %w", sessionAuth.ProxyJump, jErr)
		}
		if cErr := config.ValidateProxyJumpChainCycle(provider, config.ProxyJumpTarget{Selector: strings.TrimSpace(selector)}, resolvedJump, sessionAuth.ProxyJump); cErr != nil {
			return nil, cErr
		}
	}
	adpOpts := []Option{WithControlProxyMode(true)}
	if lookupKey != "" && (sessionAuth.OriginalHost != "" || sessionAuth.CanonicalHost != "" || sessionAuth.ProxyJump != "") {
		adpOpts = append(adpOpts, WithSessionAuthOverride(lookupKey, sessionAuth))
	}
	pol, err := NewSSHAdapter(provider, adpOpts...).Resolve(context.Background(), ResolveRequest{
		NodeID:         lookupKey,
		SessionControl: &sessionOpts,
		ResolveProxy:   true,
	})
	if err != nil {
		return nil, err
	}
	return pol.Control(), nil
}

func validateNilProviderSessionJump(lookupKey, rawJump string, ps ssh.ProxySetting) error {
	targets, ok := ps.JumpTargets()
	if !ok {
		return nil
	}
	validated, err := validateNoProviderJumpChain(targets)
	if err != nil {
		return err
	}
	return config.ValidateProxyJumpChainCycle(nil, config.ProxyJumpTarget{
		NodeID:   strings.TrimSpace(lookupKey),
		Selector: strings.TrimSpace(lookupKey),
		IsAdHoc:  true,
	}, validated, rawJump)
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

func resolveControlTargetContext(req ControlTargetRequest, connTarget config.ConnectionTarget, env ssh.Environment) (ssh.TargetContext, error) {
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
		resolved, err := config.ResolveTarget(effectiveProvider, connTarget)
		if err != nil {
			if !isTargetMissingError(err) {
				return ssh.TargetContext{}, err
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
		return ssh.TargetContext{}, err
	}
	target.JumpHost = jumpHost
	return ssh.NormalizeTargetContext(target, env), nil
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

func resolveControlTier2ProxySetting(
	provider config.ConfigProvider,
	connTarget config.ConnectionTarget,
	hasResolved bool,
	resolved config.ResolvedTarget,
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
	if !connTarget.HasProxyJump && resolved.ProxyJump != "" {
		ps, err := proxySettingFromJumpString(resolved.ProxyJump)
		if err != nil {
			return ssh.UnsetProxySetting(), fmt.Errorf("invalid node ProxyJump %q: %w", resolved.ProxyJump, err)
		}
		t2Jump = ps
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
	if !hasResolved || !resolved.Provenance.IsUnpersistedOpenSSH() {
		return ssh.UnsetProxySetting(), nil
	}
	var t4Jump, t4Parser ssh.ProxySetting
	if !connTarget.HasProxyJump && connTarget.ProxyJump == "" && resolved.ProxyJump != "" {
		ps, err := proxySettingFromJumpString(resolved.ProxyJump)
		if err != nil {
			return ssh.UnsetProxySetting(), fmt.Errorf("invalid OpenSSH ProxyJump %q: %w", resolved.ProxyJump, err)
		}
		t4Jump = ps
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
	if hasResolved {
		user := strings.TrimSpace(resolved.User)
		if connTarget.HasUser && strings.TrimSpace(connTarget.User) != "" {
			user = strings.TrimSpace(connTarget.User)
		}
		return config.ProxyJumpTarget{
			NodeID:        destID,
			Selector:      strings.TrimSpace(connTarget.Selector),
			OpenSSHAlias:  strings.TrimSpace(resolved.OpenSSHAlias),
			CanonicalHost: strings.TrimSpace(resolved.CanonicalHost),
			Host:          strings.TrimSpace(resolved.Host),
			Port:          resolved.Port,
			User:          user,
			IsAdHoc:       resolved.Created && resolved.OpenSSHAlias == "",
		}
	}
	user := strings.TrimSpace(req.FallbackUser)
	if connTarget.HasUser && strings.TrimSpace(connTarget.User) != "" {
		user = strings.TrimSpace(connTarget.User)
	}
	port := req.FallbackPort
	if connTarget.HasPort && connTarget.Port > 0 {
		port = connTarget.Port
	}
	return config.ProxyJumpTarget{
		NodeID:   destID,
		Selector: strings.TrimSpace(connTarget.Selector),
		Host:     strings.TrimSpace(req.FallbackHost),
		Port:     port,
		User:     user,
		IsAdHoc:  true,
	}
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
	t1Proxy, err := resolveControlTier1ProxySetting(connTarget, req.SessionControl)
	if err != nil {
		return "", err
	}
	t2Proxy, err := resolveControlTier2ProxySetting(req.Provider, connTarget, hasResolved, resolved)
	if err != nil {
		return "", err
	}
	t3Proxy := resolveControlTier3ProxySetting(req.Provider)
	t4Proxy, err := resolveControlTier4ProxySetting(req.Provider, connTarget, hasResolved, resolved)
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
		if resolved, err := config.ResolveTarget(provider, connTarget); err == nil && resolved.MatchedNodeID != "" {
			if !config.IsOpenSSHNodeID(resolved.MatchedNodeID) {
				auth.OriginalHost = firstNonEmptySessionValue(origHost, resolved.OpenSSHAlias, extractOpenSSHHost(nodeID), targetOrig)
				if origHost == "" && canonHost == "" {
					auth.CanonicalHost = resolved.CanonicalHost
				} else {
					auth.CanonicalHost = canonHost
				}
				return resolved.MatchedNodeID, auth, true, resolvedVirtual
			}
			if lookupKey == "" {
				return resolved.MatchedNodeID, auth, false, config.HasOpenSSHConfig(provider)
			}
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

func resolveControlSessionLookup(
	req ControlTargetRequest,
	connTarget config.ConnectionTarget,
	target ssh.TargetContext,
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
	proxyJump := effectiveControlSessionProxyJump(connTarget, req.SessionControl)
	key, savedAuth, handled, resolvedVirtual := resolveSavedControlSessionLookup(
		req.Provider, lookupKey, req.NodeID, connTarget, origHost, canonHost, targetOrig, proxyJump,
	)
	if handled {
		return key, savedAuth
	}
	if lookupKey == "" && key != "" {
		lookupKey = key
	}
	if canonHost == "" {
		canonHost = strings.TrimSpace(target.CanonicalHost)
	}
	auth := SessionAuth{ProxyJump: proxyJump}
	if canonHost != "" {
		if lookupKey == "" || !config.IsOpenSSHNodeID(lookupKey) {
			lookupKey = config.OpenSSHNodePrefix + canonHost
		} else if unwrapped := extractOpenSSHHost(lookupKey); unwrapped != "" && !strings.EqualFold(unwrapped, canonHost) {
			lookupKey = rewriteOpenSSHLookupKeyHost(lookupKey, canonHost)
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
		if targetOrig != "" {
			lookupKey = targetOrig
		} else {
			lookupKey = strings.TrimSpace(connTarget.Selector)
		}
	}
	auth.OriginalHost = firstNonEmptySessionValue(origHost, targetOrig)
	auth.CanonicalHost = canonHost
	return lookupKey, auth
}
