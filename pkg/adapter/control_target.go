package adapter

import (
	"context"
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

// ResolveControlTarget computes the canonical control-plane TargetContext,
// adapter lookup key, and SessionAuth metadata purely from caller inputs and
// read-only provider lookups (zero config mutation, zero pending-node creation).
func ResolveControlTarget(req ControlTargetRequest) ControlTargetResolution {
	env := resolveControlEnvironment(req.Environment)
	connTarget := req.Target
	if strings.TrimSpace(connTarget.Selector) == "" && strings.TrimSpace(req.NodeID) != "" {
		connTarget.Selector = strings.TrimSpace(req.NodeID)
	}
	target := resolveControlTargetContext(req, connTarget, env)
	lookupKey, sessionAuth := resolveControlSessionLookup(req, connTarget, target)
	return ControlTargetResolution{
		Target:      target,
		LookupKey:   lookupKey,
		SessionAuth: sessionAuth,
	}
}

// ResolveControlSessionLookup computes the effective adapter lookup key and
// SessionAuth metadata for an already-resolved TargetContext purely from caller
// inputs and read-only provider lookups without mutating provider state.
func ResolveControlSessionLookup(req ControlTargetRequest, target ssh.TargetContext) (string, SessionAuth) {
	return resolveControlSessionLookup(req, req.Target, target)
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
	if provider == nil {
		if sessionOpts.IsEmpty() {
			return nil, nil
		}
		provider = config.NewProviderWithoutOpenSSH(nil)
	}
	if lookupKey == "" {
		// Resolve treats an unknown selector as "no node layer" and falls
		// back to session > global > OpenSSH, which is the ad-hoc case.
		lookupKey = selector
	}
	adpOpts := []Option{WithControlProxyMode(true)}
	if lookupKey != "" && (sessionAuth.OriginalHost != "" || sessionAuth.CanonicalHost != "" || sessionAuth.ProxyJump != "") {
		adpOpts = append(adpOpts, WithSessionAuthOverride(lookupKey, sessionAuth))
	}
	pol, err := NewSSHAdapter(provider, adpOpts...).Resolve(context.Background(), ResolveRequest{
		NodeID:         lookupKey,
		SessionControl: &sessionOpts,
	})
	if err != nil {
		return nil, err
	}
	return pol.Control(), nil
}

// ResolveControlSocketPath resolves the control-plane target, lookup metadata,
// and effective ControlConfig, then expands the resulting control socket path.
// It returns ("", resolution, nil) when control multiplexing is disabled/unset.
func ResolveControlSocketPath(req ControlTargetRequest) (string, ControlTargetResolution, error) {
	env := resolveControlEnvironment(req.Environment)
	res := ResolveControlTarget(req)
	selector := strings.TrimSpace(req.Target.Selector)
	if selector == "" {
		selector = strings.TrimSpace(req.NodeID)
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

func resolveControlTargetContext(req ControlTargetRequest, connTarget config.ConnectionTarget, env ssh.Environment) ssh.TargetContext {
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
		if resolved, err := config.ResolveTarget(effectiveProvider, connTarget); err == nil {
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
	if proxyCommandOverridesControlJump(req, connTarget, hasResolved, resolvedTarget) {
		target.JumpHost = ""
	}
	return ssh.NormalizeTargetContext(target, env)
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

// proxyCommandOverridesControlJump mirrors ProxySetting precedence so a
// higher-tier ProxyCommand (active or "none") clears a lower-tier ProxyJump in
// TargetContext.JumpHost (closing %j / %C drift between control-plane lookups
// and SSHAdapter.GetConfig).
func proxyCommandOverridesControlJump(
	req ControlTargetRequest,
	connTarget config.ConnectionTarget,
	hasResolved bool,
	resolved config.ResolvedTarget,
) bool {
	if ssh.HasActiveProxyJump(connTarget.ProxyJump) {
		return false
	}
	if req.SessionControl.Options != nil {
		t1Proxy := req.SessionControl.Options.ProxyCommandSetting()
		if t1Proxy.Kind() == ssh.ProxyCommand || t1Proxy.Equal(ssh.DisabledProxySetting()) {
			return true
		}
	}
	if hasResolved && resolved.Provenance.IsUnpersistedOpenSSH() && req.Provider != nil {
		if snap := req.Provider.Snapshot(); snap != nil && snap.SSHOptions != nil {
			t3Proxy := snap.SSHOptions.ProxyCommandSetting()
			if t3Proxy.Kind() == ssh.ProxyCommand || t3Proxy.Equal(ssh.DisabledProxySetting()) {
				return true
			}
		}
	}
	return false
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
	if cleanOrig, ok := config.OpenSSHOriginalHost(orig); ok {
		orig = cleanOrig
	} else if !isResolvedSavedNode(resolved) && resolved.OpenSSHAlias != "" {
		orig = resolved.OpenSSHAlias
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
	if lookupKey != "" {
		if snap, err := provider.ResolveConnection(lookupKey); err == nil {
			if !config.IsOpenSSHNodeID(lookupKey) || snap.Provenance != config.ProvenanceOpenSSHVirtual {
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
				return lookupKey, auth, true, false
			}
			if config.HasOpenSSHConfig(provider) {
				resolvedVirtual = true
			}
		}
	}
	if strings.TrimSpace(connTarget.Selector) != "" {
		if resolved, err := config.ResolveTarget(provider, connTarget); err == nil && resolved.MatchedNodeID != "" && !config.IsOpenSSHNodeID(resolved.MatchedNodeID) {
			auth.OriginalHost = firstNonEmptySessionValue(origHost, resolved.OpenSSHAlias, extractOpenSSHHost(nodeID), targetOrig)
			if origHost == "" && canonHost == "" {
				auth.CanonicalHost = resolved.CanonicalHost
			} else {
				auth.CanonicalHost = canonHost
			}
			return resolved.MatchedNodeID, auth, true, resolvedVirtual
		}
	}
	return "", auth, false, resolvedVirtual
}

func resolveControlSessionLookup(
	req ControlTargetRequest,
	connTarget config.ConnectionTarget,
	target ssh.TargetContext,
) (string, SessionAuth) {
	origHost := strings.TrimSpace(req.CanonicalOriginalHost)
	canonHost := strings.TrimSpace(req.CanonicalHost)
	targetOrig := strings.TrimSpace(target.OriginalHost)
	proxyJump := strings.TrimSpace(connTarget.ProxyJump)
	lookupKey := strings.TrimSpace(req.NodeID)
	key, savedAuth, handled, resolvedVirtual := resolveSavedControlSessionLookup(
		req.Provider, lookupKey, req.NodeID, connTarget, origHost, canonHost, targetOrig, proxyJump,
	)
	if handled {
		return key, savedAuth
	}
	auth := SessionAuth{ProxyJump: proxyJump}
	if canonHost != "" {
		if lookupKey == "" || !config.IsOpenSSHNodeID(lookupKey) {
			lookupKey = config.OpenSSHNodePrefix + canonHost
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
