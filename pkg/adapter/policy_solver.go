package adapter

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
)

type policySolveMode struct {
	requireSnapshot bool
	resolveOptions  bool
	resolveControl  bool
}

type effectivePolicy struct {
	snapshot          config.ConnectionSnapshot
	hasSnapshot       bool
	globalCfg         *config.Configuration
	tier1             SessionControlOptions
	tier2             *ssh.Options
	tier3             *ssh.Options
	tier4             *ssh.Options
	tier1Auth         SessionAuth
	hasTier1Auth      bool
	tier1ActiveJump   bool
	higherTierCmdWins bool
	effectiveOpts     *ssh.Options
	effectiveCtrl     *ssh.ControlConfig
	originalHost      string
}

func (a *SSHAdapter) solvePolicy(nodeName string, sessionOpts SessionControlOptions, mode policySolveMode) (effectivePolicy, error) {
	if a == nil || a.cfgProvider == nil {
		return effectivePolicy{}, fmt.Errorf("configuration provider is nil")
	}
	snapshot, snapErr := a.cfgProvider.ResolveConnection(nodeName)
	if snapErr != nil && mode.requireSnapshot {
		return effectivePolicy{}, snapErr
	}
	globalCfg := a.cfgProvider.Snapshot()
	var tier3Global *ssh.Options
	if globalCfg != nil {
		tier3Global = globalCfg.SSHOptions
	}
	tier1Auth, hasTier1Auth := a.getSessionOverride(nodeName)
	pol := effectivePolicy{
		snapshot:        snapshot,
		hasSnapshot:     snapErr == nil,
		globalCfg:       globalCfg,
		tier1:           sessionOpts,
		tier1Auth:       tier1Auth,
		hasTier1Auth:    hasTier1Auth,
		tier1ActiveJump: hasTier1Auth && isActiveProxyJumpValue(tier1Auth.ProxyJump),
		originalHost:    openSSHSnapshotOriginalHost(nodeName, snapshot),
	}
	if !mode.resolveOptions && !mode.resolveControl {
		return pol, nil
	}
	t2, t3, t4 := a.resolvePolicyTiers(nodeName, snapshot, snapErr, tier3Global)
	pol.tier2, pol.tier3, pol.tier4 = t2, t3, t4

	tier1Opts := sessionOpts.ToSSHOptions()
	maskedT2, maskedT3, maskedT4, higherCmdWins := solveProxyPrecedence(
		pol.tier1ActiveJump, tier1Opts, snapshot, pol.hasSnapshot, t2, t3, t4,
	)
	pol.higherTierCmdWins = higherCmdWins

	if mode.resolveOptions {
		merged, err := a.finalizeEffectiveOptions(tier1Opts, maskedT2, maskedT3, maskedT4, pol.tier1ActiveJump)
		if err != nil {
			return pol, err
		}
		pol.effectiveOpts = merged
	}
	if mode.resolveControl && !a.disableControl {
		merged := mergeControlFields(sessionOpts, t2.ControlConfig(), t3.ControlConfig(), t4.ControlConfig())
		if merged != nil {
			if err := validateMergedControl(merged); err != nil {
				return pol, err
			}
			pol.effectiveCtrl = merged
		}
	}
	return pol, nil
}

// solveProxyPrecedence applies both halves of the 4-tier ProxyJump vs ProxyCommand
// precedence rule:
//   - An active higher-tier ProxyJump masks ProxyCommand from lower tiers.
//   - An active higher-tier ProxyCommand overrides a lower-tier ProxyJump.
func solveProxyPrecedence(
	tier1ActiveJump bool,
	tier1Opts *ssh.Options,
	snapshot config.ConnectionSnapshot,
	hasSnapshot bool,
	t2, t3, t4 *ssh.Options,
) (maskedT2, maskedT3, maskedT4 *ssh.Options, higherTierProxyCommandWins bool) {
	maskedT2, maskedT3, maskedT4 = t2, t3, t4
	if tier1ActiveJump {
		return cloneWithoutProxyCommand(t2), cloneWithoutProxyCommand(t3), cloneWithoutProxyCommand(t4), false
	}
	if !hasSnapshot || !isActiveProxyJumpValue(snapshot.Node.ProxyJump) {
		return maskedT2, maskedT3, maskedT4, false
	}
	if !snapshot.Provenance.IsUnpersistedOpenSSH() {
		maskedT3 = cloneWithoutProxyCommand(t3)
		maskedT4 = cloneWithoutProxyCommand(t4)
	}
	if tier1Opts != nil && tier1Opts.ActiveProxyCommand() != "" {
		higherTierProxyCommandWins = true
	} else if snapshot.Provenance.IsUnpersistedOpenSSH() && t3 != nil && t3.ActiveProxyCommand() != "" {
		higherTierProxyCommandWins = true
	}
	return maskedT2, maskedT3, maskedT4, higherTierProxyCommandWins
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
	return ssh.TargetContext{
		Host:         strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(p.snapshot.Host.Address), "]"), "["),
		Port:         effectiveSnapshotPort(p.snapshot.Host.Port),
		User:         effectiveSnapshotUser(p.snapshot.Identity.User),
		OriginalHost: origHost,
		JumpHost:     p.snapshot.Node.ProxyJump,
	}
}

func (a *SSHAdapter) resolvePolicyTiers(
	nodeName string,
	snapshot config.ConnectionSnapshot,
	snapErr error,
	tier3Global *ssh.Options,
) (tier2Node, tier3Out, tier4OpenSSH *ssh.Options) {
	tier3Out = tier3Global
	if snapErr == nil {
		switch snapshot.Provenance {
		case config.ProvenanceOpenSSHDerived:
			tier4OpenSSH = a.resolveTier4OpenSSHOptions(nodeName, snapErr, snapshot).Clone()
		case config.ProvenanceOpenSSHVirtual:
			tier4OpenSSH = snapshot.Node.SSHOptions.Clone()
		default:
			tier2Node = snapshot.Node.SSHOptions
			tier4OpenSSH = filterNonVirtualTier4Options(a.resolveTier4OpenSSHOptions(nodeName, snapErr, snapshot))
		}
	} else if !config.IsOpenSSHNodeID(nodeName) {
		tier4OpenSSH = filterNonVirtualTier4Options(a.resolveTier4OpenSSHOptions(nodeName, snapErr, snapshot))
	}

	if tier4OpenSSH != nil && tier4OpenSSH.ControlConfig() != nil {
		tier4OpenSSH.ImplicitTier4 = true
	}
	return tier2Node, tier3Out, tier4OpenSSH
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

func (a *SSHAdapter) resolveTier4OpenSSHOptions(nodeName string, snapErr error, snapshot config.ConnectionSnapshot) *ssh.Options {
	if snapErr == nil {
		switch snapshot.Provenance {
		case config.ProvenanceOpenSSHDerived:
			if parser := a.getOpenSSHParser(); parser != nil {
				if opts, err := parser.GetSSHOptions(snapshot.Node.OpenSSHAlias); err == nil && !opts.IsEmpty() {
					return opts
				}
			}
			return nil
		case config.ProvenanceOpenSSHVirtual:
			return nil
		}
	}
	if config.IsOpenSSHNodeID(nodeName) {
		return nil
	}
	parser := a.getOpenSSHParser()
	if parser == nil {
		return nil
	}
	lookupKeys := a.buildTier4OpenSSHLookupKeys(parser, nodeName, snapErr, snapshot)

	// 1. First pass: prioritize concrete host matches (defined without wildcards like Host *)
	// across OpenSSHAlias, nodeName, Host.Address, and Alias so specific definitions take precedence.
	var layers []*ssh.Options
	for _, key := range lookupKeys {
		if parser.HasHost(key) {
			if opts, err := parser.GetSSHOptions(key); err == nil && !opts.IsEmpty() {
				layers = append(layers, opts)
			}
		}
	}
	if len(layers) == 0 {
		// 2. Second pass: fallback to generic wildcard / pattern matches (e.g. Host *).
		for _, key := range lookupKeys {
			if opts, err := parser.GetSSHOptions(key); err == nil && !opts.IsEmpty() {
				layers = append(layers, opts)
			}
		}
	}
	return ssh.MergeOptionLayers(layers...)
}

func (a *SSHAdapter) buildTier4OpenSSHLookupKeys(parser *config.OpenSSHParser, nodeName string, snapErr error, snapshot config.ConnectionSnapshot) []string {
	var lookupKeys []string
	appendUnique := func(keys ...string) {
		for _, k := range keys {
			k = strings.TrimSpace(k)
			if k != "" && !slicesContain(lookupKeys, k) {
				lookupKeys = append(lookupKeys, k)
			}
		}
	}

	openSSHAlias := snapshot.Node.OpenSSHAlias
	if openSSHAlias == "" {
		openSSHAlias = a.lookupNodeOpenSSHAlias(nodeName)
	}
	if openSSHAlias != "" {
		appendUnique(openSSHAlias)
	}
	if snapErr != nil {
		if !strings.Contains(nodeName, "@") && !strings.Contains(nodeName, ":") {
			appendUnique(nodeName)
		}
		if addr, port, ok := parseFallbackNodeIDAddressPort(nodeName); ok {
			appendUnique(parser.FindConcreteHostsByAddress(addr, port)...)
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
		appendUnique(parser.FindConcreteHostsByAddress(snapshot.Host.Address, uint16(effectiveSnapshotPort(snapshot.Host.Port)))...)
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

func slicesContain(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
