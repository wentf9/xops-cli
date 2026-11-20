package utils

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/pkg/config"
)

// ParseExcludeFlag 将 --exclude 选项的字符串值解析为规整化的列表。
// 支持以下输入形式:
//   - 单个值: "web-01"
//   - 逗号分隔: "web-01,web-02"
//
// 空白项会被自动过滤。
func ParseExcludeFlag(values []string) []string {
	var result []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if !slices.Contains(result, part) {
				result = append(result, part)
			}
		}
	}
	return result
}

// ResolveExcludes 将用户输入的排除项(可能是别名/IP/User@Host)解析为对应的 NodeID 集合。
// 对于无法匹配的输入,会返回错误(包含未匹配项列表),避免静默放过导致执行到本应排除的主机。
func ResolveExcludes(provider config.ConfigProvider, excludes []string) (map[string]struct{}, error) {
	return ResolveExcludesForTargets(provider, excludes, nil)
}

// ResolveExcludesForTargets resolves --exclude entries against provider and optional
// resolved target candidates, supporting saved nodes, composite user@host[:port] /
// openssh: specs, IPv6 literals, and -F none / missing ssh_config ad-hoc targets.
func ResolveExcludesForTargets(provider config.ConfigProvider, excludes []string, candidates []ExcludeTargetInfo) (map[string]struct{}, error) {
	return ResolveExcludesForTargetsWithOptions(provider, excludes, candidates, nil, "")
}

// ResolveExcludesForTargetsWithOptions resolves --exclude entries against provider and
// optional resolved target candidates while honoring CLI -o canonicalization/proxy
// directives and explicit CLI -J jump overrides.
func ResolveExcludesForTargetsWithOptions(
	provider config.ConfigProvider,
	excludes []string,
	candidates []ExcludeTargetInfo,
	rawCLIOptions []string,
	cliProxyJump string,
) (map[string]struct{}, error) {
	if len(excludes) == 0 {
		return nil, nil
	}
	resolved := make(map[string]struct{}, len(excludes))
	var unmatched []string
	for _, ex := range excludes {
		ok, err := resolveSingleExclude(provider, ex, candidates, resolved, rawCLIOptions, cliProxyJump)
		if err != nil {
			return nil, err
		}
		if !ok {
			unmatched = append(unmatched, ex)
		}
	}
	if len(unmatched) > 0 {
		return nil, fmt.Errorf("exclude: no matching node for: %s", strings.Join(unmatched, ", "))
	}
	return resolved, nil
}

func resolveSingleExclude(
	provider config.ConfigProvider,
	ex string,
	candidates []ExcludeTargetInfo,
	resolved map[string]struct{},
	rawCLIOptions []string,
	cliProxyJump string,
) (bool, error) {
	hasOpenSSHPrefix, addrUser, addrHost, addrPort, parsedOK := parseExcludeSpec(ex)

	if handled, err := resolveSingleExcludeBySelector(provider, ex, hasOpenSSHPrefix, addrUser, addrHost, addrPort, candidates, resolved, rawCLIOptions, cliProxyJump); err != nil || handled {
		return handled, err
	}

	if !parsedOK {
		return false, nil
	}

	matched, err := resolveExcludeViaTarget(provider, ex, hasOpenSSHPrefix, addrUser, addrHost, addrPort, candidates, resolved)
	if err != nil {
		return false, err
	}
	canonMatched := false
	if !hasOpenSSHPrefix && addrHost != "" {
		canonMatched, err = expandExcludeCanonicalCandidates(provider, addrUser, addrHost, addrPort, candidates, resolved, rawCLIOptions, cliProxyJump)
		if err != nil {
			return false, err
		}
	}
	if matched || canonMatched {
		return true, nil
	}

	if len(candidates) > 0 {
		return resolveExcludeViaCandidates(hasOpenSSHPrefix, addrUser, addrHost, addrPort, candidates, resolved), nil
	}
	return false, nil
}

func resolveSingleExcludeBySelector(
	provider config.ConfigProvider,
	ex string,
	hasOpenSSHPrefix bool,
	addrUser, addrHost string,
	addrPort uint16,
	candidates []ExcludeTargetInfo,
	resolved map[string]struct{},
	rawCLIOptions []string,
	cliProxyJump string,
) (bool, error) {
	if provider == nil {
		return false, nil
	}
	nodeID, err := provider.ResolveSelector(ex)
	if err != nil {
		return false, fmt.Errorf("resolve excluded node %q failed: %w", ex, err)
	}
	if isSavedNodeID(nodeID) {
		resolved[nodeID] = struct{}{}
		if !hasOpenSSHPrefix {
			addSavedBaseCandidates(resolved, nodeID, addrUser, addrPort, candidates)
		}
		return true, nil
	}
	if strings.HasPrefix(nodeID, config.OpenSSHNodePrefix) && providerOpenSSHHasConcreteHost(provider, nodeID) {
		resolved[nodeID] = struct{}{}
		if !hasOpenSSHPrefix && len(candidates) > 0 {
			aliasHost := config.UnwrapOpenSSHSelector(nodeID)
			if res, rErr := config.ResolveTarget(provider, config.ConnectionTarget{Selector: nodeID}); rErr == nil {
				addOpenSSHSavedCandidates(resolved, aliasHost, res.Host, res.Port, "", 0, candidates)
			}
		}
		if !hasOpenSSHPrefix && addrHost != "" {
			if _, cErr := expandExcludeCanonicalCandidates(provider, addrUser, addrHost, addrPort, candidates, resolved, rawCLIOptions, cliProxyJump); cErr != nil {
				return false, cErr
			}
		}
		return true, nil
	}
	return false, nil
}

func parseExcludeSpec(ex string) (hasOpenSSHPrefix bool, user, host string, port uint16, ok bool) {
	ref, err := config.ParseTargetRef(ex)
	if err != nil {
		return false, "", "", 0, false
	}
	return ref.OpenSSH, ref.User, ref.Host, ref.Port, true
}

func resolveExcludeViaTarget(
	provider config.ConfigProvider,
	rawEx string,
	hasOpenSSHPrefix bool,
	addrUser, addrHost string,
	addrPort uint16,
	candidates []ExcludeTargetInfo,
	resolved map[string]struct{},
) (bool, error) {
	if provider == nil {
		return false, nil
	}
	hasConcreteOpenSSH := providerOpenSSHHasConcreteHost(provider, addrHost)
	inSaved := !hasOpenSSHPrefix && selectorInSavedInventory(provider, addrHost)
	if !hasConcreteOpenSSH && !inSaved {
		return false, nil
	}

	selector := addrHost
	if hasOpenSSHPrefix {
		selector = config.OpenSSHNodePrefix + addrHost
	}
	res, err := config.ResolveTarget(provider, config.ConnectionTarget{
		Selector: selector,
		User:     addrUser,
		HasUser:  addrUser != "",
		Port:     addrPort,
		HasPort:  addrPort != 0,
	})
	if err != nil {
		var ambigErr *config.AmbiguousNodeError
		if errors.As(err, &ambigErr) {
			return false, fmt.Errorf("resolve excluded node %q failed: %w", rawEx, err)
		}
		return false, nil
	}

	if addrUser != "" || addrPort != 0 {
		recordCompositeTargetExclude(res, hasOpenSSHPrefix, addrUser, addrHost, addrPort, candidates, resolved)
		return true, nil
	}
	return recordBareTargetExclude(res, hasOpenSSHPrefix, hasConcreteOpenSSH, addrHost, candidates, resolved), nil
}

func recordBareTargetExclude(
	res config.ResolvedTarget,
	hasOpenSSHPrefix, hasConcreteOpenSSH bool,
	addrHost string,
	candidates []ExcludeTargetInfo,
	resolved map[string]struct{},
) bool {
	if res.MatchedNodeID != "" {
		if strings.HasPrefix(res.MatchedNodeID, config.OpenSSHNodePrefix) && !hasConcreteOpenSSH {
			return false
		}
		resolved[res.MatchedNodeID] = struct{}{}
		if !hasOpenSSHPrefix && isSavedNodeID(res.MatchedNodeID) {
			addSavedBaseCandidates(resolved, res.MatchedNodeID, "", 0, candidates)
		} else if !hasOpenSSHPrefix && hasConcreteOpenSSH {
			addOpenSSHSavedCandidates(resolved, addrHost, res.Host, res.Port, "", 0, candidates)
		}
		return true
	}
	if !hasOpenSSHPrefix && isSavedNodeID(res.BaseNodeID) {
		resolved[res.BaseNodeID] = struct{}{}
		addSavedBaseCandidates(resolved, res.BaseNodeID, "", 0, candidates)
		return true
	}
	if !hasConcreteOpenSSH {
		return false
	}
	resolved[config.OpenSSHNodePrefix+addrHost] = struct{}{}
	if res.NodeID != "" {
		resolved[res.NodeID] = struct{}{}
	}
	if !hasOpenSSHPrefix {
		addOpenSSHSavedCandidates(resolved, addrHost, res.Host, res.Port, "", 0, candidates)
	}
	for _, cand := range candidates {
		if (!hasOpenSSHPrefix || isOpenSSHCandidate(cand)) && candidateMatchesHost(cand, addrHost, res.Host) && cand.NodeID != "" {
			resolved[cand.NodeID] = struct{}{}
		}
	}
	return true
}

func recordCompositeTargetExclude(
	res config.ResolvedTarget,
	hasOpenSSHPrefix bool,
	addrUser, addrHost string,
	addrPort uint16,
	candidates []ExcludeTargetInfo,
	resolved map[string]struct{},
) {
	if res.OpenSSHAlias != "" {
		recordOpenSSHCompositeTargetExclude(res, hasOpenSSHPrefix, addrUser, addrHost, addrPort, candidates, resolved)
		return
	}

	if id := firstNonEmpty(res.MatchedNodeID, res.NodeID); id != "" {
		resolved[id] = struct{}{}
	}
	if !hasOpenSSHPrefix && isSavedNodeID(res.BaseNodeID) {
		addSavedBaseCandidates(resolved, res.BaseNodeID, addrUser, addrPort, candidates)
	}
	for _, cand := range candidates {
		if (!hasOpenSSHPrefix || isOpenSSHCandidate(cand)) && candidateMatchesHost(cand, addrHost, res.Host) && matchesUserPortFilter(cand, addrUser, addrPort) && cand.NodeID != "" {
			resolved[cand.NodeID] = struct{}{}
		}
	}
}

func expandExcludeCanonicalCandidates(
	provider config.ConfigProvider,
	addrUser, addrHost string,
	addrPort uint16,
	candidates []ExcludeTargetInfo,
	resolved map[string]struct{},
	rawCLIOptions []string,
	cliProxyJump string,
) (bool, error) {
	if provider == nil {
		return false, nil
	}
	canonHosts := config.CanonicalDomainCandidatesWithOptions(provider, addrHost, rawCLIOptions, cliProxyJump)
	matchedAny := false
	for _, fqdn := range canonHosts {
		concreteFQDN := providerOpenSSHHasConcreteHost(provider, fqdn)
		matchedCandidate := false
		for _, cand := range candidates {
			if candidateMatchesHost(cand, fqdn, "") && matchesUserPortFilter(cand, addrUser, addrPort) {
				matchedCandidate = true
				break
			}
		}
		if !concreteFQDN && !matchedCandidate {
			continue
		}
		ok, err := resolveExcludeViaTarget(provider, fqdn, false, addrUser, fqdn, addrPort, candidates, resolved)
		if err != nil {
			return false, err
		}
		if ok {
			matchedAny = true
			continue
		}
		if matchedCandidate && resolveExcludeViaCandidates(false, addrUser, fqdn, addrPort, candidates, resolved) {
			matchedAny = true
		}
	}
	return matchedAny, nil
}

func candidateMatchesOpenSSHExcludeName(cand ExcludeTargetInfo, res config.ResolvedTarget, addrHost string) bool {
	wantTargets := []string{addrHost, res.OpenSSHAlias, res.CanonicalHost}
	if baseHost := unwrapExcludeBaseHost(res.BaseNodeID); baseHost != "" {
		wantTargets = append(wantTargets, baseHost)
	}
	matchesAnyWant := func(name string) bool {
		if name == "" {
			return false
		}
		for _, w := range wantTargets {
			if w != "" && sameExcludeHost(name, w) {
				return true
			}
		}
		return false
	}
	if matchesAnyWant(cand.OpenSSHAlias) || matchesAnyWant(cand.CanonicalHost) || matchesAnyWant(unwrapExcludeBaseHost(cand.BaseNodeID)) {
		return true
	}
	if cand.OpenSSHAlias == "" && cand.CanonicalHost == "" && !strings.HasPrefix(cand.BaseNodeID, config.OpenSSHNodePrefix) {
		for _, raw := range cand.UnmanagedHosts {
			unwrapped := config.UnwrapOpenSSHSelector(strings.TrimSpace(raw))
			if matchesAnyWant(unwrapped) {
				return true
			}
			if _, h, _, err := ParseAddr(unwrapped); err == nil && matchesAnyWant(h) {
				return true
			}
		}
	}
	return false
}

func unwrapExcludeBaseHost(id string) string {
	unwrapped := strings.TrimSpace(config.UnwrapOpenSSHSelector(id))
	if unwrapped == "" {
		return ""
	}
	if _, h, _, err := ParseAddr(unwrapped); err == nil && h != "" {
		return h
	}
	return unwrapped
}

func recordOpenSSHCompositeTargetExclude(
	res config.ResolvedTarget,
	hasOpenSSHPrefix bool,
	addrUser, addrHost string,
	addrPort uint16,
	candidates []ExcludeTargetInfo,
	resolved map[string]struct{},
) {
	effResPort := effectiveExcludePort(res.Port)
	if res.User != "" {
		resolved[config.OpenSSHNodePrefix+config.FormatNodeID(res.User, res.OpenSSHAlias, effResPort)] = struct{}{}
		if res.CanonicalHost != "" {
			resolved[config.OpenSSHNodePrefix+config.FormatNodeID(res.User, res.CanonicalHost, effResPort)] = struct{}{}
		}
	}
	if !hasOpenSSHPrefix && isSavedNodeID(res.BaseNodeID) {
		if id := firstNonEmpty(res.MatchedNodeID, res.NodeID); id != "" {
			resolved[id] = struct{}{}
		}
		addSavedBaseCandidates(resolved, res.BaseNodeID, addrUser, addrPort, candidates)
	}
	for _, cand := range candidates {
		if !candidateMatchesOpenSSHExcludeName(cand, res, addrHost) || !matchesUserPortFilter(cand, addrUser, addrPort) {
			continue
		}
		if cand.User != "" {
			candPort := effectiveExcludePort(cand.Port)
			if res.OpenSSHAlias != "" {
				resolved[config.OpenSSHNodePrefix+config.FormatNodeID(cand.User, res.OpenSSHAlias, candPort)] = struct{}{}
			}
			if cand.OpenSSHAlias != "" {
				resolved[config.OpenSSHNodePrefix+config.FormatNodeID(cand.User, cand.OpenSSHAlias, candPort)] = struct{}{}
			}
			if cand.CanonicalHost != "" {
				resolved[config.OpenSSHNodePrefix+config.FormatNodeID(cand.User, cand.CanonicalHost, candPort)] = struct{}{}
			}
			if res.CanonicalHost != "" {
				resolved[config.OpenSSHNodePrefix+config.FormatNodeID(cand.User, res.CanonicalHost, candPort)] = struct{}{}
			}
			if addrHost != "" {
				resolved[config.OpenSSHNodePrefix+config.FormatNodeID(cand.User, addrHost, candPort)] = struct{}{}
			}
		}
	}
	if !hasOpenSSHPrefix {
		addOpenSSHSavedCandidates(resolved, addrHost, res.Host, res.Port, addrUser, addrPort, candidates)
	}
}

func resolveExcludeViaCandidates(
	hasOpenSSHPrefix bool,
	addrUser, addrHost string,
	addrPort uint16,
	candidates []ExcludeTargetInfo,
	resolved map[string]struct{},
) bool {
	trial := make(map[string]struct{})
	for _, cand := range candidates {
		if hasOpenSSHPrefix && !isOpenSSHCandidate(cand) {
			continue
		}
		if !candidateMatchesHost(cand, addrHost, "") || !matchesUserPortFilter(cand, addrUser, addrPort) {
			continue
		}
		recordCandidateTrialExclude(trial, cand, hasOpenSSHPrefix, addrUser, addrHost, addrPort)
	}
	if len(trial) == 0 {
		return false
	}
	matchedAny := false
	for _, cand := range candidates {
		if IsTargetExcluded(trial, cand) {
			matchedAny = true
			break
		}
	}
	if !matchedAny {
		return false
	}
	for k := range trial {
		resolved[k] = struct{}{}
	}
	return true
}

func recordCandidateTrialExclude(
	trial map[string]struct{},
	cand ExcludeTargetInfo,
	hasOpenSSHPrefix bool,
	addrUser, addrHost string,
	addrPort uint16,
) {
	if addrUser != "" || addrPort != 0 {
		recordNodeID := cand.NodeID
		if recordNodeID != "" && (!strings.HasPrefix(recordNodeID, config.OpenSSHNodePrefix) || hasCompositeExcludeAddr(recordNodeID)) {
			trial[recordNodeID] = struct{}{}
		}
		if cand.User != "" {
			effPort := effectiveExcludePort(cand.Port)
			recordHost := func(h string) {
				if h == "" {
					return
				}
				trial[config.OpenSSHNodePrefix+config.FormatNodeID(cand.User, h, effPort)] = struct{}{}
				if !hasOpenSSHPrefix {
					trial[config.FormatNodeID(cand.User, h, effPort)] = struct{}{}
				}
			}
			recordHost(addrHost)
			recordHost(cand.OpenSSHAlias)
			recordHost(cand.CanonicalHost)
		} else if recordNodeID != "" {
			trial[recordNodeID] = struct{}{}
		}
		return
	}
	if cand.NodeID != "" {
		trial[cand.NodeID] = struct{}{}
	}
	if hasOpenSSHPrefix {
		trial[config.OpenSSHNodePrefix+addrHost] = struct{}{}
		return
	}
	trial[addrHost] = struct{}{}
}

func providerOpenSSHHasConcreteHost(provider config.ConfigProvider, host string) bool {
	clean := config.UnwrapOpenSSHSelector(host)
	if provider == nil || clean == "" || !config.HasOpenSSHConfig(provider) {
		return false
	}
	if src, ok := provider.(interface{ GetOpenSSHParser() *config.OpenSSHParser }); ok {
		parser := src.GetOpenSSHParser()
		return parser != nil && parser.HasHost(clean)
	}
	res, err := config.ResolveTarget(provider, config.ConnectionTarget{
		Selector: config.OpenSSHNodePrefix + clean,
	})
	return err == nil && res.OpenSSHAlias != ""
}

func isOpenSSHCandidate(cand ExcludeTargetInfo) bool {
	return cand.OpenSSHAlias != "" ||
		strings.HasPrefix(cand.NodeID, config.OpenSSHNodePrefix) ||
		strings.HasPrefix(cand.MatchedNodeID, config.OpenSSHNodePrefix) ||
		strings.HasPrefix(cand.BaseNodeID, config.OpenSSHNodePrefix)
}

func selectorInSavedInventory(provider config.ConfigProvider, host string) bool {
	if provider == nil || strings.TrimSpace(host) == "" {
		return false
	}
	nid, err := provider.ResolveSelector(host)
	if err != nil {
		var ambigErr *config.AmbiguousNodeError
		return errors.As(err, &ambigErr)
	}
	return isSavedNodeID(nid)
}

func isSavedNodeID(nodeID string) bool {
	return nodeID != "" && !strings.HasPrefix(nodeID, config.OpenSSHNodePrefix)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func addSavedBaseCandidates(
	resolved map[string]struct{},
	savedNodeID, wantUser string,
	wantPort uint16,
	candidates []ExcludeTargetInfo,
) {
	savedUser, savedHost, savedPort, parseErr := ParseAddr(savedNodeID)
	hasSavedAddr := parseErr == nil && savedUser != "" && savedHost != "" && savedPort != 0
	if hasSavedAddr && (wantUser != "" || wantPort != 0) {
		effUser := firstNonEmpty(wantUser, savedUser)
		effPort := wantPort
		if effPort == 0 {
			effPort = savedPort
		}
		resolved[config.FormatNodeID(effUser, savedHost, effPort)] = struct{}{}
	}
	for _, cand := range candidates {
		if !matchesUserPortFilter(cand, wantUser, wantPort) {
			continue
		}
		if cand.BaseNodeID == savedNodeID {
			if cand.NodeID != "" {
				resolved[cand.NodeID] = struct{}{}
			}
			if hasSavedAddr {
				effUser := firstNonEmpty(cand.User, wantUser, savedUser)
				effPort := effectiveExcludePort(cand.Port)
				if wantPort != 0 {
					effPort = wantPort
				}
				resolved[config.FormatNodeID(effUser, savedHost, effPort)] = struct{}{}
			}
			continue
		}
		if hasSavedAddr && wantUser != "" && isSavedNodeID(cand.BaseNodeID) && cand.NodeID != "" {
			effPort := effectiveExcludePort(cand.Port)
			if wantPort != 0 {
				effPort = wantPort
			}
			if cand.NodeID == config.FormatNodeID(wantUser, savedHost, effPort) {
				resolved[cand.NodeID] = struct{}{}
			}
		}
	}
}

func addOpenSSHSavedCandidates(
	resolved map[string]struct{},
	aliasHost, resHost string,
	resPort uint16,
	wantUser string,
	wantPort uint16,
	candidates []ExcludeTargetInfo,
) {
	for _, cand := range candidates {
		if cand.OpenSSHAlias != "" || !isSavedNodeID(cand.BaseNodeID) || cand.NodeID == "" {
			continue
		}
		if !matchesUserPortFilter(cand, wantUser, wantPort) {
			continue
		}
		if candidateMatchesHost(cand, aliasHost, "") {
			resolved[cand.NodeID] = struct{}{}
			continue
		}
		if resHost == "" || !candidateMatchesHost(cand, aliasHost, resHost) {
			continue
		}
		if wantPort == 0 && resPort != 0 && !savedCandidateMatchesOpenSSHPort(cand, resPort) {
			continue
		}
		resolved[cand.NodeID] = struct{}{}
	}
}

func savedCandidateMatchesOpenSSHPort(cand ExcludeTargetInfo, resPort uint16) bool {
	targetPort := effectiveExcludePort(resPort)
	if effectiveExcludePort(cand.Port) == targetPort {
		return true
	}
	_, _, basePort, err := ParseAddr(cand.BaseNodeID)
	return err == nil && basePort != 0 && basePort == targetPort
}

func effectiveExcludePort(port uint16) uint16 {
	if port == 0 {
		return 22
	}
	return port
}

func matchesUserPortFilter(cand ExcludeTargetInfo, wantUser string, wantPort uint16) bool {
	if wantUser != "" && cand.User != wantUser {
		return false
	}
	if wantPort != 0 && effectiveExcludePort(cand.Port) != wantPort {
		return false
	}
	return true
}

func hasCompositeExcludeAddr(nodeID string) bool {
	unwrapped := strings.TrimPrefix(strings.TrimSpace(nodeID), config.OpenSSHNodePrefix)
	u, _, p, err := ParseAddr(unwrapped)
	return err == nil && u != "" && p != 0
}

func candidateMatchesHost(cand ExcludeTargetInfo, wantHost, resolvedHost string) bool {
	check := func(candidateHost string) bool {
		if candidateHost == "" {
			return false
		}
		if sameExcludeHost(candidateHost, wantHost) {
			return true
		}
		return resolvedHost != "" && sameExcludeHost(candidateHost, resolvedHost)
	}
	if cand.OpenSSHAlias != "" && check(cand.OpenSSHAlias) {
		return true
	}
	if cand.CanonicalHost != "" && check(cand.CanonicalHost) {
		return true
	}
	for _, h := range cand.UnmanagedHosts {
		unwrapped := config.UnwrapOpenSSHSelector(h)
		if check(unwrapped) {
			return true
		}
		if _, parsedH, _, err := ParseAddr(unwrapped); err == nil && check(parsedH) {
			return true
		}
	}
	if cand.NodeID != "" && !strings.HasPrefix(cand.NodeID, config.OpenSSHNodePrefix) {
		if _, parsedH, _, err := ParseAddr(cand.NodeID); err == nil && check(parsedH) {
			return true
		}
	}
	return false
}

func sameExcludeHost(a, b string) bool {
	ca := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(a), "]"), "[")
	cb := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(b), "]"), "[")
	if ca == "" || cb == "" {
		return false
	}
	if strings.EqualFold(ca, cb) {
		return true
	}
	ipA, errA := netip.ParseAddr(ca)
	ipB, errB := netip.ParseAddr(cb)
	return errA == nil && errB == nil && ipA == ipB
}

// ExcludeTargetInfo describes a candidate target host or node for unified
// --exclude matching across scp and exec.
type ExcludeTargetInfo struct {
	NodeID         string
	MatchedNodeID  string
	BaseNodeID     string
	OpenSSHAlias   string
	CanonicalHost  string
	User           string
	Port           uint16
	UnmanagedHosts []string
}

func matchesOpenSSHHostExcludeKeys(excludes map[string]struct{}, host, user string, port uint16) bool {
	if host == "" {
		return false
	}
	var hostID string
	if user != "" {
		hostID = config.OpenSSHNodePrefix + config.FormatNodeID(user, host, effectiveExcludePort(port))
	}
	return hasAnyExcludeKey(excludes, config.OpenSSHNodePrefix+host, host, hostID)
}

func hasAnyExcludeKey(excludes map[string]struct{}, keys ...string) bool {
	for _, k := range keys {
		if k == "" {
			continue
		}
		if _, ok := excludes[k]; ok {
			return true
		}
	}
	return false
}

// IsTargetExcluded reports whether the target described by info matches any
// entry in excludes, handling saved NodeIDs, OpenSSH "openssh:" aliases,
// disambiguated "openssh:user@alias:port" IDs, and pre-canonicalized names.
func IsTargetExcluded(excludes map[string]struct{}, info ExcludeTargetInfo) bool {
	if len(excludes) == 0 {
		return false
	}
	if hasAnyExcludeKey(excludes, info.NodeID, info.MatchedNodeID) {
		return true
	}
	if strings.HasPrefix(info.BaseNodeID, config.OpenSSHNodePrefix) {
		unwrappedBase := config.UnwrapOpenSSHSelector(info.BaseNodeID)
		if hasAnyExcludeKey(excludes, info.BaseNodeID, config.OpenSSHNodePrefix+unwrappedBase) {
			return true
		}
		if _, parsedH, _, err := ParseAddr(unwrappedBase); err == nil && parsedH != "" {
			unwrappedBase = parsedH
		}
		if matchesOpenSSHHostExcludeKeys(excludes, unwrappedBase, info.User, info.Port) {
			return true
		}
	}
	if matchesOpenSSHHostExcludeKeys(excludes, info.OpenSSHAlias, info.User, info.Port) {
		return true
	}
	if matchesOpenSSHHostExcludeKeys(excludes, info.CanonicalHost, info.User, info.Port) {
		return true
	}
	return matchesUnmanagedHostExclude(excludes, info)
}

func matchesUnmanagedHostExclude(excludes map[string]struct{}, info ExcludeTargetInfo) bool {
	if info.MatchedNodeID != "" && !strings.HasPrefix(info.MatchedNodeID, config.OpenSSHNodePrefix) {
		return false
	}
	savedBase := isSavedNodeID(info.BaseNodeID)
	for _, h := range info.UnmanagedHosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		unwrapped := config.UnwrapOpenSSHSelector(h)
		if u, parsedH, p, err := ParseAddr(unwrapped); err == nil && parsedH != "" && (u != "" || p != 0) {
			if !matchesUserPortFilter(info, u, p) {
				unwrapped = parsedH
				h = parsedH
			}
		}
		var prefixed string
		if unwrapped != "" && !savedBase {
			prefixed = config.OpenSSHNodePrefix + unwrapped
		}
		var qualified, prefixedQualified string
		if unwrapped != "" && !savedBase && info.User != "" {
			if ip, err := netip.ParseAddr(strings.TrimPrefix(strings.TrimSuffix(unwrapped, "]"), "[")); err == nil {
				qualified = config.FormatNodeID(info.User, ip.String(), effectiveExcludePort(info.Port))
				prefixedQualified = config.OpenSSHNodePrefix + qualified
			} else if !strings.ContainsAny(unwrapped, "@:") {
				qualified = config.FormatNodeID(info.User, unwrapped, effectiveExcludePort(info.Port))
				prefixedQualified = config.OpenSSHNodePrefix + qualified
			}
		}
		if hasAnyExcludeKey(excludes, h, unwrapped, prefixed, qualified, prefixedQualified) {
			return true
		}
	}
	return false
}
