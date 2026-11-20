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
	if err != nil || nodeID == "" {
		if canonEx := canonicalExcludeKey(ex); canonEx != "" && canonEx != ex {
			if canonID, canonErr := provider.ResolveSelector(canonEx); canonErr == nil && canonID != "" {
				nodeID = canonID
				err = nil
			} else {
				var ambigErr *config.AmbiguousNodeError
				if errors.As(canonErr, &ambigErr) {
					err = canonErr
				}
			}
		}
	}
	if err != nil {
		return false, fmt.Errorf("resolve excluded node %q failed: %w", ex, err)
	}
	if isSavedNodeID(nodeID) {
		recordExcludeKey(resolved, nodeID)
		if !hasOpenSSHPrefix {
			addSavedBaseCandidates(provider, resolved, nodeID, addrUser, addrPort, candidates)
		}
		return true, nil
	}
	if strings.HasPrefix(nodeID, config.OpenSSHNodePrefix) && providerOpenSSHHasConcreteHost(provider, nodeID) {
		recordExcludeKey(resolved, nodeID)
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
	return ref.OpenSSH, ref.User, canonicalExcludeHost(ref.Host), ref.Port, true
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
	if hasOpenSSHPrefix || (!inSaved && hasConcreteOpenSSH && strings.Contains(addrHost, ":")) {
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
		recordCompositeTargetExclude(provider, res, hasOpenSSHPrefix, addrUser, addrHost, addrPort, candidates, resolved)
		return true, nil
	}
	return recordBareTargetExclude(provider, res, hasOpenSSHPrefix, hasConcreteOpenSSH, addrHost, candidates, resolved), nil
}

func recordBareTargetExclude(
	provider config.ConfigProvider,
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
		recordExcludeKey(resolved, res.MatchedNodeID)
		if !hasOpenSSHPrefix && isSavedNodeID(res.MatchedNodeID) {
			addSavedBaseCandidates(provider, resolved, res.MatchedNodeID, "", 0, candidates)
		} else if !hasOpenSSHPrefix && hasConcreteOpenSSH {
			addOpenSSHSavedCandidates(resolved, addrHost, res.Host, res.Port, "", 0, candidates)
		}
		return true
	}
	if !hasOpenSSHPrefix && isSavedNodeID(res.BaseNodeID) {
		recordExcludeKey(resolved, res.BaseNodeID)
		addSavedBaseCandidates(provider, resolved, res.BaseNodeID, "", 0, candidates)
		return true
	}
	if !hasConcreteOpenSSH {
		return false
	}
	recordExcludeKey(resolved, config.OpenSSHNodePrefix+addrHost, res.NodeID)
	if !hasOpenSSHPrefix {
		addOpenSSHSavedCandidates(resolved, addrHost, res.Host, res.Port, "", 0, candidates)
	}
	for _, cand := range candidates {
		if (!hasOpenSSHPrefix || isOpenSSHCandidate(cand)) && candidateMatchesHost(cand, addrHost, res.Host) && cand.NodeID != "" {
			recordExcludeKey(resolved, cand.NodeID)
		}
	}
	return true
}

func recordCompositeTargetExclude(
	provider config.ConfigProvider,
	res config.ResolvedTarget,
	hasOpenSSHPrefix bool,
	addrUser, addrHost string,
	addrPort uint16,
	candidates []ExcludeTargetInfo,
	resolved map[string]struct{},
) {
	if res.OpenSSHAlias != "" {
		recordOpenSSHCompositeTargetExclude(provider, res, hasOpenSSHPrefix, addrUser, addrHost, addrPort, candidates, resolved)
		return
	}

	savedBaseID := firstNonEmpty(res.MatchedNodeID, res.BaseNodeID)
	skipConcreteOpenSSH := !hasOpenSSHPrefix && isSavedNodeID(savedBaseID)

	if id := firstNonEmpty(res.MatchedNodeID, res.NodeID); id != "" && !isBareOpenSSHNodeID(id) {
		recordExcludeKey(resolved, id)
	}
	if !hasOpenSSHPrefix {
		savedBase := res.BaseNodeID
		if !isSavedNodeID(savedBase) {
			savedBase = res.MatchedNodeID
		}
		if isSavedNodeID(savedBase) {
			addSavedBaseCandidates(provider, resolved, savedBase, addrUser, addrPort, candidates)
		}
	}
	if addrUser == "" && addrPort != 0 && !skipConcreteOpenSSH {
		for _, h := range []string{addrHost, res.Host} {
			recordCompositeCandidateExcludeKey(resolved, h, "", addrPort, !hasOpenSSHPrefix)
		}
	}
	recordCompositeCandidateMatches(res, hasOpenSSHPrefix, skipConcreteOpenSSH, addrUser, addrHost, addrPort, candidates, resolved)
}

func recordCompositeCandidateMatches(
	res config.ResolvedTarget,
	hasOpenSSHPrefix, skipConcreteOpenSSH bool,
	addrUser, addrHost string,
	addrPort uint16,
	candidates []ExcludeTargetInfo,
	resolved map[string]struct{},
) {
	for _, cand := range candidates {
		if skipConcreteOpenSSH && isConcreteOpenSSHCandidate(cand) {
			continue
		}
		if hasOpenSSHPrefix && !isOpenSSHCandidate(cand) {
			continue
		}
		if !candidateMatchesHost(cand, addrHost, res.Host) || !matchesUserPortFilter(cand, addrUser, addrPort) {
			continue
		}
		if cand.NodeID != "" && !isBareOpenSSHNodeID(cand.NodeID) {
			recordExcludeKey(resolved, cand.NodeID)
			continue
		}
		if !isOpenSSHCandidate(cand) {
			continue
		}
		effPort := cand.Port
		if cand.User == "" && effPort == 0 {
			effPort = addrPort
		}
		for _, h := range []string{addrHost, res.Host, cand.OpenSSHAlias, cand.CanonicalHost, config.UnwrapOpenSSHSelector(cand.NodeID)} {
			recordCompositeCandidateExcludeKey(resolved, h, cand.User, effPort, !hasOpenSSHPrefix)
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
	provider config.ConfigProvider,
	res config.ResolvedTarget,
	hasOpenSSHPrefix bool,
	addrUser, addrHost string,
	addrPort uint16,
	candidates []ExcludeTargetInfo,
	resolved map[string]struct{},
) {
	effResPort := effectiveExcludePort(res.Port)
	if addrUser == "" && addrPort != 0 {
		resPort := firstNonZeroPort(addrPort, res.Port)
		recordCompositeCandidateExcludeKey(resolved, res.OpenSSHAlias, "", resPort, false)
		recordCompositeCandidateExcludeKey(resolved, res.CanonicalHost, "", resPort, false)
	} else if res.User != "" {
		recordCompositeCandidateExcludeKey(resolved, res.OpenSSHAlias, res.User, effResPort, false)
		recordCompositeCandidateExcludeKey(resolved, res.CanonicalHost, res.User, effResPort, false)
	} else if resPort := firstNonZeroPort(res.Port, addrPort); resPort != 0 {
		recordCompositeCandidateExcludeKey(resolved, res.OpenSSHAlias, "", resPort, false)
		recordCompositeCandidateExcludeKey(resolved, res.CanonicalHost, "", resPort, false)
	}
	if !hasOpenSSHPrefix && (isSavedNodeID(res.BaseNodeID) || isSavedNodeID(res.MatchedNodeID)) {
		if id := firstNonEmpty(res.MatchedNodeID, res.NodeID); id != "" && !isBareOpenSSHNodeID(id) {
			recordExcludeKey(resolved, id)
		}
		savedBase := res.BaseNodeID
		if !isSavedNodeID(savedBase) {
			savedBase = res.MatchedNodeID
		}
		addSavedBaseCandidates(provider, resolved, savedBase, addrUser, addrPort, candidates)
	}
	for _, cand := range candidates {
		if !candidateMatchesOpenSSHExcludeName(cand, res, addrHost) || !matchesUserPortFilter(cand, addrUser, addrPort) {
			continue
		}
		effCandPort := cand.Port
		if cand.User == "" && effCandPort == 0 {
			effCandPort = addrPort
		}
		if cand.User != "" || effCandPort != 0 {
			for _, h := range []string{res.OpenSSHAlias, cand.OpenSSHAlias, cand.CanonicalHost, res.CanonicalHost, addrHost} {
				recordCompositeCandidateExcludeKey(resolved, h, cand.User, effCandPort, false)
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
		recordExcludeKey(resolved, k)
	}
	return true
}

func firstNonZeroPort(ports ...uint16) uint16 {
	for _, p := range ports {
		if p != 0 {
			return p
		}
	}
	return 0
}

func isBareOpenSSHNodeID(nodeID string) bool {
	return strings.HasPrefix(nodeID, config.OpenSSHNodePrefix) && !hasCompositeExcludeAddr(nodeID)
}

func formatHostPortExcludeKey(host string, port uint16) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func recordCompositeCandidateExcludeKey(
	dst map[string]struct{},
	host string,
	user string,
	port uint16,
	includeSaved bool,
) {
	if host == "" {
		return
	}
	effPort := effectiveExcludePort(port)
	if user != "" {
		key := config.FormatNodeID(user, host, effPort)
		recordExcludeKey(dst, config.OpenSSHNodePrefix+key)
		if includeSaved {
			recordExcludeKey(dst, key)
		}
		return
	}
	if port != 0 {
		key := formatHostPortExcludeKey(host, effPort)
		recordExcludeKey(dst, config.OpenSSHNodePrefix+key)
		if includeSaved {
			recordExcludeKey(dst, key)
		}
	}
}

func recordCandidateTrialExclude(
	trial map[string]struct{},
	cand ExcludeTargetInfo,
	hasOpenSSHPrefix bool,
	addrUser, addrHost string,
	addrPort uint16,
) {
	if addrUser != "" || addrPort != 0 {
		if cand.NodeID != "" && !isBareOpenSSHNodeID(cand.NodeID) {
			recordExcludeKey(trial, cand.NodeID)
		}
		effPort := cand.Port
		if cand.User == "" && effPort == 0 {
			effPort = addrPort
		}
		if cand.User != "" || effPort != 0 {
			for _, h := range []string{addrHost, cand.OpenSSHAlias, cand.CanonicalHost} {
				recordCompositeCandidateExcludeKey(trial, h, cand.User, effPort, !hasOpenSSHPrefix)
			}
		}
		return
	}
	if cand.NodeID != "" {
		recordExcludeKey(trial, cand.NodeID)
	}
	if hasOpenSSHPrefix {
		recordExcludeKey(trial, config.OpenSSHNodePrefix+addrHost)
		return
	}
	recordExcludeKey(trial, addrHost)
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

func isConcreteOpenSSHCandidate(cand ExcludeTargetInfo) bool {
	return strings.TrimSpace(cand.OpenSSHAlias) != ""
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

func resolveSavedNodeEndpoint(provider config.ConfigProvider, savedNodeID string) (user, host string, port uint16, ok bool) {
	if provider != nil && savedNodeID != "" {
		if _, h, ident, err := provider.Resolve(savedNodeID); err == nil {
			host = canonicalExcludeHost(h.Address)
			port = effectiveExcludePort(h.Port)
			user = strings.TrimSpace(ident.User)
			if host != "" && port != 0 {
				return user, host, port, true
			}
		}
	}
	savedUser, savedHost, savedPort, parseErr := ParseAddr(savedNodeID)
	savedHost = canonicalExcludeHost(savedHost)
	if parseErr == nil && savedUser != "" && savedHost != "" && savedPort != 0 {
		return savedUser, savedHost, savedPort, true
	}
	return "", "", 0, false
}

func recordSavedBaseCandidateMatch(
	resolved map[string]struct{},
	savedNodeID, savedUser, savedHost string,
	savedPort uint16,
	wantUser string,
	wantPort uint16,
	hasSavedAddr bool,
	cand ExcludeTargetInfo,
) {
	if !matchesUserPortFilter(cand, wantUser, wantPort) {
		return
	}
	if cand.BaseNodeID == savedNodeID {
		recordMatchedSavedBaseNode(resolved, savedNodeID, savedUser, savedHost, wantUser, wantPort, hasSavedAddr, cand)
		return
	}
	if !hasSavedAddr || cand.NodeID == "" || isConcreteOpenSSHCandidate(cand) {
		return
	}
	recordUnmatchedSavedBaseNode(resolved, savedHost, wantUser, wantPort, cand)
}

func recordMatchedSavedBaseNode(
	resolved map[string]struct{},
	savedNodeID, savedUser, savedHost string,
	wantUser string,
	wantPort uint16,
	hasSavedAddr bool,
	cand ExcludeTargetInfo,
) {
	if cand.NodeID != "" && ((wantUser == "" && wantPort == 0) || !isBareOpenSSHNodeID(cand.NodeID)) {
		recordExcludeKey(resolved, cand.NodeID)
	}
	if !hasSavedAddr || (wantUser == "" && wantPort == 0 && cand.NodeID == savedNodeID) {
		return
	}
	effUser := firstNonEmpty(cand.User, wantUser, savedUser)
	effPort := effectiveExcludePort(cand.Port)
	if wantPort != 0 {
		effPort = wantPort
	}
	if effUser != "" {
		recordExcludeKey(resolved, config.FormatNodeID(effUser, savedHost, effPort))
	} else if wantPort != 0 || cand.Port != 0 {
		recordCompositeCandidateExcludeKey(resolved, savedHost, "", effPort, true)
	}
}

func recordUnmatchedSavedBaseNode(
	resolved map[string]struct{},
	savedHost string,
	wantUser string,
	wantPort uint16,
	cand ExcludeTargetInfo,
) {
	if isSavedNodeID(cand.BaseNodeID) && wantUser != "" {
		effPort := effectiveExcludePort(cand.Port)
		if wantPort != 0 {
			effPort = wantPort
		}
		if canonicalExcludeKey(cand.NodeID) == canonicalExcludeKey(config.FormatNodeID(wantUser, savedHost, effPort)) {
			recordExcludeKey(resolved, cand.NodeID)
		}
		return
	}
	if (cand.BaseNodeID != "" && isSavedNodeID(cand.BaseNodeID)) || !candidateMatchesHost(cand, savedHost, "") {
		return
	}
	if (wantUser != "" || wantPort != 0) && isBareOpenSSHNodeID(cand.NodeID) {
		effUser := firstNonEmpty(cand.User, wantUser)
		effPort := firstNonZeroPort(wantPort, cand.Port)
		recordCompositeCandidateExcludeKey(resolved, savedHost, effUser, effPort, true)
		recordCompositeCandidateExcludeKey(resolved, config.UnwrapOpenSSHSelector(cand.NodeID), effUser, effPort, true)
		return
	}
	recordExcludeKey(resolved, cand.NodeID)
}

func addSavedBaseCandidates(
	provider config.ConfigProvider,
	resolved map[string]struct{},
	savedNodeID, wantUser string,
	wantPort uint16,
	candidates []ExcludeTargetInfo,
) {
	savedUser, savedHost, savedPort, hasSavedAddr := resolveSavedNodeEndpoint(provider, savedNodeID)
	if hasSavedAddr && (wantUser != "" || wantPort != 0) {
		effUser := firstNonEmpty(wantUser, savedUser)
		effPort := wantPort
		if effPort == 0 {
			effPort = savedPort
		}
		if effUser != "" {
			recordExcludeKey(resolved, config.FormatNodeID(effUser, savedHost, effPort))
		}
	}
	for _, cand := range candidates {
		recordSavedBaseCandidateMatch(resolved, savedNodeID, savedUser, savedHost, savedPort, wantUser, wantPort, hasSavedAddr, cand)
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
		if cand.OpenSSHAlias != "" || cand.NodeID == "" || (!isSavedNodeID(cand.BaseNodeID) && (cand.BaseNodeID != "" || !isSavedNodeID(cand.NodeID))) {
			continue
		}
		if !matchesUserPortFilter(cand, wantUser, wantPort) {
			continue
		}
		if candidateMatchesHost(cand, aliasHost, "") {
			recordExcludeKey(resolved, cand.NodeID)
			continue
		}
		if resHost == "" || !candidateMatchesHost(cand, aliasHost, resHost) {
			continue
		}
		if wantPort == 0 && resPort != 0 && !savedCandidateMatchesOpenSSHPort(cand, resPort) {
			continue
		}
		recordExcludeKey(resolved, cand.NodeID)
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
		return candidateHost != "" && (sameExcludeHost(candidateHost, wantHost) || (resolvedHost != "" && sameExcludeHost(candidateHost, resolvedHost)))
	}
	if check(cand.OpenSSHAlias) || check(cand.CanonicalHost) {
		return true
	}
	if cand.ResolvedHost != "" {
		if sameExcludeHost(cand.ResolvedHost, wantHost) || (cand.OpenSSHAlias == "" && resolvedHost != "" && sameExcludeHost(cand.ResolvedHost, resolvedHost)) {
			return true
		}
	}
	return candidateExtraHostMatches(cand, check)
}

func candidateExtraHostMatches(cand ExcludeTargetInfo, check func(string) bool) bool {
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

func canonicalExcludeHost(raw string) string {
	return config.NormalizeHostAddress(raw)
}

func canonicalExcludeKey(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	ref, err := config.ParseTargetRef(trimmed)
	if err != nil {
		return canonicalExcludeHost(trimmed)
	}
	host := canonicalExcludeHost(ref.Host)
	if host == "" {
		return trimmed
	}
	prefix := ""
	if ref.OpenSSH {
		prefix = config.OpenSSHNodePrefix
	}
	if ref.User != "" && ref.Port != 0 {
		return prefix + config.FormatNodeID(ref.User, host, ref.Port)
	}
	formattedHost := host
	if strings.Contains(host, ":") && (ref.User != "" || ref.Port != 0) {
		formattedHost = "[" + host + "]"
	}
	if ref.User != "" {
		return prefix + ref.User + "@" + formattedHost
	}
	if ref.Port != 0 {
		return fmt.Sprintf("%s%s:%d", prefix, formattedHost, ref.Port)
	}
	return prefix + host
}

func recordExcludeKey(dst map[string]struct{}, keys ...string) {
	if dst == nil {
		return
	}
	for _, k := range keys {
		if k == "" {
			continue
		}
		dst[k] = struct{}{}
		if ck := canonicalExcludeKey(k); ck != "" {
			dst[ck] = struct{}{}
		}
	}
}

func sameExcludeHost(a, b string) bool {
	return config.SameHostAddress(a, b)
}

// ExcludeTargetInfo describes a candidate target host or node for unified
// --exclude matching across scp and exec.
type ExcludeTargetInfo struct {
	NodeID         string
	MatchedNodeID  string
	BaseNodeID     string
	OpenSSHAlias   string
	CanonicalHost  string
	ResolvedHost   string
	User           string
	Port           uint16
	UnmanagedHosts []string
}

// ExcludeTargetBuildInput captures the resolved fields needed to build a uniform ExcludeTargetInfo
// across exec and scp callers.
type ExcludeTargetBuildInput struct {
	NodeID           string
	MatchedNodeID    string
	BaseNodeID       string
	OpenSSHAlias     string
	CanonicalHost    string
	ResolvedHost     string
	User             string
	Port             uint16
	UnmanagedHosts   []string
	HostNameOverride string
}

// BuildExcludeTargetInfo constructs an ExcludeTargetInfo, preserving ResolvedHost as an explicit
// endpoint field while only mirroring ResolvedHost into UnmanagedHosts for saved/ad-hoc targets
// (never for OpenSSH alias targets).
func BuildExcludeTargetInfo(in ExcludeTargetBuildInput) ExcludeTargetInfo {
	unmanaged := make([]string, 0, len(in.UnmanagedHosts)+2)
	appendUnique := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || slices.Contains(unmanaged, v) {
			return
		}
		unmanaged = append(unmanaged, v)
	}
	for _, h := range in.UnmanagedHosts {
		appendUnique(h)
	}
	if in.ResolvedHost != "" && in.OpenSSHAlias == "" && !strings.HasPrefix(in.NodeID, config.OpenSSHNodePrefix) {
		appendUnique(in.ResolvedHost)
	}
	appendUnique(in.HostNameOverride)
	return ExcludeTargetInfo{
		NodeID:         in.NodeID,
		MatchedNodeID:  in.MatchedNodeID,
		BaseNodeID:     in.BaseNodeID,
		OpenSSHAlias:   in.OpenSSHAlias,
		CanonicalHost:  in.CanonicalHost,
		ResolvedHost:   in.ResolvedHost,
		User:           in.User,
		Port:           in.Port,
		UnmanagedHosts: unmanaged,
	}
}

func matchesOpenSSHHostExcludeKeys(excludes map[string]struct{}, host, user string, port uint16) bool {
	if host == "" {
		return false
	}
	canonHost := canonicalExcludeHost(host)
	effPort := effectiveExcludePort(port)
	var hostID, canonHostID string
	if user != "" {
		hostID = config.OpenSSHNodePrefix + config.FormatNodeID(user, host, effPort)
		if canonHost != "" {
			canonHostID = config.OpenSSHNodePrefix + config.FormatNodeID(user, canonHost, effPort)
		}
	}
	hostPort := formatHostPortExcludeKey(host, effPort)
	var canonHostPort string
	if canonHost != "" {
		canonHostPort = formatHostPortExcludeKey(canonHost, effPort)
	}
	var prefixedHostPort, prefixedCanonHostPort string
	if hostPort != "" {
		prefixedHostPort = config.OpenSSHNodePrefix + hostPort
	}
	if canonHostPort != "" {
		prefixedCanonHostPort = config.OpenSSHNodePrefix + canonHostPort
	}
	return hasAnyExcludeKey(
		excludes,
		config.OpenSSHNodePrefix+host,
		config.OpenSSHNodePrefix+canonHost,
		host,
		canonHost,
		hostID,
		canonHostID,
		hostPort,
		canonHostPort,
		prefixedHostPort,
		prefixedCanonHostPort,
	)
}

func hasAnyExcludeKey(excludes map[string]struct{}, keys ...string) bool {
	for _, k := range keys {
		if k == "" {
			continue
		}
		if _, ok := excludes[k]; ok {
			return true
		}
		if ck := canonicalExcludeKey(k); ck != "" && ck != k {
			if _, ok := excludes[ck]; ok {
				return true
			}
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
		if unmanagedHostMatchesExclude(excludes, info, savedBase, h) {
			return true
		}
	}
	return false
}

func isSavedBaseExcludeMatch(baseNodeID, rawCandidate, unwrappedCandidate string) bool {
	if rawCandidate == baseNodeID || unwrappedCandidate == baseNodeID {
		return true
	}
	canonBase := canonicalExcludeKey(baseNodeID)
	if canonBase != "" && (canonicalExcludeKey(rawCandidate) == canonBase || canonicalExcludeKey(unwrappedCandidate) == canonBase) {
		return true
	}
	return sameExcludeHost(unwrappedCandidate, baseNodeID)
}

func formatQualifiedExcludeKeys(info ExcludeTargetInfo, savedBase bool, canonHost string) (string, string) {
	if canonHost == "" || savedBase || info.User == "" {
		return "", ""
	}
	if ip, err := netip.ParseAddr(canonHost); err == nil {
		qualified := config.FormatNodeID(info.User, ip.String(), effectiveExcludePort(info.Port))
		return qualified, config.OpenSSHNodePrefix + qualified
	}
	if !strings.ContainsAny(canonHost, "@:") {
		qualified := config.FormatNodeID(info.User, canonHost, effectiveExcludePort(info.Port))
		return qualified, config.OpenSSHNodePrefix + qualified
	}
	return "", ""
}

func formatUnmanagedPortExcludeKeys(info ExcludeTargetInfo, savedBase bool, canonHost string) (string, string) {
	if savedBase || canonHost == "" {
		return "", ""
	}
	var hostPort string
	if ip, err := netip.ParseAddr(canonHost); err == nil {
		hostPort = formatHostPortExcludeKey(ip.String(), effectiveExcludePort(info.Port))
	} else if !strings.ContainsAny(canonHost, "@:") {
		hostPort = formatHostPortExcludeKey(canonHost, effectiveExcludePort(info.Port))
	}
	if hostPort == "" {
		return "", ""
	}
	return hostPort, config.OpenSSHNodePrefix + hostPort
}

func unmanagedHostMatchesExclude(excludes map[string]struct{}, info ExcludeTargetInfo, savedBase bool, h string) bool {
	h = strings.TrimSpace(h)
	if h == "" {
		return false
	}
	unwrapped := config.UnwrapOpenSSHSelector(h)
	if savedBase && isSavedBaseExcludeMatch(info.BaseNodeID, h, unwrapped) {
		return false
	}
	hostPart := unwrapped
	if u, parsedH, p, err := ParseAddr(unwrapped); err == nil && parsedH != "" && (u != "" || p != 0) {
		hostPart = parsedH
		if !matchesUserPortFilter(info, u, p) {
			unwrapped = parsedH
			h = parsedH
		}
	}
	if savedBase && isSavedBaseExcludeMatch(info.BaseNodeID, h, unwrapped) {
		return false
	}
	canonHost := canonicalExcludeHost(hostPart)
	if savedBase && isSavedBaseExcludeMatch(info.BaseNodeID, hostPart, canonHost) {
		canonHost = ""
	}
	var prefixed, prefixedCanon string
	if unwrapped != "" && !savedBase {
		prefixed = config.OpenSSHNodePrefix + unwrapped
		if canonHost != "" {
			prefixedCanon = config.OpenSSHNodePrefix + canonHost
		}
	}
	hostPort, prefixedHostPort := formatUnmanagedPortExcludeKeys(info, savedBase, canonHost)
	qualified, prefixedQualified := formatQualifiedExcludeKeys(info, savedBase, canonHost)
	return hasAnyExcludeKey(excludes, h, unwrapped, canonHost, prefixed, prefixedCanon, qualified, prefixedQualified, hostPort, prefixedHostPort)
}
