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
	if len(excludes) == 0 {
		return nil, nil
	}
	resolved := make(map[string]struct{}, len(excludes))
	var unmatched []string
	for _, ex := range excludes {
		ok, err := resolveSingleExclude(provider, ex, candidates, resolved)
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

func resolveSingleExclude(provider config.ConfigProvider, ex string, candidates []ExcludeTargetInfo, resolved map[string]struct{}) (bool, error) {
	if provider != nil {
		nodeID, err := provider.ResolveSelector(ex)
		if err != nil {
			return false, fmt.Errorf("resolve excluded node %q failed: %w", ex, err)
		}
		if nodeID != "" {
			resolved[nodeID] = struct{}{}
			if !strings.Contains(ex, "@") && !strings.HasPrefix(strings.TrimSpace(ex), config.OpenSSHNodePrefix) && isSavedNodeID(nodeID) {
				addSavedBaseCandidates(resolved, nodeID, candidates)
			}
			return true, nil
		}
	}

	hasOpenSSHPrefix, addrUser, addrHost, addrPort, ok := parseExcludeSpec(ex)
	if !ok {
		return false, nil
	}

	matched, err := resolveExcludeViaTarget(provider, ex, hasOpenSSHPrefix, addrUser, addrHost, addrPort, candidates, resolved)
	if err != nil {
		return false, err
	}
	if matched {
		return true, nil
	}

	if len(candidates) > 0 {
		return resolveExcludeViaCandidates(addrUser, addrHost, addrPort, candidates, resolved), nil
	}
	return false, nil
}

func parseExcludeSpec(ex string) (hasOpenSSHPrefix bool, user, host string, port uint16, ok bool) {
	rawSpec := strings.TrimSpace(ex)
	if after, found := strings.CutPrefix(rawSpec, config.OpenSSHNodePrefix); found {
		hasOpenSSHPrefix = true
		rawSpec = strings.TrimSpace(after)
	}
	if rawSpec == "" {
		return false, "", "", 0, false
	}
	u, h, p, err := ParseAddr(rawSpec)
	if err == nil && h != "" {
		return hasOpenSSHPrefix, u, h, p, true
	}
	// Support IPv6 literals with zone IDs such as [fe80::1%eth0] or fe80::1%eth0.
	clean := strings.TrimPrefix(strings.TrimSuffix(rawSpec, "]"), "[")
	if addr, addrErr := netip.ParseAddr(clean); addrErr == nil && addr.Is6() {
		return hasOpenSSHPrefix, "", clean, 0, true
	}
	return false, "", "", 0, false
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
	hasOpenSSH := config.HasOpenSSHConfig(provider)
	inSaved := !hasOpenSSHPrefix && selectorInSavedInventory(provider, addrHost)
	if !hasOpenSSH && !inSaved {
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
		recordCompositeTargetExclude(res, addrUser, addrHost, addrPort, candidates, resolved)
		return true, nil
	}

	if res.MatchedNodeID != "" {
		resolved[res.MatchedNodeID] = struct{}{}
		if !hasOpenSSHPrefix && isSavedNodeID(res.MatchedNodeID) {
			addSavedBaseCandidates(resolved, res.MatchedNodeID, candidates)
		}
		return true, nil
	}
	if !hasOpenSSHPrefix && isSavedNodeID(res.BaseNodeID) {
		resolved[res.BaseNodeID] = struct{}{}
		addSavedBaseCandidates(resolved, res.BaseNodeID, candidates)
		return true, nil
	}
	if hasOpenSSH {
		resolved[config.OpenSSHNodePrefix+addrHost] = struct{}{}
		if res.NodeID != "" {
			resolved[res.NodeID] = struct{}{}
		}
		for _, cand := range candidates {
			if candidateMatchesHost(cand, addrHost, res.Host) && cand.NodeID != "" {
				resolved[cand.NodeID] = struct{}{}
			}
		}
		return true, nil
	}
	return false, nil
}

func recordCompositeTargetExclude(
	res config.ResolvedTarget,
	addrUser, addrHost string,
	addrPort uint16,
	candidates []ExcludeTargetInfo,
	resolved map[string]struct{},
) {
	if res.OpenSSHAlias != "" {
		if res.User != "" && res.Port > 0 {
			resolved[config.OpenSSHNodePrefix+config.FormatNodeID(res.User, res.OpenSSHAlias, res.Port)] = struct{}{}
		}
		for _, cand := range candidates {
			if cand.OpenSSHAlias != res.OpenSSHAlias || !matchesUserPortFilter(cand, addrUser, addrPort) {
				continue
			}
			if cand.User != "" && cand.Port > 0 {
				resolved[config.OpenSSHNodePrefix+config.FormatNodeID(cand.User, cand.OpenSSHAlias, cand.Port)] = struct{}{}
			}
			if cand.NodeID != "" {
				resolved[cand.NodeID] = struct{}{}
			}
		}
		return
	}

	id := res.MatchedNodeID
	if id == "" {
		id = res.NodeID
	}
	if id != "" {
		resolved[id] = struct{}{}
	}
	for _, cand := range candidates {
		if candidateMatchesHost(cand, addrHost, res.Host) && matchesUserPortFilter(cand, addrUser, addrPort) && cand.NodeID != "" {
			resolved[cand.NodeID] = struct{}{}
		}
	}
}

func resolveExcludeViaCandidates(
	addrUser, addrHost string,
	addrPort uint16,
	candidates []ExcludeTargetInfo,
	resolved map[string]struct{},
) bool {
	trial := make(map[string]struct{})
	for _, cand := range candidates {
		if !candidateMatchesHost(cand, addrHost, "") || !matchesUserPortFilter(cand, addrUser, addrPort) {
			continue
		}
		if addrUser != "" || addrPort != 0 {
			if cand.NodeID != "" {
				trial[cand.NodeID] = struct{}{}
			} else if cand.User != "" {
				trial[config.FormatNodeID(cand.User, addrHost, effectiveExcludePort(cand.Port))] = struct{}{}
			}
			continue
		}
		if cand.NodeID != "" {
			trial[cand.NodeID] = struct{}{}
		}
		trial[addrHost] = struct{}{}
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

func addSavedBaseCandidates(resolved map[string]struct{}, savedNodeID string, candidates []ExcludeTargetInfo) {
	for _, cand := range candidates {
		if cand.BaseNodeID == savedNodeID && cand.NodeID != "" {
			resolved[cand.NodeID] = struct{}{}
		}
	}
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
	User           string
	Port           uint16
	UnmanagedHosts []string
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
		if hasAnyExcludeKey(excludes, info.BaseNodeID, config.OpenSSHNodePrefix+config.UnwrapOpenSSHSelector(info.BaseNodeID)) {
			return true
		}
	}
	if info.OpenSSHAlias != "" {
		var aliasID string
		if info.User != "" && info.Port > 0 {
			aliasID = config.OpenSSHNodePrefix + config.FormatNodeID(info.User, info.OpenSSHAlias, info.Port)
		}
		if hasAnyExcludeKey(excludes, config.OpenSSHNodePrefix+info.OpenSSHAlias, info.OpenSSHAlias, aliasID) {
			return true
		}
	}
	if info.MatchedNodeID == "" || strings.HasPrefix(info.MatchedNodeID, config.OpenSSHNodePrefix) {
		savedBase := isSavedNodeID(info.BaseNodeID)
		for _, h := range info.UnmanagedHosts {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			unwrapped := config.UnwrapOpenSSHSelector(h)
			var prefixed string
			if unwrapped != "" && !savedBase {
				prefixed = config.OpenSSHNodePrefix + unwrapped
			}
			if hasAnyExcludeKey(excludes, h, unwrapped, prefixed) {
				return true
			}
		}
	}
	return false
}
