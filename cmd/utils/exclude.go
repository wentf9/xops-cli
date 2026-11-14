package utils

import (
	"fmt"
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
	if len(excludes) == 0 {
		return nil, nil
	}
	resolved := make(map[string]struct{}, len(excludes))
	var unmatched []string
	for _, ex := range excludes {
		nodeID, err := provider.ResolveSelector(ex)
		if err != nil {
			return nil, fmt.Errorf("resolve excluded node %q failed: %w", ex, err)
		}
		if nodeID == "" {
			unmatched = append(unmatched, ex)
			continue
		}
		resolved[nodeID] = struct{}{}
	}
	if len(unmatched) > 0 {
		return nil, fmt.Errorf("exclude: no matching node for: %s", strings.Join(unmatched, ", "))
	}
	return resolved, nil
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
	if info.MatchedNodeID == "" {
		for _, h := range info.UnmanagedHosts {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			unwrapped := config.UnwrapOpenSSHSelector(h)
			var prefixed string
			if unwrapped != "" {
				prefixed = config.OpenSSHNodePrefix + unwrapped
			}
			if hasAnyExcludeKey(excludes, h, unwrapped, prefixed) {
				return true
			}
		}
	}
	return false
}
