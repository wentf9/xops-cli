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
		nodeID := provider.Find(ex)
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
