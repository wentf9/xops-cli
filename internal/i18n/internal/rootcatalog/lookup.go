package rootcatalog

import "slices"

// Lookup 按纯字符串键返回根模块错误、诊断与提示消息对应的规范英文兜底模板；
// 未注册键、纯展示类键或空串一律返回空串（纯函数 switch 零分配跳转表）。
func Lookup(id string) string {
	if id == "" {
		return ""
	}
	if text := lookupRoot(id); text != "" {
		return text
	}
	if text := lookupCLI(id); text != "" {
		return text
	}
	if text := lookupCmdAndLabels(id); text != "" {
		return text
	}
	if text := lookupHost(id); text != "" {
		return text
	}
	return lookupSFTPTUIInteract(id)
}

// ErrorKeys 返回根模块须登记规范英文兜底模板的全部错误、诊断与提示消息键
// （严格按字典序升序排列、去重，且每次返回独立切片副本）。
func ErrorKeys() []string {
	return sortAndCompactCopy(
		errorKeysRoot(),
		errorKeysCLI(),
		errorKeysCmdAndLabels(),
		errorKeysHost(),
		errorKeysSFTPTUIInteract(),
	)
}

// AllKeys 返回根模块注册的全部消息键（含错误/提示键与全部纯 UI/帮助/TUI/SFTP/交互展示键，
// 严格按字典序升序排列、去重，且每次返回独立切片副本）。
func AllKeys() []string {
	return sortAndCompactCopy(
		errorKeysRoot(),
		errorKeysCLI(),
		errorKeysCmdAndLabels(),
		errorKeysHost(),
		errorKeysSFTPTUIInteract(),
		displayKeysCLI(),
		displayKeysSFTPTUIInteract(),
	)
}

func sortAndCompactCopy(groups ...[]string) []string {
	total := 0
	for _, g := range groups {
		total += len(g)
	}
	out := make([]string, 0, total)
	for _, g := range groups {
		out = append(out, g...)
	}
	slices.Sort(out)
	return slices.Clip(slices.Compact(out))
}
