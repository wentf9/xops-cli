package corecatalog

import "slices"

// Lookup 按纯字符串键返回 core/ 模块注册消息对应的规范英文兜底模板；未注册或空键一律返回空串。
func Lookup(id string) string {
	if id == "" {
		return ""
	}
	if text := lookupCommon(id); text != "" {
		return text
	}
	if text := lookupDomain(id); text != "" {
		return text
	}
	if text := lookupPorts(id); text != "" {
		return text
	}
	if text := lookupRuntime(id); text != "" {
		return text
	}
	return lookupUsecase(id)
}

// AllKeys 返回已注册的全部核心消息键（严格按字典序升序排列、去重、每次返回独立切片副本）。
func AllKeys() []string {
	common := keysCommon()
	domain := keysDomain()
	ports := keysPorts()
	runtime := keysRuntime()
	usecase := keysUsecase()
	out := make([]string, 0, len(common)+len(domain)+len(ports)+len(runtime)+len(usecase))
	out = append(out, common...)
	out = append(out, domain...)
	out = append(out, ports...)
	out = append(out, runtime...)
	out = append(out, usecase...)
	slices.Sort(out)
	return out
}
