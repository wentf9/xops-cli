package usecase

import "slices"

// Lookup 返回 usecase/**、mcpruntime/** 与 engine 键对应的规范英文兜底模板；未命中返回空串。
func Lookup(id string) string {
	if text := lookupUsecase(id); text != "" {
		return text
	}
	if text := lookupDoctor(id); text != "" {
		return text
	}
	return lookupMCPEngine(id)
}

// AllKeys 返回本分片注册的全部消息键（按字典序升序排列，每次返回独立切片副本）。
func AllKeys() []string {
	uc := keysUsecase()
	doc := keysDoctor()
	me := keysMCPEngine()
	out := make([]string, 0, len(uc)+len(doc)+len(me))
	out = append(out, uc...)
	out = append(out, doc...)
	out = append(out, me...)
	slices.Sort(out)
	return out
}
