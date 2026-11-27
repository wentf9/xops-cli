package runtime

import "slices"

// Lookup 返回 pool、gate 与 sshnet/** 运行时键对应的规范英文兜底模板；未命中返回空串。
func Lookup(id string) string {
	if text := lookupPoolGate(id); text != "" {
		return text
	}
	return lookupSSHNet(id)
}

// AllKeys 返回本分片注册的全部消息键（按字典序升序排列，每次返回独立切片副本）。
func AllKeys() []string {
	pg := keysPoolGate()
	ssh := keysSSHNet()
	out := make([]string, 0, len(pg)+len(ssh))
	out = append(out, pg...)
	out = append(out, ssh...)
	slices.Sort(out)
	return out
}
