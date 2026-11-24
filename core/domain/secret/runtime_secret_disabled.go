//go:build !goexperiment.runtimesecret

package secret

// Do 在未启用 GOEXPERIMENT=runtimesecret 的构建下以普通同步闭包直接执行 fn，
// 保持与启用构建完全一致的调用语义与 //xops:syncclosure 静态分析契约。
//
//xops:syncclosure
func Do(fn func()) {
	if fn == nil {
		return
	}
	fn()
}

// InSecretScope 在未启用 GOEXPERIMENT=runtimesecret 的构建下恒返回 false。
func InSecretScope() bool {
	return false
}

// RuntimeSecretBuildEnabled 报告当前二进制是否以 GOEXPERIMENT=runtimesecret 构建（本分支恒为 false）。
func RuntimeSecretBuildEnabled() bool {
	return false
}
