//go:build goexperiment.runtimesecret

package secret

import runtimesecret "runtime/secret"

// Do 在 Go 1.27 runtime/secret.Do 保护作用域内同步执行 fn：
// 在受支持平台（如 linux/amd64、linux/arm64）下，返回前会清零该调用树使用的寄存器与栈帧，
// 并在垃圾回收确认不可达后擦除期间分配的堆内存。
//
// 本函数仅标注 //xops:syncclosure（非 //xops:secretuse），供本包及受控密码学路径复用。
//
//xops:syncclosure
func Do(fn func()) {
	if fn == nil {
		return
	}
	runtimesecret.Do(fn)
}

// InSecretScope 报告当前协程此刻是否正处于 runtime/secret.Do 保护作用域内。
func InSecretScope() bool {
	return runtimesecret.Enabled()
}

// RuntimeSecretBuildEnabled 报告当前二进制是否以 GOEXPERIMENT=runtimesecret 构建。
func RuntimeSecretBuildEnabled() bool {
	return true
}
