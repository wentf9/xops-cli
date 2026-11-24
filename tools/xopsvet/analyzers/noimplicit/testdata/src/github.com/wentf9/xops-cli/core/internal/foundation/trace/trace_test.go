package trace

import "testing"

// M3a: 即便在 8 个特权白名单包内部，白盒 *_test.go 同样 100% 禁止行内 //nolint:。
func TestWhiteboxNolintForbidden(t *testing.T) {
	//nolint:errcheck // want "测试文件（含特权包白盒 \\*_test.go）禁止使用行内 //nolint 注解"
	_ = t
}
