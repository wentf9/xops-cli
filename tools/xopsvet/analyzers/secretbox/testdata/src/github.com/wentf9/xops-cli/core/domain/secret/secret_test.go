package secret

import (
	"bytes"
	"encoding/json/v2"
	"testing"
)

// v2.3.3 CRIT-1 / B1 / N1: 白盒 *_test.go 直调 encoding/json/v2.Marshal* 测原生 SemanticError 联合放行；
// 但容器包装 []any{box} 与逃逸变量 var a any = box 仍严禁擦除。
func TestJSONv2SemanticErrorAllowedInWhiteboxTest(t *testing.T) {
	_ = WithBytes([]byte("pw"), func(box *SecretBox) error {
		_, _ = json.Marshal(box)
		_, _ = json.Marshal(*box)
		var buf bytes.Buffer
		_ = json.MarshalWrite(&buf, box)

		// 非精确直调：放入容器 []any{box} 仍被精准拦截（同时触发擦除与序列化汇点）
		_, _ = json.Marshal([]any{box}) // want "禁止将 secret.SecretBox 传入序列化汇点" "禁止将 secret.SecretBox 擦除为接口"
		_ = []any{box}                  // want "禁止将 secret.SecretBox 擦除为接口"
		return nil
	})
}
