package secret_test

import (
	"encoding/json/v2"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/secret"
)

func TestExternalTestDenied(t *testing.T) {
	_ = secret.WithBytes([]byte("pw"), func(box *secret.SecretBox) error {
		// 外置 *_test 包既禁止调用 Use，也禁止豁免 json/v2.Marshal
		_, _ = json.Marshal(box)                  // want "禁止将 secret.SecretBox 传入序列化汇点"
		return box.Use(func(plain []byte) error { // want "禁止在白名单"
			_ = len(plain)
			return nil
		})
	})
}
