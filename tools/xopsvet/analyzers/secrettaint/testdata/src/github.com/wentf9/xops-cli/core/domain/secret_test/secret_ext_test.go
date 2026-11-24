package secret_test

import (
	"testing"

	"github.com/wentf9/xops-cli/core/domain/secret"
)

func TestExternalTestUseDenied(t *testing.T) {
	_ = secret.WithBytes([]byte("pw"), func(box *secret.SecretBox) error {
		return box.Use(func(plain []byte) error { // want "禁止在白名单"
			_ = len(plain)
			return nil
		})
	})
}
