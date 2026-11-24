package secret

import (
	"log/slog"
	"testing"
)

func TestInternalSecretUseAllowed(t *testing.T) {
	_ = WithBytes([]byte("pw"), func(box *SecretBox) error {
		return box.Use(func(plain []byte) error {
			defer func() {
				clear(plain)
			}()
			n := len(plain)
			c := cap(plain)
			slog.Info("meta", "len", n, "cap", c)
			return nil
		})
	})
}
