package sim

import (
	"crypto/cipher"
	"log/slog"

	"github.com/wentf9/xops-cli/core/domain/secret"
)

func okSimSeal(box *secret.SecretBox, aead cipher.AEAD, nonce []byte) ([]byte, error) {
	var ct []byte
	err := box.Use(func(plain []byte) error {
		ct = aead.Seal(nil, nonce, plain, nil)
		return nil
	})
	return ct, err
}

func badSimLeak(box *secret.SecretBox) {
	_ = box.Use(func(plain []byte) error {
		slog.Info("sim-leak", "k", string(plain)) // want "禁止将明文机密.*传入日志汇点"
		return nil
	})
}
