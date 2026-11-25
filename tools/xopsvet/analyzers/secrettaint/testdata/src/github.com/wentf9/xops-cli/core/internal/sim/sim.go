package sim

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"log/slog"

	"github.com/wentf9/xops-cli/core/domain/secret"
)

func okSimSeal(box *secret.SecretBox, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	var ct []byte
	err = box.Use(func(plain []byte) error {
		ct = aead.Seal(nil, nonce, plain, nil)
		return nil
	})
	return ct, err
}

type simAEADHolder struct {
	aead cipher.AEAD
}

func badSimLeak(box *secret.SecretBox, wc io.WriteCloser, key, nonce []byte) {
	block, _ := aes.NewCipher(key)
	var holder simAEADHolder
	holder.aead, _ = cipher.NewGCM(block)
	_ = box.Use(func(plain []byte) error {
		slog.Info("sim-leak", "k", string(plain))    // want "禁止将明文机密.*传入日志汇点"
		_, _ = wc.Write(plain)                       // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_ = holder.aead.Seal(nil, nonce, plain, nil) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}
