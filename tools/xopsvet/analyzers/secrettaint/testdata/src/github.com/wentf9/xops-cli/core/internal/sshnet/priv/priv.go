package priv

import (
	"log/slog"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"golang.org/x/crypto/ssh"
)

func okPrivParse(box *secret.SecretBox) (ssh.Signer, error) {
	var signer ssh.Signer
	err := box.Use(func(plain []byte) error {
		s, err := ssh.ParsePrivateKey(plain)
		if err != nil {
			return err
		}
		signer = s
		return nil
	})
	return signer, err
}

func badPrivLeak(box *secret.SecretBox) {
	_ = box.Use(func(plain []byte) error {
		slog.Info("priv-leak", "k", string(plain)) // want "禁止将明文机密.*传入日志汇点"
		return nil
	})
}
