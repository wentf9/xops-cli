package dial

import (
	"crypto/subtle"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"golang.org/x/crypto/ssh"
)

func okDialAuth(box *secret.SecretBox, expected []byte) (*ssh.ClientConfig, ssh.Signer, error) {
	var cfg *ssh.ClientConfig
	var signer ssh.Signer
	err := box.Use(func(plain []byte) error {
		_ = subtle.ConstantTimeCompare(plain, expected)
		localBuf := make([]byte, len(plain)+4)
		copy(localBuf[1:], plain)
		clear(localBuf)
		cfg = &ssh.ClientConfig{
			User: "ops",
			Auth: []ssh.AuthMethod{
				ssh.Password(string(plain)),
			},
		}
		s, err := ssh.ParsePrivateKey(plain)
		if err != nil {
			return err
		}
		signer = s
		return nil
	})
	return cfg, signer, err
}
