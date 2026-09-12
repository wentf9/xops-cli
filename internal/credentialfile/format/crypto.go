package format

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

func aead(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("validate AES-256 key: %w", ErrCorrupt)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	return gcm, nil
}

func derive(key, salt, info []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("validate derivation key: %w", ErrCorrupt)
	}
	k, err := hkdf.Key(sha256.New, key, salt, string(info), 32)
	if err != nil {
		return nil, fmt.Errorf("derive domain key: %w", err)
	}
	return k, nil
}
