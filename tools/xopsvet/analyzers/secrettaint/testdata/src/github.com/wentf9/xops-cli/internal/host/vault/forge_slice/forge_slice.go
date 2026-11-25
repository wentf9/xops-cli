package forge_slice

import (
	"crypto/cipher"
	"unsafe"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"golang.org/x/crypto/chacha20poly1305"
)

// 独立验证包级防线 2：包内出现 unsafe.Slice 时必须触发全包 Fail-Closed，禁止私有 AEAD 字段 Seal。
type sliceForgeVault struct {
	aead cipher.AEAD
}

func useUnsafeSlice(p *byte, n int) []byte { return unsafe.Slice(p, n) }

func (v *sliceForgeVault) badWithUnsafeSlice(key, nonce []byte, box *secret.SecretBox) {
	v.aead, _ = chacha20poly1305.NewX(key)
	_ = useUnsafeSlice
	_ = box.Use(func(plain []byte) error {
		_ = v.aead.Seal(nil, nonce, plain, nil) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}
