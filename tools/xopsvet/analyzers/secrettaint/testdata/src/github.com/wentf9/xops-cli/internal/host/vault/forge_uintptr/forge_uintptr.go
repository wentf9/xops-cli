package forge_uintptr

import (
	"crypto/cipher"
	"unsafe"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"golang.org/x/crypto/chacha20poly1305"
)

// 独立验证包级防线 3：包内出现 uintptr -> unsafe.Pointer 转换时必须触发全包 Fail-Closed。
type uintptrForgeVault struct {
	aead cipher.AEAD
}

func fromUintptr(u uintptr) unsafe.Pointer { return unsafe.Pointer(u) }

func (v *uintptrForgeVault) badWithUintptrToUnsafe(key, nonce []byte, box *secret.SecretBox) {
	v.aead, _ = chacha20poly1305.NewX(key)
	_ = fromUintptr
	_ = box.Use(func(plain []byte) error {
		_ = v.aead.Seal(nil, nonce, plain, nil) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}
