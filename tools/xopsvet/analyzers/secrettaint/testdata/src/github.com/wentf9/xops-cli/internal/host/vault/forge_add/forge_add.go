package forge_add

import (
	"crypto/cipher"
	"unsafe"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"golang.org/x/crypto/chacha20poly1305"
)

// 独立验证包级防线 1：辅助函数 toUnsafe(&v.tag) + unsafe.Add 必须触发全包 Fail-Closed，禁止任何私有 AEAD 字段 Seal。
type helperAddVault struct {
	tag  int
	aead cipher.AEAD
}

func toUnsafePtr(p *int) unsafe.Pointer { return unsafe.Pointer(p) }

func (v *helperAddVault) badHelperUnsafeAdd(key, nonce []byte, box *secret.SecretBox) {
	v.aead, _ = chacha20poly1305.NewX(key)
	_ = unsafe.Add(toUnsafePtr(&v.tag), unsafe.Offsetof(v.aead))
	_ = box.Use(func(plain []byte) error {
		_ = v.aead.Seal(nil, nonce, plain, nil) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}
