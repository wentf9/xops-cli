package forge_cast

import (
	"crypto/cipher"
	"unsafe"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"golang.org/x/crypto/chacha20poly1305"
)

// 独立验证包级防线 4：涉及 crypto/cipher.AEAD 的非等价类型转换（异构结构体强转或 (*cipher.AEAD)(unsafe.Pointer)）必须触发 Fail-Closed。
type targetConvertedVault struct {
	aead cipher.AEAD
}

type fakeConvertedVault targetConvertedVault

type cleanNeighborVault struct {
	aead cipher.AEAD
}

func badCastVault(key, nonce []byte, evil cipher.AEAD, p unsafe.Pointer, box *secret.SecretBox) {
	var good targetConvertedVault
	good.aead, _ = chacha20poly1305.NewX(key)
	v := targetConvertedVault(fakeConvertedVault{aead: evil})
	_ = (*cipher.AEAD)(p)

	var neighbor cleanNeighborVault
	neighbor.aead, _ = chacha20poly1305.NewX(key)

	_ = box.Use(func(plain []byte) error {
		_ = v.aead.Seal(nil, nonce, plain, nil)        // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_ = neighbor.aead.Seal(nil, nonce, plain, nil) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}
