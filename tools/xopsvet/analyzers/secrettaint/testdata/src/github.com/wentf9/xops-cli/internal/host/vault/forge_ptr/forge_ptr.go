package forge_ptr

import (
	"crypto/cipher"
	"unsafe"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"golang.org/x/crypto/chacha20poly1305"
)

// 独立验证包级防线 5：任何 unsafe.Pointer -> 非 uintptr 类型重解释（含辅助函数强转 fakeLayout 与闭包捕获指针强转 *[64]byte）
// 均须触发全包 Fail-Closed，禁止通过内存布局双关覆盖私有 cipher.AEAD 字段。
type fakeLayout struct {
	tag        int
	itab, data uintptr
}

type helperPunVault struct {
	tag  int
	aead cipher.AEAD
}

func toFakeLayout(p *int) *fakeLayout { return (*fakeLayout)(unsafe.Pointer(p)) }

type closurePunVault struct {
	tag  int
	aead cipher.AEAD
}

func badUnsafePointerTypePunning(key, nonce []byte, box *secret.SecretBox) {
	var v1 helperPunVault
	v1.aead, _ = chacha20poly1305.NewX(key)
	fl := toFakeLayout(&v1.tag)
	fl.itab, fl.data = 0, 0

	var v2 closurePunVault
	v2.aead, _ = chacha20poly1305.NewX(key)
	var p *int
	func() { p = &v2.tag }()
	raw := (*[64]byte)(unsafe.Pointer(p))
	raw[0] = 0

	_ = box.Use(func(plain []byte) error {
		_ = v1.aead.Seal(nil, nonce, plain, nil) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_ = v2.aead.Seal(nil, nonce, plain, nil) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}
