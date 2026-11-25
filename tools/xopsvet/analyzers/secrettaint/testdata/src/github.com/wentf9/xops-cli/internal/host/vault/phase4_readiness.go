package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"errors"
	"hash"
	"sync"
	"unsafe"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

// Phase 2.5 / Phase 4 离线 AEAD Vault 解锁态私有字段 Seal 正/反例验证套件。

type unlockedChaChaVault struct {
	mu   sync.Mutex
	salt []byte
	aead cipher.AEAD
}

func (v *unlockedChaChaVault) Unlock(passBox *secret.SecretBox) error {
	return passBox.Use(func(plain []byte) error {
		dk := argon2.IDKey(plain, v.salt, 1, 64*1024, 1, 32)
		defer clear(dk)
		aead, err := chacha20poly1305.NewX(dk)
		if err != nil {
			return err
		}
		v.mu.Lock()
		v.aead = aead
		v.mu.Unlock()
		return nil
	})
}

func (v *unlockedChaChaVault) UnlockWithLocalVar(passBox *secret.SecretBox) error {
	var next cipher.AEAD
	err := passBox.Use(func(plain []byte) error {
		dk := argon2.IDKey(plain, v.salt, 1, 64*1024, 1, 32)
		defer clear(dk)
		var aErr error
		next, aErr = chacha20poly1305.NewX(dk)
		return aErr
	})
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.aead = next
	v.mu.Unlock()
	return nil
}

func (v *unlockedChaChaVault) Lock() {
	v.mu.Lock()
	v.aead = nil
	v.mu.Unlock()
}

func (v *unlockedChaChaVault) currentAEAD() (cipher.AEAD, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.aead == nil {
		return nil, errors.New("locked")
	}
	return v.aead, nil
}

func (v *unlockedChaChaVault) okPutAndVerify(nonce, aad []byte, box *secret.SecretBox) ([]byte, error) {
	// 1. 持锁快照 v.aead 后在 box.Use 闭包内 Seal
	v.mu.Lock()
	snap := v.aead
	v.mu.Unlock()
	if snap == nil {
		return nil, errors.New("locked")
	}
	var ct []byte
	if err := box.Use(func(plain []byte) error {
		ct = snap.Seal(nil, nonce, plain, aad)
		return nil
	}); err != nil {
		return nil, err
	}

	// 2. 直接通过 v.aead.Seal 与同包辅助函数 currentAEAD().Seal
	aead, err := v.currentAEAD()
	if err != nil {
		return nil, err
	}
	err = box.Use(func(plain []byte) error {
		v.mu.Lock()
		defer v.mu.Unlock()
		ct = v.aead.Seal(nil, nonce, plain, aad)
		ct = aead.Seal(nil, nonce, plain, aad)
		return nil
	})
	return ct, err
}

func (v *unlockedChaChaVault) badDstAndOpen(nonce, aad []byte, box *secret.SecretBox) {
	_ = box.Use(func(plain []byte) error {
		_ = v.aead.Seal(plain[:0], nonce, plain, aad)   // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_ = v.aead.Seal(leakedBytes, nonce, plain, aad) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = v.aead.Open(nil, nonce, plain, aad)      // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}

// okWindowsCredentialWCoexists 验证 Windows CREDENTIALW 所需的 *T -> unsafe.Pointer -> uintptr + LazyProc.Call
// 与同包 unlockedChaChaVault 私有 AEAD 字段校验安全共存（不误伤合法 Vault）。
func okWindowsCredentialWCoexists(proc *windows.LazyProc, box *secret.SecretBox) error {
	return box.Use(func(plain []byte) error {
		if len(plain) == 0 {
			return nil
		}
		var cred credentialW
		cred.CredentialBlob = &plain[0]
		_, _, _ = proc.Call(uintptr(unsafe.Pointer(&cred)), uintptr(unsafe.Pointer(&plain[0])))
		return nil
	})
}

type unlockedGCMVault struct {
	aead cipher.AEAD
}

func (v *unlockedGCMVault) UnlockGCM(passBox *secret.SecretBox, salt []byte) error {
	return passBox.Use(func(plain []byte) error {
		dk := argon2.IDKey(plain, salt, 1, 64*1024, 1, 32)
		defer clear(dk)
		block, err := aes.NewCipher(dk)
		if err != nil {
			return err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		v.aead = aead
		return nil
	})
}

func (v *unlockedGCMVault) okSealLocalDst(nonce, aad []byte, box *secret.SecretBox) error {
	return box.Use(func(plain []byte) error {
		localDst := make([]byte, 0, len(plain)+32)
		_ = v.aead.Seal(localDst, nonce, plain, aad)
		return nil
	})
}

type vaultInnerState struct {
	aead cipher.AEAD
}

type nestedStateVault struct {
	state vaultInnerState
}

func (v *nestedStateVault) okNestedStateSeal(key, nonce []byte, box *secret.SecretBox) error {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	v.state.aead = aead
	return box.Use(func(plain []byte) error {
		_ = v.state.aead.Seal(nil, nonce, plain, nil)
		return nil
	})
}

// 对抗反例 1：私有字段在任一写点被外部参数 cipher.AEAD 投毒，全包所有 Seal 均须 Fail-Closed 拦截。
type poisonedParamVault struct {
	aead cipher.AEAD
}

func (v *poisonedParamVault) initGood(key []byte) {
	v.aead, _ = chacha20poly1305.NewX(key)
}

func (v *poisonedParamVault) injectEvil(a cipher.AEAD) {
	v.aead = a
}

func (v *poisonedParamVault) badSealPoisoned(nonce []byte, box *secret.SecretBox) {
	_ = box.Use(func(plain []byte) error {
		_ = v.aead.Seal(nil, nonce, plain, nil) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}

// 对抗反例 2：导出字段 AEAD 可被跨包改写，即使本包仅用 NewX 写入也必须 Fail-Closed 拦截。
type exportedAEADVault struct {
	AEAD cipher.AEAD
}

func (v *exportedAEADVault) badSealExported(key, nonce []byte, box *secret.SecretBox) {
	v.AEAD, _ = chacha20poly1305.NewX(key)
	_ = box.Use(func(plain []byte) error {
		_ = v.AEAD.Seal(nil, nonce, plain, nil) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}

// 对抗反例 3：取址 &v.aead 逃逸至指针变量后间接篡改，必须 Fail-Closed 拦截。
type escapedAddrVault struct {
	aead cipher.AEAD
}

func overwriteAEADPtr(p *cipher.AEAD, evil cipher.AEAD) {
	*p = evil
}

func (v *escapedAddrVault) badSealEscapedAddr(key, nonce []byte, evil cipher.AEAD, box *secret.SecretBox) {
	v.aead, _ = chacha20poly1305.NewX(key)
	overwriteAEADPtr(&v.aead, evil)
	_ = box.Use(func(plain []byte) error {
		_ = v.aead.Seal(nil, nonce, plain, nil) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}

// 对抗反例 4：两层嵌套字段 &v.meta.tag 转 unsafe.Pointer，必须穿透投毒外层结构体。
type nestedMeta struct {
	tag int
}

type nestedFieldUnsafeVault struct {
	meta nestedMeta
	aead cipher.AEAD
}

func (v *nestedFieldUnsafeVault) badSealNestedUnsafe(key, nonce []byte, box *secret.SecretBox) {
	v.aead, _ = chacha20poly1305.NewX(key)
	_ = unsafe.Pointer(&v.meta.tag)
	_ = box.Use(func(plain []byte) error {
		_ = v.aead.Seal(nil, nonce, plain, nil) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}

// 对抗反例 5：数组元素 &v.pad[0] 转 unsafe.Pointer，必须穿透 IndexAddr 投毒外层结构体。
type indexedFieldUnsafeVault struct {
	pad  [16]byte
	aead cipher.AEAD
}

func (v *indexedFieldUnsafeVault) badSealIndexedUnsafe(key, nonce []byte, box *secret.SecretBox) {
	v.aead, _ = chacha20poly1305.NewX(key)
	_ = unsafe.Pointer(&v.pad[0])
	_ = box.Use(func(plain []byte) error {
		_ = v.aead.Seal(nil, nonce, plain, nil) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}

// 对抗反例 6：经局部指针与条件 Phi 间接转 unsafe.Pointer(q)，必须穿透 Phi 投毒外层结构体。
type phiIndirectUnsafeVault struct {
	tag  int
	aead cipher.AEAD
}

func (v *phiIndirectUnsafeVault) badSealPhiUnsafe(key, nonce []byte, cond bool, box *secret.SecretBox) {
	v.aead, _ = chacha20poly1305.NewX(key)
	p := &v.tag
	var q *int
	if cond {
		q = p
	}
	_ = unsafe.Pointer(q)
	_ = box.Use(func(plain []byte) error {
		_ = v.aead.Seal(nil, nonce, plain, nil) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}

// 对抗反例 7：自定义 cipher.Block 伪造 gcmAble 绕过 cipher.NewGCM，直接调用与结构体缓存均须 Fail-Closed 拦截。
type evilGCMBlock struct{}

func (evilGCMBlock) BlockSize() int          { return 16 }
func (evilGCMBlock) Encrypt(dst, src []byte) {}
func (evilGCMBlock) Decrypt(dst, src []byte) {}

type evilGCMBlockVault struct {
	aead cipher.AEAD
}

func (v *evilGCMBlockVault) badSealEvilGCMBlock(paramBlock cipher.Block, nonce []byte, box *secret.SecretBox) {
	directEvil, _ := cipher.NewGCM(evilGCMBlock{})
	paramEvil, _ := cipher.NewGCM(paramBlock)
	v.aead, _ = cipher.NewGCM(evilGCMBlock{})
	_ = box.Use(func(plain []byte) error {
		_ = directEvil.Seal(nil, nonce, plain, nil) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_ = paramEvil.Seal(nil, nonce, plain, nil)  // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_ = v.aead.Seal(nil, nonce, plain, nil)     // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}

// 对抗反例 8：非 LayerCoreSSHNetPriv（LayerHostVault）不得享受 SSH 通道写入器豁免；伪造 HMAC 哈希的 Write 亦须拦截。
func badNonPrivWriterAndFakeHMACWrite(sess *ssh.Session, ch ssh.Channel, untaintedKey []byte, box *secret.SecretBox) {
	stdin, _ := sess.StdinPipe()
	h := hmac.New(func() hash.Hash { return &fakeHash{} }, untaintedKey)
	_ = box.Use(func(plain []byte) error {
		_, _ = stdin.Write(plain) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = ch.Write(plain)    // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = h.Write(plain)     // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}
