package wincred

import (
	"crypto/cipher"
	"log/slog"
	"unsafe"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/windows"
)

// 验证 LayerHostVault 子包 internal/host/vault/wincred 隔离 Windows CredWriteW / CredReadW：
// 局部 credentialW + LazyProc.Call + unsafe.Slice（用于读取非密文或 CredReadW 缓冲）合法放行，
// 同时全局 credentialW、日志泄漏与同包内私有 AEAD 字段 Seal 仍按 Fail-Closed 拦截。
type credentialW struct {
	CredentialBlobSize uint32
	CredentialBlob     *byte
}

var globalSubCred credentialW

func okWinCredSubpkgWrite(proc *windows.LazyProc, box *secret.SecretBox) error {
	return box.Use(func(plain []byte) error {
		if len(plain) == 0 {
			return nil
		}
		var cred credentialW
		cred.CredentialBlobSize = uint32(len(plain))
		cred.CredentialBlob = &plain[0]
		_, _, _ = proc.Call(uintptr(unsafe.Pointer(&cred)))
		return nil
	})
}

func readCredBytes(p *byte, n uint32) []byte {
	return unsafe.Slice(p, n)
}

type isolatedVault struct {
	aead cipher.AEAD
}

func badWinCredViolations(key, nonce []byte, box *secret.SecretBox) {
	_ = readCredBytes
	var v isolatedVault
	v.aead, _ = chacha20poly1305.NewX(key)
	_ = box.Use(func(plain []byte) error {
		if len(plain) > 0 {
			globalSubCred.CredentialBlob = &plain[0] // want "禁止将明文机密存入结构体或非字节切片容器字面量"
		}
		slog.Info("wincred-leak", "v", string(plain)) // want "禁止将明文机密.*传入日志汇点"
		_ = v.aead.Seal(nil, nonce, plain, nil)       // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}
