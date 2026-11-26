package keychain

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"log/slog"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
)

func okPuregoKeychainWrite(symAdd uintptr, box *secret.SecretBox) error {
	return box.Use(func(plain []byte) error {
		if len(plain) == 0 {
			return nil
		}
		_, _, _ = purego.SyscallN(symAdd, uintptr(len(plain)), uintptr(unsafe.Pointer(&plain[0])))
		return nil
	})
}

func badPuregoKeychainViolations(ctx context.Context, proc ports.ProcessPort, key, iv []byte, box *secret.SecretBox) {
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	_ = box.Use(func(plain []byte) error {
		// 反例 1：arg 0 fn uintptr 染毒必须拒绝。
		taintedFn := uintptr(unsafe.Pointer(&plain[0]))
		_, _, _ = purego.SyscallN(taintedFn, 1) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		// 反例 2：跨子包借用 helper 或 secretservice 窄钩子必须拒绝。
		_, _ = proc.Run(ctx, ports.ProcessSpec{Command: "helper"}, bytes.NewReader(plain)) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		dst := make([]byte, len(plain))
		mode.CryptBlocks(dst, plain)                   // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		slog.Info("keychain-leak", "v", string(plain)) // want "禁止将明文机密.*传入日志汇点"
		return nil
	})
}
