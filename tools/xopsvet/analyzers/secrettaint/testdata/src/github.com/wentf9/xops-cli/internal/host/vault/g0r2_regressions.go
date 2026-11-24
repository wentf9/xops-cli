package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/secret"
)

//xops:syncclosure
func localSyncRun(fn func()) { fn() }

func identityBytes(b []byte) []byte { return b }

type g0r2FakeHash struct{}

func (g0r2FakeHash) Write(p []byte) (int, error) { return len(p), nil }
func (g0r2FakeHash) Sum(b []byte) []byte         { return b }
func (g0r2FakeHash) Reset()                      {}
func (g0r2FakeHash) Size() int                   { return 32 }
func (g0r2FakeHash) BlockSize() int              { return 64 }

type secretStringer []byte

func (s secretStringer) String() string { return string(s) }

type credentialW struct {
	CredentialBlob *byte
}

var globalCred credentialW

// okSyncNestedConstAlloc 验证同步嵌套闭包内局部变量与常量容量分配不被误杀（B-3 / B-5）。
func okSyncNestedConstAlloc(box *secret.SecretBox) {
	const bufCap = 16
	_ = box.Use(func(plain []byte) error {
		localSyncRun(func() {
			buf := make([]byte, bufCap)
			copy(buf, plain)
			h := hmac.New(sha256.New, buf)
			_, _ = h.Write(plain)
			_ = h.Sum(nil)
			clear(buf)
		})
		return nil
	})
}

// badG0R2SecretTaintVectors 覆盖 C1/C2/C3/C5 与 ST-1/ST-2/ST-4/ST-5/ST-6/ST-10/ST-11/ST-12/ST-13/ST-14/ST-16。
func badG0R2SecretTaintVectors(box *secret.SecretBox, key, nonce []byte) {
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	var outerBuf bytes.Buffer
	_ = box.Use(func(plain []byte) error {
		// ST-1: panic 逃逸（置于条件分支内，避免后续测试用例被 SSA 死代码消除）
		if len(plain) > 999 {
			panic(plain) // want "禁止将明文机密传入 panic"
		}

		// ST-2: 同包函数透传返回值（ReturnMask）
		leaked := identityBytes(plain)
		slog.Info("retmask", "v", leaked) // want "禁止将明文机密.*传入日志汇点"

		// C1: 经局部指针间接写入外层切片
		p := &leakedBytes
		(*p)[0] = plain[0] // want "禁止将明文机密逃逸至外层变量"

		// C2: append 写入局部缓冲后送入日志
		localAppend := make([]byte, 0, len(plain))
		localAppend = append(localAppend, plain...)
		slog.Info("append", "v", localAppend) // want "禁止将明文机密.*传入日志汇点"

		// C3 / ST-11: 算术/位运算衍生值污点传播
		xored := plain[0] ^ 0x55
		inv := ^plain[0]
		slog.Info("arith", "x", xored, "i", inv) // want "禁止将明文机密.*传入日志汇点"

		// C5: 两层嵌套同步闭包回写外层变量
		localSyncRun(func() {
			localSyncRun(func() {
				leakedBytes = plain // want "禁止将明文机密逃逸至外层变量"
			})
		})

		// ST-4: strconv.Append* / hex.Append* 写入外层目标缓冲
		_ = strconv.AppendQuote(leakedBytes, string(plain)) // want "禁止通过 strconv\\.AppendQuote 将明文机密写入外层"
		_ = hex.AppendEncode(leakedBytes, plain)            // want "禁止通过 hex\\.AppendEncode 将明文机密写入外层"

		// ST-5 / ST-16: 非标准 hash 的 hmac.New 与非局部/染毒 dst 的 AEAD.Seal 必须阻断
		_ = hmac.New(func() hash.Hash { return g0r2FakeHash{} }, plain) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_ = aead.Seal(plain[:0], nonce, plain, nil)                     // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_ = aead.Seal(leakedBytes, nonce, plain, nil)                   // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_ = aead.Seal(nil, nonce, plain, nil)

		// ST-6: 直接调用 bytes.SplitSeq 返回的 iter.Seq 回调
		bytes.SplitSeq(plain, []byte(":"))(func(part []byte) bool {
			slog.Info("seq", "p", part) // want "禁止将明文机密.*传入日志汇点"
			return true
		})

		// ST-10: 全局 credentialW 字段写入（非本作用域拥有）必须拦截
		globalCred.CredentialBlob = &plain[0] // want "禁止将明文机密存入结构体或非字节切片容器字面量"

		// ST-12: bytes.TrimFunc 含用户回调必须拦截
		_ = bytes.TrimFunc(plain, func(r rune) bool { return r == ' ' }) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"

		// ST-13: 自定义 fmt.Stringer 传入 fmt.Sprintf 必须拦截
		_ = fmt.Sprintf("%v", secretStringer(plain)) // want "禁止将自定义 Stringer/GoStringer 明文值传入 fmt 格式化函数"

		// ST-14: io.CopyBuffer 第 3 参数 buf 携带明文必须拦截
		_, _ = io.CopyBuffer(&outerBuf, strings.NewReader("clean"), plain) // want "禁止通过 io\\.CopyBuffer 将明文机密写入外层缓冲或写入器"
		return nil
	})
}
