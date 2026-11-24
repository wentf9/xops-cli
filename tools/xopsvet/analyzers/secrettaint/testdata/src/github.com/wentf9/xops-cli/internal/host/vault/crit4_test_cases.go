package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"io"
	"log/slog"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"
)

//xops:syncclosure
func runSyncVault(fn func()) { fn() }

// v2.3.3 CRIT-4 / C4 / HIGH-1 专项对抗回归套件。

//xops:secretuse
type SecretCB func(plain []byte) error

type cbHolder struct {
	CB SecretCB
}

func getDynamicSecretCB() SecretCB { return nil }

type fakeHash struct {
	out []byte
}

func (f *fakeHash) Write(p []byte) (int, error) { f.out = append(f.out, p...); return len(p), nil }
func (f *fakeHash) Sum(b []byte) []byte         { return append(b, f.out...) }
func (f *fakeHash) Reset()                      {}
func (f *fakeHash) Size() int                   { return 32 }
func (f *fakeHash) BlockSize() int              { return 64 }

type sinkWriter interface {
	WriteFile(name string, data []byte) error
}

func copyOutCallerParam(dst, plain []byte) {
	copy(dst, plain) // want "禁止通过 copy 将明文机密写入外层变量或字段"
}

func badCrit4AndHigh1(
	box *secret.SecretBox,
	passBox *secret.SecretBox,
	aead cipher.AEAD,
	w io.Writer,
	fs sinkWriter,
	holder cbHolder,
	directCB SecretCB,
	unknownCB func([]byte) error,
	nonce, salt []byte,
) {
	// CRIT-4C: 直接形参 SecretCB 合法；结构体字段、函数返回值、未知回调一律 Fail-Closed
	_ = box.Use(directCB)
	_ = box.Use(holder.CB)            // want "禁止将无法静态验证的未知函数或回调传入 SecretBox.Use"
	_ = box.Use(getDynamicSecretCB()) // want "禁止将无法静态验证的未知函数或回调传入 SecretBox.Use"
	_ = box.Use(unknownCB)            // want "禁止将无法静态验证的未知函数或回调传入 SecretBox.Use"

	// CRIT-4C: 构造 SecretCB 具名回调类型时当场审计函数体
	var badNamedCB SecretCB = func(plain []byte) error {
		slog.Info("named-cb-leak", "v", string(plain)) // want "禁止将明文机密.*传入日志汇点"
		return nil
	}
	_ = badNamedCB

	// CRIT-4D: 嵌套同步 keyBox.Use -> passBox.Use 与 //xops:syncclosure 同步闭包合法放行
	_ = box.Use(func(keyBytes []byte) error {
		var digest [32]byte
		runSyncVault(func() {
			digest = sha256.Sum256(keyBytes)
		})
		_ = digest
		return passBox.Use(func(passBytes []byte) error {
			_, _ = ssh.ParsePrivateKeyWithPassphrase(keyBytes, passBytes)
			return nil
		})
	})

	_ = box.Use(func(plain []byte) error {
		// CRIT-4A: 出参全面 Fail-Closed 拦截任意 io.Writer / 接口写入
		_, _ = w.Write(plain)             // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_ = fs.WriteFile("secret", plain) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"

		// CRIT-4B: argon2 保污（禁入 slog，但可送入 aes.NewCipher）、禁 AEAD.Open、禁 ssh.Marshal、禁伪造 hash.Hash
		dk := argon2.IDKey(plain, salt, 1, 64*1024, 1, 32)
		slog.Info("dk-leak", "v", dk) // want "禁止将明文机密.*传入日志汇点"
		_, _ = aes.NewCipher(dk)

		_, _ = aead.Open(nil, nonce, plain, nil) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_ = ssh.Marshal(plain)                   // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = ssh.ParseRawPrivateKey(plain)     // want "禁止将明文机密传入未经授权的外部调用或未知汇点"

		// 标准库 sha256/hmac hash.Hash.Write 合法；本地伪造 fakeHash 严格拦截（评审 #12）
		h := sha256.New()
		_, _ = h.Write(plain)
		hm := hmac.New(sha256.New, plain)
		_, _ = hm.Write(plain)
		var fh hash.Hash = &fakeHash{}
		_, _ = fh.Write(plain) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"

		// C4: 调用方非种子形参 CallerParam 隔离
		copyOutCallerParam(leakedBytes, plain)

		// HIGH-1 陷阱 4: 写后子切片别名反溯（先赋值 leakedBytes，再向 buf[2:] copy 明文）
		buf := make([]byte, 32)
		leakedBytes = buf // want "禁止将明文机密逃逸至外层变量"
		copy(buf[2:], plain)

		// HIGH-1 陷阱 3: 标准库同步 bytes.SplitSeq(plain) 自动注入 yield 参数并拦截泄露
		for part := range bytes.SplitSeq(plain, []byte(":")) {
			slog.Info("splitseq-leak", "v", string(part)) // want "禁止将明文机密.*传入日志汇点"
		}
		return nil
	})
}
