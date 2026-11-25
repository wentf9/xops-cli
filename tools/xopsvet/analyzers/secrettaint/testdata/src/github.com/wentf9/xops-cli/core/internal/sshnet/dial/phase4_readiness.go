package dial

import (
	"crypto"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"log/slog"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ssh"
)

// okTOTPFlow 验证 RFC 6238 TOTP 完整链路：base32 解码（槽 1 error 不染毒）+ hmac.New(sha1.New, key)。
func okTOTPFlow(box *secret.SecretBox, counter uint64, alg string) (string, error) {
	var code string
	err := box.Use(func(plain []byte) error {
		cleaned := strings.ToUpper(strings.TrimSpace(string(plain)))
		key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cleaned)
		if err != nil {
			return err
		}
		defer clear(key)

		var hashCtor func() hash.Hash
		switch alg {
		case "SHA256":
			hashCtor = sha256.New
		case "SHA512":
			hashCtor = sha512.New
		default:
			hashCtor = sha1.New
		}
		mac := hmac.New(hashCtor, key)
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], counter)
		_, _ = mac.Write(buf[:])
		sum := mac.Sum(nil)
		offset := sum[len(sum)-1] & 0x0f
		binCode := (uint32(sum[offset]&0x7f) << 24) |
			(uint32(sum[offset+1]) << 16) |
			(uint32(sum[offset+2]) << 8) |
			uint32(sum[offset+3])
		code = fmt.Sprintf("%06d", binCode%1000000)

		// 合法局部 base32 Decode/AppendDecode 消费后经 hmac.New(sha1.New, ...) 净化
		localDst := make([]byte, base32.StdEncoding.DecodedLen(len(plain)))
		defer clear(localDst)
		if _, dErr := base32.StdEncoding.Decode(localDst, plain); dErr != nil {
			return dErr
		}
		_ = hmac.New(sha1.New, localDst)

		appended, aErr := base32.StdEncoding.AppendDecode(nil, plain)
		if aErr != nil {
			return aErr
		}
		defer clear(appended)
		_ = hmac.New(sha1.New, appended)
		return nil
	})
	return code, err
}

// okParseRawPrivateKeyToSigner 验证 ParseRawPrivateKey* 保污输出在 Use 作用域内经 NewSignerFromKey / NewSignerFromSigner 净化为不透明 ssh.Signer。
func okParseRawPrivateKeyToSigner(keyBox, passBox *secret.SecretBox) (ssh.Signer, error) {
	var signer ssh.Signer
	err := keyBox.Use(func(keyBytes []byte) error {
		raw1, err := ssh.ParseRawPrivateKey(keyBytes)
		if err != nil {
			return err
		}
		s1, err := ssh.NewSignerFromKey(raw1)
		if err != nil {
			return err
		}
		signer = s1
		if cs, ok := raw1.(crypto.Signer); ok {
			sCs, csErr := ssh.NewSignerFromSigner(cs)
			if csErr != nil {
				return csErr
			}
			signer = sCs
		}
		return passBox.Use(func(passBytes []byte) error {
			raw2, pErr := ssh.ParseRawPrivateKeyWithPassphrase(keyBytes, passBytes)
			if pErr != nil {
				return pErr
			}
			s2, sErr := ssh.NewSignerFromKey(raw2)
			if sErr != nil {
				return sErr
			}
			signer = s2
			return nil
		})
	})
	return signer, err
}

var (
	outerDialBytes  []byte
	outerDialRawKey any
)

type nonVaultAEADHolder struct {
	aead cipher.AEAD
}

// badUnkeyedSHA1AndBase32Leaks 验证未加密钥 sha1、base32 泄漏、ParseRawPrivateKey 逃逸、非 priv 通道写入及非 vault 字段 Seal 均严格 Fail-Closed。
func badUnkeyedSHA1AndBase32Leaks(box *secret.SecretBox, sess *ssh.Session, ch ssh.Channel, key, nonce []byte) {
	var holder nonVaultAEADHolder
	holder.aead, _ = chacha20poly1305.NewX(key)
	stdin, _ := sess.StdinPipe()

	_ = box.Use(func(plain []byte) error {
		// 1. 未加密钥的 sha1.New().Write / sha1.Sum 必须继续禁止
		h := sha1.New()
		_, _ = h.Write(plain) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_ = sha1.Sum(plain)   // want "禁止将明文机密传入未经授权的外部调用或未知汇点"

		// 2. base32 编解码输出必须保持污点，不得逃逸到日志或外层缓冲
		dec, _ := base32.StdEncoding.DecodeString(string(plain))
		slog.Info("b32-dec", "v", dec) // want "禁止将明文机密.*传入日志汇点"
		enc := base32.StdEncoding.EncodeToString(plain)
		slog.Info("b32-enc", "v", enc)                                // want "禁止将明文机密.*传入日志汇点"
		_, _ = base32.StdEncoding.Decode(outerDialBytes, plain)       // want "禁止通过 Decode 将明文机密写入外层变量或字段"
		_, _ = base32.StdEncoding.AppendDecode(outerDialBytes, plain) // want "禁止通过 base32\\.AppendDecode 将明文机密写入外层变量或字段"

		// 3. ParseRawPrivateKey / ParseRawPrivateKeyWithPassphrase 原始私钥输出必须保污（禁外泄/禁日志）
		raw1, _ := ssh.ParseRawPrivateKey(plain)
		outerDialRawKey = raw1             // want "禁止将明文机密逃逸至外层变量"
		slog.Info("raw-leak-1", "k", raw1) // want "禁止将明文机密.*传入日志汇点"
		raw2, _ := ssh.ParseRawPrivateKeyWithPassphrase(plain, plain)
		slog.Info("raw-leak-2", "k", raw2) // want "禁止将明文机密.*传入日志汇点"

		// 4. 非 LayerCoreSSHNetPriv 禁止向 ssh.Channel 或 StdinPipe 写入明文
		_, _ = ch.Write(plain)    // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = stdin.Write(plain) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"

		// 5. 非 LayerHostVault 禁止通过结构体字段调用 cipher.AEAD.Seal
		_ = holder.aead.Seal(nil, nonce, plain, nil) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}
