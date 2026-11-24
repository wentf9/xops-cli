package vault

import (
	"bytes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"gopkg.in/yaml.v3"
)

//xops:secretuse
func WithMasterKey(fn func(plain []byte) error) error { // want WithMasterKey:"secretuse"
	key := []byte("master-key")
	defer clear(key)
	return fn(key)
}

func okVaultUse(box *secret.SecretBox, aead cipher.AEAD, nonce, expected []byte) ([]byte, error) {
	var ct []byte
	err := box.Use(func(plain []byte) error {
		defer func() {
			clear(plain)
		}()
		p2 := plain[1:4]
		slog.Info("sizes", "len", len(plain), "cap", cap(p2))
		_ = fmt.Errorf("length=%d", len(plain))
		if subtle.ConstantTimeCompare(plain, expected) == 1 {
			return nil
		}
		if bytes.Equal(plain, expected) {
			return nil
		}
		ct = aead.Seal(nil, nonce, plain, nil)
		return nil
	})
	return ct, err
}

var (
	leakedBytes  []byte
	leakedString string
	leakedChan   chan []byte
)

type holder struct {
	P []byte
}

func badVaultLeaks(box *secret.SecretBox) {
	_ = box.Use(func(plain []byte) error {
		p2 := plain
		s := string(p2)
		slog.Info("leak", "v", s)                   // want "禁止将明文机密.*传入日志汇点"
		log.Println(plain[:2])                      // want "禁止将明文机密.*传入日志汇点"
		_ = fmt.Errorf("e: %s", bytes.Clone(plain)) // want "禁止将明文机密.*传入错误格式化汇点"
		sl := slices.Clone(plain[:2])
		_, _ = json.Marshal(sl) // want "禁止将明文机密.*传入序列化汇点"

		dst := make([]byte, len(plain))
		copy(dst, plain)
		_ = errors.New(string(dst)) // want "禁止将明文机密.*传入错误格式化汇点"

		buf := append([]byte(nil), plain...)
		_, _ = yaml.Marshal(buf) // want "禁止将明文机密.*传入序列化汇点"

		enc := base64.StdEncoding.EncodeToString(plain)
		slog.Info("b64", "v", enc) // want "禁止将明文机密.*传入日志汇点"
		hx := hex.EncodeToString(plain)
		slog.Info("hex", "v", hx) // want "禁止将明文机密.*传入日志汇点"

		var b bytes.Buffer
		b.Write(plain)
		slog.Info("buf", "v", b.String()) // want "禁止将明文机密.*传入日志汇点"

		leakedBytes = plain       // want "禁止将明文机密逃逸至外层变量"
		leakedString = string(p2) // want "禁止将明文机密逃逸至外层变量"
		leakedChan <- plain       // want "禁止将明文机密发送至 channel"

		_ = holder{P: plain}              // want "禁止将明文机密存入结构体"
		_ = map[string][]byte{"k": plain} // want "禁止将明文机密存入结构体"
		_ = []string{string(plain)}       // want "禁止将明文机密存入结构体"

		fn := func() { // want "禁止在内层闭包中捕获明文机密变量"
			_ = string(plain)
		}
		_ = fn

		_ = func() string { // want "禁止在内层闭包中捕获明文机密变量"
			return string(plain)
		}
		return nil
	})
}

//xops:secretuse
func badDirectReturnPlain(plain []byte) string { // want badDirectReturnPlain:"secretuse"
	return string(plain) // want "禁止通过 return 返回明文机密"
}

func badReturnPlain(box *secret.SecretBox) string {
	var out string
	_ = box.Use(func(plain []byte) error {
		out = string(plain) // want "禁止将明文机密逃逸至外层变量"
		return nil
	})
	return out
}
