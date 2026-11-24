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
	"io"
	"log"
	"log/slog"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/events"
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

func badBypassS4CommaOKTypeAssert(box *secret.SecretBox) {
	_ = box.Use(func(plain []byte) error {
		var anyPlain any = plain
		extracted, _ := anyPlain.([]byte)
		slog.Info("bypass-comma-ok", "v", extracted) // want "禁止将明文机密.*传入日志汇点"
		var ok bool
		leakedBytes, ok = anyPlain.([]byte) // want "禁止将明文机密逃逸至外层变量"
		_ = ok

		cleanAny, ok := anyPlain.([]byte)
		if ok {
			clear(cleanAny)
		}
		return nil
	})
}

func badBypassS5IIFEAndDefer(box *secret.SecretBox) {
	_ = box.Use(func(plain []byte) error {
		func(b []byte) {
			slog.Info("bypass-iife", "v", string(b)) // want "禁止将明文机密.*传入日志汇点"
			leakedBytes = b                          // want "禁止将明文机密逃逸至外层变量"
		}(plain)

		helper := func(b []byte) {
			slog.Info("bypass-helper", "v", string(b)) // want "禁止将明文机密.*传入日志汇点"
		}
		helper(plain)

		defer func(b []byte) {
			slog.Info("bypass-defer", "v", string(b)) // want "禁止将明文机密.*传入日志汇点"
		}(plain)

		defer func(b []byte) {
			clear(b)
		}(plain)
		_ = func(b []byte) int {
			return len(b)
		}(plain)
		return nil
	})
}

func badBypassS6WriteToAndRead(box *secret.SecretBox) {
	_ = box.Use(func(plain []byte) error {
		slog.Info("rep-bytes", "v", bytes.Repeat(plain, 1))       // want "禁止将明文机密.*传入日志汇点"
		slog.Info("rep-slices", "v", slices.Repeat(plain, 1))     // want "禁止将明文机密.*传入日志汇点"
		slog.Info("newbuf", "v", bytes.NewBuffer(plain).String()) // want "禁止将明文机密.*传入日志汇点"
		slog.Info("join-bytes", "v", bytes.Join(                  // want "禁止将明文机密.*传入日志汇点"
			[][]byte{plain}, nil)) // want "禁止将明文机密存入结构体或非字节切片容器字面量"
		slog.Info("join-str", "v", strings.Join( // want "禁止将明文机密.*传入日志汇点"
			[]string{string(plain)}, ",")) // want "禁止将明文机密存入结构体或非字节切片容器字面量"

		_, _ = bytes.NewBuffer(plain).WriteTo(io.Discard)           // want "禁止通过 WriteTo 导出明文缓冲或读取器内容"
		_, _ = bytes.NewReader(plain).WriteTo(io.Discard)           // want "禁止通过 WriteTo 导出明文缓冲或读取器内容"
		_, _ = strings.NewReader(string(plain)).WriteTo(io.Discard) // want "禁止通过 WriteTo 导出明文缓冲或读取器内容"

		var safeBuf bytes.Buffer
		safeBuf.WriteString("safe")
		_, _ = safeBuf.WriteTo(io.Discard)

		br := bytes.NewReader(plain)
		readDst := make([]byte, len(plain))
		_, _ = br.Read(readDst)
		slog.Info("read-dst", "v", string(readDst)) // want "禁止将明文机密.*传入日志汇点"
		_, _ = br.Read(leakedBytes)                 // want "禁止通过 Read 将明文机密写入外层变量或字段"

		appended := fmt.Appendf(nil, "%s", plain)
		slog.Info("fmt-appendf", "v", string(appended)) // want "禁止将明文机密.*传入日志汇点"
		_ = fmt.Append(leakedBytes, plain)              // want "禁止通过 fmt.Append 将明文机密写入外层变量或字段"
		return nil
	})
}

func badBypassS11CopySliceAndMap(box *secret.SecretBox) {
	_ = box.Use(func(plain []byte) error {
		localBuf := make([]byte, len(plain)+4)
		copy(localBuf[1:], plain)
		slog.Info("copy-slice", "v", string(localBuf)) // want "禁止将明文机密.*传入日志汇点"

		copy(leakedBytes[1:], plain) // want "禁止通过 copy 将明文机密写入外层变量或字段"

		localMap := map[string][]byte{"k": make([]byte, len(plain))}
		copy(localMap["k"], plain) // want "禁止通过 copy 将明文机密写入外层变量或字段"
		return nil
	})
}

func badHelperConsume(plain []byte) error {
	slog.Info("helper-consume", "v", string(plain)) // want "禁止将明文机密.*传入日志汇点"
	return nil
}

func okHelperConsume(plain []byte) error {
	clear(plain)
	return nil
}

type helperStruct struct{}

func (helperStruct) badMethodConsume(plain []byte) error {
	leakedBytes = plain // want "禁止将明文机密逃逸至外层变量"
	return nil
}

func badUseHelperAndDeepChain(box *secret.SecretBox) {
	_ = box.Use(badHelperConsume)
	_ = box.Use(okHelperConsume)
	var hs helperStruct
	_ = box.Use(hs.badMethodConsume)
	_ = box.Use(events.UnannotatedConsumer) // want "禁止将未标注 //xops:secretuse 的跨包函数传入 SecretBox.Use"

	_ = box.Use(func(plain []byte) error {
		var t1, t2, t3, t4, t5, t6, t7, t8 []byte
		for range 1 {
			t8 = t7
			t7 = t6
			t6 = t5
			t5 = t4
			t4 = t3
			t3 = t2
			t2 = t1
			t1 = plain
		}
		slog.Info("deep-chain", "v", string(t8)) // want "禁止将明文机密.*传入日志汇点"
		return nil
	})
}

var (
	outerBuf    bytes.Buffer
	outerBufPtr = &bytes.Buffer{}
)

type localConsumer interface {
	Consume(plain []byte) error
}

type annotatedConsumer interface {
	//xops:secretuse
	Consume(plain []byte) error // want Consume:"secretuse"
}

type badConsumerImpl struct{}

func (badConsumerImpl) Consume(plain []byte) error {
	slog.Info("iface-leak", "v", string(plain))
	return nil
}

func badHelperTypeAssert(plain []byte) error {
	slog.Info("type-assert-helper", "v", string(plain)) // want "禁止将明文机密.*传入日志汇点"
	return nil
}

func badHelper10Hops(plain []byte) error {
	slog.Info("10hops-helper", "v", string(plain)) // want "禁止将明文机密.*传入日志汇点"
	return nil
}

func badNewBypassesNB(box *secret.SecretBox) {
	// NB-S1: Buffer.ReadFrom 与 io.Copy
	_ = box.Use(func(plain []byte) error {
		var rfBuf bytes.Buffer
		_, _ = rfBuf.ReadFrom(bytes.NewReader(plain))
		slog.Info("readfrom", "v", rfBuf.String()) // want "禁止将明文机密.*传入日志汇点"

		_, _ = outerBuf.ReadFrom(bytes.NewReader(plain)) // want "禁止通过 ReadFrom 将明文机密写入外层缓冲"

		var copyBuf bytes.Buffer
		_, _ = io.Copy(&copyBuf, bytes.NewReader(plain))
		slog.Info("iocopy", "v", copyBuf.String()) // want "禁止将明文机密.*传入日志汇点"

		_, _ = io.Copy(outerBufPtr, bytes.NewReader(plain)) // want "禁止通过 io.Copy 将明文机密写入外层缓冲或写入器"
		_, _ = io.Copy(&outerBuf, bytes.NewReader(plain))   // want "禁止通过 io.Copy 将明文机密写入外层缓冲或写入器"

		var safeBuf bytes.Buffer
		_, _ = safeBuf.ReadFrom(strings.NewReader("ok"))
		_, _ = io.Copy(&safeBuf, strings.NewReader("ok"))

		// NB-S2a: 类型断言包裹的 IIFE 回调与干净对照
		any(func(b []byte) {
			slog.Info("any-iife", "v", string(b)) // want "禁止将明文机密.*传入日志汇点"
		}).(func([]byte))(plain)

		any(func(b []byte) {
			clear(b)
		}).(func([]byte))(plain)
		return nil
	})

	// NB-S3b: 类型断言包裹的 SecretBox.Use 具名辅助函数
	_ = box.Use(any(badHelperTypeAssert).(func([]byte) error))

	// NB-S3a: 同包未标注接口方法 vs 已标注 //xops:secretuse 接口方法
	var ic localConsumer = badConsumerImpl{}
	_ = box.Use(ic.Consume) // want "禁止将未标注 //xops:secretuse 的接口方法或无体函数传入 SecretBox.Use"

	var okIC annotatedConsumer = badConsumerImpl{}
	_ = box.Use(okIC.Consume)

	// NB-S3c: 10 跳逆序回调别名链
	var c1, c2, c3, c4, c5, c6, c7, c8, c9, c10 func([]byte) error
	c10 = c9
	c9 = c8
	c8 = c7
	c7 = c6
	c6 = c5
	c5 = c4
	c4 = c3
	c3 = c2
	c2 = c1
	c1 = badHelper10Hops
	_ = box.Use(c10)
}
