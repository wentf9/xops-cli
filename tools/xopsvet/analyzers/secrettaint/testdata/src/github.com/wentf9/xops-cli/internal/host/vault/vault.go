package vault

import (
	"bytes"
	"crypto/aes"
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

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
	"gopkg.in/yaml.v3"
)

//xops:secretuse
func WithMasterKey(fn func(plain []byte) error) error {
	key := []byte("master-key")
	defer clear(key)
	return fn(key)
}

func okVaultUse(box *secret.SecretBox, key, nonce, expected []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	var ct []byte
	err = box.Use(func(plain []byte) error {
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

func badUntrustedAEADParam(box *secret.SecretBox, aead cipher.AEAD, nonce []byte) {
	_ = box.Use(func(plain []byte) error {
		_ = aead.Seal(nil, nonce, plain, nil) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
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
func badDirectReturnPlain(plain []byte) string {
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
	outerBufPtr       = &bytes.Buffer{}
	outerCopyN  int64 = 4
)

type localConsumer interface {
	Consume(plain []byte) error
}

type annotatedConsumer interface {
	//xops:secretuse
	Consume(plain []byte) error
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

	// NB-S3c: 10 跳逆序回调别名链（循环确保 SSA 真实可达）
	var c1, c2, c3, c4, c5, c6, c7, c8, c9, c10 func([]byte) error
	for range 10 {
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
	}
	_ = box.Use(c10)
}

func badBypassNBS4AndNBS5(box *secret.SecretBox) {
	_ = box.Use(func(plain []byte) error {
		// NB-S4: 多返回值 io.ReadAll / ReadBytes / ReadString 在短变量声明、赋值与 var 声明中的污点传播与逃逸
		out, _ := io.ReadAll(bytes.NewReader(plain))
		slog.Info("readall", "v", string(out)) // want "禁止将明文机密.*传入日志汇点"

		rb, _ := bytes.NewBuffer(plain).ReadBytes('\n')
		slog.Info("readbytes", "v", string(rb)) // want "禁止将明文机密.*传入日志汇点"

		rs, _ := bytes.NewBuffer(plain).ReadString('\n')
		slog.Info("readstring", "v", rs) // want "禁止将明文机密.*传入日志汇点"

		leakedBytes, _ = io.ReadAll(bytes.NewReader(plain))       // want "禁止将明文机密逃逸至外层变量"
		leakedString, _ = bytes.NewBuffer(plain).ReadString('\n') // want "禁止将明文机密逃逸至外层变量"
		var out2, err2 = io.ReadAll(bytes.NewReader(plain))
		_ = err2
		slog.Info("readall-var", "v", string(out2)) // want "禁止将明文机密.*传入日志汇点"

		// NB-S4 干净对照：非污点输入与不传播污点值的 io.Copy / ReadFrom 不应误报
		outClean, errClean := io.ReadAll(strings.NewReader("ok"))
		_, _ = outClean, errClean
		var safeBuf bytes.Buffer
		nCopy, errCopy := io.Copy(&safeBuf, strings.NewReader("ok"))
		_, _ = nCopy, errCopy
		nRF, errRF := safeBuf.ReadFrom(strings.NewReader("ok"))
		_, _ = nRF, errRF

		// NB-S5: io.CopyBuffer 第三参数 scratch 缓冲污点与外层逃逸（nil 与 io.CopyN 不应误报）
		var copyBufDst bytes.Buffer
		localScratch := make([]byte, 32)
		_, _ = io.CopyBuffer(&copyBufDst, bytes.NewReader(plain), localScratch)
		slog.Info("copybuf-local-scratch", "v", string(localScratch))          // want "禁止将明文机密.*传入日志汇点"
		_, _ = io.CopyBuffer(&copyBufDst, bytes.NewReader(plain), leakedBytes) // want "禁止通过 io.CopyBuffer 将明文机密写入外层缓冲或切片"

		_, _ = io.CopyBuffer(&copyBufDst, bytes.NewReader(plain), nil)
		_, _ = io.CopyBuffer(&copyBufDst, strings.NewReader("ok"), leakedBytes)
		_, _ = io.CopyN(&copyBufDst, bytes.NewReader(plain), outerCopyN)
		return nil
	})
}

// v2.3.2 B3 回归用例：回调并格不覆盖、同包 FuncDecl/MethodExpr 递归追踪、copy/io.Copy 收紧。
type myVaultBytes []byte

type wrapVaultWriter struct {
	w io.Writer
}

func (w *wrapVaultWriter) Write(p []byte) (int, error) {
	return w.w.Write(p)
}

func getOuterVaultSlice() []byte     { return leakedBytes }
func getOuterVaultWriter() io.Writer { return io.Discard }

func badMixedBranchHelper(plain []byte) error {
	slog.Info("mixed-branch-helper", "v", string(plain)) // want "禁止将明文机密.*传入日志汇点"
	return nil
}

func leakViaDirectHelper(p []byte) {
	slog.Info("direct-helper", "v", string(p)) // want "禁止将明文机密.*传入日志汇点"
}

func leakViaLocalFuncVar(p []byte) {
	leakedString = string(p) // want "禁止将明文机密逃逸至外层变量"
}

type methodLeakHelper struct{}

func (methodLeakHelper) leakMethodVal(p []byte) {
	slog.Info("method-val", "v", string(p)) // want "禁止将明文机密.*传入日志汇点"
}

func (methodLeakHelper) leakMethodExpr(p []byte) {
	slog.Info("method-expr", "v", string(p)) // want "禁止将明文机密.*传入日志汇点"
}

func (methodLeakHelper) leakMethodExprVar(p []byte) {
	leakedBytes = p // want "禁止将明文机密逃逸至外层变量"
}

type secretBuf []byte

func (b secretBuf) leakReceiver() {
	slog.Info("tainted-recv", "v", string(b)) // want "禁止将明文机密.*传入日志汇点"
}

func (b secretBuf) leakReceiverExpr() {
	leakedString = string(b) // want "禁止将明文机密逃逸至外层变量"
}

func leakGenericHelper[T ~[]byte](p T) {
	slog.Info("generic-helper", "v", string(p)) // want "禁止将明文机密.*传入日志汇点"
}

func recLeakHelper(p []byte, n int) {
	if n > 0 {
		recLeakHelper(p, n-1)
	}
	slog.Info("rec-helper", "v", string(p)) // want "禁止将明文机密.*传入日志汇点"
}

func okCleanHelper(p []byte) bool {
	_ = len(p)
	return bytes.Equal(p, []byte("ok"))
}

func badV232B3Regressions(box *secret.SecretBox, cond bool) {
	// 1. 回调单调并格：条件分支覆写 FuncLit 与具名函数均不丢失
	var cb1 func([]byte) error
	if cond {
		cb1 = func(p []byte) error {
			slog.Info("cb-overwrite-lit", "v", string(p)) // want "禁止将明文机密.*传入日志汇点"
			return nil
		}
	} else {
		cb1 = func(p []byte) error {
			clear(p)
			return nil
		}
	}
	_ = box.Use(cb1)

	var cb2 func([]byte) error
	if cond {
		cb2 = func(p []byte) error {
			clear(p)
			return nil
		}
	} else {
		cb2 = badMixedBranchHelper
	}
	_ = box.Use(cb2)

	// 2. 同包具名函数、localFuncs 变量转发、MethodVal、MethodExpr 与污点接收者递归追踪
	_ = box.Use(func(plain []byte) error {
		leakViaDirectHelper(plain)
		h := leakViaLocalFuncVar
		h(plain)

		var mh methodLeakHelper
		mh.leakMethodVal(plain)
		(methodLeakHelper).leakMethodExpr(mh, plain)
		me := (methodLeakHelper).leakMethodExprVar
		me(mh, plain)

		secretBuf(plain).leakReceiver()
		secretBuf.leakReceiverExpr(secretBuf(plain))
		leakGenericHelper[[]byte](plain)
		recLeakHelper(plain, 2)
		_ = okCleanHelper(plain)

		// 3. 收紧 copy / io.Copy 写入目标检查
		copy(getOuterVaultSlice(), plain)                                       // want "禁止通过 copy 将明文机密写入外层变量或字段"
		copy(myVaultBytes(leakedBytes), plain)                                  // want "禁止通过 copy 将明文机密写入外层变量或字段"
		copy([][]byte{leakedBytes}[0], plain)                                   // want "禁止通过 copy 将明文机密写入外层变量或字段"
		_, _ = io.Copy(&wrapVaultWriter{w: io.Discard}, bytes.NewReader(plain)) // want "禁止通过 io.Copy 将明文机密写入外层缓冲或写入器"
		_, _ = io.Copy(getOuterVaultWriter(), bytes.NewReader(plain))           // want "禁止通过 io.Copy 将明文机密写入外层缓冲或写入器"

		// 合法新建局部切片对照
		fresh1 := append([]byte{}, plain...)
		clear(fresh1)
		copy([]byte("xxxx"), plain)
		copy([]byte(nil), plain)
		copy(make([]byte, len(plain)), plain)
		return nil
	})
}

func badI18nSinkLeaks(box *secret.SecretBox, loc *i18n.Localizer) {
	_ = box.Use(func(plain []byte) error {
		s := string(plain)
		_ = domi18n.Str("secret", s)        // want "禁止将明文机密.*传入错误格式化汇点"
		_ = domi18n.BoundStr("secret", s)   // want "禁止将明文机密.*传入错误格式化汇点"
		_ = domi18n.BoundDisplayText(s, 32) // want "禁止将明文机密.*传入错误格式化汇点"
		_ = i18n.Str("secret", s)           // want "禁止将明文机密.*传入错误格式化汇点"
		_ = i18n.BoundStr("secret", s)      // want "禁止将明文机密.*传入错误格式化汇点"
		_ = domi18n.E(domi18n.KeySample, domi18n.Int("len", len(plain)))
		_ = i18n.E(domi18n.KeySample, domi18n.Str("k", s)) // want "禁止将明文机密.*传入错误格式化汇点"
		_ = loc.T(domi18n.KeySample, domi18n.Str("k", s))  // want "禁止将明文机密.*传入错误格式化汇点"
		_ = loc.Render(domi18n.NewMessage(domi18n.KeySample, domi18n.Int("len", len(plain))))
		return nil
	})
}

func badSyncClosureReturnAndSlotLeaks(box *secret.SecretBox) {
	_ = box.Use(func(plain []byte) error {
		// 1. FormatTemplate 属于 SinkError，即便带 //xops:syncclosure 也绝不放行明文捕获闭包。
		_ = domi18n.FormatTemplate("{k}", func(string) (string, bool) { // want "禁止在内层闭包中捕获明文机密变量"
			return string(plain), true
		})

		// 2. 跨包合法 //xops:syncclosure 回调禁止通过 return 返回明文机密。
		_ = ports.RunSyncStr(func() string { // want "禁止在同步闭包回调中通过 return 返回明文机密"
			return string(plain)
		})

		// 3. 本地捕获明文的 IIFE 返回明文并流入 slog.Info：同步闭包 return 与日志汇点双重拦截。
		leaked := func() string { // want "禁止在同步闭包回调中通过 return 返回明文机密"
			return string(plain)
		}()
		slog.Info("iife-capture-leak", "v", leaked) // want "禁止将明文机密.*传入日志汇点"

		// 4. 混合回调的非机密槽位不得搭便车享受 //xops:secretuse 具名回调放行。
		_ = ports.WithMixedCallback(func() { // want "禁止在内层闭包中捕获明文机密变量"
			_ = len(plain)
		}, func(b []byte) error {
			clear(b)
			return nil
		})

		// 5. 正例对照：defer 清零与同步闭包返回 nil / 非污点 error 零误报。
		defer func() {
			clear(plain)
		}()
		_ = ports.RunSyncErr(func() error {
			clear(plain)
			return nil
		})
		_ = ports.RunSyncErr(func() error {
			_ = len(plain)
			return errors.New("clean error")
		})
		return nil
	})
}
