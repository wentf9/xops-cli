package secret

import (
	"bytes"
	"crypto/subtle"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"testing"
)

func TestSecretBoxZeroValueAndNilFailClosed(t *testing.T) {
	var zero SecretBox
	var nilBox *SecretBox

	if zero.IsValid() || zero.IsWiped() || zero.Len() != 0 {
		t.Fatalf("零值 SecretBox 状态错误: valid=%v wiped=%v len=%d", zero.IsValid(), zero.IsWiped(), zero.Len())
	}
	if nilBox.IsValid() || nilBox.IsWiped() || nilBox.Len() != 0 {
		t.Fatalf("nil SecretBox 状态错误: valid=%v wiped=%v len=%d", nilBox.IsValid(), nilBox.IsWiped(), nilBox.Len())
	}
	if zero.Equal(&zero) || nilBox.Equal(nilBox) || zero.Equal(nilBox) {
		t.Fatal("零值或 nil SecretBox 不得与任何对象相等（fail-closed）")
	}
	if err := zero.Use(func(plain []byte) error { return nil }); !errors.Is(err, ErrSecretInvalid) {
		t.Fatalf("零值 Use() = %v, 期望 ErrSecretInvalid", err)
	}
	if err := nilBox.Use(func(plain []byte) error { return nil }); !errors.Is(err, ErrSecretInvalid) {
		t.Fatalf("nil Use() = %v, 期望 ErrSecretInvalid", err)
	}
	// 编译期验证非可寻址值接收者满足 fmt.Stringer / fmt.GoStringer（零 MakeInterface，兼容 secretbox）；
	// 对 (*SecretBox)(nil)，Go 标准库 fmt 内置空指针防护会安全输出 <nil>，不会回退反射。
	if (SecretBox{}).String() != "[REDACTED]" || (SecretBox{}).GoString() != "[REDACTED]" ||
		zero.String() != "[REDACTED]" || zero.GoString() != "[REDACTED]" {
		t.Fatal("值接收者 String/GoString 必须始终返回恒定脱敏占位符")
	}

	nilBox.Wipe()
	zero.Wipe()
	if zero.IsValid() || !zero.IsWiped() {
		t.Fatalf("Wipe 后的零值状态错误: valid=%v wiped=%v", zero.IsValid(), zero.IsWiped())
	}
	if err := zero.Use(func(plain []byte) error { return nil }); !errors.Is(err, ErrSecretWiped) {
		t.Fatalf("Wipe 后 Use() = %v, 期望 ErrSecretWiped", err)
	}
}

func TestWithBytesCopyClearUseAndImmutability(t *testing.T) {
	nilRaw := []byte("must-be-cleared-on-nil-fn")
	if err := WithBytes(nilRaw, nil); !errors.Is(err, ErrNilCallback) || !allBytesZero(nilRaw) {
		t.Fatal("WithBytes(raw, nil) 必须立即清零 raw 并返回 ErrNilCallback")
	}

	raw := []byte("top-secret-token")
	want := []byte("top-secret-token")
	sentinelErr := errors.New("caller-err")

	err := WithBytes(raw, func(box *SecretBox) error {
		if !allBytesZero(raw) {
			t.Fatal("进入 WithBytes 回调前必须已清零调用方 raw 切片")
		}
		assertValidRedactedBox(t, box, len(want))
		if err := mutateUseCopyOnce(t, box, want); err != nil {
			return err
		}
		if err := verifyImmutableAndNestedUse(t, box, want); err != nil {
			return err
		}
		return sentinelErr
	})
	if !errors.Is(err, sentinelErr) {
		t.Fatalf("WithBytes 未透传回调错误: got=%v want=%v", err, sentinelErr)
	}
}

func assertValidRedactedBox(t *testing.T, box *SecretBox, wantLen int) {
	t.Helper()
	if !box.IsValid() || box.IsWiped() || box.Len() != wantLen ||
		box.String() != "[REDACTED]" || box.GoString() != "[REDACTED]" ||
		(*box).String() != "[REDACTED]" || (*box).GoString() != "[REDACTED]" {
		t.Fatalf("有效 SecretBox 状态或脱敏输出异常: valid=%v wiped=%v len=%d", box.IsValid(), box.IsWiped(), box.Len())
	}
}

func mutateUseCopyOnce(t *testing.T, box *SecretBox, want []byte) error {
	t.Helper()
	return box.Use(func(plain []byte) error {
		defer clear(plain)
		if subtle.ConstantTimeCompare(plain, want) != 1 {
			t.Fatal("首次 Use 明文与输入不匹配")
		}
		plain[0] = 'X'
		return nil
	})
}

func verifyImmutableAndNestedUse(t *testing.T, box *SecretBox, want []byte) error {
	t.Helper()
	return box.Use(func(plain []byte) error {
		if !bytes.Equal(plain, want) {
			t.Fatal("首次 Use 对副本的修改污染了 SecretBox 内部字节")
		}
		return WithBytes([]byte("nested-pass"), func(passBox *SecretBox) error {
			return passBox.Use(func(passPlain []byte) error {
				if !bytes.Equal(passPlain, []byte("nested-pass")) || !bytes.Equal(plain, want) {
					t.Fatal("嵌套 Use 明文读取异常")
				}
				return nil
			})
		})
	})
}

func TestSecretBoxConstantTimeEqual(t *testing.T) {
	if err := WithBytes([]byte("same-secret"), func(box *SecretBox) error {
		assertBoxEqualToBytes(t, box, []byte("same-secret"), true)
		assertBoxEqualToBytes(t, box, []byte("same-secreX"), false)
		assertBoxEqualToBytes(t, box, []byte("short"), false)
		return nil
	}); err != nil {
		t.Fatalf("Equal 验证失败: %v", err)
	}
}

func assertBoxEqualToBytes(t *testing.T, box *SecretBox, otherBytes []byte, wantEqual bool) {
	t.Helper()
	err := WithBytes(otherBytes, func(other *SecretBox) error {
		if box.Equal(other) != wantEqual || other.Equal(box) != wantEqual {
			t.Fatalf("SecretBox.Equal 结果与预期不符: want=%v", wantEqual)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("嵌套 WithBytes 失败: %v", err)
	}
}

func TestSecretBoxEmptySecretDistinguishedFromZero(t *testing.T) {
	if err := WithBytes([]byte{}, func(emptyBox *SecretBox) error {
		var zero SecretBox
		if !emptyBox.IsValid() || emptyBox.Len() != 0 || emptyBox.Equal(&zero) {
			t.Fatalf("有效空 SecretBox 状态异常: valid=%v len=%d", emptyBox.IsValid(), emptyBox.Len())
		}
		assertBoxEqualToBytes(t, emptyBox, nil, true)
		return nil
	}); err != nil {
		t.Fatalf("空切片 WithBytes 失败: %v", err)
	}
}

func TestSecretBoxWipeAndPanicSafety(t *testing.T) {
	// 回调内显式 Wipe 幂等且立即失效
	if err := WithBytes([]byte("to-wipe"), func(box *SecretBox) error {
		box.Wipe()
		box.Wipe()
		if box.IsValid() || !box.IsWiped() || box.Len() != 0 || box.Equal(box) {
			t.Fatal("Wipe 后 SecretBox 必须永久失效")
		}
		if err := box.Use(func(plain []byte) error { return nil }); !errors.Is(err, ErrSecretWiped) {
			t.Fatalf("Wipe 后 Use() = %v, 期望 ErrSecretWiped", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithBytes 失败: %v", err)
	}

	// panic 路径仍清零调用方 raw 并透传 panic
	panicRaw := []byte("panic-secret")
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_ = WithBytes(panicRaw, func(box *SecretBox) error {
			panic("boom")
		})
	}()
	if recovered != "boom" || !allBytesZero(panicRaw) {
		t.Fatalf("panic 路径异常: recovered=%v rawZeroed=%v", recovered, allBytesZero(panicRaw))
	}

	// 白盒直接验证 Wipe 清零底层缓冲数组并置空切片引用
	backing := []byte("direct-backing")
	direct := &SecretBox{raw: backing, valid: true}
	direct.Wipe()
	if !allBytesZero(backing) || direct.IsValid() || !direct.IsWiped() || direct.raw != nil {
		t.Fatal("Wipe 必须清零底层切片并断开引用")
	}
}

func TestSecretBoxJSONv2NativeSemanticError(t *testing.T) {
	// 白盒 *_test.go 直调 encoding/json/v2.Marshal / MarshalWrite / MarshalEncode 验证原生 SemanticError
	// （受 xopsvet/secretbox AllowMakeInterface 精确联合豁免）。
	if err := WithBytes([]byte("do-not-serialize"), func(box *SecretBox) error {
		if _, err := jsonv2.Marshal(box); !isJSONv2SemanticError(err) {
			t.Fatalf("jsonv2.Marshal(*SecretBox) = %v, 期望 *jsonv2.SemanticError", err)
		}
		if _, err := jsonv2.Marshal(*box); !isJSONv2SemanticError(err) {
			t.Fatalf("jsonv2.Marshal(SecretBox) = %v, 期望 *jsonv2.SemanticError", err)
		}

		var writeBuf bytes.Buffer
		if err := jsonv2.MarshalWrite(&writeBuf, box); !isJSONv2SemanticError(err) || writeBuf.Len() != 0 {
			t.Fatalf("jsonv2.MarshalWrite(*SecretBox) = (len=%d, err=%v), 期望 0 字节且 *SemanticError", writeBuf.Len(), err)
		}

		var encBuf bytes.Buffer
		enc := jsontext.NewEncoder(&encBuf)
		if err := jsonv2.MarshalEncode(enc, box); !isJSONv2SemanticError(err) {
			t.Fatalf("jsonv2.MarshalEncode(*SecretBox) = %v, 期望 *jsonv2.SemanticError", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithBytes 意外失败: %v", err)
	}

	var zero SecretBox
	if _, err := jsonv2.Marshal(zero); !isJSONv2SemanticError(err) {
		t.Fatalf("jsonv2.Marshal(零值 SecretBox) = %v, 期望 *jsonv2.SemanticError", err)
	}
}

func TestRuntimeSecretScopeHook(t *testing.T) {
	if InSecretScope() {
		t.Fatal("在 Do / WithBytes / Use 外部时 InSecretScope() 必须为 false")
	}
	Do(nil)

	ranDo, inDo := false, false
	Do(func() {
		ranDo = true
		inDo = InSecretScope()
	})
	if !ranDo {
		t.Fatal("Do 必须同步执行回调")
	}

	inWithBytes, inUse := false, false
	if err := WithBytes([]byte("hook-test"), func(box *SecretBox) error {
		inWithBytes = InSecretScope()
		return box.Use(func(plain []byte) error {
			inUse = InSecretScope()
			if len(plain) != len("hook-test") {
				t.Fatalf("Use 明文长度异常: %d", len(plain))
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("WithBytes 失败: %v", err)
	}

	t.Logf("runtimesecret build=%v inDo=%v inWithBytes=%v inUse=%v", RuntimeSecretBuildEnabled(), inDo, inWithBytes, inUse)
	// WithBytes 回调 fn(box) 绝不得运行在 runtime/secret.Do 内部，避免向长生命周期子协程永久泄漏 secret 模式。
	if inWithBytes {
		t.Fatal("WithBytes 回调 fn(box) 必须在 runtime/secret.Do 外部执行，避免污染派生协程")
	}
	if RuntimeSecretBuildEnabled() {
		if inDo != inUse || InSecretScope() {
			t.Fatalf("runtime/secret 作用域状态不一致: inDo=%v inUse=%v after=%v",
				inDo, inUse, InSecretScope())
		}
	} else if inDo || inUse {
		t.Fatal("未启用 GOEXPERIMENT=runtimesecret 时 InSecretScope() 必须恒为 false")
	}
}

func TestRefZeroValueFailClosed(t *testing.T) {
	var zero Ref
	if zero.IsValid() || !zero.IsZero() || zero.Store() != "" || zero.Item() != "" || zero.String() != "" || zero.Equal(zero) {
		t.Fatalf("零值 Ref 必须严格失败关闭: %+v", zero)
	}
	if _, err := zero.MarshalText(); !errors.Is(err, ErrInvalidRef) {
		t.Fatalf("零值 Ref.MarshalText() = %v, 期望 ErrInvalidRef", err)
	}
	if _, err := jsonv2.Marshal(zero); !errors.Is(err, ErrInvalidRef) {
		t.Fatalf("零值 Ref JSON Marshal = %v, 期望包装 ErrInvalidRef", err)
	}
}

func TestRefValidRoundTripAndOrdering(t *testing.T) {
	var zero Ref
	ref, err := NewRef("local-offline", "key_01.ed25519")
	if err != nil {
		t.Fatalf("NewRef 失败: %v", err)
	}
	if !ref.IsValid() || ref.IsZero() || ref.Store() != "local-offline" || ref.Item() != "key_01.ed25519" ||
		ref.String() != "local-offline/key_01.ed25519" {
		t.Fatalf("Ref 属性异常: %+v", ref)
	}
	appended, err := ref.AppendText([]byte("ref:"))
	if err != nil || string(appended) != "ref:local-offline/key_01.ed25519" {
		t.Fatalf("AppendText = (%q, %v)", appended, err)
	}

	raw, err := jsonv2.Marshal(ref, jsonv2.Deterministic(true))
	if err != nil || string(raw) != `"local-offline/key_01.ed25519"` {
		t.Fatalf("jsonv2.Marshal(Ref) = (%s, %v)", raw, err)
	}
	var decoded Ref
	if err := jsonv2.Unmarshal(raw, &decoded); err != nil || !decoded.Equal(ref) || decoded.Compare(ref) != 0 {
		t.Fatalf("jsonv2.Unmarshal(Ref) = (%+v, %v)", decoded, err)
	}

	ref2, err := ParseRef("os-keychain/a1b2c3")
	if err != nil {
		t.Fatalf("ParseRef 失败: %v", err)
	}
	if zero.Compare(ref) >= 0 || ref.Compare(zero) <= 0 || zero.Compare(zero) != 0 ||
		ref.Compare(ref2) >= 0 || ref2.Compare(ref) <= 0 {
		t.Fatal("Ref.Compare 违反全序律")
	}
}

func TestRefRejectsInvalidInputsAndResetsOnError(t *testing.T) {
	badInputs := []string{
		"", "no-slash", "/item", "store/", "store/a/b",
		"./item", "../item", "store/.", "store/..",
		".hidden/item", "store/.hidden", "-flag/item", "store/-flag",
		"store./item", "store/item.", "store:1/item", "store/item:1",
		"store/item name", "store/item\x00", "store/中文",
		string(bytes.Repeat([]byte{'a'}, 129)) + "/item",
		"store/" + string(bytes.Repeat([]byte{'b'}, 129)),
		// Windows DOS 保留设备主干名（大小写不敏感、含首个 '.' 之前的主干）
		"vault/CON", "vault/con.key", "vault/PRN", "vault/aux.enc", "vault/NUL", "vault/nul.lock",
		"vault/COM1", "vault/com9.bak", "vault/LPT1", "vault/LPT9.dat",
		"CON/item", "nul.store/item",
	}
	for _, bad := range badInputs {
		if _, err := ParseRef(bad); !errors.Is(err, ErrInvalidRef) {
			t.Fatalf("ParseRef(%q) = %v, 期望 ErrInvalidRef", bad, err)
		}
	}

	// 合法相似非保留设备名必须正常放行
	for _, good := range []string{"vault/console", "vault/com10", "vault/com0", "vault/lpt0", "vault/null", "vault/my_con"} {
		if ref, err := ParseRef(good); err != nil || !ref.IsValid() {
			t.Fatalf("ParseRef(%q) 应放行合法名称，实际=(%+v, %v)", good, ref, err)
		}
	}

	target, err := NewRef("local-offline", "item-1")
	if err != nil {
		t.Fatalf("NewRef 失败: %v", err)
	}
	if err := target.UnmarshalText([]byte("bad-ref")); !errors.Is(err, ErrInvalidRef) || target.IsValid() {
		t.Fatalf("UnmarshalText 失败后未重置零值: target=%+v err=%v", target, err)
	}
	var nilRef *Ref
	if err := nilRef.UnmarshalText([]byte("a/b")); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("nil Ref.UnmarshalText = %v, 期望 ErrNilReceiver", err)
	}
}

func FuzzParseRef(f *testing.F) {
	for _, seed := range []string{"local-offline/a1b2c3", "s/i", "", "a/b/c", "../x", "a/b."} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		ref, err := ParseRef(raw)
		if err != nil {
			if !errors.Is(err, ErrInvalidRef) {
				t.Fatalf("ParseRef(%q) 错误未包装 ErrInvalidRef: %v", raw, err)
			}
			return
		}
		if !ref.IsValid() {
			t.Fatalf("ParseRef(%q) 返回无效 Ref 却无错误", raw)
		}
		ref2, err := ParseRef(ref.String())
		if err != nil || !ref.Equal(ref2) {
			t.Fatalf("ParseRef 破坏幂等性: raw=%q canon=%q err=%v", raw, ref.String(), err)
		}
	})
}

func allBytesZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func isJSONv2SemanticError(err error) bool {
	_, ok := errors.AsType[*jsonv2.SemanticError](err)
	return ok
}
