package i18n

import (
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"
)

type customSingleWrap struct {
	msg   string
	inner error
}

func (c *customSingleWrap) Error() string { return c.msg }
func (c *customSingleWrap) Unwrap() error { return c.inner }

type customLocalizable struct {
	sentinel error
	msg      Message
	cause    error
}

func (c *customLocalizable) Error() string { return c.msg.Canonical() }
func (c *customLocalizable) LocalizableView() ErrorNode {
	return ErrorNode{Sentinel: c.sentinel, Message: c.msg, Cause: c.cause}
}

func TestErrorConstructorsAndChainSemantics(t *testing.T) {
	s1 := Sentinel(KeyCommonNotFound)
	s2 := Sentinel(KeyCommonNotFound)
	if !errors.Is(s1, s2) || s1.Error() != "resource not found" {
		t.Fatalf("同 MessageID 哨兵应语义相等: s1=%q", s1.Error())
	}
	if errors.Is(E(KeyCommonNotFound), s1) {
		t.Fatal("普通 E 错误不应被误判为哨兵")
	}

	ef := EF(s1, KeyLocaleInvalidValue, Str("value", "xx"))
	if !errors.Is(ef, s1) || !errors.Is(ef, s2) || ef.Error() != "i18n: invalid locale xx" {
		t.Fatalf("EF 语义异常: err=%q", ef.Error())
	}
	assertWrapAndFacadeChain(t, s1, ef)
}

func assertWrapAndFacadeChain(t *testing.T, s1, ef error) {
	t.Helper()
	rootCause := errors.New("io timeout")
	wrapped := Wrap(rootCause, KeyCommonTimeout)
	if !errors.Is(wrapped, rootCause) || wrapped.Error() != "operation timed out: io timeout" {
		t.Fatalf("Wrap 语义异常: err=%q", wrapped.Error())
	}
	wrapS := WrapS(ErrInvalidParam, rootCause, KeyParamInvalidValue, Str("key", "port"))
	if !errors.Is(wrapS, ErrInvalidParam) || !errors.Is(wrapS, rootCause) {
		t.Fatal("WrapS 应同时匹配 sentinel 与 cause")
	}
	if _, ok := errors.AsType[*Error](wrapS); !ok {
		t.Fatal("errors.AsType[*Error] 应成功匹配结构化错误")
	}

	facade := Sentinel(KeyCommonPermissionDeny)
	mapped := WrapSentinel(facade, ef)
	if !errors.Is(mapped, facade) || !errors.Is(mapped, s1) {
		t.Fatal("WrapSentinel 应同时保留门面哨兵与底层错误链")
	}
	view, ok := InspectNode(mapped)
	if !ok || !view.SuppressInnerID || !errors.Is(view.Sentinel, facade) || !errors.Is(view.Cause, ef) {
		t.Fatalf("WrapSentinel 视图异常: ok=%v view=%+v", ok, view)
	}
	if id, found := ErrorID(mapped); !found || id != KeyCommonPermissionDeny {
		t.Fatalf("WrapSentinel ErrorID = (%q, %v), 期望 %q", id, found, KeyCommonPermissionDeny)
	}
}

func TestInspectNodeUnwrapDirectAndFallbacks(t *testing.T) {
	assertNilAndZeroErrorSafety(t)
	assertCustomNodeAndJoinInspect(t)
	assertWithFallbackConstructors(t)
}

func assertNilAndZeroErrorSafety(t *testing.T) {
	t.Helper()
	if _, ok := InspectNode(nil); ok {
		t.Fatal("InspectNode(nil) 应返回 false")
	}
	var nilErr *Error
	var typedNil error = nilErr
	if _, ok := InspectNode(typedNil); ok || nilErr.Error() != "" || nilErr.Unwrap() != nil || nilErr.Is(ErrInvalidLocale) {
		t.Fatal("typed-nil *Error 应安全失败关闭")
	}
	var zeroErr Error
	if _, ok := InspectNode(&zeroErr); ok || zeroErr.Error() != "" || zeroErr.Unwrap() != nil {
		t.Fatal("零值 Error 应安全失败关闭")
	}
}

func assertCustomNodeAndJoinInspect(t *testing.T) {
	t.Helper()
	custom := &customLocalizable{
		sentinel: ErrInvalidParam,
		msg:      NewMessage(KeyParamInvalidKey, Str("key", "x")),
		cause:    errors.New("root"),
	}
	wrappedCustom := &customSingleWrap{msg: "outer", inner: custom}
	if _, ok := InspectNode(wrappedCustom); ok {
		t.Fatal("InspectNode 不得穿透非 LocalizableNode 外层")
	}
	children := UnwrapDirect(wrappedCustom)
	if len(children) != 1 || !errors.Is(children[0], custom) {
		t.Fatalf("UnwrapDirect 单解包异常: %v", children)
	}
	if id, ok := ErrorID(wrappedCustom); !ok || id != KeyParamInvalidKey {
		t.Fatalf("ErrorID 穿透外层非结构化包装失败: (%q, %v)", id, ok)
	}

	joined := errors.Join(errors.New("plain"), EWithFallback(MessageID("root.custom"), "custom {k}", Str("k", "v")))
	if len(UnwrapDirect(joined)) != 2 {
		t.Fatal("UnwrapDirect 应完整返回 errors.Join 子错误")
	}
	if id, ok := ErrorID(joined); !ok || id != MessageID("root.custom") {
		t.Fatalf("ErrorID(joined) = (%q, %v)", id, ok)
	}
}

func assertWithFallbackConstructors(t *testing.T) {
	t.Helper()
	if SentinelWithFallback(MessageID("root.s"), "root sentinel").Error() != "root sentinel" {
		t.Fatal("SentinelWithFallback 文本异常")
	}
	if EFWithFallback(ErrInvalidParam, MessageID("root.ef"), "ef {x}", Int("x", 7)).Error() != "ef 7" {
		t.Fatal("EFWithFallback 文本异常")
	}
	if WrapWithFallback(errors.New("c"), MessageID("root.w"), "w").Error() != "w: c" {
		t.Fatal("WrapWithFallback 文本异常")
	}
	if WrapSWithFallback(ErrInvalidParam, errors.New("c"), MessageID("root.ws"), "ws").Error() != "ws: c" {
		t.Fatal("WrapSWithFallback 文本异常")
	}
	if E(MessageIDInvalid) == nil || WrapSentinel(nil, nil) == nil {
		t.Fatal("错误构造器在非法输入下亦绝不能返回 nil")
	}
}

func TestLocaleTextCodec(t *testing.T) {
	for _, loc := range []Locale{LocaleEn, LocaleZh} {
		appended, err := loc.AppendText([]byte("lang="))
		marshaled, mErr := loc.MarshalText()
		if err != nil || mErr != nil || string(appended) != "lang="+string(marshaled) {
			t.Fatalf("Locale 文本编码不一致: %q vs %q errs=(%v,%v)", appended, marshaled, err, mErr)
		}
		var out Locale
		if err := out.UnmarshalText(marshaled); err != nil || out != loc {
			t.Fatalf("Locale 文本往返失败: out=%v err=%v", out, err)
		}
	}
	if _, err := LocaleInvalid.MarshalText(); !errors.Is(err, ErrInvalidLocale) {
		t.Fatalf("LocaleInvalid.MarshalText 应失败关闭: %v", err)
	}
	var nilLoc *Locale
	if err := nilLoc.UnmarshalText([]byte("en")); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("nil *Locale.UnmarshalText 应返回 ErrNilReceiver: %v", err)
	}
	out := LocaleZh
	if err := out.UnmarshalText([]byte("C")); !errors.Is(err, ErrInvalidLocale) || out != LocaleInvalid {
		t.Fatalf("非法文本反序列化应重置为 LocaleInvalid: out=%v err=%v", out, err)
	}
}

func TestParamAndMessageJSONCodec(t *testing.T) {
	inner := NewMessage(KeyParamInvalidKey, Str("key", "host"))
	msg := NewPluralMessageWithFallback(
		KeyCommonErrorJoin,
		"{head}: {tail} ({count})",
		0,
		Str("head", ""),
		Int("i", -10),
		Int64("i64", 99),
		Uint64("u64", 12345),
		Float("f", 3.25, 2),
		Bool("b", false),
		Dur("d", 2*time.Second+500*time.Millisecond),
		Msg("tail", inner),
	)
	raw1, err := jsonv2.Marshal(msg, jsonv2.Deterministic(true))
	raw2, err2 := jsonv2.Marshal(msg, jsonv2.Deterministic(true))
	if err != nil || err2 != nil || string(raw1) != string(raw2) {
		t.Fatalf("Message JSON 确定性编码失败: errs=(%v,%v)", err, err2)
	}
	var decoded Message
	if err := jsonv2.Unmarshal(raw1, &decoded); err != nil || !decoded.Equal(msg) {
		t.Fatalf("Message JSON 往返失败: raw=%s err=%v", raw1, err)
	}
	if c, ok := decoded.Count(); !ok || c != 0 {
		t.Fatalf("显式 count=0 往返丢失: c=%d ok=%v", c, ok)
	}
	assertJSONCodecRejectsInvalid(t)
}

func assertJSONCodecRejectsInvalid(t *testing.T) {
	t.Helper()
	if _, err := jsonv2.Marshal(Param{}); !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("零值 Param JSON 编码应失败: %v", err)
	}
	if _, err := jsonv2.Marshal(Message{}); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("零值 Message JSON 编码应失败: %v", err)
	}
	badParams := []string{
		`null`,
		`{"key":"k","kind":"string","str":"v","extra":1}`,
		`{"key":"k","kind":"string"}`,
		`{"key":"k","kind":"string","str":"v","int64":1}`,
		`{"key":"k","kind":"string","str":"v","prec":2}`,
		`{"key":"k","kind":"unknown","str":"v"}`,
		`{"key":"k","kind":"duration","duration":"not-a-dur"}`,
		`{"key":"k","kind":"float64","float64":1.5,"prec":99}`,
		`{"key":"bad key","kind":"string","str":"v"}`,
	}
	for _, raw := range badParams {
		p := Str("seed", "ok")
		if err := jsonv2.Unmarshal([]byte(raw), &p); err == nil || p.IsValid() {
			t.Fatalf("非法 Param JSON 应拒绝并重置: raw=%s", raw)
		}
	}

	// 验证超深嵌套 JSON（深度 5 > MaxMessageDepth=4）被拒绝。
	deep := `{"id":"common.not_found"}`
	for range int(MaxMessageDepth) + 1 {
		deep = `{"id":"common.error_join","params":[{"key":"m","kind":"message","message":` + deep + `}]}`
	}
	badMsgs := []string{
		`null`,
		`{"id":"BadID"}`,
		`{"id":"common.not_found","unknown":true}`,
		`{"id":"common.not_found","params":[{"key":"a","kind":"int64","int64":1},{"key":"a","kind":"int64","int64":2}]}`,
		`{"id":"common.not_found","fallback":"` + strings.Repeat("x", MaxTemplateBytes+1) + `"}`,
		deep,
	}
	for _, raw := range badMsgs {
		m := NewMessage(KeyCommonNotFound)
		if err := jsonv2.Unmarshal([]byte(raw), &m); err == nil || m.IsValid() {
			t.Fatalf("非法 Message JSON 应拒绝并重置: raw=%s", raw)
		}
	}
}
