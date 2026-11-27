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
	mapped := WrapSentinel(facade, ef, s1)
	if !errors.Is(mapped, facade) || !errors.Is(mapped, s1) {
		t.Fatal("WrapSentinel 应同时保留门面哨兵与底层错误链")
	}
	view, ok := InspectNode(mapped)
	if !ok || len(view.SuppressedSentinels) != 1 || !errors.Is(view.SuppressedSentinels[0], s1) || !errors.Is(view.Sentinel, facade) || !errors.Is(view.Cause, ef) {
		t.Fatalf("WrapSentinel 视图异常: ok=%v view=%+v", ok, view)
	}
	if id, found := ErrorID(mapped); !found || id != KeyCommonPermissionDeny {
		t.Fatalf("WrapSentinel ErrorID = (%q, %v), 期望 %q", id, found, KeyCommonPermissionDeny)
	}
	assertWrapSentinelDetailAndDynamicDetail(t, s1, facade)
}

func assertWrapSentinelDetailAndDynamicDetail(t *testing.T, srcSentinel, facade error) {
	t.Helper()
	assertWrapSentinelDetailBehavior(t, srcSentinel, facade)
	assertDynamicDetailErrorBehavior(t)
}

func assertWrapSentinelDetailBehavior(t *testing.T, srcSentinel, facade error) {
	t.Helper()
	// 1. WrapSentinelDetail 完整保留门面头段语义、动态明细、replaced 抑制集与 cause 展开。
	cause := errors.New("peer reset")
	withCause := WrapSentinelDetail(facade, cause, "remote-err\xff", srcSentinel)
	if !errors.Is(withCause, facade) || !errors.Is(withCause, cause) || errors.Is(withCause, srcSentinel) {
		t.Fatal("WrapSentinelDetail errors.Is 语义异常")
	}
	if got := withCause.Error(); got != "permission denied: remote-err\uFFFD: peer reset" {
		t.Fatalf("WrapSentinelDetail 规范渲染异常: got=%q", got)
	}
	zhRendered := RenderErrorChain(withCause, ErrorRenderHooks{
		RenderMessage: func(m Message) string {
			if m.ID() == KeyCommonPermissionDeny {
				return "权限不足"
			}
			return m.Canonical()
		},
		JoinCausal: func(head, tail string) string { return head + "：" + tail },
	})
	if zhRendered != "权限不足：remote-err\uFFFD：peer reset" {
		t.Fatalf("WrapSentinelDetail 本地化渲染未保留哨兵头段: got=%q", zhRendered)
	}
	// 2. 折叠被 replaced 抑制的同义源哨兵；空串/纯空白/超长空白明细退化为 WrapSentinel。
	if got := WrapSentinelDetail(facade, srcSentinel, "ctx-info", srcSentinel).Error(); got != "permission denied: ctx-info" {
		t.Fatalf("WrapSentinelDetail 抑制源哨兵异常: got=%q", got)
	}
	for _, blank := range []string{"", "  \t\n ", strings.Repeat(" ", MaxParamStringBytes+8) + "tail"} {
		deg := WrapSentinelDetail(facade, srcSentinel, blank, srcSentinel)
		if !errors.Is(deg, facade) || deg.Error() != "permission denied" {
			t.Fatalf("WrapSentinelDetail 空白退化异常 (len=%d): got=%q", len(blank), deg.Error())
		}
	}
	if degNil := WrapSentinelDetail(nil, nil, "   "); degNil == nil || degNil.Error() != "invalid argument" {
		t.Fatalf("WrapSentinelDetail(nil, nil, blank) 应退化为 KeyCommonInvalidArgument: %v", degNil)
	}
}

func assertDynamicDetailErrorBehavior(t *testing.T) {
	t.Helper()
	// DynamicDetailError 有界 UTF-8 叶子与空白安全降级。
	dyn := DynamicDetailError("remote\xff" + strings.Repeat("a", MaxParamStringBytes+32))
	view, ok := InspectNode(dyn)
	if !ok || view.Sentinel != nil || view.Cause != nil || view.IsSentinel || view.Message.ID() != KeyCommonDetail {
		t.Fatalf("DynamicDetailError 视图异常: ok=%v view=%+v", ok, view)
	}
	if len(dyn.Error()) > MaxParamStringBytes || !strings.HasPrefix(dyn.Error(), "remote\uFFFD") {
		t.Fatalf("DynamicDetailError 裁剪/净化异常: len=%d", len(dyn.Error()))
	}
	for _, blank := range []string{"", " \t\r\n ", strings.Repeat(" ", MaxParamStringBytes+8) + "x"} {
		fb := DynamicDetailError(blank)
		if id, found := ErrorID(fb); !found || id != KeyCommonInternalError || fb.Error() != "internal error" {
			t.Fatalf("DynamicDetailError 空白降级异常: id=%q err=%q", id, fb.Error())
		}
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

	joined := errors.Join(errors.New("plain"), NewErrorWithFallback(nil, nil, MessageID("root.custom"), "custom {k}", Str("k", "v")))
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
	if NewErrorWithFallback(nil, nil, MessageID("root.e"), "e {x}", Int("x", 3)).Error() != "e 3" {
		t.Fatal("NewErrorWithFallback(nil, nil) 文本异常")
	}
	if NewErrorWithFallback(ErrInvalidParam, nil, MessageID("root.ef"), "ef {x}", Int("x", 7)).Error() != "ef 7" {
		t.Fatal("NewErrorWithFallback(sentinel, nil) 文本异常")
	}
	if NewErrorWithFallback(nil, errors.New("c"), MessageID("root.w"), "w").Error() != "w: c" {
		t.Fatal("NewErrorWithFallback(nil, cause) 文本异常")
	}
	ws := NewErrorWithFallback(ErrInvalidParam, errors.New("c"), MessageID("root.ws"), "ws")
	if !errors.Is(ws, ErrInvalidParam) || ws.Error() != "ws: c" {
		t.Fatalf("NewErrorWithFallback(sentinel, cause) 异常: err=%q", ws.Error())
	}
	if E(MessageIDInvalid) == nil || WrapSentinel(nil, nil) == nil {
		t.Fatal("错误构造器在非法输入下亦绝不能返回 nil")
	}
	assertDegradedSentinelIsolation(t)
	assertEnsureErrorMessageSalvage(t)
}

func assertDegradedSentinelIsolation(t *testing.T) {
	t.Helper()
	validInvalidArg := Sentinel(KeyCommonInvalidArgument)
	degradedEmpty := SentinelWithFallback(MessageIDInvalid, "")
	degradedBad := SentinelWithFallback(MessageID("BadID"), "oops")
	for name, err := range map[string]error{"empty": degradedEmpty, "bad": degradedBad} {
		view, ok := InspectNode(err)
		if !ok || view.IsSentinel || view.Message.ID() != KeyCommonInvalidArgument {
			t.Fatalf("退化哨兵 %s 视图异常: ok=%v view=%+v", name, ok, view)
		}
		if errors.Is(err, validInvalidArg) || errors.Is(validInvalidArg, err) {
			t.Fatalf("退化哨兵 %s 不得与合法 Sentinel(KeyCommonInvalidArgument) 假阳性匹配", name)
		}
	}
	if errors.Is(degradedEmpty, degradedBad) {
		t.Fatal("两个不同退化哨兵实例不得互相 errors.Is 匹配")
	}
	// 合法 ID 即使 fallback 含非法 UTF-8 经净化后仍应保留 isSentinel=true。
	sanitized := SentinelWithFallback(MessageID("root.sanitized"), "bad\xfftext")
	if sv, ok := InspectNode(sanitized); !ok || !sv.IsSentinel || sanitized.Error() != "bad\uFFFDtext" {
		t.Fatalf("合法 ID 净化兜底应保持哨兵语义: ok=%v view=%+v err=%q", ok, sv, sanitized.Error())
	}
}

func assertEnsureErrorMessageSalvage(t *testing.T) {
	t.Helper()
	// 单参超长/非法 UTF-8 时保留其余合法参数，并对缺失占位符回填 "<invalid>"（零 {key} 裸露）。
	oversized := strings.Repeat("x", MaxParamStringBytes+10)
	err := NewErrorWithFallback(
		nil, nil,
		MessageID("test.salvage"),
		"host={host} path={path} port={port}",
		Str("host", "web-1"),
		Str("path", oversized),
		Int("port", 22),
	)
	if got := err.Error(); got != "host=web-1 path=<invalid> port=22" {
		t.Fatalf("部分参数保留与占位符回填异常: got=%q", got)
	}
	if strings.Contains(err.Error(), "{path}") {
		t.Fatalf("降级错误不得裸露原始占位符: got=%q", err.Error())
	}

	// 重复参数键时保留首个有效值及兄弟参数，并回填缺失占位符。
	dupErr := NewErrorWithFallback(
		nil, nil,
		MessageID("test.dup"),
		"a={a} b={b} c={c}",
		Str("a", "first"),
		Str("a", "second"),
		Str("b", "\xff"),
		Int("c", 9),
	)
	if got := dupErr.Error(); got != "a=first b=<invalid> c=9" {
		t.Fatalf("重复/非法参数抢救异常: got=%q", got)
	}

	// 超过 MaxMessageParams 时裁剪保留前 MaxMessageParams 个有效唯一参数且不 panic。
	tooMany := make([]Param, MaxMessageParams+3)
	for i := range tooMany {
		tooMany[i] = Int("k"+string(rune('a'+i)), i)
	}
	excessErr := NewErrorWithFallback(nil, nil, MessageID("test.excess"), "first={ka} last={kp}", tooMany...)
	if got := excessErr.Error(); got != "first=0 last=15" {
		t.Fatalf("超限参数抢救异常: got=%q", got)
	}

	// fallback 含非法 UTF-8 或超长且伴随非法参数时仍可安全净化并回填；畸形模板语法亦保留合法参数且不 panic。
	badFB := NewErrorWithFallback(nil, nil, MessageID("test.badfb"), "bad\xff {key}", Str("key", "\xff"))
	if got := badFB.Error(); got != "bad\uFFFD <invalid>" {
		t.Fatalf("非法 UTF-8 fallback 净化异常: got=%q", got)
	}
	longFB := NewErrorWithFallback(nil, nil, MessageID("test.longfb"), strings.Repeat("a", MaxTemplateBytes+32))
	if got := longFB.Error(); len(got) != MaxTemplateBytes {
		t.Fatalf("超长 fallback 应裁剪至 MaxTemplateBytes: len=%d", len(got))
	}
	malformedFB := NewErrorWithFallback(nil, nil, MessageID("test.malformed"), "ok={ok} {unclosed", Str("ok", "yes"), Str("bad", "\xff"))
	if got := malformedFB.Error(); got != "ok=yes {unclosed" {
		t.Fatalf("畸形模板语法降级应保留有效参数: got=%q", got)
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
		`{"key":"k","kind":"string","str":"v","int64":null}`,
		`{"key":"k","kind":"string","str":null}`,
		`{"key":"k","kind":"string","str":"v","message":null}`,
		`{"key":"k","kind":"string","str":"v","prec":2}`,
		`{"key":"k","kind":"float64","float64":1.5,"prec":null}`,
		`{"key":null,"kind":"string","str":"v"}`,
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
		`{"id":null}`,
		`{"id":"common.not_found","count":null}`,
		`{"id":"common.not_found","params":null}`,
		`{"id":"common.not_found","fallback":null}`,
		`{"id":"common.not_found","params":[null]}`,
		`{"id":"common.not_found","params":[{"key":"k","kind":"string","str":"ok","bool":null}]}`,
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
