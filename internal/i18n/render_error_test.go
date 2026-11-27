package i18n

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/conc"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

type customLocalizableError struct {
	sentinel error
	msg      domi18n.Message
	cause    error
}

func (e *customLocalizableError) Error() string {
	if e.cause != nil {
		return e.msg.Canonical() + ": " + e.cause.Error()
	}
	return e.msg.Canonical()
}

func (e *customLocalizableError) Unwrap() []error {
	var out []error
	if e.sentinel != nil {
		out = append(out, e.sentinel)
	}
	if e.cause != nil {
		out = append(out, e.cause)
	}
	return out
}

func (e *customLocalizableError) LocalizableView() domi18n.ErrorNode {
	return domi18n.ErrorNode{
		Sentinel: e.sentinel,
		Message:  e.msg,
		Cause:    e.cause,
	}
}

type rawWrapperError struct {
	prefix string
	inner  error
}

func (e *rawWrapperError) Error() string {
	return e.prefix + ": " + e.inner.Error()
}

func (e *rawWrapperError) Unwrap() error {
	return e.inner
}

type cyclicError struct {
	next error
}

func (e *cyclicError) Error() string { return "cyclic-error" }
func (e *cyclicError) LocalizableView() domi18n.ErrorNode {
	return domi18n.ErrorNode{
		Message: domi18n.NewMessage(domi18n.KeyCommonInternalError),
		Cause:   e.next,
	}
}

func mustLoadBilingualLocalizers(t *testing.T) (enLoc, zhLoc *Localizer) {
	t.Helper()
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() 失败: %v", err)
	}
	return cat.For(domi18n.LocaleEn), cat.For(domi18n.LocaleZh)
}

func TestRenderErrorNestedAndYAMLJoin(t *testing.T) {
	enLoc, zhLoc := mustLoadBilingualLocalizers(t)

	rawLeaf := errors.New("connection reset by peer")
	inner := domi18n.Wrap(rawLeaf, domi18n.KeyCommonTimeout)
	outer := Wrap(inner, KeyCatalogLoadFailed, domi18n.Str("file", "nodes.yaml"))

	wantEn := "i18n: failed to load catalog file nodes.yaml: operation timed out: connection reset by peer"
	wantZh := "加载国际化词库文件 nodes.yaml 失败：操作超时：connection reset by peer"
	if got := enLoc.RenderError(outer); got != wantEn {
		t.Fatalf("en RenderError = %q, 期望 %q", got, wantEn)
	}
	if got := zhLoc.RenderError(outer); got != wantZh {
		t.Fatalf("zh RenderError = %q, 期望 %q", got, wantZh)
	}
}

func TestRenderErrorSuppressInnerIDAndDedup(t *testing.T) {
	enLoc, zhLoc := mustLoadBilingualLocalizers(t)

	assertWrapSentinelSuppression(t, enLoc, zhLoc)
	assertAdjacentDedupWithoutPrefixHack(t, enLoc, zhLoc)
}

func assertWrapSentinelSuppression(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()
	facade := domi18n.Sentinel(domi18n.KeyCommonNotFound)
	innerDiffSentinel := Sentinel(KeyCatalogCorrupt)

	// 1. 门面哨兵包装不同文案的底层哨兵：应折叠紧邻同义内层哨兵，仅渲染门面哨兵。
	mappedBare := domi18n.WrapSentinel(facade, innerDiffSentinel)
	if got := enLoc.RenderError(mappedBare); got != "resource not found" {
		t.Fatalf("en WrapSentinel(bare) = %q", got)
	}
	if got := zhLoc.RenderError(mappedBare); got != "资源不存在" {
		t.Fatalf("zh WrapSentinel(bare) = %q", got)
	}

	// 2. 门面哨兵包装带参数明细的 EF：保留明细，不误删业务上下文。
	detail := EF(innerDiffSentinel, KeyCatalogLoadFailed, domi18n.Str("file", "hosts.yaml"))
	mappedDetail := domi18n.WrapSentinel(facade, detail)
	if got := zhLoc.RenderError(mappedDetail); got != "资源不存在：加载国际化词库文件 hosts.yaml 失败" {
		t.Fatalf("zh WrapSentinel(detail) = %q", got)
	}

	// 3. 双层 WrapSentinel 串联：跳过中间门面哨兵，保留底层参数化明细。
	outerFacade := domi18n.Sentinel(domi18n.KeyCommonPermissionDeny)
	doubleMapped := domi18n.WrapSentinel(outerFacade, mappedDetail)
	if got := zhLoc.RenderError(doubleMapped); got != "权限不足：加载国际化词库文件 hosts.yaml 失败" {
		t.Fatalf("zh double WrapSentinel = %q", got)
	}

	// 4. 门面哨兵包装 context.Canceled 叶子哨兵：跳过紧邻内层哨兵。
	mappedCancel := domi18n.WrapSentinel(domi18n.Sentinel(domi18n.KeyCommonCanceled), context.Canceled)
	if got := zhLoc.RenderError(mappedCancel); got != "操作已取消" {
		t.Fatalf("zh WrapSentinel(context.Canceled) = %q", got)
	}

	// 5. 门面哨兵包装裸第三方错误：保留底层原文技术细节。
	mappedRaw := domi18n.WrapSentinel(facade, errors.New("enoent"))
	if got := zhLoc.RenderError(mappedRaw); got != "资源不存在：enoent" {
		t.Fatalf("zh WrapSentinel(raw) = %q", got)
	}
}

func assertAdjacentDedupWithoutPrefixHack(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()
	// 相同渲染文本的相邻段应确定性折叠，即使后接底层原文叶子。
	dupChain := domi18n.Wrap(
		domi18n.Wrap(errors.New("i/o timeout"), domi18n.KeyCommonTimeout),
		domi18n.KeyCommonTimeout,
	)
	if got := enLoc.RenderError(dupChain); got != "operation timed out: i/o timeout" {
		t.Fatalf("en 相邻去重失败: %q", got)
	}
	if got := zhLoc.RenderError(dupChain); got != "操作超时：i/o timeout" {
		t.Fatalf("zh 相邻去重失败: %q", got)
	}

	// 仅前缀相似但不完全相等的两段严禁误删（杜绝脆弱子串前缀匹配）。
	prefixSimilar := domi18n.Wrap(
		domi18n.E(domi18n.KeyLocaleInvalidValue, domi18n.Str("value", "fr")),
		domi18n.KeyLocaleInvalid,
	)
	if got := enLoc.RenderError(prefixSimilar); got != "i18n: invalid locale: i18n: invalid locale fr" {
		t.Fatalf("前缀相似的非重复段被误折叠: %q", got)
	}
	if got := zhLoc.RenderError(prefixSimilar); got != "无效的语言标识：无效的语言标识：fr" {
		t.Fatalf("zh 前缀相似的非重复段被误折叠: %q", got)
	}
}

func TestRenderErrorStdAndConcSentinels(t *testing.T) {
	enLoc, zhLoc := mustLoadBilingualLocalizers(t)

	cases := []struct {
		name   string
		err    error
		wantEn string
		wantZh string
	}{
		{"context.Canceled", context.Canceled, "context canceled", "上下文已取消"},
		{"context.DeadlineExceeded", context.DeadlineExceeded, "context deadline exceeded", "上下文已超时"},
		{"conc.ErrNurseryNotInitialized", conc.ErrNurseryNotInitialized, "conc: nursery is not initialized", "并发作用域 Nursery 未初始化"},
		{"conc.ErrNurseryClosed", conc.ErrNurseryClosed, "conc: nursery is closed or waiting and rejects new tasks", "并发作用域 Nursery 已关闭或正在等待退出，拒绝新增任务"},
		{"conc.ErrNilTask", conc.ErrNilTask, "conc: task callback must not be nil", "并发任务回调不能为空"},
		{"conc.ErrTaskPanicked", conc.ErrTaskPanicked, "conc: supervised goroutine panicked", "受监督并发协程发生 panic"},
		{"conc.ErrMutexNotInitialized", conc.ErrMutexNotInitialized, "conc: CtxMutex is not initialized", "可取消互斥锁 CtxMutex 未初始化"},
		{"conc.ErrNilContext", conc.ErrNilContext, "conc: context must not be nil", "并发操作上下文不能为空"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := enLoc.RenderError(tc.err); got != tc.wantEn {
				t.Fatalf("en RenderError(%s) = %q, 期望 %q", tc.name, got, tc.wantEn)
			}
			if got := zhLoc.RenderError(tc.err); got != tc.wantZh {
				t.Fatalf("zh RenderError(%s) = %q, 期望 %q", tc.name, got, tc.wantZh)
			}
		})
	}
}

func TestRenderErrorConcPanicAndJoinAndCustomNode(t *testing.T) {
	enLoc, zhLoc := mustLoadBilingualLocalizers(t)

	assertConcPanicRendering(t, enLoc, zhLoc)
	assertJoinTreeAndCustomNode(t, enLoc, zhLoc)
	assertDepthLimitSafety(t, zhLoc)
}

func assertConcPanicRendering(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()
	panicErr := conc.RunWait(context.Background(), func(_ context.Context, _ *conc.Nursery) error {
		panic("boom")
	})
	if panicErr == nil {
		t.Fatal("预期 conc.RunWait 捕获 panic")
	}

	// Nursery 返回 errors.Join(*conc.PanicError)，应穿透单元素 Join 并本地化 *conc.PanicError。
	if got := enLoc.RenderError(panicErr); got != "conc: supervised goroutine panicked: boom" {
		t.Fatalf("en PanicError RenderError = %q", got)
	}
	if got := zhLoc.RenderError(panicErr); got != "受监督并发协程发生 panic：boom" {
		t.Fatalf("zh PanicError RenderError = %q", got)
	}

	wrappedPanic := domi18n.Wrap(panicErr, domi18n.KeyCommonInternalError)
	if got := zhLoc.RenderError(wrappedPanic); got != "内部错误：受监督并发协程发生 panic：boom" {
		t.Fatalf("zh Wrap(PanicError) RenderError = %q", got)
	}

	// 非 LocalizableNode 的第三方外层包装应保留外层技术文本，不误删外层上下文。
	rawOuter := &rawWrapperError{prefix: "thirdparty", inner: panicErr}
	if got := zhLoc.RenderError(rawOuter); !strings.HasPrefix(got, "thirdparty: ") {
		t.Fatalf("第三方外层包装应保留前缀上下文: %q", got)
	}
}

func assertJoinTreeAndCustomNode(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()
	custom := &customLocalizableError{
		sentinel: ErrCatalogCorrupt,
		msg:      NewMessage(KeyCatalogMissingKey, domi18n.Str("key", "app.title"), domi18n.Str("locale", "zh")),
		cause:    errors.New("disk read fault"),
	}
	if got := enLoc.RenderError(custom); got != "i18n: missing message key app.title in locale zh: disk read fault" {
		t.Fatalf("en custom LocalizableNode = %q", got)
	}
	if got := zhLoc.RenderError(custom); got != "语言 zh 的国际化词库缺少消息键 app.title：disk read fault" {
		t.Fatalf("zh custom LocalizableNode = %q", got)
	}

	joined := errors.Join(
		domi18n.E(domi18n.KeyCommonTimeout),
		errors.Join(context.Canceled, conc.ErrNilTask),
		custom,
	)
	wantZh := strings.Join([]string{
		"操作超时",
		"上下文已取消",
		"并发任务回调不能为空",
		"语言 zh 的国际化词库缺少消息键 app.title：disk read fault",
	}, "\n")
	if got := zhLoc.RenderError(joined); got != wantZh {
		t.Fatalf("zh errors.Join 树渲染异常:\ngot:\n%s\nwant:\n%s", got, wantZh)
	}

	wrappedJoin := Wrap(errors.Join(context.Canceled, context.DeadlineExceeded), KeyCatalogLoadFailed, domi18n.Str("file", "zh.yaml"))
	if got := zhLoc.RenderError(wrappedJoin); got != "加载国际化词库文件 zh.yaml 失败：上下文已取消\n上下文已超时" {
		t.Fatalf("zh Wrap(errors.Join) 渲染异常: %q", got)
	}
}

func assertDepthLimitSafety(t *testing.T, zhLoc *Localizer) {
	t.Helper()
	c := &cyclicError{}
	c.next = c
	got := zhLoc.RenderError(c)
	if !strings.Contains(got, "内部错误") || !strings.Contains(got, "cyclic-error") {
		t.Fatalf("循环错误链应受深度上限保护且安全收敛: %q", got)
	}
}
