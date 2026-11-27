package i18n

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/conc"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

type customLocalizableError struct {
	sentinel   error
	msg        domi18n.Message
	cause      error
	suppressed []error
}

func (e *customLocalizableError) Error() string { return domi18n.CanonicalError(e) }

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
		Sentinel:            e.sentinel,
		Message:             e.msg,
		Cause:               e.cause,
		SuppressedSentinels: e.suppressed,
	}
}

type rawWrapperError struct {
	prefix string
	inner  error
}

func (e *rawWrapperError) Error() string { return e.prefix + ": " + e.inner.Error() }
func (e *rawWrapperError) Unwrap() error { return e.inner }

type customIsLeafError struct {
	target error
	detail string
}

func (e customIsLeafError) Error() string        { return e.detail }
func (e customIsLeafError) Is(target error) bool { return target == e.target }

type cyclicLocalizableError struct {
	sentinel error
	msg      domi18n.Message
	cause    error
}

func (e *cyclicLocalizableError) Error() string { return domi18n.CanonicalError(e) }
func (e *cyclicLocalizableError) LocalizableView() domi18n.ErrorNode {
	return domi18n.ErrorNode{Sentinel: e.sentinel, Message: e.msg, Cause: e.cause}
}

func mustLoadBilingualLocalizers(t *testing.T) (enLoc, zhLoc *Localizer) {
	t.Helper()
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() 失败: %v", err)
	}
	return cat.For(domi18n.LocaleEn), cat.For(domi18n.LocaleZh)
}

func assertCanonicalParity(t *testing.T, enLoc *Localizer, err error, wantEn string) {
	t.Helper()
	gotEn := enLoc.RenderError(err)
	raw := err.Error()
	if gotEn != wantEn {
		t.Fatalf("en RenderError = %q, 期望 %q", gotEn, wantEn)
	}
	if gotEn != raw {
		t.Fatalf("enLoc.RenderError(err) 与 err.Error() 不等价:\nRenderError: %q\nerr.Error(): %q", gotEn, raw)
	}
}

func assertBilingualParity(t *testing.T, enLoc, zhLoc *Localizer, err error, wantEn, wantZh string) {
	t.Helper()
	assertCanonicalParity(t, enLoc, err, wantEn)
	if gotZh := zhLoc.RenderError(err); gotZh != wantZh {
		t.Fatalf("zh RenderError = %q, 期望 %q", gotZh, wantZh)
	}
}

func TestRenderErrorNestedAndAdjacentDedup(t *testing.T) {
	enLoc, zhLoc := mustLoadBilingualLocalizers(t)

	outer := Wrap(domi18n.Wrap(errors.New("connection reset by peer"), domi18n.KeyCommonTimeout), KeyCatalogLoadFailed, Str("file", "nodes.yaml"))
	assertBilingualParity(t, enLoc, zhLoc, outer,
		"i18n: failed to load catalog file nodes.yaml: operation timed out: connection reset by peer",
		"加载国际化词库文件 nodes.yaml 失败：操作超时：connection reset by peer",
	)

	// 相同渲染文本的相邻段应确定性折叠，后接底层原文叶子不受影响。
	dupChain := domi18n.Wrap(domi18n.Wrap(errors.New("i/o timeout"), domi18n.KeyCommonTimeout), domi18n.KeyCommonTimeout)
	assertBilingualParity(t, enLoc, zhLoc, dupChain, "operation timed out: i/o timeout", "操作超时：i/o timeout")

	// 仅前缀相似但不完全相等的两段严禁误折叠（杜绝脆弱前缀子串截断）。
	prefixSimilar := domi18n.Wrap(domi18n.E(domi18n.KeyLocaleInvalidValue, Str("value", "fr")), domi18n.KeyLocaleInvalid)
	assertBilingualParity(t, enLoc, zhLoc, prefixSimilar,
		"i18n: invalid locale: i18n: invalid locale fr",
		"无效的语言标识：无效的语言标识：fr",
	)
}

func TestRenderErrorUnifiedAlgebraTopologies(t *testing.T) {
	enLoc, zhLoc := mustLoadBilingualLocalizers(t)

	assertMultiSentinelAndNormalization(t, enLoc, zhLoc)
	assertJoinedBranchesAndSiblingIsolation(t, enLoc, zhLoc)
	assertTransitiveAndNoReplacedIsolation(t, enLoc, zhLoc)
}

func assertMultiSentinelAndNormalization(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()
	pubNotFound := domi18n.Sentinel(domi18n.KeyCommonNotFound)
	pubPerm := domi18n.Sentinel(domi18n.KeyCommonPermissionDeny)
	srcCorrupt := Sentinel(KeyCatalogCorrupt)
	srcEmpty := Sentinel(KeyCatalogEmptyEntry)
	srcMissingOther := Sentinel(KeyCatalogMissingOther)
	unattached := Sentinel(KeyCatalogInvalidEntryNode)

	// 1. 模拟 engine.mapEngineError 多哨兵映射链：双门面均保留，双源哨兵折叠，且 SuppressedSentinels 不污染 errors.Is。
	mappedDual := domi18n.WrapSentinel(
		pubNotFound,
		domi18n.WrapSentinel(pubPerm, errors.Join(srcCorrupt, srcEmpty), srcEmpty, unattached),
		srcCorrupt,
	)
	if !errors.Is(mappedDual, pubNotFound) || !errors.Is(mappedDual, pubPerm) ||
		!errors.Is(mappedDual, srcCorrupt) || !errors.Is(mappedDual, srcEmpty) {
		t.Fatal("多哨兵链应保留全部门面与底层原因 errors.Is 语义")
	}
	if errors.Is(mappedDual, unattached) {
		t.Fatal("SuppressedSentinels 不得经 Unwrap 暴露导致 errors.Is 假阳性")
	}
	assertBilingualParity(t, enLoc, zhLoc, mappedDual, "resource not found: permission denied", "资源不存在：权限不足")

	// 2. 多源归一：同一门面替代多个同义源哨兵 {srcCorrupt, srcMissingOther} -> pubNotFound。
	multiSrc := domi18n.WrapSentinel(pubNotFound, errors.Join(srcCorrupt, srcMissingOther), srcCorrupt, srcMissingOther)
	assertBilingualParity(t, enLoc, zhLoc, multiSrc, "resource not found", "资源不存在")

	// 3. 中间 usecase.Wrap 穿透传播 SuppressedSentinels：上下文完整保留且尾部源哨兵零复读。
	facadeWrapped := domi18n.WrapSentinel(pubNotFound, Wrap(srcCorrupt, KeyCatalogLoadFailed, Str("file", "hosts.yaml")), srcCorrupt)
	assertBilingualParity(t, enLoc, zhLoc, facadeWrapped,
		"resource not found: i18n: failed to load catalog file hosts.yaml",
		"资源不存在：加载国际化词库文件 hosts.yaml 失败",
	)
}

func assertJoinedBranchesAndSiblingIsolation(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()
	pubNotFound := domi18n.Sentinel(domi18n.KeyCommonNotFound)
	pubPerm := domi18n.Sentinel(domi18n.KeyCommonPermissionDeny)
	srcCorrupt := Sentinel(KeyCatalogCorrupt)
	srcEmpty := Sentinel(KeyCatalogEmptyEntry)

	// 4a. errors.Join 混合已映射源哨兵、带上下文包装与未映射 context.DeadlineExceeded：完全等价且未映射分支保留。
	mixedStd := errors.Join(srcCorrupt, Wrap(srcEmpty, KeyCatalogLoadFailed, Str("file", "nodes.yaml")), context.DeadlineExceeded)
	mappedStd := domi18n.WrapSentinel(pubNotFound, domi18n.WrapSentinel(pubPerm, mixedStd, srcEmpty), srcCorrupt)
	assertBilingualParity(t, enLoc, zhLoc, mappedStd,
		"resource not found: permission denied: i18n: failed to load catalog file nodes.yaml\ncontext deadline exceeded",
		"资源不存在：权限不足：加载国际化词库文件 nodes.yaml 失败\n上下文已超时",
	)

	// 4b. errors.Join 混合已映射源哨兵与未映射 conc.ErrNilTask：已映射源省略，未映射 conc.ErrNilTask 双语保留。
	mappedConc := domi18n.WrapSentinel(pubNotFound, errors.Join(srcCorrupt, context.DeadlineExceeded, conc.ErrNilTask), srcCorrupt)
	if got := enLoc.RenderError(mappedConc); got != "resource not found: context deadline exceeded\nconc: task callback must not be nil" {
		t.Fatalf("en mixed Join(conc.ErrNilTask) = %q", got)
	}
	if got := zhLoc.RenderError(mappedConc); got != "资源不存在：上下文已超时\n并发任务回调不能为空" {
		t.Fatalf("zh mixed Join(conc.ErrNilTask) = %q", got)
	}
	singleSurvivor := domi18n.WrapSentinel(pubNotFound, errors.Join(srcCorrupt, conc.ErrNilTask), srcCorrupt)
	if got := enLoc.RenderError(singleSurvivor); got != "resource not found: conc: task callback must not be nil" {
		t.Fatalf("en single-survivor Join(conc.ErrNilTask) = %q", got)
	}
	if got := zhLoc.RenderError(singleSurvivor); got != "资源不存在：并发任务回调不能为空" {
		t.Fatalf("zh single-survivor Join(conc.ErrNilTask) = %q", got)
	}

	// 4c. errors.Join 兄弟分支隔离：分支 0 登记的抑制集不得串扰分支 1。
	siblingJoin := errors.Join(domi18n.WrapSentinel(pubNotFound, srcCorrupt, srcCorrupt, srcEmpty), srcEmpty)
	assertBilingualParity(t, enLoc, zhLoc, siblingJoin,
		"resource not found\ni18n: catalog entry template must not be empty",
		"资源不存在\n国际化词库条目模板不能为空",
	)
}

func assertTransitiveAndNoReplacedIsolation(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()
	s1 := domi18n.Sentinel(domi18n.KeyCommonPermissionDeny)
	s2 := domi18n.Sentinel(domi18n.KeyCommonNotFound)
	s3 := Sentinel(KeyCatalogCorrupt)

	// 5. 三层传递映射 s1 -> s2 -> s3（含裸链与跨中间上下文包装）。
	assertBilingualParity(t, enLoc, zhLoc, domi18n.WrapSentinel(s1, domi18n.WrapSentinel(s2, s3, s3), s2), "permission denied", "权限不足")

	transCtx := domi18n.WrapSentinel(s1, domi18n.WrapSentinel(s2, Wrap(s3, KeyCatalogLoadFailed, Str("file", "zh.yaml")), s3), s2)
	assertBilingualParity(t, enLoc, zhLoc, transCtx,
		"permission denied: i18n: failed to load catalog file zh.yaml",
		"权限不足：加载国际化词库文件 zh.yaml 失败",
	)

	// 6. 未传 replaced 的 WrapSentinel(pub, otherSentinel) 绝不盲目吞噬异类哨兵；
	//    仅对同门面自身沿因果链去重，并保留原始底层错误详情。
	assertBilingualParity(t, enLoc, zhLoc, domi18n.WrapSentinel(s1, s3),
		"permission denied: i18n: catalog data is corrupt",
		"权限不足：国际化词库数据损坏",
	)
	assertBilingualParity(t, enLoc, zhLoc, domi18n.WrapSentinel(s1, Wrap(s1, KeyCatalogLoadFailed, Str("file", "a.yaml"))),
		"permission denied: i18n: failed to load catalog file a.yaml",
		"权限不足：加载国际化词库文件 a.yaml 失败",
	)
	assertBilingualParity(t, enLoc, zhLoc, domi18n.WrapSentinel(s2, errors.New("enoent")),
		"resource not found: enoent",
		"资源不存在：enoent",
	)
}

func TestRenderErrorStdConcSentinelsAndExactLeaf(t *testing.T) {
	enLoc, zhLoc := mustLoadBilingualLocalizers(t)

	cases := []struct {
		name        string
		err         error
		wantEn      string
		wantZh      string
		checkParity bool
	}{
		{"context.Canceled", context.Canceled, "context canceled", "上下文已取消", true},
		{"context.DeadlineExceeded", context.DeadlineExceeded, "context deadline exceeded", "上下文已超时", true},
		{"conc.ErrNurseryNotInitialized", conc.ErrNurseryNotInitialized, "conc: nursery is not initialized", "并发作用域 Nursery 未初始化", false},
		{"conc.ErrNurseryClosed", conc.ErrNurseryClosed, "conc: nursery is closed or waiting and rejects new tasks", "并发作用域 Nursery 已关闭或正在等待退出，拒绝新增任务", false},
		{"conc.ErrNilTask", conc.ErrNilTask, "conc: task callback must not be nil", "并发任务回调不能为空", false},
		{"conc.ErrTaskPanicked", conc.ErrTaskPanicked, "conc: supervised goroutine panicked", "受监督并发协程发生 panic", false},
		{"conc.ErrMutexNotInitialized", conc.ErrMutexNotInitialized, "conc: CtxMutex is not initialized", "可取消互斥锁 CtxMutex 未初始化", false},
		{"conc.ErrNilContext", conc.ErrNilContext, "conc: context must not be nil", "并发操作上下文不能为空", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.checkParity {
				assertBilingualParity(t, enLoc, zhLoc, tc.err, tc.wantEn, tc.wantZh)
				return
			}
			if got := enLoc.RenderError(tc.err); got != tc.wantEn {
				t.Fatalf("en RenderError(%s) = %q, 期望 %q", tc.name, got, tc.wantEn)
			}
			if got := zhLoc.RenderError(tc.err); got != tc.wantZh {
				t.Fatalf("zh RenderError(%s) = %q, 期望 %q", tc.name, got, tc.wantZh)
			}
		})
	}

	assertExactLeafContract(t, enLoc, zhLoc)
}

func assertExactLeafContract(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()
	canceledFacade := domi18n.Sentinel(domi18n.KeyCommonCanceled)
	internalFacade := domi18n.Sentinel(domi18n.KeyCommonInternalError)

	// 裸 context.Canceled 在 replaced 包含自身时被精准折叠。
	assertBilingualParity(t, enLoc, zhLoc, domi18n.WrapSentinel(canceledFacade, context.Canceled, context.Canceled), "operation canceled", "操作已取消")

	// 7. CORE-2 精确叶子校验：实现 Is(context.Canceled) / Is(conc.ErrTaskPanicked) 但携带自定义错误文本的叶子绝不被覆写或吞噬。
	customCancel := customIsLeafError{target: context.Canceled, detail: "peer aborted stream"}
	assertBilingualParity(t, enLoc, zhLoc, customCancel, "peer aborted stream", "peer aborted stream")
	assertBilingualParity(t, enLoc, zhLoc, domi18n.WrapSentinel(canceledFacade, customCancel, context.Canceled),
		"operation canceled: peer aborted stream",
		"操作已取消：peer aborted stream",
	)

	customPanicLeaf := customIsLeafError{target: conc.ErrTaskPanicked, detail: "worker panic summary"}
	assertBilingualParity(t, enLoc, zhLoc, domi18n.WrapSentinel(internalFacade, customPanicLeaf, conc.ErrTaskPanicked),
		"internal error: worker panic summary",
		"内部错误：worker panic summary",
	)
}

func TestRenderErrorPanicCustomNodeAndCycles(t *testing.T) {
	enLoc, zhLoc := mustLoadBilingualLocalizers(t)

	assertNonNilPanicRendering(t, enLoc, zhLoc)
	assertTypedNilAndZeroPanicSuppression(t, enLoc, zhLoc)
	assertCustomNodeAndJoinTree(t, enLoc, zhLoc)
	assertCycleAndDepthSafety(t, enLoc, zhLoc)
}

func assertNonNilPanicRendering(t *testing.T, enLoc, zhLoc *Localizer) {
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

	// 携带非空值的 *conc.PanicError 永不受 SuppressedSentinels 抑制。
	suppressedNonNil := domi18n.WrapSentinel(domi18n.Sentinel(domi18n.KeyCommonInternalError), panicErr, conc.ErrTaskPanicked)
	if got := enLoc.RenderError(suppressedNonNil); got != "internal error: conc: supervised goroutine panicked: boom" {
		t.Fatalf("en 非空 *conc.PanicError 不得被抑制: %q", got)
	}
	if got := zhLoc.RenderError(suppressedNonNil); got != "内部错误：受监督并发协程发生 panic：boom" {
		t.Fatalf("zh 非空 *conc.PanicError 不得被抑制: %q", got)
	}

	// 超长且含非法 UTF-8 的 panic 值应经 BoundStr 确定性净化与裁剪且不泄露占位符。
	hugeInvalid := strings.Repeat("p", domi18n.MaxParamStringBytes+128) + string([]byte{0xff, 0xfe})
	hugePanic := conc.RunWait(context.Background(), func(_ context.Context, _ *conc.Nursery) error {
		panic(hugeInvalid)
	})
	gotHuge := zhLoc.RenderError(hugePanic)
	if !utf8.ValidString(gotHuge) || strings.Contains(gotHuge, "{value}") || !strings.HasPrefix(gotHuge, "受监督并发协程发生 panic：") {
		t.Fatalf("超长/非法 UTF-8 panic 渲染异常: len=%d valid=%v", len(gotHuge), utf8.ValidString(gotHuge))
	}

	// 非 LocalizableNode 的第三方外层包装应保留外层技术文本，不误删外层上下文。
	rawOuter := &rawWrapperError{prefix: "thirdparty", inner: panicErr}
	if got := zhLoc.RenderError(rawOuter); !strings.HasPrefix(got, "thirdparty: ") {
		t.Fatalf("第三方外层包装应保留前缀上下文: %q", got)
	}
}

func assertTypedNilAndZeroPanicSuppression(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()
	internalFacade := domi18n.Sentinel(domi18n.KeyCommonInternalError)
	var nilPanic *conc.PanicError
	var zeroPanic conc.PanicError

	// 未被抑制时，typed-nil 与零值 *conc.PanicError 均映射为 KeyConcTaskPanicked。
	for _, pe := range []error{nilPanic, &zeroPanic} {
		if got := enLoc.RenderError(pe); got != "conc: supervised goroutine panicked" {
			t.Fatalf("en 空值 *conc.PanicError = %q", got)
		}
		if got := zhLoc.RenderError(pe); got != "受监督并发协程发生 panic" {
			t.Fatalf("zh 空值 *conc.PanicError = %q", got)
		}
	}

	// 8. typed-nil 与零值 *conc.PanicError 严格遵守 SuppressedSentinels。
	assertBilingualParity(t, enLoc, zhLoc, domi18n.WrapSentinel(internalFacade, nilPanic, conc.ErrTaskPanicked), "internal error", "内部错误")
	suppressedZero := domi18n.WrapSentinel(internalFacade, &zeroPanic, conc.ErrTaskPanicked)
	if enLoc.RenderError(suppressedZero) != "internal error" || zhLoc.RenderError(suppressedZero) != "内部错误" {
		t.Fatalf("零值 *conc.PanicError 应遵守抑制集: en=%q zh=%q", enLoc.RenderError(suppressedZero), zhLoc.RenderError(suppressedZero))
	}

	// 当 SuppressedSentinels 不含 conc.ErrTaskPanicked 时不得误抑。
	unsuppressedNil := domi18n.WrapSentinel(internalFacade, nilPanic, domi18n.ErrInvalidParam)
	if enLoc.RenderError(unsuppressedNil) != "internal error: conc: supervised goroutine panicked" ||
		zhLoc.RenderError(unsuppressedNil) != "内部错误：受监督并发协程发生 panic" {
		t.Fatalf("未命中抑制集的 typed-nil PanicError 不得被吞噬: en=%q zh=%q", enLoc.RenderError(unsuppressedNil), zhLoc.RenderError(unsuppressedNil))
	}
}

func assertCustomNodeAndJoinTree(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()
	custom := &customLocalizableError{
		sentinel: ErrCatalogCorrupt,
		msg:      NewMessage(KeyCatalogMissingKey, Str("key", "app.title"), Str("locale", "zh")),
		cause:    errors.New("disk read fault"),
	}
	assertBilingualParity(t, enLoc, zhLoc, custom,
		"i18n: missing message key app.title in locale zh: disk read fault",
		"语言 zh 的国际化词库缺少消息键 app.title：disk read fault",
	)

	// 自定义节点自带 SuppressedSentinels 折叠默认占位哨兵（对齐 AuditPostWriteError 模式）。
	customFolded := &customLocalizableError{
		sentinel:   ErrCatalogCorrupt,
		msg:        NewMessage(KeyCatalogLoadFailed, Str("file", "zh.yaml")),
		cause:      ErrCatalogCorrupt,
		suppressed: []error{ErrCatalogCorrupt},
	}
	assertBilingualParity(t, enLoc, zhLoc, customFolded,
		"i18n: failed to load catalog file zh.yaml",
		"加载国际化词库文件 zh.yaml 失败",
	)

	joined := errors.Join(domi18n.E(domi18n.KeyCommonTimeout), errors.Join(context.Canceled, conc.ErrNilTask), custom)
	wantZh := strings.Join([]string{"操作超时", "上下文已取消", "并发任务回调不能为空", "语言 zh 的国际化词库缺少消息键 app.title：disk read fault"}, "\n")
	if got := zhLoc.RenderError(joined); got != wantZh {
		t.Fatalf("zh errors.Join 树渲染异常:\ngot:\n%s\nwant:\n%s", got, wantZh)
	}

	wrappedJoin := Wrap(errors.Join(context.Canceled, context.DeadlineExceeded), KeyCatalogLoadFailed, Str("file", "zh.yaml"))
	assertBilingualParity(t, enLoc, zhLoc, wrappedJoin,
		"i18n: failed to load catalog file zh.yaml: context canceled\ncontext deadline exceeded",
		"加载国际化词库文件 zh.yaml 失败：上下文已取消\n上下文已超时",
	)
}

func assertCycleAndDepthSafety(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()
	// 9a. 自环 LocalizableNode 绝不重入或爆栈，折叠重复段后确定性收敛。
	selfCycle := &cyclicLocalizableError{msg: domi18n.NewMessage(domi18n.KeyCommonInternalError)}
	selfCycle.cause = selfCycle
	assertBilingualParity(t, enLoc, zhLoc, selfCycle, "internal error", "内部错误")

	// 9b. 双节点互环 LocalizableNode 在深度与节点预算内安全终止且保持等价。
	nodeA := &cyclicLocalizableError{msg: domi18n.NewMessage(domi18n.KeyCommonNotFound)}
	nodeB := &cyclicLocalizableError{msg: domi18n.NewMessage(domi18n.KeyCommonPermissionDeny), cause: nodeA}
	nodeA.cause = nodeB
	gotMutualEn := enLoc.RenderError(nodeA)
	if !strings.HasPrefix(gotMutualEn, "resource not found: permission denied") || gotMutualEn != nodeA.Error() {
		t.Fatalf("互环 LocalizableNode 英文渲染或等价性异常: got=%q raw=%q", gotMutualEn, nodeA.Error())
	}
	if gotMutualZh := zhLoc.RenderError(nodeA); !strings.HasPrefix(gotMutualZh, "资源不存在：权限不足") {
		t.Fatalf("互环 LocalizableNode 中文渲染异常: %q", gotMutualZh)
	}

	// 9c. 二叉分支纯门面环路（sentinel==self && cause==self）瞬时安全收敛为空串。
	branchCycle := &cyclicLocalizableError{}
	branchCycle.sentinel = branchCycle
	branchCycle.cause = branchCycle
	assertBilingualParity(t, enLoc, zhLoc, branchCycle, "", "")

	// 9d. 超过深度上限（>64）的深链确定性截断且保持规范英文等价。
	deep := domi18n.Sentinel(domi18n.KeyCommonNotFound)
	for i := range 80 {
		if i%2 == 0 {
			deep = domi18n.Wrap(deep, domi18n.KeyCommonTimeout)
		} else {
			deep = domi18n.Wrap(deep, domi18n.KeyCommonPermissionDeny)
		}
	}
	if gotDeepEn := enLoc.RenderError(deep); gotDeepEn == "" || gotDeepEn != deep.Error() {
		t.Fatalf("超深链渲染或等价性异常: enLen=%d rawLen=%d", len(gotDeepEn), len(deep.Error()))
	}
	if gotDeepZh := zhLoc.RenderError(deep); !strings.HasPrefix(gotDeepZh, "权限不足：操作超时") {
		t.Fatalf("超深链中文渲染异常: %q", gotDeepZh)
	}
}
