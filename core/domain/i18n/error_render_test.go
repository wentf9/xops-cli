package i18n

import (
	"errors"
	"strings"
	"testing"
)

type customCanceledLeaf struct {
	target error
	detail string
}

func (c customCanceledLeaf) Error() string        { return c.detail }
func (c customCanceledLeaf) Is(target error) bool { return target == c.target }

type cyclicLocalizable struct {
	sentinel error
	msg      Message
	cause    error
}

func (c *cyclicLocalizable) Error() string { return CanonicalError(c) }
func (c *cyclicLocalizable) LocalizableView() ErrorNode {
	return ErrorNode{Sentinel: c.sentinel, Message: c.msg, Cause: c.cause}
}

type catchAllLeaf struct {
	detail string
}

func (c catchAllLeaf) Error() string { return c.detail }
func (c catchAllLeaf) Is(error) bool { return true }

type suppressedCustomNode struct {
	sentinel   error
	msg        Message
	cause      error
	suppressed []error
	isSentinel bool
}

func (s *suppressedCustomNode) Error() string { return CanonicalError(s) }
func (s *suppressedCustomNode) LocalizableView() ErrorNode {
	return ErrorNode{
		Sentinel:            s.sentinel,
		Message:             s.msg,
		Cause:               s.cause,
		SuppressedSentinels: s.suppressed,
		IsSentinel:          s.isSentinel,
	}
}

func TestRenderErrorChainMultiSentinelAndNormalization(t *testing.T) {
	portsNotFound := SentinelWithFallback(MessageID("ports.not_found"), "ports: not found")
	ucinvNotFound := SentinelWithFallback(MessageID("ucinv.asset_not_found"), "ucinv: asset not found")
	portsPerm := SentinelWithFallback(MessageID("ports.permission_denied"), "ports: permission denied")
	engNotFound := SentinelWithFallback(MessageID("engine.not_found"), "engine: resource not found")
	engPerm := SentinelWithFallback(MessageID("engine.permission_denied"), "engine: permission denied")
	unlinkedSrc := SentinelWithFallback(MessageID("ports.unrelated"), "ports: unrelated")

	// 1. 模拟 engine.mapEngineError 多哨兵链：双门面均保留，已替代双源裸哨兵折叠，未挂载的 replaced 不污染 errors.Is。
	joined := errors.Join(portsNotFound, portsPerm)
	mapped := WrapSentinel(
		engNotFound,
		WrapSentinel(engPerm, joined, portsPerm, unlinkedSrc),
		portsNotFound,
	)
	if !errors.Is(mapped, engNotFound) || !errors.Is(mapped, engPerm) || !errors.Is(mapped, portsNotFound) || !errors.Is(mapped, portsPerm) {
		t.Fatal("WrapSentinel 多哨兵链应完整保留全部门面与底层原因 errors.Is")
	}
	if errors.Is(mapped, unlinkedSrc) {
		t.Fatal("WrapSentinel.SuppressedSentinels 绝不得经 Unwrap 暴露导致 errors.Is 假阳性")
	}
	if len(UnwrapDirect(mapped)) != 2 {
		t.Fatalf("WrapSentinel.UnwrapDirect 应仅返回 [sentinel, cause], 实际=%d", len(UnwrapDirect(mapped)))
	}
	wantDual := "engine: resource not found: engine: permission denied"
	if got := mapped.Error(); got != wantDual || CanonicalError(mapped) != wantDual {
		t.Fatalf("多哨兵链折叠异常: got=%q, 期望 %q", got, wantDual)
	}

	// 2. 多源归一（{portsNotFound, ucinvNotFound} -> engNotFound）。
	multiSrc := WrapSentinel(engNotFound, errors.Join(portsNotFound, ucinvNotFound), portsNotFound, ucinvNotFound)
	if got := multiSrc.Error(); got != "engine: resource not found" {
		t.Fatalf("多源归一应折叠全部同义源哨兵: got=%q", got)
	}

	// 3. 中间 usecase.Wrap 穿透传播 S：上下文段永不抑制，尾部源哨兵精准消除。
	ucWrapped := Wrap(portsNotFound, KeyParamInvalidValue, Str("key", "web-1"))
	facadeWrapped := WrapSentinel(engNotFound, ucWrapped, portsNotFound)
	wantMid := "engine: resource not found: i18n: invalid parameter value for web-1"
	if got := facadeWrapped.Error(); got != wantMid {
		t.Fatalf("跨中间 Wrap 穿透抑制失败: got=%q, 期望 %q", got, wantMid)
	}
}

func TestRenderErrorChainJoinedBranchesAndTransitive(t *testing.T) {
	portsNotFound := SentinelWithFallback(MessageID("ports.not_found"), "ports: not found")
	portsPerm := SentinelWithFallback(MessageID("ports.permission_denied"), "ports: permission denied")
	engNotFound := SentinelWithFallback(MessageID("engine.not_found"), "engine: not found")
	engPerm := SentinelWithFallback(MessageID("engine.permission_denied"), "engine: denied")
	unmappedLeaf := errors.New("network unreachable")

	// 1. errors.Join 混合已映射裸哨兵、带上下文包装与未映射叶子分支。
	mixed := errors.Join(
		portsNotFound,
		Wrap(portsPerm, KeyParamInvalidKey, Str("key", "host")),
		unmappedLeaf,
	)
	mapped := WrapSentinel(engNotFound, WrapSentinel(engPerm, mixed, portsPerm), portsNotFound)
	wantMixed := "engine: not found: engine: denied: i18n: invalid parameter key host\nnetwork unreachable"
	if got := mapped.Error(); got != wantMixed {
		t.Fatalf("errors.Join 混合分支折叠异常:\n got=%q\nwant=%q", got, wantMixed)
	}

	// 2. errors.Join 兄弟分支隔离：分支 0 新增的抑制集合不得污染分支 1。
	siblingJoin := errors.Join(
		WrapSentinel(engNotFound, portsNotFound, portsNotFound, portsPerm),
		portsPerm,
	)
	wantSibling := "engine: not found\nports: permission denied"
	if got := CanonicalError(siblingJoin); got != wantSibling {
		t.Fatalf("errors.Join 兄弟分支抑制集合发生串扰: got=%q, 期望 %q", got, wantSibling)
	}

	// 3. 单子错误 errors.Join 透明解包。
	singleJoin := WrapSentinel(engNotFound, errors.Join(portsNotFound), portsNotFound)
	if got := singleJoin.Error(); got != "engine: not found" {
		t.Fatalf("单子错误 errors.Join 折叠异常: got=%q", got)
	}

	// 4. 三层传递映射 A -> B -> C（以及中间含上下文）。
	sC := SentinelWithFallback(MessageID("layer.c"), "layer C")
	sB := SentinelWithFallback(MessageID("layer.b"), "layer B")
	sA := SentinelWithFallback(MessageID("layer.a"), "layer A")
	transBare := WrapSentinel(sA, WrapSentinel(sB, sC, sC), sB)
	if got := transBare.Error(); got != "layer A" {
		t.Fatalf("三层传递裸映射失败: got=%q", got)
	}
	transCtx := WrapSentinel(sA, WrapSentinel(sB, Wrap(sC, KeyParamInvalidKey, Str("key", "k")), sC), sB)
	if got := transCtx.Error(); got != "layer A: i18n: invalid parameter key k" {
		t.Fatalf("三层传递带上下文映射失败: got=%q", got)
	}
}

func TestRenderErrorChainNoReplacedAndExactLeaf(t *testing.T) {
	portsNotFound := SentinelWithFallback(MessageID("ports.not_found"), "ports: not found")
	engPerm := SentinelWithFallback(MessageID("engine.permission_denied"), "engine: permission denied")
	stdCanceled := errors.New("context canceled")
	engCanceled := Sentinel(KeyCommonCanceled)

	// 1. 未传 replaced 时零跨类型盲目抑制；仅同哨兵自身沿因果路径去重。
	noReplaceCross := WrapSentinel(engPerm, portsNotFound)
	if got := noReplaceCross.Error(); got != "engine: permission denied: ports: not found" {
		t.Fatalf("无 replaced 时不应跨类型误吞内层哨兵: got=%q", got)
	}
	noReplaceSame := WrapSentinel(engPerm, Wrap(engPerm, KeyParamInvalidKey, Str("key", "id")))
	if got := noReplaceSame.Error(); got != "engine: permission denied: i18n: invalid parameter key id" {
		t.Fatalf("无 replaced 时同哨兵应自动去重: got=%q", got)
	}

	// 2. 精确叶子核验：裸 stdCanceled 被抑制/本地化，而携带自定义文本且 Is(stdCanceled) 的叶子绝不被覆写或吞噬。
	customLeaf := customCanceledLeaf{target: stdCanceled, detail: "peer aborted stream"}
	hooks := ErrorRenderHooks{
		RenderMessage: func(m Message) string {
			if m.ID() == KeyCommonCanceled {
				return "已取消"
			}
			return m.Canonical()
		},
		JoinCausal: func(head, tail string) string { return head + "：" + tail },
		RenderUnstructured: func(err error, children []error) (string, error, bool) {
			if len(children) == 0 && errors.Is(err, stdCanceled) && err.Error() == stdCanceled.Error() {
				return "上下文已取消", stdCanceled, true
			}
			return "", nil, false
		},
	}

	bareWrapped := WrapSentinel(engCanceled, stdCanceled, stdCanceled)
	if got := bareWrapped.Error(); got != "operation canceled" {
		t.Fatalf("规范英文应抑制精确匹配的裸叶子哨兵: got=%q", got)
	}
	if got := RenderErrorChain(bareWrapped, hooks); got != "已取消" {
		t.Fatalf("钩子模式应按 bareTarget 抑制裸叶子哨兵: got=%q", got)
	}
	if got := RenderErrorChain(stdCanceled, hooks); got != "上下文已取消" {
		t.Fatalf("未抑制的裸叶子应被 RenderUnstructured 本地化: got=%q", got)
	}

	customWrapped := WrapSentinel(engCanceled, customLeaf, stdCanceled)
	if got := customWrapped.Error(); got != "operation canceled: peer aborted stream" {
		t.Fatalf("自定义 Is(canceled) 叶子不得被规范折叠吞噬: got=%q", got)
	}
	if got := RenderErrorChain(customWrapped, hooks); got != "已取消：peer aborted stream" {
		t.Fatalf("自定义 Is(canceled) 叶子不得被钩子覆写或吞噬: got=%q", got)
	}

	// 3. RenderUnstructured 返回 bareTarget==nil 时（如带上下文 panic 值）永不被抑制。
	panicSentinel := errors.New("task panicked")
	panicLeaf := customCanceledLeaf{target: panicSentinel, detail: "panic: boom"}
	panicHooks := ErrorRenderHooks{
		RenderUnstructured: func(err error, _ []error) (string, error, bool) {
			if errors.Is(err, panicSentinel) {
				return "recovered: boom", nil, true
			}
			return "", nil, false
		},
	}
	panicWrapped := WrapSentinel(Sentinel(KeyCommonInternalError), panicLeaf, panicSentinel)
	if got := RenderErrorChain(panicWrapped, panicHooks); got != "internal error: recovered: boom" {
		t.Fatalf("bareTarget==nil 的非结构化上下文节点不得被抑制: got=%q", got)
	}
}

func TestRenderErrorChainCyclesDepthAndCustomNode(t *testing.T) {
	// 0. nil 输入安全返回空串。
	if CanonicalError(nil) != "" || RenderErrorChain(nil, ErrorRenderHooks{}) != "" {
		t.Fatal("nil error 渲染应返回空串")
	}

	// 1. 空视图 LocalizableNode（零值自定义结构）委托 CanonicalError 绝不重入爆栈。
	emptyCustom := &cyclicLocalizable{}
	if got := emptyCustom.Error(); got != "" {
		t.Fatalf("空视图 LocalizableNode 应返回空串: got=%q", got)
	}

	// 2. 自环与双节点环路必须在深度/节点预算内确定性终止。
	selfCycle := &cyclicLocalizable{msg: NewMessage(KeyCommonInternalError)}
	selfCycle.cause = selfCycle
	if got := selfCycle.Error(); got != "internal error" {
		t.Fatalf("自环 LocalizableNode 应折叠相邻重复段并安全终止: got=%q", got)
	}

	nodeA := &cyclicLocalizable{msg: NewMessage(KeyCommonNotFound)}
	nodeB := &cyclicLocalizable{msg: NewMessage(KeyCommonPermissionDeny), cause: nodeA}
	nodeA.cause = nodeB
	if got := nodeA.Error(); !strings.HasPrefix(got, "resource not found: permission denied") {
		t.Fatalf("互环 LocalizableNode 应确定性终止: got=%q", got)
	}

	// 3. 二叉分支型纯门面环路（Sentinel==self && Cause==self）受 maxErrorVisitNodes 保护瞬时终止。
	branchCycle := &cyclicLocalizable{}
	branchCycle.sentinel = branchCycle
	branchCycle.cause = branchCycle
	if got := branchCycle.Error(); got != "" {
		t.Fatalf("纯门面二叉环路应安全终止且输出空串: got=%q", got)
	}

	// 4. 超过 maxErrorRenderDepth 的深链确定性截断，且不触发重入。
	deep := Sentinel(KeyCommonNotFound)
	for range maxErrorRenderDepth + 16 {
		deep = Wrap(deep, KeyCommonTimeout)
	}
	if got := deep.Error(); got == "" {
		t.Fatal("超深链渲染不应返回空串")
	}

	// 5. 超过 maxErrorSuppressed 的替换集截断有界。
	many := make([]error, maxErrorSuppressed+10)
	for i := range many {
		many[i] = errors.New("src")
	}
	capped := WrapSentinel(Sentinel(KeyCommonInternalError), errors.New("leaf"), many...)
	if view, ok := InspectNode(capped); !ok || len(view.SuppressedSentinels) != maxErrorSuppressed {
		t.Fatalf("WrapSentinel 替换集应受 maxErrorSuppressed=%d 上限保护, 实际=%d", maxErrorSuppressed, len(view.SuppressedSentinels))
	}

	// 6. 模拟 ports.AuditPostWriteError（带 SuppressedSentinels 的自定义上下文节点）。
	auditOp := &suppressedCustomNode{
		sentinel:   ErrInvalidParam,
		msg:        NewMessage(KeyParamInvalidKey, Str("key", "op-1")),
		cause:      ErrInvalidParam,
		suppressed: []error{ErrInvalidParam},
	}
	if got := auditOp.Error(); got != "i18n: invalid parameter key op-1" {
		t.Fatalf("自定义节点 SuppressedSentinels 折叠默认占位哨兵失败: got=%q", got)
	}
	auditWithDisk := &suppressedCustomNode{
		sentinel:   ErrInvalidParam,
		msg:        NewMessage(KeyParamInvalidKey, Str("key", "op-1")),
		cause:      errors.New("disk full"),
		suppressed: []error{ErrInvalidParam},
	}
	if got := auditWithDisk.Error(); got != "i18n: invalid parameter key op-1: disk full" {
		t.Fatalf("自定义节点应保留非哨兵真实根因: got=%q", got)
	}
}

func TestRenderErrorChainExactLeafO1AndAcyclicJoin(t *testing.T) {
	// 1. 自指 SuppressedSentinels + 捕获全部目标的 Is 叶子绝不重入爆栈（O(1) 裸叶子判定）。
	selfSuppressed := &suppressedCustomNode{
		msg:        NewMessage(KeyCommonInternalError),
		cause:      catchAllLeaf{detail: "catch-all leaf"},
		isSentinel: true,
	}
	selfSuppressed.suppressed = []error{selfSuppressed}
	if got := selfSuppressed.Error(); got != "internal error: catch-all leaf" {
		t.Fatalf("自指 SuppressedSentinels + catch-all 叶子应 O(1) 安全终止并保留叶子文本: got=%q", got)
	}

	// 2. 深度 k=30 的无环 WrapSentinel + errors.Join(leaf, leaf) 链必须在节点预算内 O(1) 裸叶匹配并瞬时终止，零指数挂起。
	leaf := catchAllLeaf{detail: "leaf"}
	cur := Sentinel(KeyCommonNotFound)
	for range 30 {
		cur = WrapSentinel(cur, errors.Join(leaf, leaf))
	}
	if got := cur.Error(); !strings.HasPrefix(got, "resource not found: ") {
		t.Fatalf("深层无环 WrapSentinel+Join 链应瞬时终止: got=%q", got)
	}

	// 3. 复合 LocalizableNode 与带直接子错误的非结构化容器不作为裸叶子哨兵参与精确叶子吞噬。
	wrappedTarget := &suppressedCustomNode{sentinel: ErrInvalidParam, cause: errors.New("inner")}
	if isExactLeafSentinel(catchAllLeaf{detail: wrappedTarget.Error()}, wrappedTarget) {
		t.Fatal("复合 LocalizableNode 不得通过 isExactLeafSentinel 裸叶子匹配")
	}
	joinedTarget := errors.Join(errors.New("a"), errors.New("b"))
	if isExactLeafSentinel(catchAllLeaf{detail: joinedTarget.Error()}, joinedTarget) {
		t.Fatal("带直接子错误的非结构化容器不得通过 isExactLeafSentinel 裸叶子匹配")
	}
}
