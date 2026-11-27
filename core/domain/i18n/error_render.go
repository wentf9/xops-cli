package i18n

import "github.com/wentf9/xops-cli/core/domain/i18n/internal/errchain"

const (
	// maxErrorRenderDepth 限制错误链递归展开的最大深度，防止病态长链或环路导致栈溢出。
	maxErrorRenderDepth = errchain.MaxRenderDepth
	// maxErrorSuppressed 限制单条因果路径上累积的已抑制哨兵集合容量上限，防止病态膨胀。
	maxErrorSuppressed = errchain.MaxSuppressed
)

// ErrorRenderHooks 定义错误链折叠渲染代数中仅有的 3 个可插拔展示钩子；
// 任意字段为 nil 时均自动采用规范英文默认行为。
type ErrorRenderHooks struct {
	// RenderMessage 将结构化 Message 渲染为目标语种文本；为 nil 时默认调用 Message.Canonical()。
	RenderMessage func(Message) string
	// JoinCausal 将相邻两个因果段按目标语种连接符拼接；为 nil 时默认输出 head + ": " + tail。
	JoinCausal func(head, tail string) string
	// RenderUnstructured 处理非 LocalizableNode 节点（如 *conc.PanicError、context.*、conc.Err*）：
	//   - handled == false：交由核心代数继续执行 errors.Join 展开、精确叶子抑制或原文保留；
	//   - handled == true && bareTarget != nil：视为裸哨兵映射，受当前路径抑制集合精准过滤；
	//   - handled == true && bareTarget == nil：视为携带现场上下文的节点，永不受抑制集合吞噬。
	RenderUnstructured func(err error, children []error) (text string, bareTarget error, handled bool)
}

// CanonicalError 使用零钩子执行规范英文错误链折叠渲染。
// (*Error).Error() 及仓内自定义 LocalizableNode 错误类型的 .Error() 均应委托至此，
// 保证审计日志、事件与 enLoc.RenderError 严格遵守同一套折叠不变量。
func CanonicalError(err error) string {
	return RenderErrorChain(err, ErrorRenderHooks{})
}

// RenderErrorChain 是 core/domain/i18n 与 internal/i18n.(*Localizer).RenderError 共享的唯一递归渲染代数引擎。
// 遵循形式化折叠规则 M1–M6（核心折叠代数下沉至无环内部叶包 internal/errchain）：
//   - M1 纯门面节点：仅当门面未命中已抑制集合 S 时渲染头段，且恒合并 S' = S ∪ {Sentinel} ∪ SuppressedSentinels 向下传播；
//   - M2 裸结构化哨兵：仅当未命中 S 时渲染；
//   - M3 带上下文结构化节点：永不被 S 抑制，并携带 S' = S ∪ SuppressedSentinels 穿透递归 Cause；
//   - M4 errors.Join 容器：以纯函数识别并将独立不可变 S 传入每个子分支，省略空分支后以 "\n" 拼接；
//   - M5 精确叶子核验：仅当 errors.Is 且错误文本完全相等时判定为裸叶子哨兵，严防覆盖或吞噬携带自定义文本的叶子错误；
//   - M6 防重入保护：对任意 LocalizableNode 永不调用 .Error()，并在深度与节点数双上限下确定性终止。
func RenderErrorChain(err error, hooks ErrorRenderHooks) string {
	return errchain.Render(err, errchain.Ops[Message]{
		Inspect:            inspectErrChainNode,
		RenderMessage:      hooks.RenderMessage,
		CanonicalMessage:   Message.Canonical,
		JoinCausal:         hooks.JoinCausal,
		RenderUnstructured: hooks.RenderUnstructured,
	})
}

func inspectErrChainNode(err error) (errchain.NodeView[Message], bool, bool) {
	view, isNode, hasView := inspectLocalizable(err)
	if !hasView {
		return errchain.NodeView[Message]{}, isNode, false
	}
	return errchain.NodeView[Message]{
		Sentinel:            view.Sentinel,
		Message:             view.Message,
		HasMessage:          view.Message.IsValid(),
		Cause:               view.Cause,
		SuppressedSentinels: view.SuppressedSentinels,
		IsSentinel:          view.IsSentinel,
	}, true, true
}
