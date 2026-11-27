package i18n

import (
	"errors"
	"strings"
)

const (
	// maxErrorRenderDepth 限制错误链递归展开的最大深度，防止病态长链或环路导致栈溢出。
	maxErrorRenderDepth = 64
	// maxErrorSuppressed 限制单条因果路径上累积的已抑制哨兵集合容量上限，防止病态膨胀。
	maxErrorSuppressed = 32
	// maxErrorVisitNodes 限制单次渲染遍历的最大节点数，杜绝分支型环路或 DAG 指数爆炸。
	maxErrorVisitNodes = 256
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
// 遵循形式化折叠规则 M1–M6：
//   - M1 纯门面节点：仅当门面未命中已抑制集合 S 时渲染头段，且恒合并 S' = S ∪ {Sentinel} ∪ SuppressedSentinels 向下传播；
//   - M2 裸结构化哨兵：仅当未命中 S 时渲染；
//   - M3 带上下文结构化节点：永不被 S 抑制，并携带 S' = S ∪ SuppressedSentinels 穿透递归 Cause；
//   - M4 errors.Join 容器：以纯函数识别并将独立不可变 S 传入每个子分支，省略空分支后以 "\n" 拼接；
//   - M5 精确叶子核验：仅当 errors.Is 且错误文本完全相等时判定为裸叶子哨兵，严防覆盖或吞噬携带自定义文本的叶子错误；
//   - M6 防重入保护：对任意 LocalizableNode 永不调用 .Error()，并在深度与节点数双上限下确定性终止。
func RenderErrorChain(err error, hooks ErrorRenderHooks) string {
	if err == nil {
		return ""
	}
	r := errorRenderer{hooks: hooks}
	return r.renderBranch(err, nil, 0)
}

type errorRenderer struct {
	hooks  ErrorRenderHooks
	visits int
}

func (r *errorRenderer) renderBranch(err error, suppressed []error, depth int) string {
	if err == nil {
		return ""
	}
	segments := r.collectSegments(err, suppressed, depth, nil)
	segments = collapseAdjacentDuplicates(segments)
	if len(segments) == 0 {
		return ""
	}
	return r.joinSegments(segments)
}

func (r *errorRenderer) collectSegments(err error, suppressed []error, depth int, acc []string) []string {
	if err == nil {
		return acc
	}
	view, isNode, hasView := inspectLocalizable(err)
	if isNode {
		if !hasView {
			return acc
		}
		if depth >= maxErrorRenderDepth || r.visits >= maxErrorVisitNodes {
			return r.collectStructuredAtLimit(err, view, suppressed, acc)
		}
		r.visits++
		return r.collectStructured(err, view, suppressed, depth, acc)
	}
	if depth >= maxErrorRenderDepth || r.visits >= maxErrorVisitNodes {
		return appendNonEmpty(acc, err.Error())
	}
	r.visits++
	return r.collectUnstructured(err, suppressed, depth, acc)
}

func (r *errorRenderer) collectStructuredAtLimit(orig error, view ErrorNode, suppressed []error, acc []string) []string {
	if !view.Message.IsValid() {
		return acc
	}
	if view.IsSentinel && matchesAnySentinel(orig, suppressed) {
		return acc
	}
	return appendNonEmpty(acc, r.renderMessage(view.Message))
}

func (r *errorRenderer) collectStructured(orig error, view ErrorNode, suppressed []error, depth int, acc []string) []string {
	if !view.Message.IsValid() && view.Sentinel != nil {
		// 规则 M1：纯门面映射节点；无论本层门面是否被外层抑制，恒向下传递合并后的抑制集。
		if !matchesAnySentinel(view.Sentinel, suppressed) {
			acc = appendNonEmpty(acc, r.renderBranch(view.Sentinel, suppressed, depth+1))
		}
		if view.Cause != nil {
			next := mergeSuppressed(suppressed, view.Sentinel, view.SuppressedSentinels...)
			acc = r.collectSegments(view.Cause, next, depth+1, acc)
		}
		return acc
	}
	if view.Message.IsValid() {
		// 规则 M2/M3：裸哨兵受 suppressed 精准过滤；带业务上下文节点永不抑制。
		if !view.IsSentinel || !matchesAnySentinel(orig, suppressed) {
			acc = appendNonEmpty(acc, r.renderMessage(view.Message))
		}
	}
	if view.Cause != nil {
		next := mergeSuppressed(suppressed, nil, view.SuppressedSentinels...)
		acc = r.collectSegments(view.Cause, next, depth+1, acc)
	}
	return acc
}

func (r *errorRenderer) collectUnstructured(err error, suppressed []error, depth int, acc []string) []string {
	children := UnwrapDirect(err)
	if r.hooks.RenderUnstructured != nil {
		if text, bareTarget, handled := r.hooks.RenderUnstructured(err, children); handled {
			if bareTarget != nil && matchesAnySentinel(bareTarget, suppressed) {
				return acc
			}
			return appendNonEmpty(acc, text)
		}
	}
	if len(children) > 0 && matchesJoinedErrorText(err, children) {
		if len(children) == 1 {
			return r.collectSegments(children[0], suppressed, depth+1, acc)
		}
		return appendNonEmpty(acc, r.renderJoinedErrors(children, suppressed, depth))
	}
	if len(children) == 0 && matchesExactLeafSentinel(err, suppressed) {
		return acc
	}
	return appendNonEmpty(acc, err.Error())
}

func (r *errorRenderer) renderJoinedErrors(children []error, suppressed []error, depth int) string {
	parts := make([]string, 0, len(children))
	for _, child := range children {
		if rendered := r.renderBranch(child, suppressed, depth+1); rendered != "" {
			parts = append(parts, rendered)
		}
	}
	return strings.Join(parts, "\n")
}

func (r *errorRenderer) renderMessage(msg Message) string {
	if r.hooks.RenderMessage != nil {
		return r.hooks.RenderMessage(msg)
	}
	return msg.Canonical()
}

func (r *errorRenderer) joinSegments(segments []string) string {
	if len(segments) == 0 {
		return ""
	}
	out := segments[0]
	for _, seg := range segments[1:] {
		out = r.joinTwo(out, seg)
	}
	return out
}

func (r *errorRenderer) joinTwo(head, tail string) string {
	if head == "" {
		return tail
	}
	if tail == "" || tail == head {
		return head
	}
	if r.hooks.JoinCausal != nil {
		return r.hooks.JoinCausal(head, tail)
	}
	return head + ": " + tail
}

// mergeSuppressed 返回在 base 基础上追加去重非空哨兵的新切片（上限 maxErrorSuppressed），
// 绝不原地修改 base 底层数组，保证 errors.Join 各子分支抑制集合完全隔离。
func mergeSuppressed(base []error, primary error, extras ...error) []error {
	if len(base) >= maxErrorSuppressed || (primary == nil && len(extras) == 0) {
		return base
	}
	out := make([]error, len(base), min(len(base)+1+len(extras), maxErrorSuppressed))
	copy(out, base)
	out = appendUniqueSuppressed(out, primary)
	for _, item := range extras {
		if len(out) >= maxErrorSuppressed {
			break
		}
		out = appendUniqueSuppressed(out, item)
	}
	if len(out) == len(base) {
		return base
	}
	return out
}

func appendUniqueSuppressed(out []error, candidate error) []error {
	if candidate == nil || len(out) >= maxErrorSuppressed {
		return out
	}
	for _, existing := range out {
		if errors.Is(candidate, existing) && errors.Is(existing, candidate) {
			return out
		}
	}
	return append(out, candidate)
}

func matchesAnySentinel(err error, suppressed []error) bool {
	if err == nil {
		return false
	}
	for _, s := range suppressed {
		if s != nil && errors.Is(err, s) {
			return true
		}
	}
	return false
}

// isExactLeafSentinel 执行精确叶子哨兵匹配（对齐 CORE-2 不变量）：
// 要求 errors.Is 成立且叶子原文与目标哨兵规范文本逐字节相等，杜绝吞噬携带自定义诊断信息的叶子错误。
func isExactLeafSentinel(err, target error) bool {
	if err == nil || target == nil {
		return false
	}
	return errors.Is(err, target) && err.Error() == sentinelErrorText(target)
}

func sentinelErrorText(target error) string {
	if _, isNode, _ := inspectLocalizable(target); isNode {
		return CanonicalError(target)
	}
	return target.Error()
}

func matchesExactLeafSentinel(err error, suppressed []error) bool {
	if err == nil || len(suppressed) == 0 {
		return false
	}
	for _, s := range suppressed {
		if isExactLeafSentinel(err, s) {
			return true
		}
	}
	return false
}

// matchesJoinedErrorText 判断非结构化错误 err 是否为纯 errors.Join 风格多错误容器（无额外前缀文案），
// 通过纯字符串拼接函数 joinChildErrorTexts 避免产生局部 error，零触发 failclosed 检查。
func matchesJoinedErrorText(err error, children []error) bool {
	return len(children) > 0 && err.Error() == joinChildErrorTexts(children)
}

func joinChildErrorTexts(children []error) string {
	texts := make([]string, len(children))
	for i, child := range children {
		texts[i] = child.Error()
	}
	return strings.Join(texts, "\n")
}

func appendNonEmpty(acc []string, s string) []string {
	if s == "" {
		return acc
	}
	return append(acc, s)
}

func collapseAdjacentDuplicates(segments []string) []string {
	if len(segments) <= 1 {
		return segments
	}
	out := make([]string, 0, len(segments))
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		if len(out) > 0 && out[len(out)-1] == seg {
			continue
		}
		out = append(out, seg)
	}
	return out
}
