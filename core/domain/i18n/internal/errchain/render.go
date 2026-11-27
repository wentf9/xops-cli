package errchain

import (
	"errors"
	"strings"
)

const (
	// MaxRenderDepth 限制错误链递归展开的最大深度，防止病态长链或环路导致栈溢出。
	MaxRenderDepth = 64
	// MaxSuppressed 限制单条因果路径上累积的已抑制哨兵集合容量上限，防止病态膨胀。
	MaxSuppressed = 32
	// MaxVisitNodes 限制单次渲染遍历的最大节点数，杜绝分支型环路或 DAG 指数爆炸。
	MaxVisitNodes = 256
)

// NodeView 描述错误链折叠代数所需的单层只读结构化节点视图（以泛型载荷 M 承接消息值，零 any 擦除）。
type NodeView[M any] struct {
	// Sentinel 是当前错误节点关联的哨兵分类错误（用于 errors.Is 语义匹配）。
	Sentinel error
	// Message 是当前错误节点的泛型结构化消息载荷（仅当 HasMessage 为 true 时有效）。
	Message M
	// HasMessage 标识 Message 是否为有效结构化消息。
	HasMessage bool
	// Cause 是被当前节点包装的下层根因错误（需要递归展开渲染）。
	Cause error
	// SuppressedSentinels 声明渲染期被本节点替代的同义源哨兵集合。
	SuppressedSentinels []error
	// IsSentinel 标识当前节点本身是否为不可变纯哨兵定义。
	IsSentinel bool
}

// Ops 定义泛型错误链折叠渲染代数所需的结构探测与展示回调钩子。
type Ops[M any] struct {
	// Inspect 非穿透探测单个 error 是否为结构化节点及其有效视图；
	// 当返回 isNode == true 时，核心渲染代数严禁对其调用 .Error()（规则 M6 防重入保护）。
	Inspect func(error) (view NodeView[M], isNode, hasView bool)
	// RenderMessage 将结构化消息渲染为目标语种文本；为 nil 时回退 CanonicalMessage。
	RenderMessage func(M) string
	// CanonicalMessage 将结构化消息渲染为规范英文文本（供默认渲染与 M5 精确裸叶匹配使用）。
	CanonicalMessage func(M) string
	// JoinCausal 将相邻两个因果段按目标语种连接符拼接；为 nil 时默认输出 head + ": " + tail。
	JoinCausal func(head, tail string) string
	// RenderUnstructured 处理非结构化节点：
	//   - handled == false：交由核心代数继续执行 errors.Join 展开、精确叶子抑制或原文保留；
	//   - handled == true && bareTarget != nil：视为裸哨兵映射，受当前路径抑制集合精准过滤；
	//   - handled == true && bareTarget == nil：视为携带现场上下文的节点，永不受抑制集合吞噬。
	RenderUnstructured func(err error, children []error) (text string, bareTarget error, handled bool)
}

// singleUnwrapper 与 multiUnwrapper 为包内具名解包接口（满足 noimplicit 禁止匿名接口断言要求）。
type singleUnwrapper interface {
	Unwrap() error
}

type multiUnwrapper interface {
	Unwrap() []error
}

// UnwrapDirect 非穿透提取单个错误节点的直接下层子错误（支持 Unwrap() []error 与 Unwrap() error）。
func UnwrapDirect(err error) []error {
	if err == nil {
		return nil
	}
	if u, ok := any(err).(multiUnwrapper); ok && u != nil {
		return FilterNonNil(u.Unwrap())
	}
	if u, ok := any(err).(singleUnwrapper); ok && u != nil {
		if child := u.Unwrap(); child != nil {
			return []error{child}
		}
	}
	return nil
}

// FilterNonNil 过滤错误切片中的 nil 元素；若过滤后为空则返回 nil。
func FilterNonNil(raw []error) []error {
	if len(raw) == 0 {
		return nil
	}
	out := make([]error, 0, len(raw))
	for _, item := range raw {
		if item != nil {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// FindFirst 按广度优先顺序遍历错误链（上限 maxNodes 防止环路死循环），返回首个令 match 命中的结果。
func FindFirst[T any](err error, maxNodes int, match func(error) (T, bool)) (T, bool) {
	var zero T
	if err == nil || maxNodes <= 0 || match == nil {
		return zero, false
	}
	queue := []error{err}
	for visited := 0; len(queue) > 0 && visited < maxNodes; visited++ {
		cur := queue[0]
		queue = queue[1:]
		if val, ok := match(cur); ok {
			return val, true
		}
		queue = append(queue, UnwrapDirect(cur)...)
	}
	return zero, false
}

// Render 按形式化折叠规则 M1–M6 执行错误链递归折叠渲染，零 any 擦除、零反射且在双预算内确定性终止。
func Render[M any](err error, ops Ops[M]) string {
	if err == nil {
		return ""
	}
	r := renderer[M]{ops: ops}
	return r.renderBranch(err, nil, 0)
}

// IsExactLeafSentinel 执行 O(1) 零递归精确裸叶子哨兵匹配（规则 M5/M6 不变量）：
// 仅当 target 为裸叶子哨兵、errors.Is 成立且叶子原文与哨兵规范文本逐字节相等时返回 true，
// 严禁对复合或自指结构化节点重入渲染，杜绝环路爆栈、指数级复杂度与吞噬自定义诊断文本。
func IsExactLeafSentinel[M any](err, target error, ops Ops[M]) bool {
	if err == nil || target == nil {
		return false
	}
	targetText, ok := bareSentinelLeafText(target, ops)
	if !ok {
		return false
	}
	return errors.Is(err, target) && err.Error() == targetText
}

type renderer[M any] struct {
	ops    Ops[M]
	visits int
}

func (r *renderer[M]) renderBranch(err error, suppressed []error, depth int) string {
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

func (r *renderer[M]) collectSegments(err error, suppressed []error, depth int, acc []string) []string {
	if err == nil {
		return acc
	}
	if r.ops.Inspect != nil {
		if view, isNode, hasView := r.ops.Inspect(err); isNode {
			if !hasView {
				return acc
			}
			if depth >= MaxRenderDepth || r.visits >= MaxVisitNodes {
				return r.collectStructuredAtLimit(err, view, suppressed, acc)
			}
			r.visits++
			return r.collectStructured(err, view, suppressed, depth, acc)
		}
	}
	if depth >= MaxRenderDepth || r.visits >= MaxVisitNodes {
		return appendNonEmpty(acc, err.Error())
	}
	r.visits++
	return r.collectUnstructured(err, suppressed, depth, acc)
}

func (r *renderer[M]) collectStructuredAtLimit(orig error, view NodeView[M], suppressed []error, acc []string) []string {
	if !view.HasMessage {
		return acc
	}
	if view.IsSentinel && matchesAnySentinel(orig, suppressed) {
		return acc
	}
	return appendNonEmpty(acc, r.renderMessage(view.Message))
}

func (r *renderer[M]) collectStructured(orig error, view NodeView[M], suppressed []error, depth int, acc []string) []string {
	if !view.HasMessage && view.Sentinel != nil {
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
	if view.HasMessage {
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

func (r *renderer[M]) collectUnstructured(err error, suppressed []error, depth int, acc []string) []string {
	children := UnwrapDirect(err)
	if r.ops.RenderUnstructured != nil {
		if text, bareTarget, handled := r.ops.RenderUnstructured(err, children); handled {
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
	if len(children) == 0 && r.matchesExactLeafSentinel(err, suppressed) {
		return acc
	}
	return appendNonEmpty(acc, err.Error())
}

func (r *renderer[M]) renderJoinedErrors(children []error, suppressed []error, depth int) string {
	parts := make([]string, 0, len(children))
	for _, child := range children {
		if rendered := r.renderBranch(child, suppressed, depth+1); rendered != "" {
			parts = append(parts, rendered)
		}
	}
	return strings.Join(parts, "\n")
}

func (r *renderer[M]) renderMessage(msg M) string {
	if r.ops.RenderMessage != nil {
		return r.ops.RenderMessage(msg)
	}
	if r.ops.CanonicalMessage != nil {
		return r.ops.CanonicalMessage(msg)
	}
	return ""
}

func (r *renderer[M]) joinSegments(segments []string) string {
	if len(segments) == 0 {
		return ""
	}
	out := segments[0]
	for _, seg := range segments[1:] {
		out = r.joinTwo(out, seg)
	}
	return out
}

func (r *renderer[M]) joinTwo(head, tail string) string {
	if head == "" {
		return tail
	}
	if tail == "" || tail == head {
		return head
	}
	if r.ops.JoinCausal != nil {
		return r.ops.JoinCausal(head, tail)
	}
	return head + ": " + tail
}

func (r *renderer[M]) matchesExactLeafSentinel(err error, suppressed []error) bool {
	if err == nil || len(suppressed) == 0 {
		return false
	}
	for _, s := range suppressed {
		if IsExactLeafSentinel(err, s, r.ops) {
			return true
		}
	}
	return false
}

// bareSentinelLeafText 仅对裸叶子哨兵返回其 O(1) 规范文本：
//   - 结构化节点：仅当有效纯哨兵且无下层 Cause/Sentinel 时取 CanonicalMessage(view.Message)（零递归）；
//   - 非结构化节点：仅当无直接子错误（len(UnwrapDirect(target)) == 0）时取 target.Error()。
func bareSentinelLeafText[M any](target error, ops Ops[M]) (string, bool) {
	if ops.Inspect != nil {
		if view, isNode, hasView := ops.Inspect(target); isNode {
			if hasView && view.IsSentinel && view.HasMessage && view.Cause == nil && view.Sentinel == nil && ops.CanonicalMessage != nil {
				return ops.CanonicalMessage(view.Message), true
			}
			return "", false
		}
	}
	if len(UnwrapDirect(target)) != 0 {
		return "", false
	}
	return target.Error(), true
}

// mergeSuppressed 返回在 base 基础上追加去重非空哨兵的新切片（上限 MaxSuppressed），
// 绝不原地修改 base 底层数组，保证 errors.Join 各子分支抑制集合完全隔离。
func mergeSuppressed(base []error, primary error, extras ...error) []error {
	if len(base) >= MaxSuppressed || (primary == nil && len(extras) == 0) {
		return base
	}
	out := make([]error, len(base), min(len(base)+1+len(extras), MaxSuppressed))
	copy(out, base)
	out = appendUniqueSuppressed(out, primary)
	for _, item := range extras {
		if len(out) >= MaxSuppressed {
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
	if candidate == nil || len(out) >= MaxSuppressed {
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
