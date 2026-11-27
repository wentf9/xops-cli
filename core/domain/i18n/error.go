package i18n

import (
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	maxErrorInspectNodes     = 64
	degradedParamPlaceholder = "<invalid>"
)

// ErrorNode 描述单个结构化错误节点的只读视图，供核心渲染代数与展示层逐层无穿透本地化与结构化去重。
type ErrorNode struct {
	// Sentinel 是当前错误节点关联的哨兵分类错误（用于 errors.Is 语义匹配）。
	Sentinel error
	// Message 是当前错误节点的结构化消息载荷。
	Message Message
	// Cause 是被当前节点包装的下层根因错误（需要递归展开渲染）。
	Cause error
	// SuppressedSentinels 声明渲染期被本节点替代的同义源哨兵集合；绝不经 Unwrap 暴露。
	SuppressedSentinels []error
	// IsSentinel 标识当前节点本身是否为不可变纯哨兵定义。
	IsSentinel bool
}

// LocalizableNode 由全部结构化错误及自定义业务错误实现。
//
// 设计理由：本接口刻意不嵌入 error，使边界通过 any(err).(LocalizableNode) 检查单层节点，
// 避免触发 golangci-lint 的 errorlint 告警且无需任何行内 lint 豁免注释。
type LocalizableNode interface {
	LocalizableView() ErrorNode
}

// singleUnwrapper 与 multiUnwrapper 为包内具名解包接口（满足 noimplicit 禁止匿名接口断言要求）。
type singleUnwrapper interface {
	Unwrap() error
}

type multiUnwrapper interface {
	Unwrap() []error
}

// InspectNode 非穿透读取单个 error 节点的 LocalizableNode 视图（不递归展开 Unwrap 链）。
func InspectNode(err error) (ErrorNode, bool) {
	view, _, hasView := inspectLocalizable(err)
	return view, hasView
}

// inspectLocalizable 非穿透探测单个 error 是否实现 LocalizableNode 及是否携带有效视图。
// 当返回 isNode == true 时，核心渲染代数严禁对其调用 .Error()（规则 M6 防重入与环路爆栈保护）。
func inspectLocalizable(err error) (ErrorNode, bool, bool) {
	if err == nil {
		return ErrorNode{}, false, false
	}
	node, ok := any(err).(LocalizableNode)
	if !ok {
		return ErrorNode{}, false, false
	}
	if node == nil {
		return ErrorNode{}, true, false
	}
	view := node.LocalizableView()
	if !view.Message.IsValid() && view.Sentinel == nil && view.Cause == nil {
		return ErrorNode{}, true, false
	}
	return view, true, true
}

// UnwrapDirect 非穿透提取单个错误节点的直接下层子错误（支持 Unwrap() []error 与 Unwrap() error）。
func UnwrapDirect(err error) []error {
	if err == nil {
		return nil
	}
	if u, ok := any(err).(multiUnwrapper); ok && u != nil {
		return filterNonNilErrors(u.Unwrap())
	}
	if u, ok := any(err).(singleUnwrapper); ok && u != nil {
		if child := u.Unwrap(); child != nil {
			return []error{child}
		}
	}
	return nil
}

func filterNonNilErrors(raw []error) []error {
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

// Error 是 XOps v2 纯数据不可变结构化错误节点，实现 error、LocalizableNode、Unwrap 与 Is 契约。
// 零值恒无效且对外输出空视图；所有导出构造器均保证失败关闭且永不返回 nil error。
//
//xops:opaque
//xops:failclosed
type Error struct {
	sentinel            error
	msg                 Message
	cause               error
	suppressedSentinels []error
	isSentinel          bool
	valid               bool
}

// Sentinel 使用核心规范英文兜底构造不可变哨兵错误（供各核心包以 var ErrX = i18n.Sentinel(KeyX) 声明）。
func Sentinel(id MessageID) error {
	return SentinelWithFallback(id, CanonicalFallback(id))
}

// SentinelWithFallback 使用显式规范英文兜底构造不可变哨兵错误（仅供根模块 internal/i18n 桥接调用）。
// 当传入非法或零值 MessageID 触发降级时，仍返回非 nil 有效错误但严格置 isSentinel=false，
// 防止退化实例在 errors.Is 下与合法 Sentinel(KeyCommonInvalidArgument) 发生假阳性匹配。
func SentinelWithFallback(id MessageID, fallback string) error {
	msg := ensureErrorMessage(id, fallback, nil)
	return &Error{
		msg:        msg,
		isSentinel: id.IsValid() && msg.IsValid() && msg.ID() == id,
		valid:      true,
	}
}

// NewErrorWithFallback 以显式规范英文兜底构造结构化错误节点（仅供根模块 internal/i18n 桥接调用）。
// sentinel 与 cause 均可为 nil，统一承接 E/EF/Wrap/WrapS 四类结构化错误构造路径。
func NewErrorWithFallback(sentinel, cause error, id MessageID, fallback string, params ...Param) error {
	return &Error{
		sentinel: sentinel,
		msg:      ensureErrorMessage(id, fallback, params),
		cause:    cause,
		valid:    true,
	}
}

// E 构造携带核心规范英文兜底与参数的独立结构化错误。
func E(id MessageID, params ...Param) error {
	return NewErrorWithFallback(nil, nil, id, CanonicalFallback(id), params...)
}

// EF 构造同时关联分类哨兵 sentinel 与参数化上下文消息的结构化错误。
func EF(sentinel error, id MessageID, params ...Param) error {
	return NewErrorWithFallback(sentinel, nil, id, CanonicalFallback(id), params...)
}

// Wrap 以核心规范英文兜底与参数包装下层根因错误 cause。
func Wrap(cause error, id MessageID, params ...Param) error {
	return NewErrorWithFallback(nil, cause, id, CanonicalFallback(id), params...)
}

// WrapS 同时绑定分类哨兵 sentinel、下层根因 cause 与参数化上下文消息。
func WrapS(sentinel, cause error, id MessageID, params ...Param) error {
	return NewErrorWithFallback(sentinel, cause, id, CanonicalFallback(id), params...)
}

// WrapSentinel 将底层错误 cause 映射至门面哨兵 sentinel，并显式登记本次映射替代的同义源哨兵集合 replaced。
// Unwrap 仅返回 [sentinel, cause]（绝不暴露 replaced，避免污染 errors.Is）；
// 未传 replaced 时仅对 sentinel 自身沿因果路径去重，绝不做跨类型盲目抑制。
func WrapSentinel(sentinel, cause error, replaced ...error) error {
	if sentinel == nil && cause == nil {
		return E(KeyCommonInvalidArgument)
	}
	suppressed := filterNonNilErrors(replaced)
	if len(suppressed) > maxErrorSuppressed {
		suppressed = suppressed[:maxErrorSuppressed]
	}
	return &Error{
		sentinel:            sentinel,
		cause:               cause,
		suppressedSentinels: suppressed,
		valid:               true,
	}
}

// ensureErrorMessage 保证错误构造路径严格失败关闭并最大化保留有效诊断参数：
//   - 非法 id 降级为 KeyCommonInvalidArgument；
//   - 非法 UTF-8 或超长 fallback 按 BoundDisplayText 确定性净化；
//   - 若因个别参数非法/重复/超限导致直构失败，保留全部合法非重复参数并对缺失占位符回填 "<invalid>"，
//     彻底杜绝原始 "{key}" 占位符泄露至错误文本、审计或终端。
func ensureErrorMessage(id MessageID, fallback string, params []Param) Message {
	if !id.IsValid() {
		return NewMessage(KeyCommonInvalidArgument)
	}
	safeFallback := fallback
	if len(safeFallback) > MaxTemplateBytes || !utf8.ValidString(safeFallback) {
		safeFallback = BoundDisplayText(safeFallback, MaxTemplateBytes)
	}
	if m := buildMessage(id, safeFallback, false, 0, params); m.IsValid() {
		return m
	}
	salvaged := salvageErrorParams(safeFallback, params)
	if m := buildMessage(id, safeFallback, false, 0, salvaged); m.IsValid() {
		return m
	}
	return NewMessage(KeyCommonInvalidArgument)
}

func salvageErrorParams(fallback string, params []Param) []Param {
	out := make([]Param, 0, min(len(params), MaxMessageParams))
	for _, p := range params {
		if len(out) >= MaxMessageParams {
			break
		}
		if p.IsValid() && !hasParamKey(out, p.key) {
			out = append(out, p)
		}
	}
	return backfillMissingPlaceholders(fallback, out)
}

func backfillMissingPlaceholders(fallback string, out []Param) []Param {
	if len(out) >= MaxMessageParams || !strings.ContainsRune(fallback, '{') {
		return out
	}
	keys, errID, _ := parsePlaceholderKeys(fallback)
	if errID != MessageIDInvalid {
		return out
	}
	for _, k := range keys {
		if len(out) >= MaxMessageParams {
			break
		}
		if !hasParamKey(out, k) {
			out = append(out, Str(k, degradedParamPlaceholder))
		}
	}
	return out
}

// Error 返回恒定规范英文错误文本（委托至 CanonicalError，与 enLoc.RenderError 共享唯一折叠代数）。
func (e *Error) Error() string {
	if e == nil || !e.valid {
		return ""
	}
	return CanonicalError(e)
}

// LocalizableView 返回当前错误节点的只读结构化视图（nil 接收者或无效节点安全返回零值）。
func (e *Error) LocalizableView() ErrorNode {
	if e == nil || !e.valid {
		return ErrorNode{}
	}
	return ErrorNode{
		Sentinel:            e.sentinel,
		Message:             e.msg.clone(),
		Cause:               e.cause,
		SuppressedSentinels: slices.Clone(e.suppressedSentinels),
		IsSentinel:          e.isSentinel,
	}
}

// Unwrap 返回当前错误节点关联的直接下层错误切片（按 Sentinel -> Cause 顺序，绝不包含 SuppressedSentinels），
// 完整支持 errors.Is / errors.AsType 语义匹配。
func (e *Error) Unwrap() []error {
	if e == nil || !e.valid {
		return nil
	}
	switch {
	case e.sentinel != nil && e.cause != nil:
		return []error{e.sentinel, e.cause}
	case e.sentinel != nil:
		return []error{e.sentinel}
	case e.cause != nil:
		return []error{e.cause}
	default:
		return nil
	}
}

// Is 实现哨兵语义相等：当且仅当双方均为有效哨兵节点（IsSentinel == true）且 MessageID 完全相同时返回 true，
// 从根源消除跨包哨兵重导出或同义哨兵指针不等导致的 errors.Is 漏判。
func (e *Error) Is(target error) bool {
	if e == nil || !e.valid || !e.isSentinel || !e.msg.IsValid() || target == nil {
		return false
	}
	view, ok := InspectNode(target)
	return ok && view.IsSentinel && view.Message.IsValid() && view.Message.id == e.msg.id
}

// ErrorID 按广度优先顺序从错误链提取首个有效结构化 MessageID（供测试与边界按语义而非脆弱文本断言）。
// 本函数不依赖 errors.As/Is 之外的报错路径，并对异常环路设节点遍历上限确保必定终止。
func ErrorID(err error) (MessageID, bool) {
	if err == nil {
		return MessageIDInvalid, false
	}
	queue := []error{err}
	for visited := 0; len(queue) > 0 && visited < maxErrorInspectNodes; visited++ {
		cur := queue[0]
		queue = queue[1:]
		if id, ok := inspectNodeMessageID(cur); ok {
			return id, true
		}
		queue = append(queue, UnwrapDirect(cur)...)
	}
	return MessageIDInvalid, false
}

func inspectNodeMessageID(cur error) (MessageID, bool) {
	view, ok := InspectNode(cur)
	if !ok {
		return MessageIDInvalid, false
	}
	if view.Message.IsValid() {
		return view.Message.ID(), true
	}
	if view.Sentinel != nil {
		if sv, sok := InspectNode(view.Sentinel); sok && sv.Message.IsValid() {
			return sv.Message.ID(), true
		}
	}
	return MessageIDInvalid, false
}
