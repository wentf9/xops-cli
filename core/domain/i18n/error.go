package i18n

import (
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/i18n/internal/errchain"
	"github.com/wentf9/xops-cli/core/domain/i18n/internal/textalg"
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
	return errchain.UnwrapDirect(err)
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
	return &Error{msg: msg, isSentinel: id.IsValid() && msg.IsValid() && msg.ID() == id, valid: true}
}

// NewErrorWithFallback 以显式规范英文兜底构造结构化错误节点（仅供根模块 internal/i18n 桥接调用）。
// sentinel 与 cause 均可为 nil，统一承接 E/EF/Wrap/WrapS 四类结构化错误构造路径。
func NewErrorWithFallback(sentinel, cause error, id MessageID, fallback string, params ...Param) error {
	return &Error{sentinel: sentinel, msg: ensureErrorMessage(id, fallback, params), cause: cause, valid: true}
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
	suppressed := errchain.FilterNonNil(replaced)
	if len(suppressed) > maxErrorSuppressed {
		suppressed = suppressed[:maxErrorSuppressed]
	}
	return &Error{sentinel: sentinel, cause: cause, suppressedSentinels: suppressed, valid: true}
}

// WrapSentinelDetail 按规则 M1 将运行期动态明细 detail（经 BoundStr 确定性净化与裁剪）与可选根因 cause
// 挂载至门面哨兵 sentinel 之下，完整保留 sentinel 头段语义渲染、replaced 抑制集与 cause 展开。
// 当 detail 为空或纯空白时自动退化为 WrapSentinel(sentinel, cause, replaced...)。
func WrapSentinelDetail(sentinel, cause error, detail string, replaced ...error) error {
	bounded, ok := textalg.BoundNonBlankText(detail, MaxParamStringBytes)
	if !ok {
		return WrapSentinel(sentinel, cause, replaced...)
	}
	inner := NewErrorWithFallback(nil, cause, KeyCommonDetail, CanonicalFallback(KeyCommonDetail), BoundStr("detail", bounded))
	return WrapSentinel(sentinel, inner, replaced...)
}

// DynamicDetailError 将不可预知的外部或对端动态错误文本封装为有界有效 UTF-8 叶子结构化错误（不绑定哨兵）。
// 当 detail 为空或纯空白时安全降级为 E(KeyCommonInternalError)，确保永不返回 nil 或空错误文本。
func DynamicDetailError(detail string) error {
	bounded, ok := textalg.BoundNonBlankText(detail, MaxParamStringBytes)
	if !ok {
		return E(KeyCommonInternalError)
	}
	return NewErrorWithFallback(nil, nil, KeyCommonDetail, CanonicalFallback(KeyCommonDetail), BoundStr("detail", bounded))
}

// ensureErrorMessage 保证错误构造路径严格失败关闭并最大化保留有效诊断参数：
//   - 非法 id 降级为 KeyCommonInvalidArgument；
//   - 非法 UTF-8 或超长 fallback 按 BoundDisplayText 确定性净化；
//   - 快路径以 O(n) 零堆分配检查顶层与全部嵌套 ParamKindMessage 是否缺失占位符，完整闭合时直接返回；
//   - 慢路径按模板实际必填槽位优先保序抢救、递归闭合嵌套消息并对缺失占位符回填 "<invalid>"；
//     超过 MaxMessageParams 个不同占位符的病态模板直接降级为 KeyCommonInvalidArgument，彻底杜绝 "{key}" 泄露。
func ensureErrorMessage(id MessageID, fallback string, params []Param) Message {
	return ensureClosedMessage(id, fallback, false, 0, params, MaxMessageDepth)
}

func ensureClosedMessage(id MessageID, fallback string, hasCount bool, count int64, params []Param, remDepth uint8) Message {
	if !id.IsValid() {
		return NewMessage(KeyCommonInvalidArgument)
	}
	safeFallback := textalg.SanitizeTemplate(fallback)
	if m := buildMessage(id, safeFallback, hasCount, count, params); m.IsValid() && !hasMissingErrorPlaceholder(m, remDepth) {
		return m
	}
	salvaged, ok := salvageErrorParams(safeFallback, hasCount, params, remDepth)
	if !ok {
		return NewMessage(KeyCommonInvalidArgument)
	}
	if m := buildMessage(id, safeFallback, hasCount, count, salvaged); m.IsValid() {
		return m
	}
	return NewMessage(KeyCommonInvalidArgument)
}

func hasMissingErrorPlaceholder(m Message, remDepth uint8) bool {
	if !m.IsValid() || hasTopLevelMissingPlaceholder(m) {
		return true
	}
	for _, p := range m.params {
		if p.kind != ParamKindMessage {
			continue
		}
		if remDepth == 0 || p.msgVal == nil || hasMissingErrorPlaceholder(*p.msgVal, remDepth-1) {
			return true
		}
	}
	return false
}

func hasTopLevelMissingPlaceholder(m Message) bool {
	if !strings.ContainsRune(m.fallback, '{') {
		return false
	}
	return textalg.HasMissingPlaceholder(m.fallback, func(key string) bool {
		return hasParamKey(m.params, key) || (key == "count" && m.hasCount)
	})
}

func salvageErrorParams(fallback string, hasCount bool, params []Param, remDepth uint8) ([]Param, bool) {
	required := textalg.CollectFormatPlaceholderKeys(fallback)
	if hasCount && len(required) > 0 {
		required = slices.DeleteFunc(required, func(k string) bool { return k == "count" })
	}
	if len(required) > MaxMessageParams {
		return nil, false
	}
	out := make([]Param, 0, min(max(len(params), len(required)), MaxMessageParams))
	out = appendSalvagedParams(out, params, required, true, remDepth)
	for _, k := range required {
		if !hasParamKey(out, k) {
			out = append(out, Str(k, degradedParamPlaceholder))
		}
	}
	out = appendSalvagedParams(out, params, nil, false, remDepth)
	return out, true
}

func appendSalvagedParams(out, params []Param, required []string, requiredOnly bool, remDepth uint8) []Param {
	for _, p := range params {
		if len(out) >= MaxMessageParams {
			break
		}
		if !p.IsValid() || hasParamKey(out, p.key) || (requiredOnly && !slices.Contains(required, p.key)) {
			continue
		}
		if normalized, ok := normalizeSalvagedParam(p, remDepth); ok {
			out = append(out, normalized)
		}
	}
	return out
}

func normalizeSalvagedParam(p Param, remDepth uint8) (Param, bool) {
	if p.kind != ParamKindMessage {
		return p, true
	}
	if p.msgVal == nil || !p.msgVal.IsValid() {
		return Param{}, false
	}
	if remDepth == 0 {
		rebuilt := Msg(p.key, NewMessage(KeyCommonInvalidArgument))
		return rebuilt, rebuilt.IsValid()
	}
	if !hasMissingErrorPlaceholder(*p.msgVal, remDepth-1) {
		return p, true
	}
	closed := ensureClosedMessage(p.msgVal.id, p.msgVal.fallback, p.msgVal.hasCount, p.msgVal.count, p.msgVal.params, remDepth-1)
	rebuilt := Msg(p.key, closed)
	if !rebuilt.IsValid() {
		rebuilt = Msg(p.key, NewMessage(KeyCommonInvalidArgument))
	}
	return rebuilt, rebuilt.IsValid()
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
	return errchain.FindFirst(err, maxErrorInspectNodes, inspectNodeMessageID)
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
