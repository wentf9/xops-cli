package i18n

const maxErrorInspectNodes = 64

// ErrorNode 描述单个结构化错误节点的只读视图，供展示层逐层无穿透本地化与结构化去重。
type ErrorNode struct {
	// Sentinel 是当前错误节点关联的哨兵分类错误（用于 errors.Is 语义匹配）。
	Sentinel error
	// Message 是当前错误节点的结构化消息载荷。
	Message Message
	// Cause 是被当前节点包装的下层根因错误（需要递归展开渲染）。
	Cause error
	// IsSentinel 标识当前节点本身是否为不可变哨兵错误。
	IsSentinel bool
	// SuppressInnerID 由 WrapSentinel 标记，指示边界 RenderError 折叠紧邻同义内层哨兵节点。
	SuppressInnerID bool
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
	if err == nil {
		return ErrorNode{}, false
	}
	node, ok := any(err).(LocalizableNode)
	if !ok || node == nil {
		return ErrorNode{}, false
	}
	view := node.LocalizableView()
	if !view.Message.IsValid() && view.Sentinel == nil && view.Cause == nil {
		return ErrorNode{}, false
	}
	return view, true
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
	sentinel        error
	msg             Message
	cause           error
	isSentinel      bool
	suppressInnerID bool
	valid           bool
}

// Sentinel 使用核心规范英文兜底构造不可变哨兵错误（供各核心包以 var ErrX = i18n.Sentinel(KeyX) 声明）。
func Sentinel(id MessageID) error {
	return SentinelWithFallback(id, CanonicalFallback(id))
}

// SentinelWithFallback 使用显式规范英文兜底构造不可变哨兵错误（供根模块 internal/i18n 定义专属哨兵）。
func SentinelWithFallback(id MessageID, fallback string) error {
	msg := ensureErrorMessage(id, fallback, nil)
	return &Error{msg: msg, isSentinel: true, valid: true}
}

// E 构造携带核心规范英文兜底与参数的独立结构化错误。
func E(id MessageID, params ...Param) error {
	return EWithFallback(id, CanonicalFallback(id), params...)
}

// EWithFallback 以显式规范英文兜底构造独立结构化错误（供 internal/i18n 根模块封装使用）。
func EWithFallback(id MessageID, fallback string, params ...Param) error {
	return &Error{msg: ensureErrorMessage(id, fallback, params), valid: true}
}

// EF 构造同时关联分类哨兵 sentinel 与参数化上下文消息的结构化错误。
func EF(sentinel error, id MessageID, params ...Param) error {
	return EFWithFallback(sentinel, id, CanonicalFallback(id), params...)
}

// EFWithFallback 以显式兜底构造同时关联分类哨兵与参数化上下文消息的结构化错误。
func EFWithFallback(sentinel error, id MessageID, fallback string, params ...Param) error {
	return &Error{sentinel: sentinel, msg: ensureErrorMessage(id, fallback, params), valid: true}
}

// Wrap 以核心规范英文兜底与参数包装下层根因错误 cause。
func Wrap(cause error, id MessageID, params ...Param) error {
	return WrapWithFallback(cause, id, CanonicalFallback(id), params...)
}

// WrapWithFallback 以显式兜底与参数包装下层根因错误 cause。
func WrapWithFallback(cause error, id MessageID, fallback string, params ...Param) error {
	return &Error{msg: ensureErrorMessage(id, fallback, params), cause: cause, valid: true}
}

// WrapS 同时绑定分类哨兵 sentinel、下层根因 cause 与参数化上下文消息。
func WrapS(sentinel, cause error, id MessageID, params ...Param) error {
	return WrapSWithFallback(sentinel, cause, id, CanonicalFallback(id), params...)
}

// WrapSWithFallback 以显式兜底同时绑定分类哨兵、下层根因与参数化上下文消息。
func WrapSWithFallback(sentinel, cause error, id MessageID, fallback string, params ...Param) error {
	return &Error{sentinel: sentinel, msg: ensureErrorMessage(id, fallback, params), cause: cause, valid: true}
}

// WrapSentinel 将底层错误 cause 映射至门面哨兵 sentinel，并置 SuppressInnerID = true
// 以指示展示层 RenderError 在本地化时结构化折叠紧邻的同义内层哨兵。
func WrapSentinel(sentinel, cause error) error {
	if sentinel == nil && cause == nil {
		return E(KeyCommonInvalidArgument)
	}
	return &Error{
		sentinel:        sentinel,
		cause:           cause,
		suppressInnerID: sentinel != nil && cause != nil,
		valid:           true,
	}
}

// ensureErrorMessage 保证错误构造路径严格失败关闭：非法 id 或参数降级为有效通用错误消息，永不产生无效节点。
func ensureErrorMessage(id MessageID, fallback string, params []Param) Message {
	if m := NewMessageWithFallback(id, fallback, params...); m.IsValid() {
		return m
	}
	if m := NewMessageWithFallback(id, fallback); m.IsValid() {
		return m
	}
	return NewMessageWithFallback(KeyCommonInvalidArgument, CanonicalFallback(KeyCommonInvalidArgument))
}

// Error 返回恒定规范英文错误文本（用于日志、审计、事件与机器诊断，零运行期 locale 依赖）。
func (e *Error) Error() string {
	if e == nil || !e.valid {
		return ""
	}
	head := e.canonicalHead()
	if e.cause == nil {
		return head
	}
	return joinCanonicalError(head, e.cause.Error())
}

func (e *Error) canonicalHead() string {
	if e.msg.IsValid() {
		return e.msg.Canonical()
	}
	if e.sentinel != nil {
		return e.sentinel.Error()
	}
	return ""
}

func joinCanonicalError(head, tail string) string {
	if head == "" {
		return tail
	}
	if tail == "" || tail == head {
		return head
	}
	return head + ": " + tail
}

// LocalizableView 返回当前错误节点的只读结构化视图（nil 接收者或无效节点安全返回零值）。
func (e *Error) LocalizableView() ErrorNode {
	if e == nil || !e.valid {
		return ErrorNode{}
	}
	return ErrorNode{
		Sentinel:        e.sentinel,
		Message:         e.msg.clone(),
		Cause:           e.cause,
		IsSentinel:      e.isSentinel,
		SuppressInnerID: e.suppressInnerID,
	}
}

// Unwrap 返回当前错误节点关联的直接下层错误切片（按 Sentinel -> Cause 顺序），完整支持 errors.Is / errors.AsType。
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
