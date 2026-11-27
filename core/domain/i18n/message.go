package i18n

import (
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxMessageIDBytes = 128

// MessageID 表示强类型国际化消息标识（规范格式：[a-z][a-z0-9_.]*，不含空分段）；
// 零值 MessageIDInvalid（""）严格失败关闭。
//
// 设计理由：本类型不标注 //xops:opaque，以便根模块 internal/i18n 可声明根模块专属 MessageID 常量，
// 其全仓声明与传递完整性由 xopsvet/i18nguard 规则 1 静态强制。
//
//xops:failclosed
type MessageID string

// MessageIDInvalid 表示未初始化的无效消息标识，零值严格失败关闭。
const MessageIDInvalid MessageID = ""

// IsValid 报告 id 是否为非空规范小写点分/下划线标识符（[a-z][a-z0-9_.]* 且不含连续或尾部点号）。
func (id MessageID) IsValid() bool {
	s := string(id)
	if len(s) == 0 || len(s) > maxMessageIDBytes || s[0] < 'a' || s[0] > 'z' || s[len(s)-1] == '.' {
		return false
	}
	prevDot := false
	for i := range len(s) {
		c := s[i]
		if c == '.' {
			if prevDot {
				return false
			}
			prevDot = true
			continue
		}
		prevDot = false
		isAllowed := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
		if !isAllowed {
			return false
		}
	}
	return true
}

// IsZero 报告 id 是否为零值无效标识（MessageIDInvalid）。
func (id MessageID) IsZero() bool {
	return id == MessageIDInvalid
}

// String 返回底层字符串标识。
func (id MessageID) String() string {
	return string(id)
}

// Message 表示延迟渲染的不可变结构化国际化消息（零 Locale 感知、零仓内依赖）；
// 零值恒无效并严格失败关闭。
//
// 计数语义采用 count int64 + hasCount bool（不依赖 core/domain/algebraic.Option），
// 以保障 core/domain/i18n 作为绝对叶包无循环导入。
//
//xops:opaque
//xops:failclosed
type Message struct {
	id       MessageID
	fallback string
	params   []Param
	count    int64
	hasCount bool
	depth    uint8
	valid    bool
}

// NewMessage 以 id 与强类型参数构造不可变结构化消息，自动从 CanonicalFallback(id) 填充规范英文兜底模板。
func NewMessage(id MessageID, params ...Param) Message {
	return NewMessageWithFallback(id, CanonicalFallback(id), params...)
}

// NewMessageWithFallback 以显式规范英文兜底模板构造不可变结构化消息（供根模块 internal/i18n 专属 Key 使用）。
// 若 id 非法、fallback 非法或超长、参数超限/重复/无效或嵌套超深，均失败关闭返回零值 Message。
func NewMessageWithFallback(id MessageID, fallback string, params ...Param) Message {
	return buildMessage(id, fallback, false, 0, params)
}

// NewPluralMessage 构造携带复数计数 count 的不可变结构化消息，自动填充 CanonicalFallback(id)。
func NewPluralMessage(id MessageID, count int64, params ...Param) Message {
	return NewPluralMessageWithFallback(id, CanonicalFallback(id), count, params...)
}

// NewPluralMessageWithFallback 以显式兜底模板与复数计数 count 构造不可变结构化消息。
func NewPluralMessageWithFallback(id MessageID, fallback string, count int64, params ...Param) Message {
	return buildMessage(id, fallback, true, count, params)
}

func buildMessage(id MessageID, fallback string, hasCount bool, count int64, params []Param) Message {
	if !id.IsValid() || len(fallback) > MaxTemplateBytes || !utf8.ValidString(fallback) || len(params) > MaxMessageParams {
		return Message{}
	}
	cloned, depth, ok := cloneValidatedParams(params)
	if !ok {
		return Message{}
	}
	return Message{
		id:       id,
		fallback: fallback,
		params:   cloned,
		count:    count,
		hasCount: hasCount,
		depth:    depth,
		valid:    true,
	}
}

func cloneValidatedParams(params []Param) ([]Param, uint8, bool) {
	if len(params) == 0 {
		return nil, 0, true
	}
	out := make([]Param, 0, len(params))
	var maxDepth uint8
	for _, p := range params {
		if !p.IsValid() || hasParamKey(out, p.key) {
			return nil, 0, false
		}
		if p.kind == ParamKindMessage {
			childDepth := p.msgVal.depth + 1
			if childDepth > MaxMessageDepth {
				return nil, 0, false
			}
			if childDepth > maxDepth {
				maxDepth = childDepth
			}
		}
		out = append(out, p.clone())
	}
	return out, maxDepth, true
}

func hasParamKey(items []Param, key string) bool {
	for _, item := range items {
		if item.key == key {
			return true
		}
	}
	return false
}

// IsValid 报告 m 是否为合法构造的有效 Message（零值恒返回 false）。
func (m Message) IsValid() bool {
	return m.valid && m.id.IsValid() && m.depth <= MaxMessageDepth && len(m.params) <= MaxMessageParams
}

// IsZero 报告 m 是否处于无效零值态。
func (m Message) IsZero() bool {
	return !m.IsValid()
}

// ID 返回消息标识；无效 Message 返回 MessageIDInvalid。
func (m Message) ID() MessageID {
	if !m.IsValid() {
		return MessageIDInvalid
	}
	return m.id
}

// Fallback 返回规范英文兜底模板；无效 Message 返回空串。
func (m Message) Fallback() string {
	if !m.IsValid() {
		return ""
	}
	return m.fallback
}

// Count 返回复数计数及是否显式设置了计数；非复数或无效 Message 返回 (0, false)。
func (m Message) Count() (int64, bool) {
	if !m.IsValid() || !m.hasCount {
		return 0, false
	}
	return m.count, true
}

// Depth 返回当前消息的嵌套深度（无嵌套消息参数时为 0）；无效 Message 返回 0。
func (m Message) Depth() uint8 {
	if !m.IsValid() {
		return 0
	}
	return m.depth
}

// ParamCount 返回参数个数；无效 Message 返回 0。
func (m Message) ParamCount() int {
	if !m.IsValid() {
		return 0
	}
	return len(m.params)
}

// Params 返回参数列表的深拷贝切片，确保外部修改不影响 Message 不可变性。
func (m Message) Params() []Param {
	if !m.IsValid() || len(m.params) == 0 {
		return nil
	}
	out := make([]Param, len(m.params))
	for i, p := range m.params {
		out[i] = p.clone()
	}
	return out
}

// ParamByKey 按键名查找并返回参数的深拷贝；未命中或消息无效时返回 (Param{}, false)。
func (m Message) ParamByKey(key string) (Param, bool) {
	if !m.IsValid() || key == "" {
		return Param{}, false
	}
	for _, p := range m.params {
		if p.key == key {
			return p.clone(), true
		}
	}
	return Param{}, false
}

// Equal 执行两个 Message 的深度值相等比较（支撑 core/ports 非 comparable 结构体比对；无效消息永不相等）。
func (m Message) Equal(o Message) bool {
	if !m.IsValid() || !o.IsValid() {
		return false
	}
	if m.id != o.id || m.fallback != o.fallback || m.hasCount != o.hasCount || m.depth != o.depth || len(m.params) != len(o.params) {
		return false
	}
	if m.hasCount && m.count != o.count {
		return false
	}
	for i := range m.params {
		if !m.params[i].Equal(o.params[i]) {
			return false
		}
	}
	return true
}

// Canonical 将消息渲染为确定性规范英文文本（供 err.Error()、审计、事件与兜底回退使用）。
// 无效 Message 返回空串；兜底模板为空时降级返回 string(m.id)。
func (m Message) Canonical() string {
	if !m.IsValid() {
		return ""
	}
	if m.fallback == "" {
		return string(m.id)
	}
	return FormatTemplate(m.fallback, m.resolveCanonicalParam)
}

func (m Message) resolveCanonicalParam(key string) (string, bool) {
	for _, p := range m.params {
		if p.key == key {
			return p.FormatCanonical(), true
		}
	}
	if key == "count" && m.hasCount {
		return strconv.FormatInt(m.count, 10), true
	}
	return "", false
}

func (m Message) clone() Message {
	cp := m
	if len(m.params) > 0 {
		cp.params = make([]Param, len(m.params))
		for i, p := range m.params {
			cp.params[i] = p.clone()
		}
	}
	return cp
}

// FormatTemplate 对模板执行单遍零反射 {key} 占位符替换，支持 {{ 与 }} 转义为字面花括号。
// 缺失键值或 resolve 为 nil 时原样保留 "{key}"；畸形花括号片段按字面安全输出，永不 panic。
func FormatTemplate(tmpl string, resolve func(string) (string, bool)) string {
	if !strings.ContainsAny(tmpl, "{}") {
		return tmpl
	}
	var b strings.Builder
	b.Grow(len(tmpl))
	for i := 0; i < len(tmpl); {
		switch tmpl[i] {
		case '{':
			if i+1 < len(tmpl) && tmpl[i+1] == '{' {
				b.WriteByte('{')
				i += 2
				continue
			}
			rep, next, ok := consumeFormatPlaceholder(tmpl, i, resolve)
			if ok {
				b.WriteString(rep)
				i = next
				continue
			}
			b.WriteByte('{')
			i++
		case '}':
			if i+1 < len(tmpl) && tmpl[i+1] == '}' {
				b.WriteByte('}')
				i += 2
				continue
			}
			b.WriteByte('}')
			i++
		default:
			b.WriteByte(tmpl[i])
			i++
		}
	}
	return b.String()
}

func consumeFormatPlaceholder(tmpl string, start int, resolve func(string) (string, bool)) (string, int, bool) {
	end := findPlaceholderEnd(tmpl, start+1)
	if end < 0 {
		return "", 0, false
	}
	key := tmpl[start+1 : end]
	if !isValidParamKey(key) {
		return "", 0, false
	}
	if resolve != nil {
		if val, found := resolve(key); found {
			return val, end + 1, true
		}
	}
	return tmpl[start : end+1], end + 1, true
}

// findPlaceholderEnd 从 '{' 之后扫描对应 '}'；若先遇到另一 '{' 或末尾则返回 -1。
func findPlaceholderEnd(tmpl string, from int) int {
	for j := from; j < len(tmpl); j++ {
		if tmpl[j] == '{' {
			return -1
		}
		if tmpl[j] == '}' {
			return j
		}
	}
	return -1
}

// ExtractPlaceholders 严格校验模板语法并提取升序去重后的占位符键名集合。
// 拒绝非 UTF-8、超长模板、未转义 '}'、未闭合 '{' 以及非法占位符键名，失败时返回包装 ErrInvalidTemplate 的错误。
func ExtractPlaceholders(tmpl string) ([]string, error) {
	keys, errID, badKey := parsePlaceholderKeys(tmpl)
	if errID != MessageIDInvalid {
		if errID == KeyTemplateBadKey {
			return nil, EF(ErrInvalidTemplate, errID, Str("key", BoundDisplayText(badKey, MaxParamKeyBytes)))
		}
		return nil, EF(ErrInvalidTemplate, errID)
	}
	return keys, nil
}

// parsePlaceholderKeys 执行无哨兵依赖的纯模板占位符扫描（供 ExtractPlaceholders 与 ensureErrorMessage 共享，
// 避免包级哨兵初始化路径与 ErrInvalidTemplate 形成编译期初始化环）。
func parsePlaceholderKeys(tmpl string) ([]string, MessageID, string) {
	if len(tmpl) > MaxTemplateBytes || !utf8.ValidString(tmpl) {
		return nil, KeyTemplateInvalid, ""
	}
	var keys []string
	for i := 0; i < len(tmpl); {
		key, next, hasKey, errID, badKey := stepParsePlaceholder(tmpl, i)
		if errID != MessageIDInvalid {
			return nil, errID, badKey
		}
		if hasKey {
			keys = append(keys, key)
		}
		i = next
	}
	slices.Sort(keys)
	return slices.Compact(keys), MessageIDInvalid, ""
}

func stepParsePlaceholder(tmpl string, i int) (string, int, bool, MessageID, string) {
	switch tmpl[i] {
	case '{':
		if i+1 < len(tmpl) && tmpl[i+1] == '{' {
			return "", i + 2, false, MessageIDInvalid, ""
		}
		key, next, errID, badKey := parseStrictPlaceholderKey(tmpl, i)
		return key, next, errID == MessageIDInvalid, errID, badKey
	case '}':
		if i+1 < len(tmpl) && tmpl[i+1] == '}' {
			return "", i + 2, false, MessageIDInvalid, ""
		}
		return "", 0, false, KeyTemplateUnescaped, ""
	default:
		return "", i + 1, false, MessageIDInvalid, ""
	}
}

func parseStrictPlaceholderKey(tmpl string, start int) (string, int, MessageID, string) {
	end := findPlaceholderEnd(tmpl, start+1)
	if end < 0 {
		return "", 0, KeyTemplateUnclosed, ""
	}
	key := tmpl[start+1 : end]
	if !isValidParamKey(key) {
		return "", 0, KeyTemplateBadKey, key
	}
	return key, end + 1, MessageIDInvalid, ""
}
