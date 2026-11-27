package i18n

import (
	"math"
	"strconv"
	"time"
	"unicode/utf8"
)

const (
	// MaxMessageDepth 限制通过 ParamKindMessage 嵌套 Message 的最大深度（顶层消息深度为 0）。
	MaxMessageDepth uint8 = 4
	// MaxMessageParams 限制单条 Message 携带的最大参数个数。
	MaxMessageParams = 16
	// MaxParamKeyBytes 限制参数键名与模板占位符键名的最大字节长度。
	MaxParamKeyBytes = 64
	// MaxParamStringBytes 限制单个字符串参数值的最大 UTF-8 字节长度。
	MaxParamStringBytes = 4096
	// MaxTemplateBytes 限制单条消息模板或兜底文本的最大 UTF-8 字节长度。
	MaxTemplateBytes = 8192
	// MaxFloatPrec 限制浮点参数固定小数位数的上限，防止格式化输出爆炸。
	MaxFloatPrec = 15
)

// ParamKind 标识结构化消息参数 Param 的封闭值变体种类；零值 ParamKindInvalid 严格失败关闭。
//
//xops:opaque
//xops:failclosed
type ParamKind uint8

const (
	// ParamKindInvalid 表示未初始化或非法的参数种类（零值失败关闭）。
	ParamKindInvalid ParamKind = 0
	// ParamKindString 表示有界有效 UTF-8 字符串参数。
	ParamKindString ParamKind = 1
	// ParamKindInt64 表示 64 位有符号整数参数。
	ParamKindInt64 ParamKind = 2
	// ParamKindUint64 表示 64 位无符号整数参数。
	ParamKindUint64 ParamKind = 3
	// ParamKindFloat64 表示有限 64 位浮点数参数（拒绝 NaN/±Inf，-0.0 归一化为 0.0）。
	ParamKindFloat64 ParamKind = 4
	// ParamKindBool 表示布尔参数。
	ParamKindBool ParamKind = 5
	// ParamKindDuration 表示纳秒精度时长参数（底层存 durNanos int64）。
	ParamKindDuration ParamKind = 6
	// ParamKindMessage 表示受限深度嵌套的结构化 Message 参数。
	ParamKindMessage ParamKind = 7
)

// IsValid 报告 k 是否为已定义的合法参数种类。
func (k ParamKind) IsValid() bool {
	return k >= ParamKindString && k <= ParamKindMessage
}

// IsZero 报告 k 是否处于零值无效态（ParamKindInvalid）。
func (k ParamKind) IsZero() bool {
	return k == ParamKindInvalid
}

// String 返回规范小写参数种类名称；非法值返回 "invalid"。
func (k ParamKind) String() string {
	switch k {
	case ParamKindString:
		return "string"
	case ParamKindInt64:
		return "int64"
	case ParamKindUint64:
		return "uint64"
	case ParamKindFloat64:
		return "float64"
	case ParamKindBool:
		return "bool"
	case ParamKindDuration:
		return "duration"
	case ParamKindMessage:
		return "message"
	default:
		return "invalid"
	}
}

// Param 表示零 any、零反射、不可变的强类型消息模板参数；零值恒无效并严格失败关闭。
//
// 设计理由：本结构体故意不使用 time.Duration 字段而以 durNanos int64 存储时长，
// 既避免触犯 noimplicit/duration_dto，又可保持零 core/domain/algebraic 依赖。
//
//xops:opaque
//xops:failclosed
type Param struct {
	key       string
	kind      ParamKind
	strVal    string
	intVal    int64
	uintVal   uint64
	floatVal  float64
	floatPrec int
	boolVal   bool
	durNanos  int64
	msgVal    *Message
	valid     bool
}

// Str 构造有界 UTF-8 字符串参数；若键名非法、超长或非有效 UTF-8 则返回无效零值 Param。
func Str(k, v string) Param {
	if !isValidParamKey(k) || len(v) > MaxParamStringBytes || !utf8.ValidString(v) {
		return Param{}
	}
	return Param{key: k, kind: ParamKindString, strVal: v, valid: true}
}

// Int 构造整数参数（内部规范存储为 ParamKindInt64）；若键名非法则返回无效零值 Param。
func Int(k string, v int) Param {
	return Int64(k, int64(v))
}

// Int64 构造 64 位有符号整数参数；若键名非法则返回无效零值 Param。
func Int64(k string, v int64) Param {
	if !isValidParamKey(k) {
		return Param{}
	}
	return Param{key: k, kind: ParamKindInt64, intVal: v, valid: true}
}

// Uint64 构造 64 位无符号整数参数；若键名非法则返回无效零值 Param。
func Uint64(k string, v uint64) Param {
	if !isValidParamKey(k) {
		return Param{}
	}
	return Param{key: k, kind: ParamKindUint64, uintVal: v, valid: true}
}

// Float 构造有限浮点数参数（prec 为 -1 表示最短精确表示，0..MaxFloatPrec 表示固定小数位数）。
// 严格拒绝 NaN、±Inf、越界 prec 与非法键名，并将 -0.0 确定性归一化为 0.0。
func Float(k string, v float64, prec int) Param {
	if !isValidParamKey(k) || math.IsNaN(v) || math.IsInf(v, 0) || prec < -1 || prec > MaxFloatPrec {
		return Param{}
	}
	if v == 0 {
		v = 0
	}
	return Param{key: k, kind: ParamKindFloat64, floatVal: v, floatPrec: prec, valid: true}
}

// Bool 构造布尔参数；若键名非法则返回无效零值 Param。
func Bool(k string, v bool) Param {
	if !isValidParamKey(k) {
		return Param{}
	}
	return Param{key: k, kind: ParamKindBool, boolVal: v, valid: true}
}

// Dur 构造时长参数（以纳秒 int64 存储）；若键名非法则返回无效零值 Param。
func Dur(k string, d time.Duration) Param {
	return DurNanos(k, int64(d))
}

// DurNanos 以显式纳秒 int64 构造时长参数；若键名非法则返回无效零值 Param。
func DurNanos(k string, nanos int64) Param {
	if !isValidParamKey(k) {
		return Param{}
	}
	return Param{key: k, kind: ParamKindDuration, durNanos: nanos, valid: true}
}

// Msg 构造嵌套结构化 Message 参数；若键名非法、m 无效或嵌套后深度超过 MaxMessageDepth 则返回无效零值 Param。
func Msg(k string, m Message) Param {
	if !isValidParamKey(k) || !m.IsValid() || m.depth >= MaxMessageDepth {
		return Param{}
	}
	cloned := m.clone()
	return Param{key: k, kind: ParamKindMessage, msgVal: &cloned, valid: true}
}

// IsValid 报告当前 Param 是否合法有效（零值与越界变体恒返回 false）。
func (p Param) IsValid() bool {
	if !p.valid || !p.kind.IsValid() || !isValidParamKey(p.key) {
		return false
	}
	switch p.kind {
	case ParamKindString:
		return len(p.strVal) <= MaxParamStringBytes && utf8.ValidString(p.strVal)
	case ParamKindFloat64:
		return !math.IsNaN(p.floatVal) && !math.IsInf(p.floatVal, 0) &&
			p.floatPrec >= -1 && p.floatPrec <= MaxFloatPrec &&
			!(p.floatVal == 0 && math.Signbit(p.floatVal))
	case ParamKindMessage:
		return p.msgVal != nil && p.msgVal.IsValid() && p.msgVal.depth < MaxMessageDepth
	default:
		return true
	}
}

// IsZero 报告当前 Param 是否处于无效零值态。
func (p Param) IsZero() bool {
	return !p.IsValid()
}

// Key 返回参数键名；无效 Param 返回空串。
func (p Param) Key() string {
	if !p.IsValid() {
		return ""
	}
	return p.key
}

// Kind 返回参数变体种类；无效 Param 返回 ParamKindInvalid。
func (p Param) Kind() ParamKind {
	if !p.IsValid() {
		return ParamKindInvalid
	}
	return p.kind
}

// StringVal 提取字符串参数值；非有效字符串参数返回 ("", false)。
func (p Param) StringVal() (string, bool) {
	if !p.IsValid() || p.kind != ParamKindString {
		return "", false
	}
	return p.strVal, true
}

// Int64Val 提取 64 位有符号整数参数值；非有效整数参数返回 (0, false)。
func (p Param) Int64Val() (int64, bool) {
	if !p.IsValid() || p.kind != ParamKindInt64 {
		return 0, false
	}
	return p.intVal, true
}

// Uint64Val 提取 64 位无符号整数参数值；非有效无符号整数参数返回 (0, false)。
func (p Param) Uint64Val() (uint64, bool) {
	if !p.IsValid() || p.kind != ParamKindUint64 {
		return 0, false
	}
	return p.uintVal, true
}

// Float64Val 提取有限浮点数参数值；非有效浮点参数返回 (0, false)。
func (p Param) Float64Val() (float64, bool) {
	if !p.IsValid() || p.kind != ParamKindFloat64 {
		return 0, false
	}
	return p.floatVal, true
}

// FloatPrec 提取浮点参数的格式化精度配置；非有效浮点参数返回 (0, false)。
func (p Param) FloatPrec() (int, bool) {
	if !p.IsValid() || p.kind != ParamKindFloat64 {
		return 0, false
	}
	return p.floatPrec, true
}

// BoolVal 提取布尔参数值；非有效布尔参数返回 (false, false)。
func (p Param) BoolVal() (bool, bool) {
	if !p.IsValid() || p.kind != ParamKindBool {
		return false, false
	}
	return p.boolVal, true
}

// DurationVal 提取时长参数值；非有效时长参数返回 (0, false)。
func (p Param) DurationVal() (time.Duration, bool) {
	if !p.IsValid() || p.kind != ParamKindDuration {
		return 0, false
	}
	return time.Duration(p.durNanos), true
}

// DurationNanos 提取时长参数的原始纳秒整数；非有效时长参数返回 (0, false)。
func (p Param) DurationNanos() (int64, bool) {
	if !p.IsValid() || p.kind != ParamKindDuration {
		return 0, false
	}
	return p.durNanos, true
}

// MessageVal 提取嵌套结构化 Message 的深拷贝；非有效消息参数返回 (Message{}, false)。
func (p Param) MessageVal() (Message, bool) {
	if !p.IsValid() || p.kind != ParamKindMessage || p.msgVal == nil {
		return Message{}, false
	}
	return p.msgVal.clone(), true
}

// Equal 执行两个 Param 的深度值相等比较（无效 Param 永不相等，浮点按位精确比对且 -0.0 已归零）。
func (p Param) Equal(o Param) bool {
	if !p.IsValid() || !o.IsValid() || p.key != o.key || p.kind != o.kind {
		return false
	}
	switch p.kind {
	case ParamKindString:
		return p.strVal == o.strVal
	case ParamKindInt64:
		return p.intVal == o.intVal
	case ParamKindUint64:
		return p.uintVal == o.uintVal
	case ParamKindFloat64:
		return p.floatPrec == o.floatPrec && math.Float64bits(p.floatVal) == math.Float64bits(o.floatVal)
	case ParamKindBool:
		return p.boolVal == o.boolVal
	case ParamKindDuration:
		return p.durNanos == o.durNanos
	case ParamKindMessage:
		return p.msgVal != nil && o.msgVal != nil && p.msgVal.Equal(*o.msgVal)
	default:
		return false
	}
}

// FormatCanonical 将参数确定性格式化为规范英文/中性字符串；无效 Param 返回空串。
func (p Param) FormatCanonical() string {
	if !p.IsValid() {
		return ""
	}
	switch p.kind {
	case ParamKindString:
		return p.strVal
	case ParamKindInt64:
		return strconv.FormatInt(p.intVal, 10)
	case ParamKindUint64:
		return strconv.FormatUint(p.uintVal, 10)
	case ParamKindFloat64:
		return strconv.FormatFloat(p.floatVal, 'f', p.floatPrec, 64)
	case ParamKindBool:
		return strconv.FormatBool(p.boolVal)
	case ParamKindDuration:
		return time.Duration(p.durNanos).String()
	case ParamKindMessage:
		return p.msgVal.Canonical()
	default:
		return ""
	}
}

func (p Param) clone() Param {
	cp := p
	if p.msgVal != nil {
		mc := p.msgVal.clone()
		cp.msgVal = &mc
	}
	return cp
}

// isValidParamKey 校验参数键名与占位符名称：长度 1..MaxParamKeyBytes，首字符为 ASCII 字母/数字/下划线，
// 其余字符仅限 ASCII 字母、数字、下划线、点或连字符。
func isValidParamKey(k string) bool {
	if len(k) == 0 || len(k) > MaxParamKeyBytes {
		return false
	}
	for i := range len(k) {
		c := k[i]
		isBase := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
		isSep := i > 0 && (c == '.' || c == '-')
		if !isBase && !isSep {
			return false
		}
	}
	return true
}

// boundDisplayText 将任意外部输入安全裁剪为有效 UTF-8 有界字符串，供内部诊断错误参数使用。
func boundDisplayText(raw string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if !utf8.ValidString(raw) {
		raw = strconv.Quote(raw)
	}
	if len(raw) <= maxBytes {
		return raw
	}
	// 按 rune 边界截断以保证结果恒为合法 UTF-8。
	end := 0
	for idx := range raw {
		if idx > maxBytes {
			break
		}
		end = idx
	}
	return raw[:end]
}
