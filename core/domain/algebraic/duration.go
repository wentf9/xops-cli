package algebraic

import (
	"cmp"
	"encoding"
	"math"
	"time"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

var (
	_ encoding.TextAppender    = Duration{}
	_ encoding.TextMarshaler   = Duration{}
	_ encoding.TextUnmarshaler = (*Duration)(nil)
)

// Duration 是面向持久化与跨协议序列化（Go 1.27 encoding/json/v2 与 YAML）的不透明时长值对象。
//
// 设计理由（ADR-001 / RFC §3.5）：Go 1.27 的 encoding/json/v2 对裸 time.Duration 默认返回 SemanticError；
// 本类型以值接收者同时实现 encoding.TextAppender 与 encoding.TextMarshaler，使结构体字段、切片及
// map[K]Duration 在 JSON/v2 与 YAML 中均能无损、确定性地以标准 Go 时长文本（如 "30s"、"1h5m"、"0s"）往返。
// 零值代表 0s（加法幺半群单位元）；若需区分“未配置”与“显式 0s”，请使用 Option[Duration] 或 FirstWins[Duration]。
//
//xops:opaque
type Duration struct {
	raw time.Duration
}

// ZeroDuration 返回表示零时长（0s）的 Duration。
func ZeroDuration() Duration {
	return Duration{}
}

// FromStdDuration 将标准库 time.Duration 无损封装为 Duration。
func FromStdDuration(d time.Duration) Duration {
	return Duration{raw: d}
}

// ParseDuration 解析标准 Go 时长文本（如 "500ms"、"30s"、"1h30m"、"-5s"、"0s"）为 Duration。
// 空串、含空白字符或非法单位均严格失败关闭，返回包装 ErrInvalidDuration 的错误。
func ParseDuration(raw string) (Duration, error) {
	if raw == "" {
		return Duration{}, domi18n.EF(ErrInvalidDuration, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "duration"))
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return Duration{}, domi18n.WrapS(ErrInvalidDuration, err, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "duration"), domi18n.BoundStr("value", raw))
	}
	return Duration{raw: d}, nil
}

// Std 返回底层标准库 time.Duration 值，供运行期定时器或纯数学计算消费。
func (d Duration) Std() time.Duration {
	return d.raw
}

// String 返回标准 Go 时长字符串表示（如 "0s"、"1m30s"）。
func (d Duration) String() string {
	return d.raw.String()
}

// IsZero 报告当前时长是否为 0s（配合 encoding/json/v2 omitzero）。
func (d Duration) IsZero() bool {
	return d.raw == 0
}

// IsPositive 报告当前时长是否严格大于 0。
func (d Duration) IsPositive() bool {
	return d.raw > 0
}

// IsNegative 报告当前时长是否严格小于 0。
func (d Duration) IsNegative() bool {
	return d.raw < 0
}

// Equal 比较两个 Duration 是否完全相等。
func (d Duration) Equal(other Duration) bool {
	return d.raw == other.raw
}

// Compare 按纳秒大小比较两个 Duration（返回 -1、0 或 +1）。
func (d Duration) Compare(other Duration) int {
	return cmp.Compare(d.raw, other.raw)
}

// CheckedAdd 执行防溢出的时长加法；若结果超出 int64 纳秒表示范围，则失败关闭返回 ErrDurationOverflow。
func (d Duration) CheckedAdd(other Duration) (Duration, error) {
	a, b := int64(d.raw), int64(other.raw)
	if b > 0 && a > math.MaxInt64-b {
		return Duration{}, ErrDurationOverflow
	}
	if b < 0 && a < math.MinInt64-b {
		return Duration{}, ErrDurationOverflow
	}
	return Duration{raw: time.Duration(a + b)}, nil
}

// AppendText 实现 encoding.TextAppender（值接收者），将标准时长文本追加到 b 且绝不修改 b 原有前缀。
func (d Duration) AppendText(b []byte) ([]byte, error) {
	return append(b, d.raw.String()...), nil
}

// MarshalText 实现 encoding.TextMarshaler（值接收者），语义与 AppendText(nil) 完全一致。
func (d Duration) MarshalText() ([]byte, error) {
	return d.AppendText(nil)
}

// UnmarshalText 实现 encoding.TextUnmarshaler，解析标准时长文本；失败时重置为零值并失败关闭。
func (d *Duration) UnmarshalText(text []byte) error {
	if d == nil {
		return ErrNilReceiver
	}
	parsed, err := ParseDuration(string(text))
	if err != nil {
		*d = Duration{}
		return err
	}
	*d = parsed
	return nil
}
