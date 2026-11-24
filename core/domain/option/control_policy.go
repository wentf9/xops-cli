package option

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
)

// ControlMasterMode、ControlPathKind 与 ControlPersistKind 为多路复用枚举；零值代表未设置。
//
//xops:failclosed
type ControlMasterMode uint8

//xops:failclosed
type ControlPathKind uint8

//xops:failclosed
type ControlPersistKind uint8

const (
	ControlMasterUnset ControlMasterMode = iota
	ControlMasterNo
	ControlMasterYes
	ControlMasterAsk
	ControlMasterAuto
	ControlMasterAutoAsk
)
const (
	ControlPathUnset ControlPathKind = iota
	ControlPathDisabled
	ControlPathTemplate
	ControlPathLiteral
)
const (
	ControlPersistUnset ControlPersistKind = iota
	ControlPersistNo
	ControlPersistIndefinite
	ControlPersistTimeout
)

// ParseControlMasterMode 解析 ControlMaster（no/false/yes/true/ask/auto/autoask）。
func ParseControlMasterMode(raw string) (ControlMasterMode, error) {
	if !hasForbiddenControlChar(raw) {
		if m, ok := map[string]ControlMasterMode{
			"no": ControlMasterNo, "false": ControlMasterNo, "yes": ControlMasterYes,
			"true": ControlMasterYes, "ask": ControlMasterAsk, "auto": ControlMasterAuto, "autoask": ControlMasterAutoAsk,
		}[strings.ToLower(strings.TrimSpace(raw))]; ok {
			return m, nil
		}
	}
	return ControlMasterUnset, fmt.Errorf("%w: 无效 ControlMaster %q", ErrInvalidControlPolicy, raw)
}
func (m ControlMasterMode) IsSet() bool { return m >= ControlMasterNo && m <= ControlMasterAutoAsk }
func (m ControlMasterMode) String() string {
	return enumName(uint8(m), "no", "yes", "ask", "auto", "autoask")
}
func (m ControlMasterMode) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, m.String(), m.IsSet(), ErrInvalidControlPolicy)
}
func (m ControlMasterMode) MarshalText() ([]byte, error) { return m.AppendText(nil) }
func (m *ControlMasterMode) UnmarshalText(text []byte) error {
	return unmarshalTextVia(m, text, ParseControlMasterMode)
}

// ControlPathSpec 表示不可变的 ControlPath 规格值对象。
//
//xops:opaque
//xops:failclosed
type ControlPathSpec struct {
	kind ControlPathKind
	raw  string
}

// UnsetControlPath、DisabledControlPath、ParseControlPath、NewLiteralControlPath 及只读访问器。
func UnsetControlPath() ControlPathSpec    { return ControlPathSpec{} }
func DisabledControlPath() ControlPathSpec { return ControlPathSpec{ControlPathDisabled, "none"} }
func ParseControlPath(raw string) (ControlPathSpec, error) {
	return parseControlPathInternal(raw, false)
}
func NewLiteralControlPath(raw string) (ControlPathSpec, error) {
	return parseControlPathInternal(raw, true)
}
func (s ControlPathSpec) Kind() ControlPathKind { return s.kind }
func (s ControlPathSpec) IsUnset() bool         { return s.kind == ControlPathUnset }
func (s ControlPathSpec) IsDisabled() bool      { return s.kind == ControlPathDisabled }
func (s ControlPathSpec) IsEnabled() bool {
	return s.kind == ControlPathTemplate || s.kind == ControlPathLiteral
}
func (s ControlPathSpec) IsLiteral() bool              { return s.kind == ControlPathLiteral }
func (s ControlPathSpec) String() string               { return s.raw }
func (s ControlPathSpec) Equal(o ControlPathSpec) bool { return s.kind == o.kind && s.raw == o.raw }

func parseControlPathInternal(raw string, literal bool) (ControlPathSpec, error) {
	t := strings.TrimSpace(raw)
	if hasForbiddenControlChar(raw) || t == "" || len(raw) > maxTokenLen {
		return ControlPathSpec{}, fmt.Errorf("%w: ControlPath %q 非法", ErrInvalidControlPolicy, raw)
	}
	if isNoneKeyword(t) {
		return DisabledControlPath(), nil
	}
	if literal {
		return ControlPathSpec{ControlPathLiteral, raw}, nil
	}
	if err := validateTemplateTokens(t, allowedPathPercentTokens, true); err != nil {
		return ControlPathSpec{}, fmt.Errorf("%w: ControlPath 占位符非法: %w", ErrInvalidControlPolicy, err)
	}
	return ControlPathSpec{ControlPathTemplate, t}, nil
}

// ControlPersistSpec 表示不可变的 ControlPersist 规格，严格使用 algebraic.Duration（零裸 time.Duration）。
//
//xops:opaque
//xops:failclosed
type ControlPersistSpec struct {
	kind    ControlPersistKind
	timeout algebraic.Duration
}

// UnsetControlPersist、DisabledControlPersist、IndefiniteControlPersist、TimeoutControlPersist 与 ParseControlPersist 构造驻留规格。
func UnsetControlPersist() ControlPersistSpec    { return ControlPersistSpec{} }
func DisabledControlPersist() ControlPersistSpec { return ControlPersistSpec{kind: ControlPersistNo} }
func IndefiniteControlPersist() ControlPersistSpec {
	return ControlPersistSpec{kind: ControlPersistIndefinite}
}
func TimeoutControlPersist(d algebraic.Duration) (ControlPersistSpec, error) {
	if !d.IsPositive() || d.Std()%time.Second != 0 {
		return ControlPersistSpec{}, fmt.Errorf("%w: 时长 %s 须为正整秒", ErrInvalidControlPolicy, d.String())
	}
	return ControlPersistSpec{ControlPersistTimeout, d}, nil
}
func ParseControlPersist(raw string) (ControlPersistSpec, error) {
	t := strings.TrimSpace(raw)
	if hasForbiddenControlChar(raw) || t == "" {
		return ControlPersistSpec{}, fmt.Errorf("%w: ControlPersist %q 无效", ErrInvalidControlPolicy, raw)
	}
	if spec, ok := map[string]ControlPersistSpec{
		"no": DisabledControlPersist(), "false": DisabledControlPersist(),
		"yes": IndefiniteControlPersist(), "true": IndefiniteControlPersist(),
	}[strings.ToLower(t)]; ok {
		return spec, nil
	}
	d, err := parseOpenSSHDuration(t)
	if err != nil {
		return ControlPersistSpec{}, fmt.Errorf("%w: %w", ErrInvalidControlPolicy, err)
	}
	if d.IsZero() {
		return IndefiniteControlPersist(), nil
	}
	return TimeoutControlPersist(d)
}

func parseNonNegativeOpenSSHDuration(raw string, allowNone bool) (algebraic.Duration, error) {
	if t := strings.TrimSpace(raw); allowNone && !hasForbiddenControlChar(raw) && isNoneKeyword(t) {
		return algebraic.ZeroDuration(), nil
	}
	d, err := parseOpenSSHDuration(raw)
	if err != nil {
		return algebraic.ZeroDuration(), fmt.Errorf("%w: %w", ErrInvalidOption, err)
	}
	return d, nil
}
func parseOpenSSHDuration(raw string) (algebraic.Duration, error) {
	s := strings.TrimSpace(raw)
	if hasForbiddenControlChar(raw) || s == "" {
		return algebraic.ZeroDuration(), fmt.Errorf("非法时长 %q", raw)
	}
	const maxDur = time.Duration(math.MaxInt64)
	var total time.Duration
	for rem := s; len(rem) > 0; {
		part, next, err := parseOpenSSHDurationSegment(rem, s, maxDur)
		if err != nil || total > maxDur-part {
			return algebraic.ZeroDuration(), fmt.Errorf("时长解析失败或溢出 %q", s)
		}
		total, rem = total+part, next
	}
	return algebraic.FromStdDuration(total), nil
}
func parseOpenSSHDurationSegment(rem, full string, maxDur time.Duration) (time.Duration, string, error) {
	i := strings.IndexFunc(rem, func(r rune) bool { return r < '0' || r > '9' })
	if i < 0 {
		i = len(rem)
	}
	n, err := strconv.ParseInt(rem[:i], 10, 64)
	if i == 0 || err != nil || n < 0 {
		return 0, "", fmt.Errorf("非法时长 %q", full)
	}
	rest, unit := rem[i:], time.Second
	if len(rest) > 0 {
		idx := strings.IndexByte("smhdw", rest[0]|0x20)
		if idx < 0 {
			return 0, "", fmt.Errorf("未知单位 %q", rest[0])
		}
		unit, rest = [5]time.Duration{time.Second, time.Minute, time.Hour, 24 * time.Hour, 7 * 24 * time.Hour}[idx], rest[1:]
	}
	if n > int64(maxDur/unit) {
		return 0, "", fmt.Errorf("时长溢出 %q", full)
	}
	return time.Duration(n) * unit, rest, nil
}

// ControlPersistSpec 只读访问器与文本编解码方法。
func (p ControlPersistSpec) Kind() ControlPersistKind { return p.kind }
func (p ControlPersistSpec) IsUnset() bool            { return p.kind == ControlPersistUnset }
func (p ControlPersistSpec) IsIndefinite() bool       { return p.kind == ControlPersistIndefinite }
func (p ControlPersistSpec) IsEnabled() bool {
	return p.kind == ControlPersistIndefinite || p.kind == ControlPersistTimeout
}
func (p ControlPersistSpec) Timeout() (algebraic.Duration, bool) {
	return p.timeout, p.kind == ControlPersistTimeout
}
func (p ControlPersistSpec) Equal(o ControlPersistSpec) bool {
	return p.kind == o.kind && p.timeout.Equal(o.timeout)
}
func (p ControlPersistSpec) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, p.String(), !p.IsUnset(), ErrInvalidControlPolicy)
}
func (p ControlPersistSpec) MarshalText() ([]byte, error) { return p.AppendText(nil) }
func (p *ControlPersistSpec) UnmarshalText(text []byte) error {
	return unmarshalTextVia(p, text, ParseControlPersist)
}
func (p ControlPersistSpec) String() string {
	if p.kind == ControlPersistTimeout {
		return strconv.FormatInt(int64(p.timeout.Std()/time.Second), 10) + "s"
	}
	return enumName(uint8(p.kind), "no", "yes")
}

// ControlPolicy 表示多路复用策略三槽 FirstWins 直积幺半群（ControlMaster × ControlPath × ControlPersist）。
// Compose 保留原始三槽维持结合律与 ssh -G 对齐；运行期投影 EffectiveMaster/EffectivePersist 在 !IsEnabled() 时一律归零。
//
//xops:opaque
//xops:failclosed
type ControlPolicy struct {
	master  algebraic.FirstWins[ControlMasterMode]
	path    ControlPathSpec
	persist ControlPersistSpec
}

// UnsetControlPolicy 及不可变槽位构造器、只读访问器、运行期投影、Compose 与 FoldControlPolicies。
func UnsetControlPolicy() ControlPolicy { return ControlPolicy{} }
func (c ControlPolicy) WithMaster(m ControlMasterMode) ControlPolicy {
	setFW(&c.master, m, m.IsSet())
	return c
}
func (c ControlPolicy) WithPath(p ControlPathSpec) ControlPolicy {
	return ControlPolicy{path: p}.Compose(c)
}
func (c ControlPolicy) WithPersist(p ControlPersistSpec) ControlPolicy {
	return ControlPolicy{persist: p}.Compose(c)
}
func (c ControlPolicy) Master() ControlMasterMode   { return c.master.OrElse(ControlMasterUnset) }
func (c ControlPolicy) Path() ControlPathSpec       { return c.path }
func (c ControlPolicy) Persist() ControlPersistSpec { return c.persist }
func (c ControlPolicy) IsUnset() bool {
	return c.master.IsUnset() && c.path.IsUnset() && c.persist.IsUnset()
}
func (c ControlPolicy) IsZero() bool     { return c.IsUnset() }
func (c ControlPolicy) IsEnabled() bool  { return c.path.IsEnabled() }
func (c ControlPolicy) IsDisabled() bool { return c.path.IsDisabled() }
func (c ControlPolicy) Equal(o ControlPolicy) bool {
	return algebraic.EqualFirstWins(c.master, o.master) && c.path.Equal(o.path) && c.persist.Equal(o.persist)
}
func FoldControlPolicies(layers ...ControlPolicy) ControlPolicy {
	return foldMonoid(UnsetControlPolicy(), ControlPolicy.Compose, layers)
}
func (c ControlPolicy) EffectiveMaster() ControlMasterMode {
	if !c.IsEnabled() {
		return ControlMasterNo
	}
	return c.master.OrElse(ControlMasterNo)
}
func (c ControlPolicy) EffectivePersist() ControlPersistSpec {
	if !c.IsEnabled() || c.persist.IsUnset() {
		return DisabledControlPersist()
	}
	return c.persist
}
func (c ControlPolicy) Compose(lower ControlPolicy) ControlPolicy {
	out := ControlPolicy{c.master.Combine(lower.master), c.path, c.persist}
	if out.path.IsUnset() {
		out.path = lower.path
	}
	if out.persist.IsUnset() {
		out.persist = lower.persist
	}
	return out
}
