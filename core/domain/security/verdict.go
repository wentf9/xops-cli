package security

import "cmp"

// Verdict 表示失败关闭的二值安全判定交半格（INV-E1 / RFC §3.6）：
// 零值恒为 VerdictDeny（0，吸收底元）；仅显式 VerdictAllow（1）代表放行（单位顶元）；越界值一律视为拒绝。
//
//xops:opaque
//xops:failclosed
type Verdict uint8

const (
	VerdictDeny  Verdict = 0 // 零值失败关闭判定（交半格吸收底元）
	VerdictAllow Verdict = 1 // 显式允许执行（交半格单位顶元）
)

// ParseVerdict 严格解析规范小写判定文本（"deny" 或 "allow"）；其余输入一律失败关闭。
func ParseVerdict(raw string) (Verdict, error) {
	return parseEnumByName(raw, VerdictDeny, VerdictAllow, VerdictDeny, Verdict.String, ErrInvalidVerdict)
}

// IsValid 报告 v 是否为已定义的合法 Verdict。
func (v Verdict) IsValid() bool { return v == VerdictDeny || v == VerdictAllow }

// IsZero 报告 v 是否处于零值拒绝态（VerdictDeny）。
func (v Verdict) IsZero() bool { return v == VerdictDeny }

// Allowed 报告 v 是否为显式 VerdictAllow（零值与越界值恒返回 false）。
func (v Verdict) Allowed() bool { return v == VerdictAllow }

// Denied 报告 v 是否拒绝执行（含零值与一切非法越界值）。
func (v Verdict) Denied() bool { return v != VerdictAllow }

// Normalize 将非法越界底层值折叠为 VerdictDeny，合法值保持不变。
func (v Verdict) Normalize() Verdict { return pickIf(v == VerdictAllow, VerdictAllow, VerdictDeny) }

// Meet 计算交半格下确界：仅双方均为 VerdictAllow 时返回 VerdictAllow，否则返回 VerdictDeny。
func (v Verdict) Meet(other Verdict) Verdict {
	return pickIf(v == VerdictAllow && other == VerdictAllow, VerdictAllow, VerdictDeny)
}

// Compare 定义 Verdict 上的确定性全序（VerdictDeny/非法值 < VerdictAllow）。
func (v Verdict) Compare(other Verdict) int { return cmp.Compare(v.Normalize(), other.Normalize()) }

// String 返回规范小写文本（"deny"、"allow"）；非法越界值返回 "deny(invalid)"。
func (v Verdict) String() string { return enumName(uint8(v), "deny(invalid)", "deny", "allow") }

// AppendText 实现 encoding.TextAppender（值接收者）；对非法越界值失败关闭。
func (v Verdict) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, v.IsValid(), v.String(), ErrInvalidVerdict, uint8(v))
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (v Verdict) MarshalText() ([]byte, error) { return v.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；解析失败时重置为 VerdictDeny 并失败关闭。
func (v *Verdict) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(v, VerdictDeny, text, ParseVerdict)
}

// FoldVerdicts 对一组判定执行顺序无关的交半格折叠；空输入严格失败关闭返回 VerdictDeny。
func FoldVerdicts(verdicts ...Verdict) Verdict {
	if len(verdicts) == 0 {
		return VerdictDeny
	}
	acc := VerdictAllow
	for _, item := range verdicts {
		if acc = acc.Meet(item); acc == VerdictDeny {
			return VerdictDeny
		}
	}
	return acc
}

// VerdictFromError 将 (Verdict, error) 折叠为纯 Verdict：任意非 nil 错误或非 VerdictAllow 值均返回 VerdictDeny。
func VerdictFromError(v Verdict, err error) Verdict {
	return pickIf(err == nil && v == VerdictAllow, VerdictAllow, VerdictDeny)
}

// Decide 同步执行安全判定闭包 fn，并将 nil 闭包、任意错误或非 VerdictAllow 值失败关闭为 VerdictDeny。
//
//xops:syncclosure
func Decide(fn func() (Verdict, error)) Verdict {
	if fn == nil {
		return VerdictDeny
	}
	return VerdictFromError(fn())
}
