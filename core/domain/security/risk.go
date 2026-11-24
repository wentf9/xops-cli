package security

import "cmp"

// RiskLevel 表示操作风险等级与审批阈值使用的有界安全格（RFC §3.6）：
// 零值恒为 RiskUnknown（0），在操作风险并半格 Join 与阈值严苛度并半格 StrictestThreshold 中均充当最高吸收顶元，
// 绝不静默视作低风险，且序列化边界严格拒绝 RiskUnknown。
//
//xops:opaque
//xops:failclosed
type RiskLevel uint8

const (
	RiskUnknown   RiskLevel = iota // 零值未设置/未知风险（全格吸收态，严禁视作低风险）
	RiskSafe                       // 只读无副作用低风险（操作风险并半格单位底元）
	RiskModerate                   // 可恢复写操作或受保护路径读取（中等风险）
	RiskDangerous                  // 破坏性写、任意命令执行、盘符根或高危隧道（最高有效风险）
)

// ParseRiskLevel 严格解析规范小写风险等级文本（"safe"、"moderate"、"dangerous"）。
func ParseRiskLevel(raw string) (RiskLevel, error) {
	return parseEnumByName(raw, RiskSafe, RiskDangerous, RiskUnknown, RiskLevel.String, ErrInvalidRiskLevel)
}

// IsValid 报告 r 是否为明确有效的业务风险等级（RiskSafe / RiskModerate / RiskDangerous）。
func (r RiskLevel) IsValid() bool { return r >= RiskSafe && r <= RiskDangerous }

// IsZero 报告 r 是否处于零值未设置态（RiskUnknown）。
func (r RiskLevel) IsZero() bool { return r == RiskUnknown }

// Normalize 将非法越界底层值折叠为 RiskUnknown，合法值保持不变。
func (r RiskLevel) Normalize() RiskLevel { return pickIf(r.IsValid(), r, RiskUnknown) }

// SeverityRank 返回操作风险严重度全序秩（Safe=1 < Moderate=2 < Dangerous=3 < Unknown/非法=4）。
func (r RiskLevel) SeverityRank() uint8 { return pickIf(r.IsValid(), uint8(r), 4) }

// ThresholdStrictnessRank 返回审批阈值严苛度全序秩（Dangerous=1 < Moderate=2 < Safe=3 < Unknown/非法=4）。
func (r RiskLevel) ThresholdStrictnessRank() uint8 { return pickIf(r.IsValid(), 4-uint8(r), 4) }

// CompareSeverity 按操作严重度顺序比较两个 RiskLevel。
func (r RiskLevel) CompareSeverity(other RiskLevel) int {
	return cmp.Compare(r.SeverityRank(), other.SeverityRank())
}

// CompareThresholdStrictness 按审批阈值严苛度顺序比较两个 RiskLevel。
func (r RiskLevel) CompareThresholdStrictness(other RiskLevel) int {
	return cmp.Compare(r.ThresholdStrictnessRank(), other.ThresholdStrictnessRank())
}

// Join 计算操作风险并半格上确界（max 严重度）；任一侧无效时吸收为 RiskUnknown。
func (r RiskLevel) Join(other RiskLevel) RiskLevel {
	return pickIf(r.IsValid() && other.IsValid(), max(r, other), RiskUnknown)
}

// StrictestThreshold 计算审批阈值严苛度并半格上确界（有效阈值取 min，RiskUnknown 吸收）。
func (r RiskLevel) StrictestThreshold(other RiskLevel) RiskLevel {
	return pickIf(r.IsValid() && other.IsValid(), min(r, other), RiskUnknown)
}

// String 返回规范小写文本（"safe"、"moderate"、"dangerous" 或 "unknown"）。
func (r RiskLevel) String() string {
	return enumName(uint8(r), "unknown", "unknown", "safe", "moderate", "dangerous")
}

// AppendText 实现 encoding.TextAppender（值接收者）；对 RiskUnknown 及越界值失败关闭。
func (r RiskLevel) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, r.IsValid(), r.String(), ErrInvalidRiskLevel, uint8(r))
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (r RiskLevel) MarshalText() ([]byte, error) { return r.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为 RiskUnknown 并失败关闭。
func (r *RiskLevel) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(r, RiskUnknown, text, ParseRiskLevel)
}

// FoldRisks 对一组操作风险等级执行顺序无关的并半格折叠；空输入严格失败关闭返回 RiskUnknown。
func FoldRisks(levels ...RiskLevel) RiskLevel {
	return foldRiskLevels(levels, RiskSafe, RiskLevel.Join)
}

// FoldThresholds 对一组审批阈值执行顺序无关的严苛度并半格折叠；空输入严格失败关闭返回 RiskUnknown。
func FoldThresholds(thresholds ...RiskLevel) RiskLevel {
	return foldRiskLevels(thresholds, RiskDangerous, RiskLevel.StrictestThreshold)
}

func foldRiskLevels(items []RiskLevel, identity RiskLevel, combine func(RiskLevel, RiskLevel) RiskLevel) RiskLevel {
	if len(items) == 0 {
		return RiskUnknown
	}
	acc := identity
	for _, lv := range items {
		if acc = combine(acc, lv); acc == RiskUnknown {
			return RiskUnknown
		}
	}
	return acc
}

// EvaluateThreshold 按单调安全格规则将 (opRisk, threshold) 映射为 GuardrailDecision：
// 任一侧无效返回 *DecisionDeny；opRisk >= threshold 返回 *DecisionNeedApproval；否则返回 *DecisionAllow。
func EvaluateThreshold(opRisk, threshold RiskLevel) GuardrailDecision {
	if !opRisk.IsValid() {
		return NewDecisionDenyWithCode("unknown_risk", "operation risk level is unknown or invalid")
	}
	if !threshold.IsValid() {
		return NewDecisionDenyWithCode("invalid_threshold", "approval threshold is unknown or invalid")
	}
	if opRisk.CompareSeverity(threshold) >= 0 {
		return &DecisionNeedApproval{risk: opRisk, reason: "operation risk meets or exceeds approval threshold", valid: true}
	}
	return NewDecisionAllow("operation risk is below approval threshold")
}
