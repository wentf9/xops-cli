package gate

import (
	"crypto/sha256"
	"encoding/binary"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
)

const guardrailPolicyDigestTag = "xops.gate.guardrail_policy.v1"

// StrictDefaultProtectedPatterns 返回 RFC §4.2 定义的默认高危受保护路径模式副本。
func StrictDefaultProtectedPatterns() []string {
	return []string{"/etc/**", "/root/**", "C:/Windows/**"}
}

// GuardrailPolicySpec 是构造不可变 GuardrailPolicy 的显式规格（严禁使用裸 time.Duration）。
type GuardrailPolicySpec struct {
	ApprovalThreshold    security.RiskLevel                       // 必填：全局基础审批风险阈值（如 RiskModerate）
	NoElicitFallback     NoElicitFallback                         // 不可交互回退策略（零值为 NoElicitFallbackDeny）
	NodeOverrides        algebraic.Option[security.NodeOverrides] // 可选：节点通配符覆写格（None 等价 EmptyNodeOverrides）
	ProtectedRules       []pathalg.ProtectedRule                  // 可选：带显式分区标签的受保护路径规则集
	ProtectedPathRisk    algebraic.Option[security.RiskLevel]     // 可选：命中受保护路径时提升的最低风险（默认 RiskDangerous）
	ApprovalTTL          algebraic.Option[algebraic.Duration]     // 可选：审批信封有效期（默认 5m，范围 (0, 24h]）
	MaxPendingChallenges int                                      // 可选：挂起待审批挑战容量上限（0 使用默认 256，负值拒绝）
	MaxReplayHistory     int                                      // 可选：已消费/作废信封防重放记录上限（0 使用默认 4096，负值拒绝）
}

// GuardrailPolicy 表示经过完整校验且带确定性密码学摘要的不可变安全护栏策略；
// 零值恒无效并失败关闭，严禁通过零值或 nil 逃逸策略求值。
//
//xops:opaque
//xops:failclosed
type GuardrailPolicy struct {
	approvalThreshold security.RiskLevel
	noElicitFallback  NoElicitFallback
	nodeOverrides     security.NodeOverrides
	protectedMatcher  pathalg.ProtectedPathMatcher
	protectedPathRisk security.RiskLevel
	approvalTTL       algebraic.Duration
	maxPending        int
	maxReplayHistory  int
	digest            security.Digest
	valid             bool
}

// NewGuardrailPolicy 校验全部阈值、节点覆盖格、受保护路径规则、审批 TTL 与容量上限，
// 并计算确定性策略摘要，构造不可变 GuardrailPolicy。
func NewGuardrailPolicy(spec GuardrailPolicySpec) (GuardrailPolicy, error) {
	if !spec.ApprovalThreshold.IsValid() {
		return GuardrailPolicy{}, domi18n.EF(ErrInvalidPolicy, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "approval_threshold"))
	}
	if !spec.NoElicitFallback.IsValid() {
		return GuardrailPolicy{}, domi18n.WrapSentinel(ErrInvalidPolicy, ErrInvalidFallback)
	}
	overrides, err := resolvePolicyOverrides(spec.NodeOverrides)
	if err != nil {
		return GuardrailPolicy{}, err
	}
	protRisk, err := resolveProtectedRisk(spec.ProtectedPathRisk)
	if err != nil {
		return GuardrailPolicy{}, err
	}
	ttl, err := resolveApprovalTTL(spec.ApprovalTTL)
	if err != nil {
		return GuardrailPolicy{}, err
	}
	maxPend, maxReplay, err := resolvePolicyLimits(spec.MaxPendingChallenges, spec.MaxReplayHistory)
	if err != nil {
		return GuardrailPolicy{}, err
	}
	matcher, err := pathalg.NewClassifiedProtectedPathMatcher(spec.ProtectedRules)
	if err != nil {
		return GuardrailPolicy{}, domi18n.WrapSentinel(ErrInvalidPolicy, err)
	}
	dig := computePolicyDigest(spec.ApprovalThreshold, spec.NoElicitFallback, overrides, spec.ProtectedRules, protRisk, ttl)
	return GuardrailPolicy{
		approvalThreshold: spec.ApprovalThreshold,
		noElicitFallback:  spec.NoElicitFallback,
		nodeOverrides:     overrides,
		protectedMatcher:  matcher,
		protectedPathRisk: protRisk,
		approvalTTL:       ttl,
		maxPending:        maxPend,
		maxReplayHistory:  maxReplay,
		digest:            dig,
		valid:             true,
	}, nil
}

// NewGuardrailPolicyFromPatterns 便捷编译一组受保护路径模式字符串并构造 GuardrailPolicy。
func NewGuardrailPolicyFromPatterns(threshold security.RiskLevel, fallback NoElicitFallback, patterns []string) (GuardrailPolicy, error) {
	rules := make([]pathalg.ProtectedRule, 0, len(patterns))
	for _, pat := range patterns {
		r, err := pathalg.ParseProtectedRule(pat)
		if err != nil {
			return GuardrailPolicy{}, domi18n.WrapSentinel(ErrInvalidPolicy, err)
		}
		rules = append(rules, r)
	}
	return NewGuardrailPolicy(GuardrailPolicySpec{
		ApprovalThreshold: threshold,
		NoElicitFallback:  fallback,
		ProtectedRules:    rules,
	})
}

func resolvePolicyOverrides(opt algebraic.Option[security.NodeOverrides]) (security.NodeOverrides, error) {
	ov, ok := opt.Get()
	if !ok {
		return security.EmptyNodeOverrides(), nil
	}
	if !ov.IsValid() {
		return zeroVal[security.NodeOverrides](), domi18n.EF(ErrInvalidPolicy, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "node_overrides"))
	}
	return ov, nil
}

func resolveProtectedRisk(opt algebraic.Option[security.RiskLevel]) (security.RiskLevel, error) {
	r, ok := opt.Get()
	if !ok {
		return security.RiskDangerous, nil
	}
	if !r.IsValid() {
		return security.RiskUnknown, domi18n.EF(ErrInvalidPolicy, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "protected_path_risk"))
	}
	return r, nil
}

func resolveApprovalTTL(opt algebraic.Option[algebraic.Duration]) (algebraic.Duration, error) {
	d, ok := opt.Get()
	if !ok {
		return algebraic.FromStdDuration(defaultApprovalTTL), nil
	}
	if !d.IsPositive() || d.Std() > maxApprovalTTL {
		return algebraic.ZeroDuration(), domi18n.EF(ErrInvalidPolicy, domi18n.KeyCommonFieldRange, domi18n.Str("field", "approval_ttl"), domi18n.Dur("value", d.Std()), domi18n.Str("min", "1ns"), domi18n.Dur("max", maxApprovalTTL))
	}
	return d, nil
}

func resolvePolicyLimits(maxPending, maxReplay int) (int, int, error) {
	if maxPending < 0 || maxReplay < 0 {
		return 0, 0, domi18n.EF(ErrInvalidPolicy, domi18n.KeyCommonFieldNegative, domi18n.Str("field", "policy capacity limit"))
	}
	if maxPending == 0 {
		maxPending = defaultPendingCapacity
	}
	if maxReplay == 0 {
		maxReplay = defaultReplayHistoryCap
	}
	return maxPending, maxReplay, nil
}

// computePolicyDigest 对策略核心判定字段计算确定性 SHA-256 摘要，锚定至 ApprovalEnvelope.PolicyDigest。
func computePolicyDigest(
	threshold security.RiskLevel,
	fallback NoElicitFallback,
	overrides security.NodeOverrides,
	rules []pathalg.ProtectedRule,
	protRisk security.RiskLevel,
	ttl algebraic.Duration,
) security.Digest {
	h := sha256.New()
	writeLenStr := func(s string) {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(len(s)))
		_, _ = h.Write(buf[:])
		_, _ = h.Write([]byte(s))
	}
	writeLenStr(guardrailPolicyDigestTag)
	_, _ = h.Write([]byte{uint8(threshold), uint8(fallback), uint8(protRisk)})
	var numBuf [8]byte
	binary.BigEndian.PutUint64(numBuf[:], uint64(ttl.Std()))
	_, _ = h.Write(numBuf[:])

	ovRules := overrides.Rules()
	binary.BigEndian.PutUint64(numBuf[:], uint64(len(ovRules)))
	_, _ = h.Write(numBuf[:])
	for _, r := range ovRules {
		writeLenStr(r.Pattern())
		_, _ = h.Write([]byte{uint8(r.ApprovalThreshold()), uint8(r.DecisionFloor())})
	}

	sortedRules := make([]string, 0, len(rules))
	for _, r := range rules {
		sortedRules = append(sortedRules, r.Class()+"\x00"+r.Canonical())
	}
	slices.Sort(sortedRules)
	sortedRules = slices.Compact(sortedRules)
	binary.BigEndian.PutUint64(numBuf[:], uint64(len(sortedRules)))
	_, _ = h.Write(numBuf[:])
	for _, item := range sortedRules {
		writeLenStr(item)
	}

	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return security.DigestFromSHA256(sum)
}

// GuardrailPolicy 只读访问器（零值恒失败关闭）。
func (p GuardrailPolicy) IsValid() bool {
	return p.valid && p.approvalThreshold.IsValid() && p.noElicitFallback.IsValid() &&
		p.nodeOverrides.IsValid() && p.protectedMatcher.IsValid() && p.protectedPathRisk.IsValid() &&
		p.approvalTTL.IsPositive() && p.digest.IsValid()
}
func (p GuardrailPolicy) IsZero() bool { return !p.IsValid() }
func (p GuardrailPolicy) ApprovalThreshold() security.RiskLevel {
	if !p.IsValid() {
		return security.RiskUnknown
	}
	return p.approvalThreshold
}
func (p GuardrailPolicy) NoElicitFallback() NoElicitFallback {
	if !p.IsValid() {
		return NoElicitFallbackDeny
	}
	return p.noElicitFallback
}
func (p GuardrailPolicy) NodeOverrides() security.NodeOverrides { return p.nodeOverrides }
func (p GuardrailPolicy) ProtectedPathRisk() security.RiskLevel {
	if !p.IsValid() {
		return security.RiskUnknown
	}
	return p.protectedPathRisk
}
func (p GuardrailPolicy) ApprovalTTL() algebraic.Duration { return p.approvalTTL }
func (p GuardrailPolicy) Digest() security.Digest         { return p.digest }
func (p GuardrailPolicy) ProtectedRuleCount() int {
	if !p.IsValid() {
		return 0
	}
	return p.protectedMatcher.RuleCount()
}

// MatchScopedPaths 使用策略内已编译的受保护路径匹配器对普通与递归路径求值，
// 返回携带完整受保护分区标签的 []security.ScopedPath 及是否存在受保护路径命中。
func (p GuardrailPolicy) MatchScopedPaths(paths, recursivePaths []string) ([]security.ScopedPath, bool, error) {
	if !p.IsValid() {
		return nil, false, ErrInvalidPolicy
	}
	return p.matchScopedPaths(paths, recursivePaths)
}

// evaluateScopeSnapshot 按有界安全格对单阶段绑定与路径集合求值，生成不可变 security.ScopeSnapshot。
func (p GuardrailPolicy) evaluateScopeSnapshot(
	profile PolicyProfileKind,
	binding security.OperationBinding,
	baseRisk security.RiskLevel,
	verdict security.Verdict,
	floor algebraic.Option[security.GuardrailDecision],
	paths, recursivePaths []string,
) (security.ScopeSnapshot, error) {
	if !p.IsValid() || !profile.IsValid() || !binding.IsValid() || !baseRisk.IsValid() {
		return zeroVal[security.ScopeSnapshot](), domi18n.EF(ErrInvalidPolicy, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "policy evaluation input"))
	}
	scopedPaths, anyProtected, pathErr := p.matchScopedPaths(paths, recursivePaths)
	if pathErr != nil {
		return zeroVal[security.ScopeSnapshot](), domi18n.WrapS(ErrAuthorizationDenied, pathErr, domi18n.KeyCommonOpFailed, domi18n.Str("op", "protected path check"))
	}
	effRisk := baseRisk
	if anyProtected {
		effRisk = effRisk.Join(p.protectedPathRisk)
	}
	effVerdict := verdict.Normalize()
	effDec := p.foldDecision(profile, binding, effRisk, effVerdict, floor, anyProtected)
	return security.NewScopeSnapshot(security.ScopeSnapshotSpec{
		Capability: binding.Capability(),
		TargetNode: binding.NodeID(),
		Endpoint:   binding.Endpoint(),
		Verdict:    effVerdict,
		Risk:       effRisk,
		Decision:   effDec,
		Paths:      scopedPaths,
	})
}

func (p GuardrailPolicy) matchScopedPaths(paths, recursivePaths []string) ([]security.ScopedPath, bool, error) {
	out := make([]security.ScopedPath, 0, len(paths)+len(recursivePaths))
	anyProtected := false
	for _, raw := range paths {
		sp, prot, err := p.matchSinglePath(raw, false)
		if err != nil {
			return nil, false, err
		}
		anyProtected = anyProtected || prot
		out = append(out, sp)
	}
	for _, raw := range recursivePaths {
		sp, prot, err := p.matchSinglePath(raw, true)
		if err != nil {
			return nil, false, err
		}
		anyProtected = anyProtected || prot
		out = append(out, sp)
	}
	return out, anyProtected, nil
}

func (p GuardrailPolicy) matchSinglePath(raw string, recursive bool) (security.ScopedPath, bool, error) {
	var m pathalg.ProtectedMatch
	var err error
	if recursive {
		m, err = p.protectedMatcher.MatchRecursive(raw)
	} else {
		m, err = p.protectedMatcher.Match(raw)
	}
	if err != nil {
		return zeroVal[security.ScopedPath](), false, err
	}
	sp, err := security.NewScopedPath(raw, recursive, m.Zones()...)
	if err != nil {
		return zeroVal[security.ScopedPath](), false, err
	}
	return sp, m.Matched(), nil
}

func (p GuardrailPolicy) foldDecision(
	profile PolicyProfileKind,
	binding security.OperationBinding,
	effRisk security.RiskLevel,
	verdict security.Verdict,
	floor algebraic.Option[security.GuardrailDecision],
	anyProtected bool,
) security.GuardrailDecision {
	ovDec := p.evaluateBindingOverrides(binding, effRisk)
	var dec security.GuardrailDecision
	switch profile {
	case PolicyProfileDirectOperator:
		dec = directOperatorBaseDecision(ovDec)
	case PolicyProfileStrictOperator, PolicyProfileStrictAgent:
		dec = strictBaseDecision(ovDec, effRisk, anyProtected)
	default:
		return security.NewDecisionDenyWithCode("invalid_profile", "invalid policy profile")
	}
	if fl, ok := floor.Get(); ok {
		dec = security.JoinDecisions(dec, fl)
	}
	if verdict.Denied() {
		dec = security.JoinDecisions(dec, security.NewDecisionDenyWithCode("verdict_denied", "security verdict denied"))
	}
	return dec
}

func (p GuardrailPolicy) evaluateBindingOverrides(binding security.OperationBinding, effRisk security.RiskLevel) security.GuardrailDecision {
	nodes := binding.NodeIDs()
	primary := binding.NodeID()
	if len(nodes) == 0 {
		return p.nodeOverrides.EvaluateNode(p.approvalThreshold, effRisk, primary)
	}
	all := make([]string, 0, len(nodes)+1)
	if primary != "" {
		all = append(all, primary)
	}
	all = append(all, nodes...)
	return p.nodeOverrides.EvaluateBatch(p.approvalThreshold, effRisk, all...)
}

func directOperatorBaseDecision(ovDec security.GuardrailDecision) security.GuardrailDecision {
	switch d := security.NormalizeDecision(ovDec).(type) {
	case *security.DecisionDeny:
		return d
	case *security.DecisionNeedApproval, *security.DecisionAllow:
		return security.NewDecisionAllow("direct operator profile allow")
	default:
		return security.NewDecisionDenyWithCode("invalid_decision", "unexpected guardrail decision")
	}
}

func strictBaseDecision(ovDec security.GuardrailDecision, effRisk security.RiskLevel, anyProtected bool) security.GuardrailDecision {
	dec := security.NormalizeDecision(ovDec)
	if !anyProtected {
		return dec
	}
	protDec, err := security.NewDecisionNeedApproval(effRisk, "operation touches protected path")
	if err != nil {
		return security.NewDecisionDenyWithCode("invalid_protected_risk", err.Error())
	}
	return security.JoinDecisions(dec, protDec)
}
