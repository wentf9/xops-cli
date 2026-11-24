package tck

import (
	"testing"

	"github.com/wentf9/xops-cli/core/domain/security"
)

func AssertDecisionTCKValid(t *testing.T, d security.GuardrailDecision) {
	switch d.(type) {
	case *security.DecisionDeny:
	case *security.DecisionAllow:
	default:
		t.Fatalf("unexpected decision: %T", d)
	}
}

func AssertDecisionTCKErrorAllowed(t *testing.T, d security.GuardrailDecision) {
	switch d.(type) {
	case *security.DecisionDeny:
	case *security.DecisionAllow:
	default:
		t.Errorf("unexpected decision: %T", d)
	}
}

func AssertDecisionTCKFailOpenStillBlocked(d security.GuardrailDecision) bool {
	switch d.(type) {
	case *security.DecisionDeny:
		return false
	case *security.DecisionAllow:
		return true
	default:
		return true // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
	}
}

func AssertDecisionTCKBreakStillBlocked(d security.GuardrailDecision) {
	switch d.(type) {
	case *security.DecisionDeny:
	case *security.DecisionAllow:
	default: // want "sumexhaust: 安全决策 default 分支必须包含显式 fail-closed 处置（返回拒绝/错误或 panic），禁止静默 break 或放行"
		break
	}
}
