package security

import "errors"

type GuardrailDecision interface {
	sealedDecision()
}

type DecisionDeny struct{}

func (*DecisionDeny) sealedDecision() {}

type DecisionAllow struct{}

func (*DecisionAllow) sealedDecision() {}

func validBoolDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return false
	}
}

func validPanicDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		panic("unexpected decision")
	}
}

func validNamedDenyReturn(d GuardrailDecision) (GuardrailDecision, error) {
	switch d.(type) {
	case *DecisionDeny:
		return &DecisionDeny{}, nil
	case *DecisionAllow:
		return &DecisionAllow{}, nil
	default:
		return &DecisionDeny{}, nil
	}
}

func invalidMissingDefault(d GuardrailDecision) bool {
	switch d.(type) { // want "sumexhaust: 安全决策封闭类型 GuardrailDecision 的 type switch 必须包含 fail-closed default 分支"
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	}
	return false
}

func invalidReturnTrueDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return true // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
	}
}

func invalidReturnNilErrorDefault(d GuardrailDecision) error {
	switch d.(type) {
	case *DecisionDeny:
		return errors.New("denied")
	case *DecisionAllow:
		return nil
	default:
		return nil // want "sumexhaust: 安全决策 default 分支禁止返回 nil error 且无显式拒绝值"
	}
}

func invalidBreakOnlyDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default: // want "sumexhaust: 安全决策 default 分支必须包含显式 fail-closed 处置（返回拒绝/错误或 panic），禁止静默 break 或放行"
		break
	}
	return false
}

func invalidAssignAllowDefault(d GuardrailDecision) bool {
	var allowed bool
	switch d.(type) {
	case *DecisionDeny:
		allowed = false
	case *DecisionAllow:
		allowed = true
	default:
		allowed = true // want "sumexhaust: 安全决策 default 分支禁止赋值放行值（fail-open）"
	}
	return allowed
}
