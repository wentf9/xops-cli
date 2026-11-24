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

func grantHelper() bool {
	return true
}

func invalidIfNoElseDefault(d GuardrailDecision, cond bool) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default: // want "sumexhaust: 安全决策 default 分支必须包含显式 fail-closed 处置（返回拒绝/错误或 panic），禁止静默 break 或放行"
		if cond {
			return false
		}
	}
	return true
}

func invalidIfIncompleteElseDefault(d GuardrailDecision, cond bool) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default: // want "sumexhaust: 安全决策 default 分支必须包含显式 fail-closed 处置（返回拒绝/错误或 panic），禁止静默 break 或放行"
		if cond {
			return false
		} else {
			_ = "log only"
		}
	}
	return true
}

func validIfBothBranchesFailClosed(d GuardrailDecision, cond bool) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		if cond {
			return false
		} else {
			panic("denied")
		}
	}
}

func invalidVarDeclPermissiveDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		var ok = true // want "sumexhaust: 安全决策 default 分支禁止赋值放行值（fail-open）"
		return ok     // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
	}
}

func invalidCallPermissiveDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return grantHelper() // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
	}
}

func invalidAssignErrFallthroughDefault(d GuardrailDecision) error {
	var err error
	switch d.(type) {
	case *DecisionDeny:
		return errors.New("denied")
	case *DecisionAllow:
		return nil
	default: // want "sumexhaust: 安全决策 default 分支必须包含显式 fail-closed 处置（返回拒绝/错误或 panic），禁止静默 break 或放行"
		err = errors.New("denied")
	}
	_ = err
	return nil
}

func validAssignAndReturnErrDefault(d GuardrailDecision) error {
	var err error
	switch d.(type) {
	case *DecisionDeny:
		return errors.New("denied")
	case *DecisionAllow:
		return nil
	default:
		err = errors.New("denied")
		return err
	}
}

// Challenger 2 - Challenge 1: default 内嵌 switch/type-switch/for/range/select 及内联/局部闭包放行逃逸。
func invalidSwitchInDefault(d GuardrailDecision, n int) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		switch n {
		case 1:
			return true // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
		}
		return false
	}
}

func invalidTypeSwitchInDefault(d GuardrailDecision, x any) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		switch x.(type) {
		case int:
			return true // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
		}
		return false
	}
}

func invalidForInDefault(d GuardrailDecision, cond bool) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		for cond {
			return true // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
		}
		return false
	}
}

func invalidRangeInDefault(d GuardrailDecision, xs []int) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		for range xs {
			return true // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
		}
		return false
	}
}

func invalidSelectInDefault(d GuardrailDecision, ch <-chan int) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		select {
		case <-ch:
			return true // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
		default:
			return false
		}
	}
}

func invalidIIFEInDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return func() bool { return true }() // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
	}
}

func invalidClosureVarInDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		fn := func() bool {
			ok := true
			return ok
		}
		return fn() // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
	}
}

func invalidOuterClosureVarInDefault(d GuardrailDecision) bool {
	fn := func() bool { return true }
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return fn() // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
	}
}

func invalidClosureVarNilErrInDefault(d GuardrailDecision) error {
	switch d.(type) {
	case *DecisionDeny:
		return errors.New("denied")
	case *DecisionAllow:
		return nil
	default:
		fn := func() error { return nil }
		return fn() // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
	}
}

func validIIFEFailClosedDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return func() bool { return false }()
	}
}

func validClosureVarFailClosedDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		fn := func() bool { return false }
		return fn()
	}
}
