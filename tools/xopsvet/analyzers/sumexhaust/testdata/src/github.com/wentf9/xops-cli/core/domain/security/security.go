package security

import (
	"errors"
	"fmt"
)

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

// Reviewer 3 Finding 2 / Challenger 3 Challenge 1: if Init、带标签语句、defer/go 闭包及命名返回值裸 return。
func invalidIfInitPermissiveDefault(d GuardrailDecision, cond bool) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		if ok := true; cond { // want "sumexhaust: 安全决策 default 分支禁止赋值放行值（fail-open）"
			return ok // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
		} else {
			return false
		}
	}
}

func invalidIfInitClosureDefault(d GuardrailDecision, cond bool) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		if fn := func() bool { return true }; cond {
			return fn() // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
		} else {
			return false
		}
	}
}

func validIfInitFailClosedDefault(d GuardrailDecision, cond bool) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		if ok := false; cond {
			return ok
		} else {
			return false
		}
	}
}

func invalidLabeledIfDefault(d GuardrailDecision, cond bool) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
	retry:
		if cond {
			return true // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
		}
		if false {
			goto retry
		}
		return false
	}
}

func invalidFuncLitNamedReturnDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return func() (ok bool) { // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
			ok = true
			return
		}()
	}
}

func invalidFuncLitNamedReturnBranchDefault(d GuardrailDecision, cond bool) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return func() (ok bool) { // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
			if cond {
				ok = true
			} else {
				ok = false
			}
			return
		}()
	}
}

func validFuncLitNamedReturnDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return func() (ok bool) {
			ok = false
			return
		}()
	}
}

func invalidDeferNamedReturnDefault(d GuardrailDecision) (allow bool) {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		defer func() {
			allow = true // want "sumexhaust: 安全决策 default 分支禁止赋值放行值（fail-open）"
		}()
		return false
	}
}

func invalidGoClosureDefault(d GuardrailDecision) bool {
	var allow bool
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		go func() {
			allow = true // want "sumexhaust: 安全决策 default 分支禁止赋值放行值（fail-open）"
		}()
		return false
	}
	_ = allow
	return false
}

func validDeferCleanupDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		defer func() {
			_ = "cleanup"
		}()
		return false
	}
}

// Challenger 4 - Challenge 2: 返回闭包体内嵌套 defer/go/IIFE 与局部函数变量调用的放行篡改。
func invalidDeferInsideFuncLitDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return func() (ok bool) { // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
			defer func() {
				ok = true
			}()
			return false
		}()
	}
}

func invalidGoInsideFuncLitDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return func() (ok bool) { // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
			go func() {
				ok = true
			}()
			return false
		}()
	}
}

func invalidNestedIIFEInsideFuncLitDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return func() (ok bool) { // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
			func() {
				ok = true
			}()
			return
		}()
	}
}

func invalidDeferVarInsideFuncLitDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return func() (ok bool) { // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
			fn := func() {
				ok = true
			}
			defer fn()
			return false
		}()
	}
}

func invalidDeferNestedIIFEInsideFuncLitDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return func() (ok bool) { // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
			defer func() {
				func() {
					ok = true
				}()
			}()
			return false
		}()
	}
}

func validDeferCleanupInsideFuncLitDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return func() (ok bool) {
			defer func() {
				_ = "cleanup"
			}()
			return false
		}()
	}
}

func validDeferShadowedOkInsideFuncLitDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return func() (ok bool) {
			defer func() {
				ok := true
				_ = ok
			}()
			return false
		}()
	}
}

func validNestedIIFEFailClosedInsideFuncLitDefault(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return func() (ok bool) {
			func() {
				ok = false
			}()
			return
		}()
	}
}

// v2.3.2 B4 回归用例：前置否定极性对偶、error(nil)、new(T)/new(expr) 与 CompositeLit 对称校验。
type Verdict int

const (
	VerdictDeny Verdict = iota
	VerdictAllow
	VerdictNotAllowed
)

type Decision struct {
	Allowed    bool
	Denied     bool
	NotAllowed bool
	Verdict    Verdict
}

var ErrNotAllowed = errors.New("not allowed")

func newNotAllowedErr() error { return ErrNotAllowed }
func allowRequest() error     { return nil }
func allowOnError() error     { return nil }
func allowIfInvalid() bool    { return true }

func validNegatedPolarityAndComposites(d GuardrailDecision) (Decision, error) {
	switch d.(type) {
	case *DecisionDeny:
		return Decision{Denied: true}, nil
	case *DecisionAllow:
		return Decision{Allowed: true}, nil
	default:
		return Decision{Denied: true}, nil
	}
}

func validNotAllowedFieldAndNewExpr(d GuardrailDecision) (*Decision, error) {
	switch d.(type) {
	case *DecisionDeny:
		return &Decision{NotAllowed: true}, nil
	case *DecisionAllow:
		return &Decision{Allowed: true}, nil
	default:
		return new(Decision{NotAllowed: true}), nil
	}
}

func validAllowedFalseField(d GuardrailDecision) (Decision, error) {
	switch d.(type) {
	case *DecisionDeny:
		return Decision{Allowed: false}, nil
	case *DecisionAllow:
		return Decision{Allowed: true}, nil
	default:
		return Decision{Allowed: false}, nil
	}
}

func validVerdictNotAllowed(d GuardrailDecision) (Verdict, error) {
	switch d.(type) {
	case *DecisionDeny:
		return VerdictDeny, nil
	case *DecisionAllow:
		return VerdictAllow, nil
	default:
		return VerdictNotAllowed, nil
	}
}

func validNewDecisionDeny(d GuardrailDecision) (GuardrailDecision, error) {
	switch d.(type) {
	case *DecisionDeny:
		return &DecisionDeny{}, nil
	case *DecisionAllow:
		return &DecisionAllow{}, nil
	default:
		return new(DecisionDeny), nil
	}
}

func validErrNotAllowedAndStdlibErrCalls(d GuardrailDecision, mode int) error {
	switch d.(type) {
	case *DecisionDeny:
		return ErrNotAllowed
	case *DecisionAllow:
		return nil
	default:
		if mode == 0 {
			return ErrNotAllowed
		} else if mode == 1 {
			return newNotAllowedErr()
		} else if mode == 2 {
			return errors.New("allow")
		} else if mode == 3 {
			return fmt.Errorf("allow: %T", d)
		} else {
			return errors.Join(ErrNotAllowed)
		}
	}
}

func invalidAllowRequestErrorCall(d GuardrailDecision) error {
	switch d.(type) {
	case *DecisionDeny:
		return ErrNotAllowed
	case *DecisionAllow:
		return nil
	default:
		return allowRequest() // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
	}
}

func invalidAllowOnErrorCall(d GuardrailDecision) error {
	switch d.(type) {
	case *DecisionDeny:
		return ErrNotAllowed
	case *DecisionAllow:
		return nil
	default:
		return allowOnError() // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
	}
}

func invalidAllowIfInvalidCall(d GuardrailDecision) bool {
	switch d.(type) {
	case *DecisionDeny:
		return false
	case *DecisionAllow:
		return true
	default:
		return allowIfInvalid() // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
	}
}

func invalidErrorNilCast(d GuardrailDecision) error {
	switch d.(type) {
	case *DecisionDeny:
		return ErrNotAllowed
	case *DecisionAllow:
		return nil
	default:
		return error(nil) // want "sumexhaust: 安全决策 default 分支禁止返回 nil error 且无显式拒绝值"
	}
}

func invalidErrorNilPairCast(d GuardrailDecision) (any, error) {
	switch d.(type) {
	case *DecisionDeny:
		return &DecisionDeny{}, nil
	case *DecisionAllow:
		return &DecisionAllow{}, nil
	default:
		return error(nil), nil // want "sumexhaust: 安全决策 default 分支禁止返回 nil error 且无显式拒绝值"
	}
}

func invalidTypedNilDecisionDeny(d GuardrailDecision) (GuardrailDecision, error) {
	switch d.(type) {
	case *DecisionDeny:
		return &DecisionDeny{}, nil
	case *DecisionAllow:
		return &DecisionAllow{}, nil
	default:
		return (*DecisionDeny)(nil), nil // want "sumexhaust: 安全决策 default 分支禁止返回 nil error 且无显式拒绝值"
	}
}

func invalidCompositeAllowedTrue(d GuardrailDecision) (Decision, error) {
	switch d.(type) {
	case *DecisionDeny:
		return Decision{Denied: true}, nil
	case *DecisionAllow:
		return Decision{Allowed: true}, nil
	default:
		return Decision{Allowed: true}, nil // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
	}
}

func invalidCompositeDeniedFalse(d GuardrailDecision) (Decision, error) {
	switch d.(type) {
	case *DecisionDeny:
		return Decision{Denied: true}, nil
	case *DecisionAllow:
		return Decision{Allowed: true}, nil
	default:
		return Decision{Denied: false}, nil // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
	}
}

func invalidNewDecisionAllow(d GuardrailDecision) (GuardrailDecision, error) {
	switch d.(type) {
	case *DecisionDeny:
		return &DecisionDeny{}, nil
	case *DecisionAllow:
		return &DecisionAllow{}, nil
	default:
		return new(DecisionAllow), nil // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
	}
}

func invalidNewExprAllowedTrue(d GuardrailDecision) (*Decision, error) {
	switch d.(type) {
	case *DecisionDeny:
		return &Decision{Denied: true}, nil
	case *DecisionAllow:
		return &Decision{Allowed: true}, nil
	default:
		return new(Decision{Allowed: true}), nil // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
	}
}

func invalidNewExprTrue(d GuardrailDecision) (*bool, error) {
	switch d.(type) {
	case *DecisionDeny:
		return new(false), nil
	case *DecisionAllow:
		return new(true), nil
	default:
		return new(true), nil // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
	}
}
