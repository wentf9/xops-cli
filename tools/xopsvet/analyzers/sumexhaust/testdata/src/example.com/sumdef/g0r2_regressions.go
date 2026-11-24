package sumdef

type ConstrainedGen[T any] interface {
	sealedCG()
}

type CGBox[T any] struct{ V T }

func (*CGBox[T]) sealedCG() {}

// CGIntOnly 仅在 ~int 约束下实现 ConstrainedGen[T]，对 ConstrainedGen[string] 不可实例化，不得误报（B-9）。
type CGIntOnly[T ~int] struct{}

func (*CGIntOnly[T]) sealedCG() {}

func okConstrainedGenericSealed(g ConstrainedGen[string]) int {
	switch g.(type) {
	case *CGBox[string]:
		return 1
	default:
		return 0
	}
}

// badBareReturnFailOpen 验证具名返回值在 default 分支裸 return 放行值必须拦截（H6）。
func badBareReturnFailOpen(step StepAction) (allowed bool) {
	allowed = true
	switch step.(type) {
	case *StepShell, *StepScript:
		return false
	default: // want "安全决策 default 分支必须包含显式 fail-closed 处置"
		return
	}
}

// badBareReturnNilErr 验证具名 error 返回值在 default 分支未赋非 nil 错误的裸 return 必须拦截（H6）。
func badBareReturnNilErr(step StepAction) (err error) {
	switch step.(type) {
	case *StepShell, *StepScript:
		return nil
	default:
		return // want "安全决策 default 分支禁止返回 nil error 且无显式拒绝值"
	}
}
