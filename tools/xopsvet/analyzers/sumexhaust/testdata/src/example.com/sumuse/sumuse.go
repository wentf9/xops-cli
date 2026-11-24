package sumuse

import (
	"errors"

	"example.com/sumdef"
)

func useValid(a sumdef.AuthMethod) int {
	switch a.(type) {
	case sumdef.AuthPassword, *sumdef.AuthPassword, *sumdef.AuthKey:
		return 1
	default:
		return 0
	}
}

func useMissingCrossPkg(a sumdef.AuthMethod) int {
	switch a.(type) { // want "sumexhaust: 对封闭接口 sumdef.AuthMethod 的 type switch 缺少变体: \\*sumdef.AuthKey"
	case sumdef.AuthPassword, *sumdef.AuthPassword:
		return 1
	default:
		return 0
	}
}

func useEmbeddedSealed(x interface{ sumdef.AuthMethod }) int {
	switch x.(type) { // want "sumexhaust: 对封闭接口 interface\\{sumdef.AuthMethod\\} 的 type switch 缺少变体: \\*sumdef.AuthKey"
	case sumdef.AuthPassword, *sumdef.AuthPassword:
		return 1
	}
	return 0
}

func useFailClosedDirectiveMissingDefault(s sumdef.StepAction) error {
	switch s.(type) { // want "sumexhaust: 安全决策封闭类型 sumdef.StepAction 的 type switch 必须包含 fail-closed default 分支"
	case *sumdef.StepShell, *sumdef.StepScript:
		return nil
	}
	return errors.New("unreachable")
}

func useFailClosedDirectiveEmptyDefault(s sumdef.StepAction) error {
	switch s.(type) {
	case *sumdef.StepShell, *sumdef.StepScript:
		return nil
	default: // want "sumexhaust: 安全决策 default 分支禁止为空，必须显式返回拒绝/错误或 panic"
	}
	return nil
}

func useFailClosedDirectiveValid(s sumdef.StepAction) error {
	switch s.(type) {
	case *sumdef.StepShell, *sumdef.StepScript:
		return nil
	default:
		return errors.New("unknown step")
	}
}
