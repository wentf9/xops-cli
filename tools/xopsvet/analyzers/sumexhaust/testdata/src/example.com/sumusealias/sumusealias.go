package sumusealias

import "example.com/sumalias"

func checkTransitiveAliasMissingDefault(s sumalias.StepAlias) int {
	switch s.(type) { // want "sumexhaust: 对封闭接口 sumdef.StepAction 的 type switch 缺少变体: \\*sumdef.StepScript, \\*sumdef.StepShell" "sumexhaust: 安全决策封闭类型 sumdef.StepAction 的 type switch 必须包含 fail-closed default 分支"
	}
	return 0
}
