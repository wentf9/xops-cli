package sumalias

import "example.com/sumdef"

// StepAlias 为跨包引用的 //xops:failclosed 封闭接口类型别名。
type StepAlias = sumdef.StepAction
