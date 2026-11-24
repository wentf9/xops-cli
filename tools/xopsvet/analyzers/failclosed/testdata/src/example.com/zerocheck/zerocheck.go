package zerocheck

// 合法 //xops:failclosed 枚举
//xops:failclosed
type Verdict uint8

const (
	VerdictDeny Verdict = iota
	VerdictAllow
)

//xops:failclosed
type Mode string

const (
	ModeUnknown Mode = ""
	ModeStrict  Mode = "strict"
)

//xops:failclosed
type DisallowCheck int

const (
	StateDisallowed DisallowCheck = 0
)

// 非法：缺少零值常量 (iota + 1)
//xops:failclosed
type NoZero int // want "failclosed: 标记 //xops:failclosed 的枚举类型 NoZero 必须定义代表最严/拒绝/无效语义的零值常量"

const (
	NoZeroFirst NoZero = iota + 1
)

// 非法：零值常量包含放行语义词
//xops:failclosed
type BadAllowZero int

const (
	ModeAllow BadAllowZero = 0 // want "failclosed: //xops:failclosed 零值常量 ModeAllow 命名不得包含放行/有效语义词"
)

// 非法：零值常量未体现拒绝/无效语义
//xops:failclosed
type BadNeutralZero int

const (
	ModeZero BadNeutralZero = 0 // want "failclosed: //xops:failclosed 零值常量 ModeZero 命名必须显式体现拒绝/无效/未设置语义"
)

// 非法：不支持标量类型 float64
//xops:failclosed
type BadFloat float64 // want "failclosed: //xops:failclosed 不支持标量类型 BadFloat"

// 合法 //xops:failclosed 结构体（全私有 + 正向门控）
//xops:failclosed
type SecretBox struct {
	data  []byte
	wiped bool
	valid bool
}

// 非法 //xops:failclosed 结构体（导出字段 + 孤立否定 bool）
//xops:failclosed
type BadStruct struct {
	Allowed bool // want "failclosed: //xops:failclosed 结构体 BadStruct 禁止导出字段 Allowed"
	wiped   bool // want "failclosed: //xops:failclosed 结构体 BadStruct 含否定语义 bool 字段 wiped"
}

// 合法 //xops:failclosed 封闭和类型接口（交由 sumexhaust 检查）
//xops:failclosed
type SealedStep interface {
	sealedStep()
}

// 非法 //xops:failclosed 非封闭接口
//xops:failclosed
type PlainIface interface { // want "failclosed: //xops:failclosed 不支持非封闭接口类型 PlainIface"
	Do()
}
