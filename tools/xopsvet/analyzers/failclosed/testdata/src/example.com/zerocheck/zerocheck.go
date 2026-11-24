package zerocheck

import "sync/atomic"

// 合法 //xops:failclosed 枚举
//
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
//
//xops:failclosed
type NoZero int // want "failclosed: 标记 //xops:failclosed 的枚举类型 NoZero 必须定义代表最严/拒绝/无效语义的零值常量"

const (
	NoZeroFirst NoZero = iota + 1
)

// 非法：零值常量包含放行语义词
//
//xops:failclosed
type BadAllowZero int

const (
	ModeAllow BadAllowZero = 0 // want "failclosed: //xops:failclosed 零值常量 ModeAllow 命名不得包含放行/有效语义词"
)

// 非法：零值常量未体现拒绝/无效语义
//
//xops:failclosed
type BadNeutralZero int

const (
	ModeZero BadNeutralZero = 0 // want "failclosed: //xops:failclosed 零值常量 ModeZero 命名必须显式体现拒绝/无效/未设置语义"
)

// 非法：不支持标量类型 float64
//
//xops:failclosed
type BadFloat float64 // want "failclosed: //xops:failclosed 不支持标量类型 BadFloat"

// 合法 //xops:failclosed 结构体（全私有 + 正向门控）
//
//xops:failclosed
type SecretBox struct {
	data  []byte
	wiped bool
	valid bool
}

// 非法 //xops:failclosed 结构体（导出字段 + 孤立否定 bool）
//
//xops:failclosed
type BadStruct struct {
	Allowed bool // want "failclosed: //xops:failclosed 结构体 BadStruct 禁止导出字段 Allowed"
	wiped   bool // want "failclosed: //xops:failclosed 结构体 BadStruct 含否定语义 bool 字段 wiped"
}

// 合法 //xops:failclosed 封闭和类型接口（交由 sumexhaust 检查）
//
//xops:failclosed
type SealedStep interface {
	sealedStep()
}

// 非法 //xops:failclosed 非封闭接口
//
//xops:failclosed
type PlainIface interface { // want "failclosed: //xops:failclosed 不支持非封闭接口类型 PlainIface"
	Do()
}

// 非法 //xops:failclosed 结构体（bypass / insecure / unverified 否定语义 bool 无正向门控）
//
//xops:failclosed
type BadBypassBool struct {
	bypassAuth bool // want "failclosed: //xops:failclosed 结构体 BadBypassBool 含否定语义 bool 字段 bypassAuth"
}

//xops:failclosed
type BadInsecureBool struct {
	insecureMode bool // want "failclosed: //xops:failclosed 结构体 BadInsecureBool 含否定语义 bool 字段 insecureMode"
}

//xops:failclosed
type BadUnverifiedBool struct {
	unverified bool // want "failclosed: //xops:failclosed 结构体 BadUnverifiedBool 含否定语义 bool 字段 unverified"
}

// Challenger 2 - Challenge 4: 底层类型为 bool 的具名布尔字段同样受否定语义零值检查约束。
type MyBool bool

//xops:failclosed
type BadNamedBoolStruct struct {
	bypassed MyBool // want "failclosed: //xops:failclosed 结构体 BadNamedBoolStruct 含否定语义 bool 字段 bypassed"
}

//xops:failclosed
type GoodNamedBoolStruct struct {
	valid MyBool
	wiped MyBool
}

// MED-3 & N5: sync/atomic.Bool 纳入检查；否定前缀 notValid 不可充当正向门控；指针 *atomic.Bool 不可充当正向门控。
type atomicBoolAlias = struct{ _ int }

//xops:failclosed
type BadNegatedPositiveGate struct {
	wiped    bool // want "failclosed: //xops:failclosed 结构体 BadNegatedPositiveGate 含否定语义 bool 字段 wiped"
	notValid bool
}

//xops:failclosed
type BadPointerPositiveGate struct {
	revoked bool // want "failclosed: //xops:failclosed 结构体 BadPointerPositiveGate 含否定语义 bool 字段 revoked"
	valid   *bool
}

//xops:failclosed
type BadAtomicRevokedWithoutValid struct {
	revoked *atomic.Bool // want "failclosed: //xops:failclosed 结构体 BadAtomicRevokedWithoutValid 含否定语义 bool 字段 revoked"
}

//xops:failclosed
type BadAtomicPointerValid struct {
	revoked *atomic.Bool // want "failclosed: //xops:failclosed 结构体 BadAtomicPointerValid 含否定语义 bool 字段 revoked"
	valid   *atomic.Bool
}

//xops:failclosed
type GoodAuthorizedWithValid struct {
	valid   bool
	revoked *atomic.Bool
}
