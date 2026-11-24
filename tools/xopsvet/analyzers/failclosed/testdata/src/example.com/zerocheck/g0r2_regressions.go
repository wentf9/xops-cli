package zerocheck

// OkNotAllowedZero 验证前置紧邻否定词 NotAllowed 合法归类为拒绝语义（B-8）。
//
//xops:failclosed
type OkNotAllowedZero uint8

const (
	VerdictNotAllowed OkNotAllowedZero = 0
	VerdictPermitted  OkNotAllowedZero = 1
)

type embeddedBadMixin struct {
	ExportedField int  // want "禁止导出字段 ExportedField"
	disabled      bool // want "含否定语义 bool 字段 disabled"
}

// BadEmbeddedFailClosedStruct 验证嵌入结构体含导出字段与否定 bool 字段时递归拦截（M6）。
//
//xops:failclosed
type BadEmbeddedFailClosedStruct struct {
	embeddedBadMixin
}
