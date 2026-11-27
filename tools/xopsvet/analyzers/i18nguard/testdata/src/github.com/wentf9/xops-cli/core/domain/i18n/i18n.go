package i18n

import "errors"

type MessageID string

const (
	MessageIDInvalid           MessageID = ""
	KeyCore                    MessageID = "core.sample"
	KeyCorePrefix              MessageID = "core."
	KeyCoreComposed            MessageID = KeyCorePrefix + "composed"
	keyCommonDetail            MessageID = "common.detail"
	KeyCommonNotFound          MessageID = "common.not_found"
	KeyCommonFieldInvalid      MessageID = "common.field_invalid"
	KeyCommonFieldValueInvalid MessageID = "common.field_value_invalid"
	KeyCommonValueInvalid      MessageID = "common.value_invalid"
	KeyCommonOpFailed          MessageID = "common.op_failed"
	KeyCommonOpTargetFailed    MessageID = "common.op_target_failed"
)

type Param struct{}

type Message struct {
	ID MessageID
}

type ErrorNode struct {
	Message Message
}

func Str(k, v string) Param                                                   { return Param{} }
func BoundStr(k, v string) Param                                              { return Param{} }
func CanonicalFallback(id MessageID) string                                   { return "" }
func NewMessage(id MessageID, params ...Param) Message                        { return Message{ID: id} }
func NewMessageWithFallback(id MessageID, fb string, params ...Param) Message { return Message{ID: id} }
func NewPluralMessage(id MessageID, n int64, params ...Param) Message         { return Message{ID: id} }
func Sentinel(id MessageID) error                                             { return nil }
func SentinelWithFallback(id MessageID, fb string) error                      { return nil }
func NewErrorWithFallback(s, c error, id MessageID, f string, params ...Param) error {
	return nil
}
func E(id MessageID, params ...Param) error                                 { return nil }
func EF(s error, id MessageID, params ...Param) error                       { return nil }
func Wrap(c error, id MessageID, params ...Param) error                     { return c }
func WrapS(s, c error, id MessageID, params ...Param) error                 { return c }
func WrapSentinelDetail(s, c error, detail string, replaced ...error) error { return c }
func DynamicDetailError(detail string) error                                { return nil }

// 合法：属主包内允许显式 MessageID(raw) 编解码转换、*WithFallback 与零值空串 ""。
func ParseID(raw string) MessageID {
	if raw == "" {
		return ""
	}
	return MessageID(raw)
}

// 合法：core/domain/i18n 位于规则 2 永久白名单，允许底层错误构造与 *WithFallback。
type coreStrErr string

func (e coreStrErr) Error() string { return string(e) }

func internalErr() error {
	_ = coreStrErr("ok")
	_ = NewMessageWithFallback(KeyCore, "core sample")
	_ = SentinelWithFallback(KeyCore, "core sample")
	var zeroID MessageID = MessageIDInvalid
	if zeroID == MessageIDInvalid {
		_ = zeroID
	}
	return errors.New("core internal error")
}

func badInCoreI18n(dyn string, s, c error) {
	_ = NewMessage(KeyCore)
	_ = NewMessage(MessageIDInvalid) // want "禁止向 i18n 构造或渲染函数传入无效标识 MessageIDInvalid"
	_ = NewMessage("hardcoded.key")  // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	_ = "中文错误提示"                     // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	_ = "full：width"                 // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	_ = '中'                          // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	_ = "\u4e2d\u6587"               // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	// 规则 4B-1：即使在 core/domain/i18n 包内也禁止向 EF/WrapS 传入 common.detail。
	_ = EF(s, keyCommonDetail, BoundStr("detail", dyn))       // want "禁止向 EF 传入 common.detail"
	_ = WrapS(s, c, keyCommonDetail, BoundStr("detail", dyn)) // want "禁止向 WrapS 传入 common.detail"
	// 合法：动态运行期值允许通过 BoundStr 与 WrapSentinelDetail/DynamicDetailError 传递。
	_ = WrapSentinelDetail(s, c, dyn)
	_ = DynamicDetailError(dyn)
}
