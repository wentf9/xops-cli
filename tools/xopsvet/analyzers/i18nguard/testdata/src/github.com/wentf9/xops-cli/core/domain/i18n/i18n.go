package i18n

import "errors"

type MessageID string

const (
	MessageIDInvalid MessageID = ""
	KeyCore          MessageID = "core.sample"
	KeyCorePrefix    MessageID = "core."
	KeyCoreComposed  MessageID = KeyCorePrefix + "composed"
)

type Message struct {
	ID MessageID
}

func NewMessage(id MessageID) Message { return Message{ID: id} }

// 合法：属主包内允许显式 MessageID(raw) 编解码转换与零值空串 ""。
func ParseID(raw string) MessageID {
	if raw == "" {
		return ""
	}
	return MessageID(raw)
}

// 合法：core/domain/i18n 位于规则 2 永久白名单，允许底层错误构造。
type coreStrErr string

func (e coreStrErr) Error() string { return string(e) }

func internalErr() error {
	_ = coreStrErr("ok")
	return errors.New("core internal error")
}

func badInCoreI18n() {
	_ = NewMessage(KeyCore)
	_ = NewMessage(MessageIDInvalid)
	_ = NewMessage("hardcoded.key") // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	_ = "中文错误提示"                    // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	_ = "full：width"                // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	_ = '中'                         // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	_ = "\u4e2d\u6587"              // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
}
