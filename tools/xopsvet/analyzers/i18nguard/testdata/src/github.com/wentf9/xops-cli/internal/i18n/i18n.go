package i18n

import (
	"errors"
	"fmt"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

const (
	rootPrefix                   = "cli."
	KeyRoot    domi18n.MessageID = rootPrefix + "help"
)

// 合法：属主包内 YAML 词库加载可将键字符串转换为 MessageID，且允许 errors.Join、结构体错误与 TUI 非 CJK 符号。
func LoadKey(raw string) domi18n.MessageID {
	if raw == "" {
		return ""
	}
	return domi18n.MessageID(raw)
}

type structErr struct{ msg string }

func (e structErr) Error() string { return e.msg }

func allowedHelpers(e1, e2 error) error {
	_ = domi18n.NewMessage(KeyRoot)
	_ = "─│┌┐→•—…"
	_ = structErr{msg: "ok"}
	return errors.Join(e1, e2)
}

// 非法规则 2：底层为 string 的自定义错误类型（值接收者与指针接收者均拦截）。
type valStrErr string // want "禁止声明基于 string 的自定义错误类型 valStrErr"

func (e valStrErr) Error() string { return string(e) }

type ptrStrErr string // want "禁止声明基于 string 的自定义错误类型 ptrStrErr"

func (e *ptrStrErr) Error() string { return string(*e) }

func badRule2AndRule3(err error) {
	_ = errors.New("raw") // want "禁止引用 errors.New"
	fn := errors.New      // want "禁止引用 errors.New"
	_ = fn("via func value")
	_ = fmt.Errorf("wrap: %w", err) // want "禁止引用 fmt.Errorf"
	ef := fmt.Errorf                // want "禁止引用 fmt.Errorf"
	_ = ef("via func value: %w", err)

	_ = "你好世界"          // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	_ = `原始中文字符串`       // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	_ = '汉'             // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	_ = "prefix：suffix" // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	_ = '。'             // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	_ = "\u4e2d"        // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	_ = "\uff01"        // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
}
