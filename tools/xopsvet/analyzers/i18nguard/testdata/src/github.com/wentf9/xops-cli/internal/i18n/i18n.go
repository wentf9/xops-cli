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

type Localizer struct{}

func NewMessage(id domi18n.MessageID) domi18n.Message {
	return domi18n.NewMessageWithFallback(id, "root")
}
func Sentinel(id domi18n.MessageID) error                       { return domi18n.SentinelWithFallback(id, "root") }
func E(id domi18n.MessageID) error                              { return domi18n.NewErrorWithFallback(nil, nil, id, "root") }
func (*Localizer) T(id domi18n.MessageID) string                { return "" }
func (*Localizer) TPlural(id domi18n.MessageID, n int64) string { return "" }

// 合法：属主包内 YAML 词库加载可将键字符串转换为 MessageID，且允许 errors.Join、实现匹配方法集 LocalizableView 的结构体错误与 TUI 非 CJK 符号。
func LoadKey(raw string) domi18n.MessageID {
	if raw == "" {
		return ""
	}
	return domi18n.MessageID(raw)
}

type okValStructErr struct{ msg string }

func (e okValStructErr) Error() string                      { return e.msg }
func (e okValStructErr) LocalizableView() domi18n.ErrorNode { return domi18n.ErrorNode{} }

type okPtrStructErr struct{ msg string }

func (e *okPtrStructErr) Error() string                      { return e.msg }
func (e *okPtrStructErr) LocalizableView() domi18n.ErrorNode { return domi18n.ErrorNode{} }

type okPtrErrValView struct{ msg string }

func (e *okPtrErrValView) Error() string                     { return e.msg }
func (e okPtrErrValView) LocalizableView() domi18n.ErrorNode { return domi18n.ErrorNode{} }

func allowedHelpers(e1, e2 error) error {
	_ = domi18n.NewMessage(domi18n.KeyCore)
	_ = domi18n.NewMessageWithFallback(KeyRoot, "help")
	_ = NewMessage(KeyRoot)
	_ = "─│┌┐→•—…"
	_ = okValStructErr{msg: "ok"}
	_ = &okPtrStructErr{msg: "ok"}
	_ = &okPtrErrValView{msg: "ok"}
	return errors.Join(e1, e2)
}

// 非法规则 2：底层为 string 的自定义错误类型（即便实现 LocalizableView 仍禁止）及未实现匹配方法集 LocalizableView 的结构体错误。
type valStrErr string // want "禁止声明基于 string 的自定义错误类型 valStrErr"

func (e valStrErr) Error() string { return string(e) }

type ptrStrErr string // want "禁止声明基于 string 的自定义错误类型 ptrStrErr"

func (e *ptrStrErr) Error() string { return string(*e) }

type strWithViewErr string // want "禁止声明基于 string 的自定义错误类型 strWithViewErr"

func (e strWithViewErr) Error() string                      { return string(e) }
func (e strWithViewErr) LocalizableView() domi18n.ErrorNode { return domi18n.ErrorNode{} }

type badNoViewStructErr struct{ msg string } // want "自定义错误类型 badNoViewStructErr 必须在匹配的接收者方法集上实现 LocalizableView"

func (e badNoViewStructErr) Error() string { return e.msg }

type badMismatchRecvErr struct{ msg string } // want "自定义错误类型 badMismatchRecvErr 必须在匹配的接收者方法集上实现 LocalizableView"

func (e badMismatchRecvErr) Error() string                       { return e.msg }
func (e *badMismatchRecvErr) LocalizableView() domi18n.ErrorNode { return domi18n.ErrorNode{} }

type fakeErrorNode struct{}

type badWrongViewRetErr struct{ msg string } // want "自定义错误类型 badWrongViewRetErr 必须在匹配的接收者方法集上实现 LocalizableView"

func (e badWrongViewRetErr) Error() string                  { return e.msg }
func (e badWrongViewRetErr) LocalizableView() fakeErrorNode { return fakeErrorNode{} }

func badRule2AndRule3(err error, loc *Localizer) {
	_ = domi18n.NewMessage(KeyRoot)     // want "禁止将 internal/i18n 声明的 MessageID 常量传入 core/domain/i18n 构造器"
	_ = loc.T(domi18n.MessageIDInvalid) // want "禁止向 i18n 构造或渲染函数传入无效标识 MessageIDInvalid"
	_ = errors.New("raw")               // want "禁止引用 errors.New"
	fn := errors.New                    // want "禁止引用 errors.New"
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
