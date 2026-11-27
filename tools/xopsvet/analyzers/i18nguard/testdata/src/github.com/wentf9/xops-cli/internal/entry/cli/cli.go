package cli

import (
	"errors"
	"fmt"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

type okStructErr struct{ code int }

func (okStructErr) Error() string                      { return "cli error" }
func (okStructErr) LocalizableView() domi18n.ErrorNode { return domi18n.ErrorNode{} }

type badCLIStructErr struct{ msg string } // want "自定义错误类型 badCLIStructErr 必须在匹配的接收者方法集上实现 LocalizableView"

func (*badCLIStructErr) Error() string { return "raw struct error" }

type badCLIStrErr string // want "禁止声明基于 string 的自定义错误类型 badCLIStrErr"

func (e badCLIStrErr) Error() string { return string(e) }

func fullScopeCheck(e1, e2 error) error {
	_ = okStructErr{code: 1}
	_ = &badCLIStructErr{msg: "bad"}
	_ = errors.Join(e1, e2)
	_ = domi18n.NewMessage("cli.lit") // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	_ = errors.New("cli raw")         // want "禁止引用 errors.New"
	_ = fmt.Errorf("cli: %w", e1)     // want "禁止引用 fmt.Errorf"
	_ = "命令行中文"                       // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	return nil
}
