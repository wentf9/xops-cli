package main

import (
	"errors"
	"fmt"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/internal/i18n"
)

type badCmdStructErr struct{ msg string } // want "自定义错误类型 badCmdStructErr 必须在匹配的接收者方法集上实现 LocalizableView"

func (e *badCmdStructErr) Error() string { return e.msg }

func checkCmdXopsM2(e1, e2 error) error {
	_ = i18n.E(i18n.KeyRoot)
	_ = errors.Join(e1, e2)
	_ = &badCmdStructErr{msg: "bad"}
	_ = domi18n.NewMessage("cmd.lit") // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	_ = errors.New("cmd raw")         // want "禁止引用 errors.New"
	_ = fmt.Errorf("cmd: %w", e1)     // want "禁止引用 fmt.Errorf"
	_ = "组合根中文"                       // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	return nil
}
