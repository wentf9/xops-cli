package interact

import (
	"errors"
	"fmt"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/internal/i18n"
)

type badInteractErr string // want "禁止声明基于 string 的自定义错误类型 badInteractErr"

func (e badInteractErr) Error() string { return string(e) }

func checkInteractM2(e1, e2 error) error {
	_ = i18n.E(i18n.KeyRoot)
	_ = errors.Join(e1, e2)
	_ = badInteractErr("bad")
	_ = domi18n.NewMessage("interact.lit") // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	_ = errors.New("interact raw")         // want "禁止引用 errors.New"
	_ = fmt.Errorf("interact: %w", e1)     // want "禁止引用 fmt.Errorf"
	_ = "交互提示中文"                           // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	return nil
}
