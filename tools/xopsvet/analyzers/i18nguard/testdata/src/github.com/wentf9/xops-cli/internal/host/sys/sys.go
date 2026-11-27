package sys

import (
	"errors"
	"fmt"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

type badSysStructErr struct{ msg string } // want "自定义错误类型 badSysStructErr 必须在匹配的接收者方法集上实现 LocalizableView"

func (e *badSysStructErr) Error() string { return e.msg }

// M3 全仓合闸：internal/host/sys 同样全面强制执行规则 1、规则 2 与规则 3。
func checkHostSysFullRepo(e error) error {
	_ = &badSysStructErr{msg: "bad"}
	_ = errors.Join(e, nil)
	_ = domi18n.NewMessage("sys.lit") // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	_ = errors.New("raw sys")         // want "禁止引用 errors.New"
	_ = fmt.Errorf("sys: %w", e)      // want "禁止引用 fmt.Errorf"
	_ = "宿主系统层禁止中文"                   // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	return nil
}
