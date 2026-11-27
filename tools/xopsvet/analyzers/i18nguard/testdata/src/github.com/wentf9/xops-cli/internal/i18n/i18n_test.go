package i18n

import (
	"errors"
	"fmt"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// 测试文件豁免全部 3 条规则。
func testOnlyHelper() error {
	_ = "测试中文：允许"
	_ = domi18n.NewMessage("test.only.key")
	return fmt.Errorf("wrap: %w", errors.New("test err"))
}
