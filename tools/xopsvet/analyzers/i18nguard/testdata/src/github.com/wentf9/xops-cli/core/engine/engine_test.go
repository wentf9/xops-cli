package engine

import (
	"errors"
	"fmt"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// 测试文件跳过全部 3 条规则。
const testOnlyID domi18n.MessageID = "engine.test.only"

func testFixture() error {
	_ = domi18n.NewMessage("engine.test.lit")
	_ = testOnlyID
	_ = "测试文件允许中文：ok"
	return fmt.Errorf("test wrap: %w", errors.New("test raw"))
}
