package engine

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

// 测试文件跳过规则 1。
const testOnlyID domi18n.MessageID = "engine.test.only"

func testFixture() {
	_ = domi18n.NewMessage("engine.test.lit")
	_ = testOnlyID
}
