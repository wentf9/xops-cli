package conc

import (
	"errors"
	"fmt"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// 规则 2 永久白名单：core/conc 允许规范英文 errors.New / fmt.Errorf。
var ErrClosed = errors.New("nursery closed")

func wrapErr(err error) error {
	return fmt.Errorf("nursery failed: %w", err)
}

// 规则 1 与规则 3 在全仓合闸模式下仍对 core/conc 生效。
const badConcID domi18n.MessageID = "conc.bad" // want "禁止在 core/domain/i18n 与 internal/i18n 之外声明 i18n.MessageID 常量"

func badConcCJK() string {
	_ = badConcID    // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	return "并发包禁止中文" // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
}
