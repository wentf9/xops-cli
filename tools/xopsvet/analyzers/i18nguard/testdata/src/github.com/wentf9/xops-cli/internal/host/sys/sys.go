package sys

import (
	"errors"
	"fmt"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// M2 阶段：非 interact 的 internal/host/sys 仍受规则 1 约束，但规则 2/3 留待 M3 Wave 3E 合闸。
func checkHostSysM2Staged() error {
	_ = domi18n.NewMessage("sys.lit") // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	return fmt.Errorf("staged sys: %w", errors.New("待 Wave 3E 迁移中文"))
}
