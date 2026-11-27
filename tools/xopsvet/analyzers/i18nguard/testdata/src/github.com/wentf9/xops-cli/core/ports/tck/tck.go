package tck

import (
	"errors"
	"fmt"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

const okTCKID domi18n.MessageID = "tck.ignored"

func Run() error {
	_ = "测试夹具中文允许"
	_ = domi18n.NewMessage("tck.raw")
	return fmt.Errorf("tck: %w", errors.New("ok"))
}
