package sim

import (
	"errors"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

func SimRun() error {
	_ = "仿真器中文允许"
	_ = domi18n.MessageID("sim.raw")
	return errors.New("sim err")
}
