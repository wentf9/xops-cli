package badengine

import (
	"github.com/wentf9/xops-cli/core/internal/sim" // want "架构边界违规：当前层禁止导入 \"github.com/wentf9/xops-cli/core/internal/sim\""
	"github.com/wentf9/xops-cli/core/ports/tck"    // want "架构边界违规：当前层禁止导入 \"github.com/wentf9/xops-cli/core/ports/tck\""
)

var (
	_ sim.SimFS
	_ = tck.CheckRootFS
)
