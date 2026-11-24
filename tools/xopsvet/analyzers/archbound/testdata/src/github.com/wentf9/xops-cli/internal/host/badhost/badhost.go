package badhost

import (
	"github.com/wentf9/xops-cli/core/engine"        // want "架构边界违规：当前层禁止导入"
	"github.com/wentf9/xops-cli/internal/entry/cli" // want "架构边界违规：当前层禁止导入"
)

type Bad struct {
	E *engine.Engine
	C *cli.CLI
}
