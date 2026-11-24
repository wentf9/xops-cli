package badevents

import (
	"net" // want "core/events 禁止导入系统/网络标准库 \"net\""
	"os"  // want "core/events 禁止导入系统/网络标准库 \"os\""

	"github.com/wentf9/xops-cli/core/ports" // want "架构边界违规：当前层禁止导入 \"github.com/wentf9/xops-cli/core/ports\""
)

var (
	_ net.Conn
	_ = os.ErrNotExist
	_ ports.ScopedRootFS
)
