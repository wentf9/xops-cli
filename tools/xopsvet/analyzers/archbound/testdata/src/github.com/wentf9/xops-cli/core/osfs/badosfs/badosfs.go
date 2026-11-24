package badosfs

import (
	"net/http" // want "core/osfs 禁止导入网络子包或进程执行标准库 \"net/http\""
	"os/exec"  // want "core/osfs 禁止导入网络子包或进程执行标准库 \"os/exec\""

	"github.com/wentf9/xops-cli/core/conc"   // want "架构边界违规：当前层禁止导入 \"github.com/wentf9/xops-cli/core/conc\""
	"github.com/wentf9/xops-cli/core/events" // want "架构边界违规：当前层禁止导入 \"github.com/wentf9/xops-cli/core/events\""
)

var (
	_ http.Client
	_ exec.Cmd
	_ conc.Nursery
	_ events.Event
)
