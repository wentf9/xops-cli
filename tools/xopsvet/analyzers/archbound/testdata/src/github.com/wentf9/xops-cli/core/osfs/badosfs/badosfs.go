package badosfs

import (
	"net"     // want "core/osfs 禁止导入网络或进程执行标准库 \"net\""
	"os/exec" // want "core/osfs 禁止导入网络或进程执行标准库 \"os/exec\""

	"github.com/wentf9/xops-cli/core/events" // want "架构边界违规：当前层禁止导入 \"github.com/wentf9/xops-cli/core/events\""
)

var (
	_ net.Conn
	_ exec.Cmd
	_ events.Event
)
