package baduc

import (
	"github.com/wentf9/xops-cli/core/internal/mcpruntime"  // want "架构边界违规：当前层禁止导入"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial" // want "架构边界违规：当前层禁止导入"
	"github.com/wentf9/xops-cli/core/osfs"                 // want "架构边界违规：当前层禁止导入"
)

type Bad struct {
	M *mcpruntime.Server
	D *dial.Dialer
	L osfs.LocalFS
}
