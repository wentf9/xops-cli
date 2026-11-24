package badpool

import (
	"github.com/wentf9/xops-cli/core/internal/gate"        // want "架构边界违规：当前层禁止导入"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial" // want "架构边界违规：当前层禁止导入"
	"github.com/wentf9/xops-cli/core/osfs"                 // want "架构边界违规：当前层禁止导入"
)

type Bad struct {
	G *gate.Gate
	D *dial.Dialer
	L osfs.LocalFS
}
