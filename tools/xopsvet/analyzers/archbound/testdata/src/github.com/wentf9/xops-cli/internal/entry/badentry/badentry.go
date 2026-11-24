package badentry

import (
	"github.com/wentf9/xops-cli/core/osfs"           // want "架构边界违规：当前层禁止导入"
	"github.com/wentf9/xops-cli/core/ports"          // want "架构边界违规：当前层禁止导入"
	"github.com/wentf9/xops-cli/internal/host/sys"   // want "架构边界违规：当前层禁止导入"
)

type Bad struct {
	L osfs.LocalFS
	F ports.ScopedRootFS
	S *sys.HostSys
}
