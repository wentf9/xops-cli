package badgate

import (
	"github.com/wentf9/xops-cli/core/internal/pool" // want "架构边界违规：当前层禁止导入"
	"github.com/wentf9/xops-cli/core/osfs"          // want "架构边界违规：当前层禁止导入"
)

type Bad struct {
	P *pool.Pool
	L osfs.LocalFS
}
