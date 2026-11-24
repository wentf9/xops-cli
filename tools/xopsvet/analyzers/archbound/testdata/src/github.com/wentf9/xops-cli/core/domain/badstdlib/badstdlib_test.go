package badstdlib

import (
	"os"   // want "core/domain/\\*\\* 禁止导入非白名单标准库 \"os\""
	"sync" // want "core/domain/\\*\\* 禁止导入非白名单标准库 \"sync\""
	"testing"

	"github.com/wentf9/xops-cli/core/conc"         // want "架构边界违规：当前层禁止导入"
	"github.com/wentf9/xops-cli/core/internal/sim" // want "架构边界违规：当前层禁止导入"
	"go.uber.org/goleak"                           // want "当前架构层禁止导入外部第三方包"
)

func TestBadStdlibStillBanned(t *testing.T) {
	goleak.VerifyNone(t)
	var (
		_ = os.ErrClosed
		_ sync.Mutex
		_ conc.Nursery
		_ sim.SimFS
	)
}
