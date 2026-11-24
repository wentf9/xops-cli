package badstdlib

import (
	"os"   // want "core/domain/\\*\\* 禁止导入非白名单标准库 \"os\""
	"sync" // want "core/domain/\\*\\* 禁止导入非白名单标准库 \"sync\""
	"testing"
)

func TestBadStdlibStillBanned(t *testing.T) {
	var (
		_ = os.ErrClosed
		_ sync.Mutex
	)
}
