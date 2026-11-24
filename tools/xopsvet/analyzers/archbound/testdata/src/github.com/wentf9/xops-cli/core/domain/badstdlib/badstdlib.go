package badstdlib

import (
	"context"     // want "core/domain/\\*\\* 禁止导入非白名单标准库 \"context\""
	"math/rand"   // want "core/domain/\\*\\* 禁止导入非白名单标准库 \"math/rand\""
	"net"         // want "core/domain/\\*\\* 禁止导入非白名单标准库 \"net\""
	"os"          // want "core/domain/\\*\\* 禁止导入非白名单标准库 \"os\""
	"os/exec"     // want "core/domain/\\*\\* 禁止导入非白名单标准库 \"os/exec\""
	"reflect"     // want "core/domain/\\*\\* 禁止导入非白名单标准库 \"reflect\""
	"sync"        // want "core/domain/\\*\\* 禁止导入非白名单标准库 \"sync\""
	"sync/atomic" // want "core/domain/\\*\\* 禁止导入非白名单标准库 \"sync/atomic\""
	"syscall"     // want "core/domain/\\*\\* 禁止导入非白名单标准库 \"syscall\""

	"github.com/wentf9/xops-cli/core/ports" // want "架构边界违规：当前层禁止导入 \"github.com/wentf9/xops-cli/core/ports\""
)

func Bad() {
	var (
		_ context.Context
		_ = rand.Int()
		_ net.Conn
		_ = os.ErrNotExist
		_ exec.Cmd
		_ reflect.Type
		_ sync.Mutex
		_ atomic.Bool
		_ syscall.Errno
		_ ports.ScopedRootFS
	)
}
