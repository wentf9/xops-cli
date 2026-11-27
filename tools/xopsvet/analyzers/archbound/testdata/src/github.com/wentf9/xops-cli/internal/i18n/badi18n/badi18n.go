package badi18n

import (
	"encoding/json/jsontext" // want "internal/i18n 禁止导入非纯内存/非白名单标准库"
	"encoding/json/v2"       // want "internal/i18n 禁止导入非纯内存/非白名单标准库"
	"log/slog"               // want "internal/i18n 禁止导入非纯内存/非白名单标准库"
	"math"                   // want "internal/i18n 禁止导入非纯内存/非白名单标准库"
	"net/http"               // want "internal/i18n 禁止导入非纯内存/非白名单标准库"
	"os"                     // want "internal/i18n 禁止导入非纯内存/非白名单标准库"
	"path/filepath"          // want "internal/i18n 禁止导入非纯内存/非白名单标准库"
	"reflect"                // want "internal/i18n 禁止导入非纯内存/非白名单标准库"
	"sort"                   // want "internal/i18n 禁止导入非纯内存/非白名单标准库"
	"sync"                   // want "internal/i18n 禁止导入非纯内存/非白名单标准库"
	"sync/atomic"            // want "internal/i18n 禁止导入非纯内存/非白名单标准库"
	"time"

	"example.com/thirdparty"                        // want "当前架构层禁止导入外部第三方包"
	"github.com/wentf9/xops-cli/core/engine"        // want "架构边界违规：当前层禁止导入"
	"github.com/wentf9/xops-cli/core/ports"         // want "架构边界违规：当前层禁止导入"
	"github.com/wentf9/xops-cli/internal/entry/cli" // want "架构边界违规：当前层禁止导入"
	"github.com/wentf9/xops-cli/internal/host/sys"  // want "架构边界违规：当前层禁止导入"
)

var (
	_ jsontext.Value
	_ = json.Marshal
	_ = slog.Default
	_ = math.Pi
	_ = http.StatusOK
	_ = os.ErrNotExist
	_ = filepath.Clean
	_ = reflect.TypeOf
	_ = sort.Strings
	_ sync.Mutex
	_ atomic.Int64
	_ = thirdparty.Flag
	_ engine.Engine
	_ ports.OperatorReadFS
	_ cli.CLI
	_ sys.HostSys
)

func badClock() {
	t := time.Now()   // want "archbound: internal/i18n 禁止使用非确定性时钟或定时符号 time.Now"
	time.Sleep(1)     // want "archbound: internal/i18n 禁止使用非确定性时钟或定时符号 time.Sleep"
	_ = time.After(1) // want "archbound: internal/i18n 禁止使用非确定性时钟或定时符号 time.After"
	_ = time.Tick(1)  // want "archbound: internal/i18n 禁止使用非确定性时钟或定时符号 time.Tick"
	_ = time.Local    // want "archbound: internal/i18n 禁止使用非确定性时钟或定时符号 time.Local"
	_ = t.Local()     // want "archbound: internal/i18n 禁止使用非确定性本地时区方法 \\(time\\.Time\\)\\.Local"
}
