package badi18n

import (
	"log/slog"      // want "internal/i18n 禁止导入非纯内存/非白名单标准库"
	"net/http"      // want "internal/i18n 禁止导入非纯内存/非白名单标准库"
	"os"            // want "internal/i18n 禁止导入非纯内存/非白名单标准库"
	"path/filepath" // want "internal/i18n 禁止导入非纯内存/非白名单标准库"
	"reflect"       // want "internal/i18n 禁止导入非纯内存/非白名单标准库"

	"example.com/thirdparty"                        // want "当前架构层禁止导入外部第三方包"
	"github.com/wentf9/xops-cli/core/engine"        // want "架构边界违规：当前层禁止导入"
	"github.com/wentf9/xops-cli/core/ports"         // want "架构边界违规：当前层禁止导入"
	"github.com/wentf9/xops-cli/internal/entry/cli" // want "架构边界违规：当前层禁止导入"
	"github.com/wentf9/xops-cli/internal/host/sys"  // want "架构边界违规：当前层禁止导入"
)

var (
	_ = slog.Default
	_ = http.StatusOK
	_ = os.ErrNotExist
	_ = filepath.Clean
	_ = reflect.TypeOf
	_ = thirdparty.Flag
	_ engine.Engine
	_ ports.OperatorReadFS
	_ cli.CLI
	_ sys.HostSys
)
