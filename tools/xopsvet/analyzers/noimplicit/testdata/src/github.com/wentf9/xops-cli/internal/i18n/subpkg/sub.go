package subpkg

import (
	"embed"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/internal/i18n"
)

func dynID() domi18n.MessageID { return i18n.KeyRootErr }

// 合法：internal/i18n.Sentinel 纯常量构造与跨包只读哨兵重导出。
var ErrFromRoot = i18n.Sentinel(i18n.KeyRootErr)
var ErrReexportRoot = i18n.ErrRoot

// 非法：子包禁止 //go:embed、非常量或字面量参数传入 internal/i18n.Sentinel。
//
//go:embed locales.txt
var subEmbed embed.FS // want "禁止声明可变包级 var"

var ErrRootNonConst = i18n.Sentinel(dynID())             // want "禁止声明可变包级 var"
var ErrRootRawLit = i18n.Sentinel("root.raw.lit")        // want "禁止声明可变包级 var"
var ErrCrossCore = domi18n.Sentinel(i18n.KeyRootErr)     // want "禁止声明可变包级 var"
var ErrCrossRoot = i18n.Sentinel(domi18n.KeyCoreErr)     // want "禁止声明可变包级 var"
var ErrRootInv = i18n.Sentinel(domi18n.MessageIDInvalid) // want "禁止声明可变包级 var"

func useSubEmbed() {
	_ = subEmbed
	ErrReexportRoot = nil // want "禁止在运行期修改哨兵错误 ErrReexportRoot"
	_ = &ErrReexportRoot  // want "禁止对哨兵错误 ErrReexportRoot 取地址"
}
