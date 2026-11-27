package crosspkg

import (
	"embed"
	"io"

	"example.com/sentinelpkg"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

const untypedKey = "raw.untyped"

func dynID() domi18n.MessageID { return domi18n.KeyCoreErr }
func dynStr() string           { return "dyn" }

// 合法：跨包只读哨兵重导出（Err* / io.EOF）与同域非空常量 i18n.Sentinel 构造。
var ErrReexport = sentinelpkg.ErrShared
var ErrEOF = io.EOF
var ErrFromCore = domi18n.Sentinel(domi18n.KeyCoreErr)

// 非法：SentinelWithFallback、空常量 MessageIDInvalid、非哨兵名跨包重导出、非常量参数与白名单外 //go:embed。
var ErrFromCoreFB = domi18n.SentinelWithFallback(domi18n.KeyCoreErr, "fallback") // want "禁止声明可变包级 var"
var ErrInvalidID = domi18n.Sentinel(domi18n.MessageIDInvalid)                    // want "禁止声明可变包级 var"
var ErrBadReexport = sentinelpkg.SharedFailure                                   // want "禁止声明可变包级 var"
var ErrRawLit = domi18n.Sentinel("raw.lit")                                      // want "禁止声明可变包级 var"
var ErrUntyped = domi18n.Sentinel(untypedKey)                                    // want "禁止声明可变包级 var"
var ErrNonConst = domi18n.Sentinel(dynID())                                      // want "禁止声明可变包级 var"
var ErrDynFB = domi18n.SentinelWithFallback(domi18n.KeyCoreErr, dynStr())        // want "禁止声明可变包级 var"
var ErrSamePkgCopy = ErrReexport                                                 // want "禁止声明可变包级 var"

//go:embed locales.txt
var wrongPkgEmbed embed.FS // want "禁止声明可变包级 var"

func mutateCrossPkgSentinel() {
	sentinelpkg.ErrShared = nil // want "禁止在运行期修改哨兵错误 ErrShared"
	p := &sentinelpkg.ErrShared // want "禁止对哨兵错误 ErrShared 取地址"
	_ = p

	ErrReexport = nil // want "禁止在运行期修改哨兵错误 ErrReexport"
	q := &ErrReexport // want "禁止对哨兵错误 ErrReexport 取地址"
	_ = q
	_ = wrongPkgEmbed

	for _, sentinelpkg.ErrShared = range []error{nil} { // want "禁止在运行期修改哨兵错误 ErrShared"
	}

	var h sentinelpkg.FieldHolder
	h.ErrField = nil
	_ = &h.ErrField
}

func callIndirectContextValue() any {
	c := sentinelpkg.NewOverriding()
	return c.Value("k") // want "禁止调用 ctx.Value"
}
