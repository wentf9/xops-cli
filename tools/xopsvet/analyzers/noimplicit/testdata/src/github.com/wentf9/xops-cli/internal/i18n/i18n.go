package i18n

import (
	"embed"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

const KeyRootErr domi18n.MessageID = "root.err"

func Sentinel(id domi18n.MessageID) error { return nil }

var ErrRoot = Sentinel(KeyRootErr)

//go:embed locales.txt
var localeFiles embed.FS

//go:embed locales.txt
var secondEmbed embed.FS // want "禁止声明可变包级 var"

//go:embed locales.txt
var ExportedEmbed embed.FS // want "禁止声明可变包级 var"

/* //go:embed locales.txt */
var blockEmbed embed.FS // want "禁止声明可变包级 var"

// go:embed locales.txt
var spaceEmbed embed.FS // want "禁止声明可变包级 var"

//go:embed locales.txt
var strEmbed string // want "禁止声明可变包级 var"

//go:embed locales.txt
var initEmbed embed.FS = embed.FS{} // want "禁止声明可变包级 var"

//go:embed locales.txt
var (
	multiA embed.FS // want "禁止声明可变包级 var"
	multiB embed.FS // want "禁止声明可变包级 var"
)

func mutateEmbed() {
	_ = localeFiles
	localeFiles = embed.FS{} // want "禁止在运行期修改只读嵌入文件系统变量 localeFiles"
	p := &localeFiles        // want "禁止对只读嵌入文件系统变量 localeFiles 取地址"
	_ = p
	for _, localeFiles = range []embed.FS{} { // want "禁止在运行期修改只读嵌入文件系统变量 localeFiles"
	}
}
