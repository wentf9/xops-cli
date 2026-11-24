package badosfs

import (
	"crypto/tls" // want "core/osfs 禁止导入"
	"reflect"    // want "core/osfs 禁止导入"

	"example.com/thirdparty" // want "当前架构层禁止导入外部第三方包"
)

var (
	_ tls.Config
	_ reflect.Type
	_ = thirdparty.Flag
)
