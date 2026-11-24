package badconc

import (
	crand "crypto/rand" // want "core/conc 与 core/internal/foundation/\\{actor,trace\\} 禁止导入非纯内存 I/O、反射或随机标准库 \"crypto/rand\""
	"math/rand"         // want "core/conc 与 core/internal/foundation/\\{actor,trace\\} 禁止导入非纯内存 I/O、反射或随机标准库 \"math/rand\""
	"net"               // want "core/conc 与 core/internal/foundation/\\{actor,trace\\} 禁止导入非纯内存 I/O、反射或随机标准库 \"net\""
	"os"                // want "core/conc 与 core/internal/foundation/\\{actor,trace\\} 禁止导入非纯内存 I/O、反射或随机标准库 \"os\""
	"path/filepath"     // want "core/conc 与 core/internal/foundation/\\{actor,trace\\} 禁止导入非纯内存 I/O、反射或随机标准库 \"path/filepath\""
	"reflect"           // want "core/conc 与 core/internal/foundation/\\{actor,trace\\} 禁止导入非纯内存 I/O、反射或随机标准库 \"reflect\""

	"example.com/thirdparty"                           // want "当前架构层禁止导入外部第三方包"
	"github.com/wentf9/xops-cli/core/domain/algebraic" // want "架构边界违规：当前层禁止导入"
)

var (
	_ = crand.Reader
	_ = rand.Int
	_ net.Conn
	_ = os.ErrClosed
	_ = filepath.Base
	_ reflect.Type
	_ = thirdparty.Flag
	_ algebraic.Duration
)
