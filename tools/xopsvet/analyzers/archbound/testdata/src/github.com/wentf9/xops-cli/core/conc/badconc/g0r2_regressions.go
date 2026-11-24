package badconc

import (
	"flag" // want "core/conc 与 core/internal/foundation/\\{actor,trace\\} 禁止导入"
	"log"  // want "core/conc 与 core/internal/foundation/\\{actor,trace\\} 禁止导入"
	"mime" // want "core/conc 与 core/internal/foundation/\\{actor,trace\\} 禁止导入"
)

var (
	_ = flag.ErrHelp
	_ = log.Flags
	_ = mime.TypeByExtension
)
