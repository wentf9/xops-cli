package engine

import (
	"errors"
	"fmt"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// 规则 1：包外禁止声明 MessageID 常量与类型别名。
const (
	badDeclaredID domi18n.MessageID = "engine.bad"    // want "禁止在 core/domain/i18n 与 internal/i18n 之外声明 i18n.MessageID 常量"
	badReexportID                   = domi18n.KeyCore // want "禁止在 core/domain/i18n 与 internal/i18n 之外声明 i18n.MessageID 常量"
)

type badAliasID = domi18n.MessageID // want "禁止在 core/domain/i18n 与 internal/i18n 之外声明 i18n.MessageID 类型别名"

const untypedRaw = "engine.untyped"

type holder struct {
	ID domi18n.MessageID
}

func goodUsage(paramID domi18n.MessageID) domi18n.MessageID {
	var zero domi18n.MessageID
	_ = zero
	id := domi18n.KeyCore
	id = i18n.KeyRoot
	id = paramID
	m := map[domi18n.MessageID]string{
		domi18n.KeyCore: "ok",
		i18n.KeyRoot:    "ok",
	}
	_ = m[id]
	s := []domi18n.MessageID{domi18n.KeyCore, i18n.KeyRoot, id}
	h := holder{ID: s[0]}
	_ = domi18n.NewMessage(h.ID)
	_ = domi18n.NewMessage(domi18n.MessageIDInvalid)
	if id == domi18n.KeyCore {
		return id
	}
	switch id {
	case domi18n.KeyCore, i18n.KeyRoot:
		return domi18n.KeyCore
	}
	// M1 阶段分阶段作用域：非 i18n 包暂未对规则 2/3 合闸。
	_ = fmt.Errorf("staged: %w", errors.New("未迁移中文提示"))
	return domi18n.KeyCore
}

func badRule1Positions(existing domi18n.MessageID, raw string, ch chan domi18n.MessageID) domi18n.MessageID {
	const localBad domi18n.MessageID = "local.bad" // want "禁止在 core/domain/i18n 与 internal/i18n 之外声明 i18n.MessageID 常量"
	_ = localBad                                   // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"

	var v1 domi18n.MessageID = "var.lit" // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	_ = v1

	id := domi18n.KeyCore
	id = "assign.lit"                                      // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	id = untypedRaw                                        // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	id += ".suffix"                                        // want "禁止通过拼接构造或修改 i18n.MessageID"
	_ = domi18n.NewMessage("call.lit")                     // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	_ = domi18n.NewMessage(existing + ".concat")           // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	_ = domi18n.NewMessage(domi18n.KeyCore + i18n.KeyRoot) // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	_ = domi18n.MessageID("conv.lit")                      // want "禁止在属主包外通过类型转换构造 i18n.MessageID"
	_ = domi18n.MessageID(raw)                             // want "禁止在属主包外通过类型转换构造 i18n.MessageID"

	_ = []domi18n.MessageID{"slice.lit"}           // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	_ = map[domi18n.MessageID]int{"map.key": 1}    // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	_ = map[string]domi18n.MessageID{"a": "map.v"} // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	_ = holder{ID: "struct.lit"}                   // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"

	m := map[domi18n.MessageID]int{}
	_ = m["index.lit"] // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	ch <- "send.lit"   // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"

	if id == "cmp.lit" { // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
		return "ret.lit" // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	}
	switch id {
	case "case.lit": // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	}
	return domi18n.KeyCore
}
