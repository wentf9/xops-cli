package engine

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"unsafe"

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

type localStr string

type okOption[T any] struct {
	V T
}

func okComparable[T comparable](a, b T) bool { return a == b }

func castStr[T ~string](s string) T           { return T(s) }
func castOrdered[T cmp.Ordered](s string) T   { var zero T; _ = s; return zero }
func castInferred[T ~string](_ T, s string) T { return T(s) }
func forgePtr[P *domi18n.MessageID](s *string) P {
	return P(s)
}

type strBox[T ~string] struct {
	V T
}

func goodUsage(paramID domi18n.MessageID, loc *i18n.Localizer) domi18n.MessageID {
	var zero domi18n.MessageID
	var zeroInit domi18n.MessageID = domi18n.MessageIDInvalid
	_ = zero
	_ = zeroInit
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
	_ = domi18n.NewMessage(domi18n.KeyCore)
	_ = domi18n.CanonicalFallback(domi18n.KeyCore)
	_ = i18n.NewMessage(i18n.KeyRoot)
	_ = loc.T(i18n.KeyRoot)
	// 合法指针转换、标准库泛型与无 ~string 约束的泛型零误报。
	_ = (*domi18n.MessageID)(nil)
	_ = (*domi18n.MessageID)(&id)
	_ = slices.Contains(s, id)
	_ = cmp.Compare(id, domi18n.KeyCore)
	_ = okOption[domi18n.MessageID]{V: id}
	_ = okOption[*domi18n.MessageID]{V: &id}
	_ = okComparable(id, domi18n.KeyCore)
	if id == domi18n.MessageIDInvalid {
		return domi18n.MessageIDInvalid
	}
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

func badRule1Positions(existing domi18n.MessageID, raw string, ch chan domi18n.MessageID, loc *i18n.Localizer) domi18n.MessageID {
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

	// Plan v2.1 绕过封堵回归 1：嵌套非 MessageID 类型转换包装绕过。
	_ = domi18n.MessageID(string("forged.id")) // want "禁止在属主包外通过类型转换构造 i18n.MessageID"
	_ = domi18n.MessageID(string(raw))         // want "禁止在属主包外通过类型转换构造 i18n.MessageID"
	_ = domi18n.MessageID([]byte("forged"))    // want "禁止在属主包外通过类型转换构造 i18n.MessageID"
	_ = domi18n.MessageID(localStr("forged"))  // want "禁止在属主包外通过类型转换构造 i18n.MessageID"

	// Plan v2.1 绕过封堵回归 2：单层与多层指针类型转换绕过。
	type localMsgPtr *domi18n.MessageID
	var lp localMsgPtr
	rawPtr := &raw
	_ = *(*domi18n.MessageID)(&raw)                    // want "禁止在属主包外通过类型转换构造 i18n.MessageID"
	_ = (**domi18n.MessageID)(unsafe.Pointer(&rawPtr)) // want "禁止在属主包外通过类型转换构造 i18n.MessageID"
	_ = (*domi18n.MessageID)(unsafe.Pointer(&raw))     // want "禁止在属主包外通过类型转换构造 i18n.MessageID"
	_ = (*domi18n.MessageID)(lp)                       // want "禁止在属主包外通过类型转换构造 i18n.MessageID"

	// Plan v2.1 绕过封堵回归 3：~string / cmp.Ordered / 类型推导 / 指针类型集 / 泛型结构体实例化绕过。
	_ = castStr[domi18n.MessageID]("forged")     // want "禁止在属主包外将 i18n.MessageID 实例化至含 string 底层约束的非标准库泛型声明"
	_ = castOrdered[domi18n.MessageID]("forged") // want "禁止在属主包外将 i18n.MessageID 实例化至含 string 底层约束的非标准库泛型声明"
	_ = castInferred(existing, "forged")         // want "禁止在属主包外将 i18n.MessageID 实例化至含 string 底层约束的非标准库泛型声明"
	_ = *forgePtr[*domi18n.MessageID](&raw)      // want "禁止在属主包外将 i18n.MessageID 实例化至含 string 底层约束的非标准库泛型声明"
	var box strBox[domi18n.MessageID]            // want "禁止在属主包外将 i18n.MessageID 实例化至含 string 底层约束的非标准库泛型声明"
	_ = box

	// Plan v2.1 绕过封堵回归 3b：禁止对 MessageID 执行字符串切片伪造未注册键或空串 MessageIDInvalid。
	_ = domi18n.NewMessage(domi18n.KeyCore[:4]) // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	_ = domi18n.E(domi18n.KeyCore[:0])          // want "i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量"
	_ = (domi18n.KeyCore[:4])[0]                // want "禁止对 i18n.MessageID 执行切片运算构造新标识"

	// Plan v2.1 绕过封堵回归 4：禁止向构造/渲染函数直传 MessageIDInvalid。
	_ = domi18n.NewMessage(domi18n.MessageIDInvalid) // want "禁止向 i18n 构造或渲染函数传入无效标识 MessageIDInvalid"
	_ = i18n.E(domi18n.MessageIDInvalid)             // want "禁止向 i18n 构造或渲染函数传入无效标识 MessageIDInvalid"
	_ = loc.T(domi18n.MessageIDInvalid)              // want "禁止向 i18n 构造或渲染函数传入无效标识 MessageIDInvalid"

	// Plan v2.1 绕过封堵回归 5：禁止将 internal/i18n 键传入 core/domain/i18n 自动兜底构造器及 CanonicalFallback。
	_ = domi18n.CanonicalFallback(i18n.KeyRoot)   // want "禁止将 internal/i18n 声明的 MessageID 常量传入 core/domain/i18n 构造器"
	_ = domi18n.NewMessage(i18n.KeyRoot)          // want "禁止将 internal/i18n 声明的 MessageID 常量传入 core/domain/i18n 构造器"
	_ = domi18n.Sentinel(i18n.KeyRoot)            // want "禁止将 internal/i18n 声明的 MessageID 常量传入 core/domain/i18n 构造器"
	_ = domi18n.E(i18n.KeyRoot)                   // want "禁止将 internal/i18n 声明的 MessageID 常量传入 core/domain/i18n 构造器"
	_ = domi18n.Wrap(nil, i18n.KeyRoot)           // want "禁止将 internal/i18n 声明的 MessageID 常量传入 core/domain/i18n 构造器"
	_ = domi18n.NewPluralMessage(i18n.KeyRoot, 2) // want "禁止将 internal/i18n 声明的 MessageID 常量传入 core/domain/i18n 构造器"

	// Plan v2.1 绕过封堵回归 6：包外禁止一切 *WithFallback 桥接符号引用（含调用与函数值）。
	_ = domi18n.NewMessageWithFallback(domi18n.KeyCore, "fb") // want "禁止在 core/domain/i18n 与 internal/i18n 之外引用 NewMessageWithFallback"
	_ = domi18n.SentinelWithFallback(domi18n.KeyCore, "fb")   // want "禁止在 core/domain/i18n 与 internal/i18n 之外引用 SentinelWithFallback"
	fbFn := domi18n.NewErrorWithFallback                      // want "禁止在 core/domain/i18n 与 internal/i18n 之外引用 NewErrorWithFallback"
	_ = fbFn

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
