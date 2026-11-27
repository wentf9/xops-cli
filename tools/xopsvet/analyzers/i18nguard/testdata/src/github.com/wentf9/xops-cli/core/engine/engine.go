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
	return domi18n.KeyCore
}

type badEngineStructErr struct{ msg string } // want "自定义错误类型 badEngineStructErr 必须在匹配的接收者方法集上实现 LocalizableView"

func (e *badEngineStructErr) Error() string { return e.msg }

func badRule2AndRule3InEngine(e error) error {
	_ = &badEngineStructErr{msg: "bad"}
	_ = errors.Join(e, nil)
	_ = errors.New("engine raw")    // want "禁止引用 errors.New"
	_ = fmt.Errorf("engine: %w", e) // want "禁止引用 fmt.Errorf"
	_ = "引擎层禁止中文"                   // want "禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量"
	return nil
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

var (
	ErrOutcomeUnknown       = domi18n.Sentinel(domi18n.KeyCore)
	ErrAuditHalted          = domi18n.Sentinel(domi18n.KeyCore)
	ErrNonLoopbackAddress   = domi18n.Sentinel(domi18n.KeyCore)
	ErrOrphanedProcessGroup = domi18n.Sentinel(domi18n.KeyCore)
	ErrMissingAssetRef      = domi18n.Sentinel(domi18n.KeyCore)
	ErrScopeEscalated       = domi18n.Sentinel(domi18n.KeyCore)
	ErrInvalidConfig        = domi18n.Sentinel(domi18n.KeyCore)
	ErrUsage                = domi18n.Sentinel(domi18n.KeyCore)
	ErrCorruptData          = domi18n.Sentinel(domi18n.KeyCore)
	ErrCatalogCorrupt       = domi18n.Sentinel(domi18n.KeyCore)
)

const (
	constDetail = "static detail"
	constProse  = "not a directory"
)

func goodRule4AndRule5(dyn string, cause, localSent error) {
	// 规则 4A 合法：运行期变量与空串常量。
	_ = domi18n.WrapSentinelDetail(ErrOutcomeUnknown, cause, dyn)
	_ = domi18n.WrapSentinelDetail(ErrOutcomeUnknown, cause, "")
	_ = domi18n.DynamicDetailError(dyn)
	_ = domi18n.DynamicDetailError("")

	// 规则 4B 合法：安全红线配自包含领域键；通用输入/损坏哨兵配骨架键；局部哨兵变量；非红线业务哨兵配非骨架键。
	_ = domi18n.EF(ErrOutcomeUnknown, domi18n.KeyCore)
	_ = domi18n.WrapS(ErrAuditHalted, cause, domi18n.KeyCore)
	_ = domi18n.EF(ErrInvalidConfig, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "host"))
	_ = domi18n.EF(ErrUsage, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "flag"))
	_ = domi18n.EF(ErrCorruptData, domi18n.KeyCommonValueInvalid, domi18n.BoundStr("value", dyn))
	_ = domi18n.EF(ErrCatalogCorrupt, domi18n.KeyCommonOpFailed)
	_ = domi18n.EF(localSent, domi18n.KeyCommonFieldInvalid)
	_ = domi18n.EF(ErrMissingAssetRef, domi18n.KeyCore)
	_ = domi18n.EF(ErrMissingAssetRef, domi18n.KeyCommonNotFound)
	_ = i18n.WrapS(ErrOrphanedProcessGroup, cause, i18n.KeyHostSpecific)

	// 规则 5A/5B 合法：运行期动态值、空串、单标识符、未受限展示槽位（options/cmd/allowed）。
	_ = domi18n.Str("reason", dyn)
	_ = domi18n.BoundStr("detail", dyn)
	_ = i18n.Str("op", dyn)
	_ = domi18n.Str("reason", "")
	_ = domi18n.Str("field", "node_id")
	_ = domi18n.BoundStr("kind", "SOCKS5")
	_ = i18n.Str("component", "SecretVault")
	_ = domi18n.Str("feature", "follow_symlink")
	_ = domi18n.Str("expected", "v2")
	_ = i18n.BoundStr("action", "exec")
	_ = domi18n.Str("field", dyn)
	_ = domi18n.Str("options", "command, argv")
	_ = i18n.Str("cmd", "config import")
	_ = i18n.Str("allowed", "zh | en")
}

func badRule4AndRule5(cause error) {
	// 规则 4A 违规：动态原语禁止传入非空编译期字符串常量。
	_ = domi18n.WrapSentinelDetail(ErrOutcomeUnknown, cause, "static literal") // want "禁止向 WrapSentinelDetail 传入非空编译期字符串常量"
	_ = domi18n.WrapSentinelDetail(ErrAuditHalted, cause, constDetail)         // want "禁止向 WrapSentinelDetail 传入非空编译期字符串常量"
	_ = domi18n.DynamicDetailError("peer static error")                        // want "禁止向 DynamicDetailError 传入非空编译期字符串常量"
	_ = domi18n.DynamicDetailError("prefix " + "suffix")                       // want "禁止向 DynamicDetailError 传入非空编译期字符串常量"

	// 规则 4B-2 违规：安全红线哨兵禁止任何 "common.*" 弱模板。
	_ = domi18n.EF(ErrOutcomeUnknown, domi18n.KeyCommonNotFound)              // want "禁止对安全红线哨兵 ErrOutcomeUnknown 在 EF 中使用泛化弱模板"
	_ = domi18n.WrapS(ErrAuditHalted, cause, domi18n.KeyCommonOpFailed)       // want "禁止对安全红线哨兵 ErrAuditHalted 在 WrapS 中使用泛化弱模板"
	_ = i18n.EF(ErrNonLoopbackAddress, domi18n.KeyCommonFieldInvalid)         // want "禁止对安全红线哨兵 ErrNonLoopbackAddress 在 EF 中使用泛化弱模板"
	_ = i18n.WrapS(ErrOrphanedProcessGroup, cause, i18n.KeyHostSysSyscallErr) // want "禁止对具名业务哨兵 ErrOrphanedProcessGroup 在 WrapS 中使用泛化骨架键"

	// 规则 4B-3 违规：非通用输入/格式具名业务哨兵禁止泛化空壳骨架键。
	_ = domi18n.EF(ErrMissingAssetRef, domi18n.KeyCommonFieldInvalid)            // want "禁止对具名业务哨兵 ErrMissingAssetRef 在 EF 中使用泛化骨架键"
	_ = domi18n.EF(ErrScopeEscalated, domi18n.KeyCommonFieldValueInvalid)        // want "禁止对具名业务哨兵 ErrScopeEscalated 在 EF 中使用泛化骨架键"
	_ = domi18n.EF(ErrScopeEscalated, domi18n.KeyCommonValueInvalid)             // want "禁止对具名业务哨兵 ErrScopeEscalated 在 EF 中使用泛化骨架键"
	_ = domi18n.WrapS(ErrScopeEscalated, cause, domi18n.KeyCommonOpTargetFailed) // want "禁止对具名业务哨兵 ErrScopeEscalated 在 WrapS 中使用泛化骨架键"
	_ = i18n.EF(ErrMissingAssetRef, i18n.KeyHostSysSyscallErr)                   // want "禁止对具名业务哨兵 ErrMissingAssetRef 在 EF 中使用泛化骨架键"

	// 规则 5A 违规：reason / detail / op 禁止任何非空编译期字符串常量。
	_ = domi18n.Str("reason", "not_a_dir")      // want "禁止向 Str\\(\"reason\", ...\\) 传入非空编译期字符串常量"
	_ = domi18n.BoundStr("detail", constDetail) // want "禁止向 BoundStr\\(\"detail\", ...\\) 传入非空编译期字符串常量"
	_ = i18n.Str("op", "decrypt")               // want "禁止向 Str\\(\"op\", ...\\) 传入非空编译期字符串常量"
	_ = i18n.BoundStr("reason", constProse)     // want "禁止向 BoundStr\\(\"reason\", ...\\) 传入非空编译期字符串常量"

	// 规则 5B 违规：field / kind / component / feature / expected / action 禁止含空格散文常量。
	_ = domi18n.Str("field", "jump host")                        // want "禁止向 Str\\(\"field\", ...\\) 传入含空格的散文常量"
	_ = domi18n.BoundStr("kind", "import format")                // want "禁止向 BoundStr\\(\"kind\", ...\\) 传入含空格的散文常量"
	_ = i18n.Str("component", "KeySignerPort or OperatorReadFS") // want "禁止向 Str\\(\"component\", ...\\) 传入含空格的散文常量"
	_ = domi18n.Str("feature", "stdin in batch_exec")            // want "禁止向 Str\\(\"feature\", ...\\) 传入含空格的散文常量"
	_ = i18n.Str("expected", "non-empty string")                 // want "禁止向 Str\\(\"expected\", ...\\) 传入含空格的散文常量"
	_ = i18n.BoundStr("action", "delete host")                   // want "禁止向 BoundStr\\(\"action\", ...\\) 传入含空格的散文常量"
}
