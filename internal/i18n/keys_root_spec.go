package i18n

import (
	"slices"
	"time"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// 本文件声明根模块专属强类型 MessageID 常量、不可变哨兵错误及紧凑结构化消息/错误构造封装。
// 所有常量均通过 xopsvet/i18nguard 规则 1 保护，并与 locales/{en,zh}/*.yaml 保持 100% 双射。
const (
	// KeyCatalogCorrupt 表示国际化词库元数据或内容损坏（哨兵）。
	KeyCatalogCorrupt domi18n.MessageID = "i18n.catalog.corrupt"
	// KeyCatalogLoadFailed 表示从嵌入文件系统读取词库文件失败。
	KeyCatalogLoadFailed domi18n.MessageID = "i18n.catalog.load_failed"
	// KeyCatalogMissingLocale 表示目标语种词库目录缺失或无有效 YAML 文件。
	KeyCatalogMissingLocale domi18n.MessageID = "i18n.catalog.missing_locale"
	// KeyCatalogInvalidYAML 表示词库文件不符合单一顶层映射 YAML 文档规范。
	KeyCatalogInvalidYAML domi18n.MessageID = "i18n.catalog.invalid_yaml"
	// KeyCatalogInvalidKey 表示词库文件包含不符合 MessageID 规范的非法键名。
	KeyCatalogInvalidKey domi18n.MessageID = "i18n.catalog.invalid_key"
	// KeyCatalogDuplicateKey 表示同一语种词库（单文件内或跨文件）存在重复消息键。
	KeyCatalogDuplicateKey domi18n.MessageID = "i18n.catalog.duplicate_key"
	// KeyCatalogInvalidEntry 表示指定消息键对应的词库条目解码或校验失败。
	KeyCatalogInvalidEntry domi18n.MessageID = "i18n.catalog.invalid_entry"
	// KeyCatalogInvalidEntryNode 表示条目 YAML 节点既非字符串标量也非合法复数映射。
	KeyCatalogInvalidEntryNode domi18n.MessageID = "i18n.catalog.invalid_entry_node"
	// KeyCatalogEmptyEntry 表示词库条目模板为空串或纯空白。
	KeyCatalogEmptyEntry domi18n.MessageID = "i18n.catalog.empty_entry"
	// KeyCatalogUnknownField 表示复数条目映射包含未定义的未知字段。
	KeyCatalogUnknownField domi18n.MessageID = "i18n.catalog.unknown_field"
	// KeyCatalogDuplicateField 表示复数条目映射重复声明同一字段。
	KeyCatalogDuplicateField domi18n.MessageID = "i18n.catalog.duplicate_field"
	// KeyCatalogNonScalarField 表示复数条目字段值非非空字符串标量。
	KeyCatalogNonScalarField domi18n.MessageID = "i18n.catalog.non_scalar_field"
	// KeyCatalogMissingOther 表示复数条目映射缺少必需的 other 字段。
	KeyCatalogMissingOther domi18n.MessageID = "i18n.catalog.missing_other"
	// KeyCatalogInvalidTemplate 表示指定消息键的模板存在非法占位符语法。
	KeyCatalogInvalidTemplate domi18n.MessageID = "i18n.catalog.invalid_template"
	// KeyCatalogPluralPlaceholderMismatch 表示复数条目的 one 与 other 模板占位符集合不一致。
	KeyCatalogPluralPlaceholderMismatch domi18n.MessageID = "i18n.catalog.plural_placeholder_mismatch"
	// KeyCatalogPlaceholderMismatch 表示同一消息键在多语种词库间的占位符集合不一致。
	KeyCatalogPlaceholderMismatch domi18n.MessageID = "i18n.catalog.placeholder_mismatch"
	// KeyCatalogMissingKey 表示目标语种词库缺少必需消息键。
	KeyCatalogMissingKey domi18n.MessageID = "i18n.catalog.missing_key"

	// KeyStdContextCanceled 表示标准库 context.Canceled 的结构化本地化键。
	KeyStdContextCanceled domi18n.MessageID = "std.context.canceled"
	// KeyStdDeadlineExceeded 表示标准库 context.DeadlineExceeded 的结构化本地化键。
	KeyStdDeadlineExceeded domi18n.MessageID = "std.context.deadline_exceeded"

	// KeyConcNurseryNotInitialized 表示 core/conc.ErrNurseryNotInitialized 的本地化键。
	KeyConcNurseryNotInitialized domi18n.MessageID = "conc.nursery.not_initialized"
	// KeyConcNurseryClosed 表示 core/conc.ErrNurseryClosed 的本地化键。
	KeyConcNurseryClosed domi18n.MessageID = "conc.nursery.closed"
	// KeyConcNilTask 表示 core/conc.ErrNilTask 的本地化键。
	KeyConcNilTask domi18n.MessageID = "conc.nil_task"
	// KeyConcTaskPanicked 表示 core/conc.ErrTaskPanicked 的本地化键。
	KeyConcTaskPanicked domi18n.MessageID = "conc.task_panicked"
	// KeyConcMutexNotInitialized 表示 core/conc.ErrMutexNotInitialized 的本地化键。
	KeyConcMutexNotInitialized domi18n.MessageID = "conc.mutex.not_initialized"
	// KeyConcNilContext 表示 core/conc.ErrNilContext 的本地化键。
	KeyConcNilContext domi18n.MessageID = "conc.nil_context"
	// KeyConcPanic 表示携带 panic 值的 *core/conc.PanicError 的本地化键。
	KeyConcPanic domi18n.MessageID = "conc.panic_value"
)

// 本包导出的不可变根模块哨兵错误，均通过单参 Sentinel(constID) 声明以满足 noimplicit 约束。
var (
	// ErrCatalogCorrupt 表示嵌入式或自定义文件系统中的国际化词库结构、语法或对称性损坏。
	ErrCatalogCorrupt = Sentinel(KeyCatalogCorrupt)
)

// RootErrorKeys 返回根模块中须在 rootFallback 登记规范英文兜底模板的全部错误、诊断与提示 MessageID 列表。
func RootErrorKeys() []domi18n.MessageID {
	base := []domi18n.MessageID{
		KeyCatalogCorrupt, KeyCatalogLoadFailed, KeyCatalogMissingLocale, KeyCatalogInvalidYAML,
		KeyCatalogInvalidKey, KeyCatalogDuplicateKey, KeyCatalogInvalidEntry, KeyCatalogInvalidEntryNode,
		KeyCatalogEmptyEntry, KeyCatalogUnknownField, KeyCatalogDuplicateField, KeyCatalogNonScalarField,
		KeyCatalogMissingOther, KeyCatalogInvalidTemplate, KeyCatalogPluralPlaceholderMismatch,
		KeyCatalogPlaceholderMismatch, KeyCatalogMissingKey,
		KeyStdContextCanceled, KeyStdDeadlineExceeded,
		KeyConcNurseryNotInitialized, KeyConcNurseryClosed, KeyConcNilTask, KeyConcTaskPanicked,
		KeyConcMutexNotInitialized, KeyConcNilContext, KeyConcPanic,
	}
	return slices.Concat(base, cliErrorKeys(), tuiErrorKeys(), sftpAndDaemonErrorKeys(), interactErrorAndPromptKeys())
}

// RootKeys 返回根模块注册的全部有效 MessageID 列表（包含错误/提示键与全部纯 UI/帮助/TUI/SFTP 展示键），
// 供 catalog_test.go 执行与 locales/{en,zh}/*.yaml 的 100% 双射校验与反向兜底穷尽校验。
func RootKeys() []domi18n.MessageID {
	return slices.Concat(RootErrorKeys(), cliDisplayKeys(), tuiDisplayKeys(), sftpDisplayKeys(), interactDisplayKeys())
}

// Sentinel 构造带根模块规范英文兜底的不可变哨兵错误（单参签名，供 var ErrX = i18n.Sentinel(i18n.KeyX) 使用）。
func Sentinel(id domi18n.MessageID) error {
	return domi18n.SentinelWithFallback(id, fallbackForID(id))
}

// NewMessage 构造携带根模块规范英文兜底模板的结构化不可变 Message。
func NewMessage(id domi18n.MessageID, params ...domi18n.Param) domi18n.Message {
	return domi18n.NewMessageWithFallback(id, fallbackForID(id), params...)
}

// NewPluralMessage 构造携带复数计数 count 与根模块规范英文兜底模板的结构化不可变 Message。
func NewPluralMessage(id domi18n.MessageID, count int64, params ...domi18n.Param) domi18n.Message {
	return domi18n.NewPluralMessageWithFallback(id, fallbackForID(id), count, params...)
}

// E 构造携带根模块规范英文兜底与强类型参数的独立结构化错误。
func E(id domi18n.MessageID, params ...domi18n.Param) error {
	return domi18n.NewErrorWithFallback(nil, nil, id, fallbackForID(id), params...)
}

// EF 构造同时绑定分类哨兵 sentinel 与根模块参数化消息的结构化错误。
func EF(sentinel error, id domi18n.MessageID, params ...domi18n.Param) error {
	return domi18n.NewErrorWithFallback(sentinel, nil, id, fallbackForID(id), params...)
}

// Wrap 以根模块规范英文兜底与强类型参数包装下层根因错误 cause。
func Wrap(cause error, id domi18n.MessageID, params ...domi18n.Param) error {
	return domi18n.NewErrorWithFallback(nil, cause, id, fallbackForID(id), params...)
}

// WrapS 同时绑定分类哨兵 sentinel、下层根因 cause 与根模块参数化消息。
func WrapS(sentinel, cause error, id domi18n.MessageID, params ...domi18n.Param) error {
	return domi18n.NewErrorWithFallback(sentinel, cause, id, fallbackForID(id), params...)
}

// 以下 10 个零开销参数构造转发器使根模块（internal/host/** 与 internal/entry/**）
// 仅导入 internal/i18n 即可一站式完成结构化消息与错误构造，无需重复导入 core/domain/i18n。

// Str 转发 core/domain/i18n.Str，构造严格校验的有界 UTF-8 字符串参数。
func Str(k, v string) domi18n.Param {
	return domi18n.Str(k, v)
}

// BoundStr 转发 core/domain/i18n.BoundStr，对外部不可信字符串执行确定性 UTF-8 净化与按 rune 边界裁剪。
func BoundStr(k, v string) domi18n.Param {
	return domi18n.BoundStr(k, v)
}

// Int 转发 core/domain/i18n.Int，构造整数参数。
func Int(k string, v int) domi18n.Param {
	return domi18n.Int(k, v)
}

// Int64 转发 core/domain/i18n.Int64，构造 64 位有符号整数参数。
func Int64(k string, v int64) domi18n.Param {
	return domi18n.Int64(k, v)
}

// Uint64 转发 core/domain/i18n.Uint64，构造 64 位无符号整数参数。
func Uint64(k string, v uint64) domi18n.Param {
	return domi18n.Uint64(k, v)
}

// Float 转发 core/domain/i18n.Float，构造有限 64 位浮点数参数。
func Float(k string, v float64, prec int) domi18n.Param {
	return domi18n.Float(k, v, prec)
}

// Bool 转发 core/domain/i18n.Bool，构造布尔参数。
func Bool(k string, v bool) domi18n.Param {
	return domi18n.Bool(k, v)
}

// Dur 转发 core/domain/i18n.Dur，构造时长参数。
func Dur(k string, d time.Duration) domi18n.Param {
	return domi18n.Dur(k, d)
}

// DurNanos 转发 core/domain/i18n.DurNanos，以显式纳秒整数构造时长参数。
func DurNanos(k string, nanos int64) domi18n.Param {
	return domi18n.DurNanos(k, nanos)
}

// Msg 转发 core/domain/i18n.Msg，构造受限深度嵌套的结构化 Message 参数。
func Msg(k string, m domi18n.Message) domi18n.Param {
	return domi18n.Msg(k, m)
}
