// Package i18n 提供 XOps v2 纯数据国际化值对象与结构化错误核心原语。
//
// 本包是 core/domain/** 零仓内依赖的绝对叶包（严禁导入 core/domain/algebraic 或任何仓内包），
// 仅依赖 archbound 白名单内的纯函数标准库，严守零 I/O、零全局可变状态、零反射与零文案词库铁律：
//   - 延迟渲染边界：core 仅构造纯数据 Message、Error 与 LocalizableNode，不感知运行期 Locale；
//     err.Error()、audit.jsonl、events 与密码学摘要恒定输出规范英文，终端多语种渲染推迟至根模块 internal/i18n；
//   - 零值失败关闭：Locale、ParamKind、MessageID、Param、Message 与 Error 的零值恒为无效态；
//   - 强类型无反射参数：Param 以封闭变体枚举承载 7 类基础值与受限深度嵌套 Message，
//     底层以 durNanos int64 存储时长（无 time.Duration 结构体字段），从类型层面阻断机密经 any 擦除泄露；
//   - 无穿透逐层错误检查：LocalizableNode 刻意不嵌入 error，通过 InspectNode 与 UnwrapDirect 支持展示层
//     逐层本地化与结构化去重，零触发 errorlint 且无需任何行内 lint 豁免注释。
package i18n

import (
	"encoding"
	jsonv2 "encoding/json/v2"
)

// 编译期接口一致性断言，保证核心值对象与错误节点持续满足文本、JSON/v2 与错误协议。
var (
	_ encoding.TextAppender    = LocaleInvalid
	_ encoding.TextMarshaler   = LocaleInvalid
	_ encoding.TextUnmarshaler = (*Locale)(nil)
	_ jsonv2.MarshalerTo       = Param{}
	_ jsonv2.UnmarshalerFrom   = (*Param)(nil)
	_ jsonv2.MarshalerTo       = Message{}
	_ jsonv2.UnmarshalerFrom   = (*Message)(nil)
	_ error                    = (*Error)(nil)
	_ LocalizableNode          = (*Error)(nil)
)
