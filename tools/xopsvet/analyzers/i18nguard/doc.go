// Package i18nguard 实现 XOps v2 第 10 个静态分析器：国际化（i18n）强类型契约与反硬编码护栏。
//
// 本分析器在全仓所有生产包强制执行规则 1 至规则 5，仅跳过 go test 合成 .test 入口包、
// 全部 *_test.go 与外置 *_test 包，以及测试基础设施与分析器自身（core/ports/tck、core/internal/sim、
// tools/xopsvet）：
//   - 规则 1（MessageID 强类型完整性）：禁止在 core/domain/i18n 与 internal/i18n 之外声明
//     i18n.MessageID 常量或类型别名、引用 core/domain/i18n.*WithFallback 桥接符号或将
//     MessageID 实例化至含 string 底层约束（如 ~string/cmp.Ordered）的非标准库泛型声明；全节点检查
//     赋值、变量初始化、函数实参、复合字面量（切片/数组/Map 键与值/结构体字段）、返回值、索引、
//     通道发送、switch case、比较、多层指针与显式类型转换，要求来源必须为上述两包导出的 *types.Const
//     或既有 MessageID 类型值，拒绝字面量、嵌套非 MessageID 类型转换与拼接；禁止向 i18n 构造/渲染
//     函数传入空常量 MessageIDInvalid，并禁止将 internal/i18n 常量传入 core/domain/i18n 自动兜底构造器；
//   - 规则 2（禁止绕过结构化错误构造器）：基于 TypesInfo.Uses 禁止直接调用或以函数值引用
//     errors.New 与 fmt.Errorf（显式放行 errors.Join），禁止在 core/domain/i18n 之外声明实现
//     Error() string 的底层 string 自定义错误类型，并要求其他具体自定义错误类型在匹配的接收者
//     方法集上同步实现 LocalizableView() core/domain/i18n.ErrorNode；永久基础设施白名单仅限
//     core/domain/i18n（精确主包，不含 internal/* 子包）、core/conc、core/internal/sim、core/ports/tck
//     与 tools/xopsvet；
//   - 规则 3（禁止生产源码硬编码 CJK 与全角中文标点）：对全部非跳过生产包无例外生效，检查生产文件
//     STRING/CHAR 字面量（含转义解码后），拦截任何 unicode.Han 字符以及 U+3000..U+303F、
//     U+FF00..U+FFEF 全角标点；
//   - 规则 4（动态明细与哨兵防吞噬守卫）：
//     4A 禁止向 core/domain/i18n.WrapSentinelDetail（arg2）与 DynamicDetailError（arg0）传入非空编译期字符串常量；
//     4B 拦截 {core/domain/i18n, internal/i18n}.{EF, WrapS} 传入 "common.detail"（含包内亦禁）、对安全/不可逆
//     红线哨兵（ErrOutcomeUnknown/ErrAuditHalted/ErrGateHalted 等）使用 "common.*" 弱模板，以及对非通用输入/格式
//     哨兵前缀（ErrInvalid*/ErrUsage/ErrCorrupt*/ErrCatalogCorrupt）的包级哨兵使用泛化空壳骨架键；
//   - 规则 5（编译期常量参数散文拦截）：拦截全仓生产包对 {core/domain/i18n, internal/i18n}.{Str, BoundStr} 的调用，
//     5A 对 "reason"/"detail"/"op" 槽位禁止任何非空编译期字符串常量，
//     5B 对 "field"/"kind"/"component"/"feature"/"expected"/"action" 槽位禁止包含 ASCII 空格。
package i18nguard
