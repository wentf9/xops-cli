// Package i18nguard 实现 XOps v2 第 10 个静态分析器：国际化（i18n）强类型契约与反硬编码护栏。
//
// 本分析器仅约束生产源码，自动跳过 go test 合成 .test 入口包、全部 *_test.go 与外置 *_test 包，
// 以及测试基础设施与分析器自身（core/ports/tck、core/internal/sim、tools/xopsvet）：
//   - 规则 1（MessageID 强类型完整性，M1 起全仓强制）：禁止在 core/domain/i18n 与 internal/i18n
//     之外声明 i18n.MessageID 常量或类型别名；全节点检查赋值、变量初始化、函数实参、复合字面量
//     （切片/数组/Map 键与值/结构体字段）、返回值、索引、通道发送、switch case、比较与类型转换，
//     要求来源必须为上述两包导出的 *types.Const 或既有 MessageID 类型值，拒绝字面量、非常量转换与拼接；
//   - 规则 2（禁止绕过结构化错误构造器）：基于 TypesInfo.Uses 禁止直接调用或以函数值引用
//     errors.New 与 fmt.Errorf（显式放行 errors.Join），并禁止在 core/domain/i18n 之外声明实现
//     Error() string 的底层 string 自定义错误类型；永久基础设施白名单为 core/domain/i18n、core/conc、
//     core/internal/sim、core/ports/tck 与 tools/xopsvet；
//   - 规则 3（禁止生产源码硬编码 CJK 与全角中文标点）：检查生产文件 STRING/CHAR 字面量（含转义解码后），
//     拦截任何 unicode.Han 字符以及 U+3000..U+303F、U+FF00..U+FFEF 全角标点。
//
// 分阶段合闸策略：M1 阶段规则 1 全仓生效，规则 2/3 通过独立函数 isRules23Enforced 限定作用于
// core/domain/i18n 与 internal/i18n；M2 扩展至入口与交互层；M3 全仓迁移完成后移除阶段过滤并全面合闸。
package i18nguard
