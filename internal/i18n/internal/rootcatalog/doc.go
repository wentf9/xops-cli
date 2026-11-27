// Package rootcatalog 为 internal/i18n 提供纯字符串规范英文兜底词表与全量键索引。
//
// 架构约束（Plan v2.2 议题一，单向无环叶包）：
//   - 本包位于 internal/i18n/internal/rootcatalog，仅允许由父包 internal/i18n 单向导入；
//   - 零仓内依赖（仅导入标准库 slices，不引用 MessageID 类型，使 internal/i18n 保持唯一根模块常量属主）；
//   - 严格纯函数实现：零 init()、零包级可变 var、零 embed 与 I/O、零反射、零生产中文字符字面量。
package rootcatalog
