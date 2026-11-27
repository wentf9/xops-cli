// Package corecatalog 为 core/domain/i18n 提供纯字符串规范英文兜底词表与全量键索引。
//
// 架构约束（Plan v2.1 §3.1 无环 DAG）：
//   - 本包位于 core/domain/i18n/internal/corecatalog，仅允许由父包 core/domain/i18n 单向导入；
//   - 零仓内依赖（不使用 MessageID 类型，使 core/domain/i18n 保持唯一 MessageID 常量属主）；
//   - 严格纯函数实现：零 init()、零包级可变 var、零 I/O、零反射、零生产中文字符字面量。
package corecatalog
