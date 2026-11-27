// Package corecatalog 为 core/domain/i18n 提供纯字符串规范英文兜底词表薄路由与全量键索引。
//
// 架构约束（Plan v2.2 无环水平分片 DAG）：
//   - 本包位于 core/domain/i18n/internal/corecatalog，仅允许由父包 core/domain/i18n 单向导入；
//   - 本包自身仅导入 slices 与下属 5 个纯字符串域叶分片包（common/domain/ports/runtime/usecase），严禁反向依赖父包；
//   - 各叶分片零仓内依赖（不使用 MessageID 类型），每包独立享有 3,000 LOC 容量配额，
//     严守零 init()、零包级可变 var、零 I/O、零反射与零生产中文字符字面量。
package corecatalog
