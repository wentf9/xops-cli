// Package errchain 为 core/domain/i18n 提供纯泛型错误链折叠渲染代数（规则 M1–M6）。
//
// 架构约束（Plan v2.2 无环叶包）：
//   - 本包位于 core/domain/i18n/internal/errchain，仅允许由父包 core/domain/i18n 单向导入；
//   - 零仓内依赖、仅导入标准库 errors 与 strings；
//   - 零 any 擦除、零反射、零全局可变 var、零 init()。
package errchain
