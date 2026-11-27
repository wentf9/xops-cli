// Package textalg 为 core/domain/i18n 提供纯字符串、UTF-8、区域标签、模板词法与 JSON null 守卫算法。
//
// 架构约束（Plan v2.2 无环叶包）：
//   - 本包位于 core/domain/i18n/internal/textalg，仅允许由父包 core/domain/i18n 单向导入；
//   - 零仓内依赖、仅依赖纯函数标准库；
//   - 严守零 I/O、零全局可变 var、零 init()、零反射与零非确定性时钟。
package textalg
