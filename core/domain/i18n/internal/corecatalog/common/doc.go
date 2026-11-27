// Package common 为 core/domain/i18n 提供 i18n 基础设施、通用错误与交互提示键的纯字符串英文兜底分片。
//
// 架构约束：零 XOps 依赖、仅导入 slices、零包级 var、零 init()、零生产中文字符字面量。
package common
