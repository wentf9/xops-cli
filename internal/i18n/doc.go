// Package i18n 提供 XOps v2 根模块纯叶层国际化词库、严格 YAML 解码器与不可变 Localizer。
//
// 本包属于根模块单向依赖拓扑的最底层叶包（LayerInternalI18n），严格遵守以下架构边界与不变量：
//   - 单向最小依赖：仅允许导入 core/domain/i18n、core/conc、纯内存/格式化标准库（含受限只读 embed）
//     及 go.yaml.in/yaml/v3，严禁触盘、网络、进程或系统调用；
//   - 零 init() 与零全局可变状态：仅在 embed_fs.go 持有经 noimplicit 六重门控保护的只读 embed.FS，
//     所有 Catalog 与 Localizer 均由组合根按需纯内存构造并显式注入；
//   - 严格失败关闭：Catalog 与 Localizer 均标注 //xops:opaque 与 //xops:failclosed；零值或 nil *Localizer
//     对 Render(msg) 回退 msg.Canonical()，对 RenderError(err) 回退 err.Error()，对 T(id)/TPlural(id) 失败关闭返回 string(id)；
//   - 零源码中文字面量与结构化错误展开：全部错误段连接符取自 YAML 词条 common.error_join，RenderError 经
//     domi18n.InspectNode 与 UnwrapDirect 逐层展开并结构化去重，同时无入侵本地化 context 与 core/conc 哨兵及 *conc.PanicError。
package i18n

import "go.yaml.in/yaml/v3"

// 编译期接口一致性断言，确保 Entry 持续实现 yaml.v3 自定义严格节点解码协议。
var _ yaml.Unmarshaler = (*Entry)(nil)
