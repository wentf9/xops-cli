// Package vetutil 为 xopsvet 的 9 大正交静态分析器及共享底座提供无状态基础设施。
//
// 本包仅包含纯函数辅助工具，涵盖：
//   - XOps v2 三模块六边形架构包路径归一化、层级分类、文件级 //nolint: 与白名单谓词；
//   - //xops:* 注释指令与 //nolint: 注释头的精准解析；
//   - 共享 passes/inspect 索引获取、go/types 符号解析、不入接口方法与签名的值承载类型遍历（ContainsValueType）
//     及含 *types.Union 的全引用类型树遍历；
//   - 含数字边界的驼峰/蛇形分词、编译期纯表达式校验（覆盖 Go 1.27 new(expr) 与非结构体字面量 Key）、
//     结构体 JSON/YAML 序列化标签解析与确定性排序去重诊断输出。
package vetutil
