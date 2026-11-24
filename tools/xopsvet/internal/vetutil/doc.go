// Package vetutil 为 xopsvet 的 8 大静态分析器提供无状态共享基础设施。
//
// 本包仅包含纯函数辅助工具，涵盖：
//   - XOps v2 三模块六边形架构包路径归一化、层级分类与白名单谓词；
//   - //xops:* 注释指令与 //nolint: 注释头的精准解析；
//   - go/types 符号解析、调用目标提取及防环类型树遍历。
package vetutil
