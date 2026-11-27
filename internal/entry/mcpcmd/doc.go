// Package mcpcmd 实现 XOps v2 极薄 MCP 入站驱动入口（ADR-001 / ADR-009 / ADR-011 / Phase 5 P5-T3）。
//
// 核心工程与安全不变量：
//   - 仅依赖 core/{domain,conc,engine} 与 Go 标准库，零引用 internal/host/**、core/osfs 与 core/ports；
//   - 零业务逻辑、零 OperatorReadFS 感知、零 SecretBox 值引用与擦除；
//   - 同时支持 stdio 与 Streamable HTTP 两种传输形态，启动期强制先执行 MCPServer.Prepare(ctx)
//     （完成 O(1) 跨进程崩溃审计对账与断传 WAL 恢复）后再对外提供服务；
//   - 全部后台监督协程严格受 core/conc.Nursery 托管，零裸 go、零 time.Sleep、零 init()、零可变包级状态、零 //nolint:；
//   - 所有配置与 DTO 时长字段统一使用 algebraic.Duration（零裸 time.Duration），零值配置严格失败关闭。
package mcpcmd

import "errors"

// 本包导出的不可变规范哨兵错误，便于组合根与上层调用方经 errors.Is 精确判别启动或参数失败原因。
var (
	ErrNilContext       = errors.New("mcpcmd: context 不能为 nil")
	ErrInvalidConfig    = errors.New("mcpcmd: 无效的 MCP 入口配置")
	ErrInvalidTransport = errors.New("mcpcmd: 不支持的 MCP 传输模式")
)
