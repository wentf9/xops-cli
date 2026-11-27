// Package protocol 定义 XOps v2 MCP 运行时（core/internal/mcpruntime）的强类型 JSON-RPC 2.0 与
// MCP 协议报文编解码器、7 个判别式工具 Schema 契约、两步审批信封 DTO 以及脱敏错误分类器（ADR-001 / ADR-006 / ADR-008）。
//
// 核心安全与编码不变量：
//   - 全部 JSON 序列化严格使用 Go 1.27 encoding/json/v2 并开启 jsonv2.Deterministic(true)；
//   - 全部 JSON 反序列化强制开启 jsonv2.RejectUnknownMembers(true)，零宽容拒绝未知字段与非法零值；
//   - 全部 DTO 严禁裸用 time.Duration（统一使用 algebraic.Duration），严禁携带 secret.SecretBox；
//   - 物理不引用 ports.OperatorReadFS、core/internal/pool、core/internal/sshnet 或 core/osfs；
//   - 全包 0 init()、0 可变包级 var、0 裸 go 语句、0 nolint 豁免。
package protocol

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

// 本包导出的不可变哨兵错误，供 mcpruntime 传输层、工具分发层与测试经 errors.Is 精确区分协议错误类别。
var (
	// ErrParseJSON 表示入站字节流不是合法 JSON 语法（JSON-RPC 2.0 -32700 Parse error）。
	ErrParseJSON = domi18n.Sentinel(domi18n.KeyMCPProtoParseJSON)
	// ErrInvalidJSONRPC 表示 JSON-RPC 2.0 报文结构、版本、未知字段或方法名非法（-32600 Invalid Request）。
	ErrInvalidJSONRPC = domi18n.Sentinel(domi18n.KeyMCPProtoInvalidRPC)
	// ErrInvalidRequestID 表示 JSON-RPC 2.0 请求标识（id）非法或处于零值无效态。
	ErrInvalidRequestID = domi18n.Sentinel(domi18n.KeyMCPProtoInvalidReqID)
	// ErrInvalidMCPMessage 表示 MCP 协议握手、工具调用或内容块载荷非法。
	ErrInvalidMCPMessage = domi18n.Sentinel(domi18n.KeyMCPProtoInvalidMsg)
	// ErrInvalidApproval 表示两步审批回执 DTO 缺失必填字段或摘要/判定非法。
	ErrInvalidApproval = domi18n.Sentinel(domi18n.KeyMCPProtoInvalidAppr)
	// ErrInvalidSchema 表示内置工具 JSON Schema 语法校验失败。
	ErrInvalidSchema = domi18n.Sentinel(domi18n.KeyMCPProtoInvalidSchema)
	// ErrInvalidParams 表示 MCP 工具或方法入参不符合强类型判别式 Schema。
	ErrInvalidParams = domi18n.Sentinel(domi18n.KeyMCPProtoInvalidParams)
	// ErrToolNotFound 表示请求的 MCP 工具名未注册。
	ErrToolNotFound = domi18n.Sentinel(domi18n.KeyMCPProtoToolNotFound)
	// ErrOutcomeUnknown 表示远端命令已启动但未取得确定终态（ADR-016：禁止自动重试）。
	ErrOutcomeUnknown = domi18n.Sentinel(domi18n.KeyMCPProtoOutcomeUnk)
)
