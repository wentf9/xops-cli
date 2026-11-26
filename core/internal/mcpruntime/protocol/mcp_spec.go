package protocol

import (
	"encoding/json/jsontext"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// MCP 协议版本协商常量与方法名常量定义。
const (
	// LatestProtocolVersion 为本运行时优先协商的 MCP 规范版本（支持 Streamable HTTP 与结构化内容）。
	LatestProtocolVersion = "2025-03-26"
	// LegacyProtocolVersion 为兼容主流 stdio/SSE 客户端的次级受支持 MCP 规范版本。
	LegacyProtocolVersion = "2024-11-05"

	MethodInitialize      = "initialize"
	MethodInitializedNote = "notifications/initialized"
	MethodCancelledNote   = "notifications/cancelled"
	MethodPing            = "ping"
	MethodToolsList       = "tools/list"
	MethodToolsCall       = "tools/call"
)

// NegotiateProtocolVersion 按 MCP 规范协商协议版本：若客户端请求受支持版本则原样采纳，否则返回最新受支持版本。
func NegotiateProtocolVersion(requested string) string {
	supported := []string{LatestProtocolVersion, LegacyProtocolVersion}
	if slices.Contains(supported, requested) {
		return requested
	}
	return LatestProtocolVersion
}

// ImplementationInfo 描述 MCP 客户端或服务端的实现标识与版本号。
type ImplementationInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InitializeParams 描述 MCP `initialize` 请求入参。
type InitializeParams struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    jsontext.Value     `json:"capabilities,omitzero"`
	ClientInfo      ImplementationInfo `json:"clientInfo"`
}

// ToolsCapability 描述服务端声明的工具集能力标志。
type ToolsCapability struct {
	ListChanged bool `json:"listChanged"`
}

// ServerCapabilities 描述 MCP `initialize` 响应中声明的服务端能力集。
type ServerCapabilities struct {
	Tools *ToolsCapability `json:"tools,omitzero"`
}

// InitializeResult 描述 MCP `initialize` 响应载荷。
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      ImplementationInfo `json:"serverInfo"`
	Instructions    string             `json:"instructions,omitzero"`
}

// ToolDescriptor 描述 `tools/list` 返回的单个强类型判别式 MCP 工具元数据与 JSON Schema。
type ToolDescriptor struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema jsontext.Value `json:"inputSchema"`
}

// ListToolsParams 描述 `tools/list` 可选分页入参。
type ListToolsParams struct {
	Cursor string `json:"cursor,omitzero"`
}

// ListToolsResult 描述 `tools/list` 响应载荷。
type ListToolsResult struct {
	Tools []ToolDescriptor `json:"tools"`
}

// CallToolParams 描述 `tools/call` 请求入参。
type CallToolParams struct {
	Name      string         `json:"name"`
	Arguments jsontext.Value `json:"arguments,omitzero"`
}

// ContentBlock 表示 MCP 工具返回的单条内容块（支持 text 与 image 两类标准变体）。
type ContentBlock struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitzero"`
	Data     string `json:"data,omitzero"`
	MIMEType string `json:"mimeType,omitzero"`
}

// NewTextContent 构造文本形态的 MCP ContentBlock。
func NewTextContent(text string) ContentBlock {
	return ContentBlock{Type: "text", Text: text}
}

// NewImageContent 构造 Base64 图像形态的 MCP ContentBlock。
func NewImageContent(mimeType, base64Data string) ContentBlock {
	return ContentBlock{Type: "image", MIMEType: mimeType, Data: base64Data}
}

// CallToolResult 描述 MCP `tools/call` 响应载荷，同时提供兼容文本内容块与结构化确定性 JSON 内容。
type CallToolResult struct {
	Content           []ContentBlock `json:"content"`
	StructuredContent jsontext.Value `json:"structuredContent,omitzero"`
	IsError           bool           `json:"isError,omitzero"`
}

// ApprovalChallengeDTO 描述护栏两步审批挑战（NoElicitFallbackChallenge）的结构化响应载荷（INV-E5）；
// 客户端展示信封并经人工确认后，将 verdict/envelope_digest/envelope 封装进 ApprovalSubmissionDTO 二次提交。
type ApprovalChallengeDTO struct {
	Envelope       security.ApprovalEnvelope `json:"envelope"`
	EnvelopeDigest security.Digest           `json:"envelope_digest"`
	Escalated      bool                      `json:"escalated"`
	Reason         string                    `json:"reason"`
	Instructions   string                    `json:"instructions"`
}

// ApprovalSubmissionDTO 描述客户端在两步审批中随工具参数回传的结构化审批提交载荷（INV-E5）。
type ApprovalSubmissionDTO struct {
	Verdict        security.Verdict                            `json:"verdict"`
	EnvelopeDigest security.Digest                             `json:"envelope_digest"`
	Envelope       algebraic.Option[security.ApprovalEnvelope] `json:"envelope,omitzero"`
	Comment        string                                      `json:"comment,omitzero"`
}

// ToolErrorPayload 描述所有 MCP 工具失败与安全拦截时的统一脱敏结构化错误响应（零机密泄露）。
type ToolErrorPayload struct {
	Code              string                `json:"code"`
	Message           string                `json:"message"`
	Retryable         bool                  `json:"retryable"`
	Uncertain         bool                  `json:"uncertain,omitzero"`
	Halted            bool                  `json:"halted,omitzero"`
	ApprovalChallenge *ApprovalChallengeDTO `json:"approval_challenge,omitzero"`
}

// EmptyResult 用于 `ping` 等返回空 JSON 对象 `{}` 的规范响应。
type EmptyResult struct{}
