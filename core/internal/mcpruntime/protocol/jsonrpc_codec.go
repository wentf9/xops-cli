package protocol

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
)

// JSON-RPC 2.0 规范版本及标准/XOps 应用层错误码定义。
const (
	// JSONRPCVersion 为唯一接受的 JSON-RPC 协议版本号。
	JSONRPCVersion = "2.0"

	// 标准 JSON-RPC 2.0 错误码。
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603

	// XOps MCP 应用层保留错误码（位于 JSON-RPC 2.0 Server Error 区间 [-32099, -32000]）。
	CodeGateHalted          = -32001 // StrictAgentProfile 不可逆 Halted 熔断，拒绝全部请求
	CodeApprovalRequired    = -32002 // 两步审批挑战（NoElicitFallbackChallenge）
	CodeAuthorizationDenied = -32003 // 护栏拒绝或审批失败/过期/重放/作用域升级
	CodeUncertainOutcome    = -32004 // 远端/持久性/提交结果未知（禁止自动重试）
	CodeInvalidState        = -32005 // 资源不存在、句柄失效或 FSM 非法状态转换
)

const (
	requestIDInvalid uint8 = iota
	requestIDString
	requestIDInt
)

// RequestID 表示 JSON-RPC 2.0 强类型请求标识（仅支持非空字符串或精确 int64 整数）；
// 零值恒无效并严格失败关闭，拒绝 null/bool/float/array/object。
//
//xops:opaque
//xops:failclosed
type RequestID struct {
	kind   uint8
	strVal string
	numVal int64
	valid  bool
}

// StringRequestID 构造字符串形态的不可变 JSON-RPC RequestID。
func StringRequestID(v string) (RequestID, error) {
	if v == "" {
		return RequestID{}, fmt.Errorf("%w: 字符串 id 不能为空", ErrInvalidRequestID)
	}
	return RequestID{kind: requestIDString, strVal: v, valid: true}, nil
}

// IntRequestID 构造整数形态的不可变 JSON-RPC RequestID。
func IntRequestID(v int64) RequestID {
	return RequestID{kind: requestIDInt, numVal: v, valid: true}
}

// IsValid 报告 RequestID 是否有效。
func (id RequestID) IsValid() bool {
	return id.valid && (id.kind == requestIDInt || (id.kind == requestIDString && id.strVal != ""))
}

// IsZero 报告 RequestID 是否处于零值无效态。
func (id RequestID) IsZero() bool { return !id.IsValid() }

// String 返回便于日志诊断的标识文本（不含额外引号）。
func (id RequestID) String() string {
	if !id.IsValid() {
		return ""
	}
	if id.kind == requestIDInt {
		return strconv.FormatInt(id.numVal, 10)
	}
	return id.strVal
}

// Equal 严格比较两个 RequestID 的类型与值是否完全一致（字符串 "1" 与整数 1 不相等）。
func (id RequestID) Equal(other RequestID) bool {
	if !id.IsValid() || !other.IsValid() || id.kind != other.kind {
		return false
	}
	if id.kind == requestIDInt {
		return id.numVal == other.numVal
	}
	return id.strVal == other.strVal
}

// AppendText 实现 encoding.TextAppender（值接收者）；零值失败关闭。
func (id RequestID) AppendText(b []byte) ([]byte, error) {
	if !id.IsValid() {
		return nil, ErrInvalidRequestID
	}
	if id.kind == requestIDInt {
		return strconv.AppendInt(b, id.numVal, 10), nil
	}
	return append(b, id.strVal...), nil
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (id RequestID) MarshalText() ([]byte, error) { return id.AppendText(nil) }

// MarshalJSONTo 实现 Go 1.27 encoding/json/v2 确定性编码；零值失败关闭。
func (id RequestID) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !id.IsValid() {
		return ErrInvalidRequestID
	}
	if id.kind == requestIDInt {
		return enc.WriteToken(jsontext.Int(id.numVal))
	}
	return enc.WriteToken(jsontext.String(id.strVal))
}

// UnmarshalJSONFrom 严格解码 JSON 字符串或精确整数至 RequestID，拒绝 null/小数/布尔/复合值。
func (id *RequestID) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if id == nil {
		return ErrInvalidRequestID
	}
	*id = RequestID{}
	tok, err := dec.ReadToken()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRequestID, err)
	}
	switch tok.Kind() {
	case '"':
		parsed, pErr := StringRequestID(tok.String())
		if pErr != nil {
			return pErr
		}
		*id = parsed
		return nil
	case '0':
		raw := tok.String()
		if strings.ContainsAny(raw, ".eE") {
			return fmt.Errorf("%w: 数值 id 必须为精确整数而非浮点 %q", ErrInvalidRequestID, raw)
		}
		n, nErr := strconv.ParseInt(raw, 10, 64)
		if nErr != nil {
			return fmt.Errorf("%w: 整数 id 越界 %q: %w", ErrInvalidRequestID, raw, nErr)
		}
		*id = IntRequestID(n)
		return nil
	default:
		return fmt.Errorf("%w: 仅接受字符串或整数 id", ErrInvalidRequestID)
	}
}

// Request 表示入站 JSON-RPC 2.0 请求或通知报文；零值恒无效。
type Request struct {
	JSONRPC string                      `json:"jsonrpc"`
	ID      algebraic.Option[RequestID] `json:"id,omitzero"`
	Method  string                      `json:"method"`
	Params  jsontext.Value              `json:"params,omitzero"`
}

// IsNotification 报告该 JSON-RPC 报文是否为无 id 的单向通知。
func (r Request) IsNotification() bool { return !r.ID.IsSome() }

// Validate 严格校验 JSON-RPC 2.0 版本、非空方法名与可选 ID 合法性。
func (r Request) Validate() error {
	if r.JSONRPC != JSONRPCVersion {
		return fmt.Errorf("%w: jsonrpc 版本必须为 %q，实际=%q", ErrInvalidJSONRPC, JSONRPCVersion, r.JSONRPC)
	}
	if strings.TrimSpace(r.Method) == "" {
		return fmt.Errorf("%w: method 不能为空", ErrInvalidJSONRPC)
	}
	if id, ok := r.ID.Get(); ok && !id.IsValid() {
		return fmt.Errorf("%w: id 无效", ErrInvalidJSONRPC)
	}
	return nil
}

// DecodeRequest 严格解码单条 JSON-RPC 2.0 请求报文：
// 精确区分 JSON 语法错误（ErrParseJSON -> -32700）与 JSON-RPC 语义/未知字段/版本非法（ErrInvalidJSONRPC -> -32600）。
func DecodeRequest(raw []byte) (Request, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return Request{}, fmt.Errorf("%w: 空报文", ErrParseJSON)
	}
	var req Request
	if err := jsonv2.Unmarshal(trimmed, &req, jsonv2.RejectUnknownMembers(true)); err != nil {
		if _, isSyntax := errors.AsType[*jsontext.SyntacticError](err); isSyntax {
			return Request{}, fmt.Errorf("%w: %w", ErrParseJSON, err)
		}
		return Request{}, fmt.Errorf("%w: %w", ErrInvalidJSONRPC, err)
	}
	if err := req.Validate(); err != nil {
		return Request{}, err
	}
	return req, nil
}

// RPCError 表示 JSON-RPC 2.0 规范错误对象。
type RPCError struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    jsontext.Value `json:"data,omitzero"`
}

// Response 表示出站 JSON-RPC 2.0 响应报文（Result 与 Error 互斥）；
// 遵循 JSON-RPC 2.0 §5：当 Error 非空且无法解析请求 ID（ID 为 None）时显式输出 "id":null。
type Response struct {
	JSONRPC string                      `json:"jsonrpc"`
	ID      algebraic.Option[RequestID] `json:"id,omitzero"`
	Result  jsontext.Value              `json:"result,omitzero"`
	Error   *RPCError                   `json:"error,omitzero"`
}

type responseWire struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      jsontext.Value `json:"id,omitzero"`
	Result  jsontext.Value `json:"result,omitzero"`
	Error   *RPCError      `json:"error,omitzero"`
}

// MarshalJSONTo 编码 JSON-RPC 2.0 响应；当错误响应无可用请求 ID 时显式输出 "id":null。
func (r Response) MarshalJSONTo(enc *jsontext.Encoder) error {
	wire := responseWire{JSONRPC: r.JSONRPC, Result: r.Result, Error: r.Error}
	if id, ok := r.ID.Get(); ok {
		rawID, err := MarshalCanonical(id)
		if err != nil {
			return err
		}
		wire.ID = jsontext.Value(rawID)
	} else if r.Error != nil {
		wire.ID = jsontext.Value("null")
	}
	return jsonv2.MarshalEncode(enc, wire, jsonv2.Deterministic(true))
}

// UnmarshalJSONFrom 严格解码 JSON-RPC 2.0 响应，接受错误响应中的 "id":null 并还原为 None。
func (r *Response) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if r == nil {
		return ErrInvalidJSONRPC
	}
	var wire responseWire
	if err := jsonv2.UnmarshalDecode(dec, &wire, jsonv2.RejectUnknownMembers(true)); err != nil {
		return err
	}
	var idOpt algebraic.Option[RequestID]
	trimmedID := bytes.TrimSpace(wire.ID)
	if len(trimmedID) > 0 && !bytes.Equal(trimmedID, []byte("null")) {
		var parsed RequestID
		if err := jsonv2.Unmarshal(trimmedID, &parsed); err != nil {
			return err
		}
		idOpt = algebraic.Some(parsed)
	}
	*r = Response{JSONRPC: wire.JSONRPC, ID: idOpt, Result: wire.Result, Error: wire.Error}
	return nil
}

// MarshalCanonical 使用 Go 1.27 encoding/json/v2 Deterministic(true) 序列化确定性规范 JSON 字节流。
func MarshalCanonical(v any) ([]byte, error) {
	return jsonv2.Marshal(v, jsonv2.Deterministic(true))
}

// UnmarshalStrict 使用 Go 1.27 encoding/json/v2 严格解码 JSON（拒绝未知成员与空输入）。
func UnmarshalStrict(raw []byte, dst any) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return fmt.Errorf("%w: JSON 载荷不能为空", ErrInvalidParams)
	}
	if err := jsonv2.Unmarshal(trimmed, dst, jsonv2.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	return nil
}

// NewResultResponse 构造携带确定性 JSON 结果的 JSON-RPC 2.0 成功响应。
func NewResultResponse(id RequestID, result any) (Response, error) {
	if !id.IsValid() {
		return Response{}, ErrInvalidRequestID
	}
	raw, err := MarshalCanonical(result)
	if err != nil {
		return Response{}, fmt.Errorf("编码 JSON-RPC result 失败: %w", err)
	}
	return Response{
		JSONRPC: JSONRPCVersion,
		ID:      algebraic.Some(id),
		Result:  jsontext.Value(raw),
	}, nil
}

// NewErrorResponse 构造携带错误码、脱敏说明及可选结构化数据的 JSON-RPC 2.0 错误响应。
func NewErrorResponse(id algebraic.Option[RequestID], code int, msg string, data any) (Response, error) {
	if v, ok := id.Get(); ok && !v.IsValid() {
		return Response{}, ErrInvalidRequestID
	}
	var rawData jsontext.Value
	if data != nil {
		encoded, err := MarshalCanonical(data)
		if err != nil {
			return Response{}, fmt.Errorf("编码 JSON-RPC error.data 失败: %w", err)
		}
		rawData = jsontext.Value(encoded)
	}
	return Response{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: msg,
			Data:    rawData,
		},
	}, nil
}
