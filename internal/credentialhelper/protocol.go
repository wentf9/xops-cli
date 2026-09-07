package credentialhelper

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

const (
	// ProtocolVersion 是当前支持的 helper 协议主版本。
	ProtocolVersion = 1

	// MaxResponseBytes 是 helper 响应 stdout 允许读取的最大字节数（64KB）。
	MaxResponseBytes = 64 * 1024

	// MaxStderrBytes 是 helper 诊断 stderr 允许读取的最大字节数（4KB）。
	MaxStderrBytes = 4 * 1024
)

// Action 表示向 helper 发起的操作动作。
type Action string

const (
	// ActionGet 获取指定引用的凭据。
	ActionGet Action = "get"
	// ActionStore 存储凭据。
	ActionStore Action = "store"
	// ActionErase 擦除凭据。
	ActionErase Action = "erase"
)

// Request 表示通过 stdin 传递给 helper 的请求 JSON 载荷。
type Request struct {
	ProtocolVersion int    `json:"protocolVersion"`
	StoreID         string `json:"storeID"`
	ItemID          string `json:"itemID"`
	Secret          string `json:"secret,omitempty"` // Base64 编码
}

// Response 表示从 helper stdout 读取的响应 JSON 载荷。
type Response struct {
	Secret    string     `json:"secret,omitempty"` // Base64 编码
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	Code      string     `json:"code,omitempty"`
	Message   string     `json:"message,omitempty"`
}

var base64Regex = regexp.MustCompile(`[A-Za-z0-9+/=]{16,}`)

// SanitizeDiagnostic 对错误和诊断信息进行脱敏处理，屏蔽可疑 Base64 与长敏感字符串。
func SanitizeDiagnostic(raw string, sensitive ...string) string {
	msg := strings.TrimSpace(raw)
	if msg == "" {
		return ""
	}
	for _, s := range sensitive {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "[REDACTED]")
		}
	}
	msg = base64Regex.ReplaceAllString(msg, "[REDACTED]")
	if len(msg) > 256 {
		return msg[:256] + "..."
	}
	return msg
}

// MapErrorCode 将 helper 协议返回的错误代码映射为系统标准的凭据哨兵错误。
func MapErrorCode(code, msg string) error {
	trimmedCode := strings.ToLower(strings.TrimSpace(code))
	sanitizedMsg := SanitizeDiagnostic(msg)

	var baseErr error
	switch trimmedCode {
	case "not-found":
		baseErr = credential.ErrCredentialNotFound
	case "locked":
		baseErr = credential.ErrCredentialStoreLocked
	case "unavailable":
		baseErr = credential.ErrCredentialStoreUnavailable
	case "denied":
		baseErr = credential.ErrCredentialAccessDenied
	case "read-only":
		baseErr = credential.ErrCredentialStoreReadOnly
	default:
		if sanitizedMsg != "" {
			return fmt.Errorf("credential helper error (%s): %s", code, sanitizedMsg)
		}
		return fmt.Errorf("credential helper error (%s)", code)
	}

	if sanitizedMsg != "" {
		return fmt.Errorf("%w: %s", baseErr, sanitizedMsg)
	}
	return baseErr
}

// EncodeRequest 将请求序列化为 JSON 并写入 writer。
func EncodeRequest(w io.Writer, req *Request) error {
	if req == nil {
		return fmt.Errorf("helper request cannot be nil")
	}
	if req.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("unsupported helper protocol version %d (expected %d)", req.ProtocolVersion, ProtocolVersion)
	}
	enc := json.NewEncoder(w)
	if err := enc.Encode(req); err != nil {
		return fmt.Errorf("encode helper request: %w", err)
	}
	return nil
}

// DecodeResponse 从 reader 读取并反序列化响应 JSON，严格限制最大字节数、强制唯一响应并校验 Base64。
func DecodeResponse(r io.Reader) (*Response, error) {
	limitedReader := io.LimitReader(r, MaxResponseBytes+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("read helper response: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty response from credential helper")
	}
	if len(data) > MaxResponseBytes {
		return nil, fmt.Errorf("credential helper response exceeds maximum allowed size of %d bytes", MaxResponseBytes)
	}

	var resp Response
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("parse credential helper response: %w", err)
	}

	// 强制要求 stdout 只能包含一个合法的 JSON 响应，拒绝第二个 JSON 或尾随非空白内容
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("unexpected multiple JSON responses or trailing content in helper output")
	}

	// 若存在错误响应 code，直接映射返回对应错误
	if strings.TrimSpace(resp.Code) != "" {
		return &resp, MapErrorCode(resp.Code, resp.Message)
	}

	// 校验 Base64 格式
	if resp.Secret != "" {
		if _, err := base64.StdEncoding.DecodeString(resp.Secret); err != nil {
			return nil, fmt.Errorf("invalid base64 secret payload in helper response: %w", err)
		}
	}

	return &resp, nil
}

// DecodeSecretBytes 从 Response 中提取并解码机密字节。调用方需负责清零。
func DecodeSecretBytes(resp *Response) ([]byte, error) {
	if resp == nil {
		return nil, errors.New("nil response")
	}
	if resp.Secret == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(resp.Secret)
	if err != nil {
		return nil, fmt.Errorf("decode secret base64: %w", err)
	}
	return raw, nil
}
