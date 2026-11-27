package mcpcmd

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// TransportKind 标识 MCP 入口的传输形态；零值 TransportInvalid 严格失败关闭。
//
//xops:opaque
//xops:failclosed
type TransportKind uint8

const (
	TransportInvalid TransportKind = iota // 零值无效传输（失败关闭默认态）
	TransportStdio                        // 标准输入输出 JSON-RPC 传输（stdio）
	TransportHTTP                         // Streamable HTTP 传输（默认仅回环地址）
)

// ParseTransportKind 严格解析 MCP 传输模式名称（stdio / http / streamable-http）。
func ParseTransportKind(raw string) (TransportKind, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "stdio":
		return TransportStdio, nil
	case "http", "streamable-http", "streamable_http":
		return TransportHTTP, nil
	default:
		return TransportInvalid, i18n.EF(ErrInvalidTransport, i18n.KeyMCPInvalidTransportValue, i18n.BoundStr("value", raw))
	}
}

// IsValid 报告 k 是否为已支持的传输形态。
func (k TransportKind) IsValid() bool { return k == TransportStdio || k == TransportHTTP }

// IsZero 报告 k 是否为零值无效传输。
func (k TransportKind) IsZero() bool { return k == TransportInvalid }

// String 返回传输形态的规范小写名称。
func (k TransportKind) String() string {
	switch k {
	case TransportStdio:
		return "stdio"
	case TransportHTTP:
		return "http"
	default:
		return "invalid"
	}
}

// AppendText 实现 encoding.TextAppender，非法枚举值拒绝序列化。
func (k TransportKind) AppendText(b []byte) ([]byte, error) {
	if !k.IsValid() {
		return nil, i18n.EF(ErrInvalidTransport, i18n.KeyMCPInvalidTransportValue, i18n.Str("value", strconv.FormatUint(uint64(k), 10)))
	}
	return append(b, k.String()...), nil
}

// MarshalText 实现 encoding.TextMarshaler。
func (k TransportKind) MarshalText() ([]byte, error) { return k.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler，非法文本回落零值并报错。
func (k *TransportKind) UnmarshalText(text []byte) error {
	if k == nil {
		return ErrInvalidTransport
	}
	parsed, err := ParseTransportKind(string(text))
	if err != nil {
		*k = TransportInvalid
		return err
	}
	*k = parsed
	return nil
}

// MCPServerContract 定义 mcpcmd 驱动所需的最小 MCP 服务器运行期契约；
// *engine.MCPServer 原生实现全部方法，测试与外部宿主亦可注入受控桩实现。
type MCPServerContract interface {
	Prepare(ctx context.Context) (engine.MCPStartupReport, error)
	ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error
	ListenAndServeHTTP(ctx context.Context, addr string) error
	ServeHTTPListener(ctx context.Context, ln net.Listener) error
	Close(ctx context.Context) error
}

// 编译期契约断言：确保 core/engine.MCPServer 完整实现 MCPServerContract。
var _ MCPServerContract = (*engine.MCPServer)(nil)

// ServerFactory 按 engine.MCPConfig 构造 MCPServerContract 实例。
type ServerFactory func(cfg engine.MCPConfig) (MCPServerContract, error)

// Config 定义 mcpcmd.Run 的显式只读启动配置（零裸 time.Duration、零值严格失败关闭）。
type Config struct {
	// Engine 为生产路径的核心引擎实例（与 ServerFactory 二选一；若 ServerFactory 非空则优先使用 ServerFactory）。
	Engine *engine.Engine
	// ServerFactory 为可选自定义 MCPServer 构造工厂（供外部宿主或无宿主单元测试注入）。
	ServerFactory ServerFactory
	// ServerConfig 透传至 Engine.NewMCPServer 的沙箱与传输安全配置（物理 0 OperatorReadFS）。
	ServerConfig engine.MCPConfig

	// Transport 指定 MCP 传输协议（必填：TransportStdio 或 TransportHTTP）。
	Transport TransportKind
	// ListenAddr 在 TransportHTTP 且未传入 Listener 时的监听地址（如 "127.0.0.1:8080"）。
	ListenAddr string
	// Listener 在 TransportHTTP 下的可选预绑定 net.Listener（非空时走 ServeHTTPListener）。
	Listener net.Listener

	// Stdin / Stdout 供 TransportStdio 读写 JSON-RPC 帧流（TransportStdio 必填）。
	Stdin  io.Reader
	Stdout io.Writer
	// Stderr 可选诊断日志输出流；严禁向 Stdout 输出任何非 JSON-RPC 文本。
	Stderr io.Writer

	// ShutdownTimeout 限制退出阶段调用 MCPServer.Close 的最大宽限期（未设置默认 5s）。
	ShutdownTimeout algebraic.Option[algebraic.Duration]
	// OnPrepared 可选启动自检完成回调，在 Prepare(ctx) 成功后、开始提供服务前同步调用。
	OnPrepared func(report engine.MCPStartupReport)
}
