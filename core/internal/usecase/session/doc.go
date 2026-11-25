// Package session 实现 XOps v2 单命令执行与交互式 SSH 会话用例服务（ADR-008 / ADR-009 / ADR-010 / Plan P2.5-T2）。
//
// Phase 2.5 Walking Skeleton 切片核心不变量：
//   - 严格强制能力门控与连接池嵌套序：gate.WithAuthorized[security.CapExecute] 恒包裹于
//     pool.WithLease 外层（严禁反序或绕过门控），并把强类型 execution.ExecutionOutcome 上报给
//     Authorized.ReportOutcome，确保 OutcomeUnknown 绝不被降级；
//   - 所有 SendEnv 环境变量均严格经由注入的 ports.EnvPort 与连接计划内的 option.EnvFilter 过滤，
//     全包零隐式 os.Environ/os.Getenv；
//   - 交互式与 PTY 会话严格通过 RemoteSession.{StdinPipe,StdoutPipe,StderrPipe}、
//     TerminalPort.WithRawTerminal 与 TerminalHandle.Relay 接线（完整支持 RequestTTY auto/yes/no/force、
//     窗口缩放事件转发、本地半关闭与远端先达 EOF），保证 0 linearlease 逃逸与 0 goleak 泄漏；
//   - 支持可选隔离 events.OperationStream，按序发射 OperationStarted / OutputChunk / OperationCompleted
//     并在返回前幂等关闭以提供确定性 EOF；
//   - 全包严禁导入 core/osfs 与 core/internal/sshnet/**，零裸 go 语句，零 nolint 豁免。
package session

import (
	"errors"
	"fmt"
	"strings"
)

const (
	defaultTTYTerm            = "xterm-256color"
	defaultTTYCols     uint16 = 80
	defaultTTYRows     uint16 = 24
	outputChunkMaxSize        = 32 * 1024
)

// 本包导出的规范化哨兵错误，供 core/engine 与上层测试以 errors.Is 精确区分故障类别。
var (
	// ErrNilContext 表示传入的 context.Context 为 nil。
	ErrNilContext = errors.New("usecase/session: context 不能为 nil")
	// ErrInvalidConfig 表示 ServiceConfig 缺少必填依赖或配置非法。
	ErrInvalidConfig = errors.New("usecase/session: 无效的 ServiceConfig 配置")
	// ErrServiceNotInitialized 表示在零值或未初始化 Service 上调用方法。
	ErrServiceNotInitialized = errors.New("usecase/session: Service 未初始化")
	// ErrInvalidRequest 表示会话或命令执行请求字段非法。
	ErrInvalidRequest = errors.New("usecase/session: 无效的会话执行请求")
	// ErrInvalidRequestTTY 表示 RequestTTYMode 值非法。
	ErrInvalidRequestTTY = errors.New("usecase/session: 无效的 RequestTTY 模式")
)

// RequestTTYMode 标识 SSH 伪终端分配策略（对应 OpenSSH RequestTTY auto/yes/no/force 与 -t/-tt/-T）；
// 零值 RequestTTYUnset 失败关闭于文本编解码，运行期按操作类型取确定性默认策略（交互 Shell=auto，单命令=no）。
//
//xops:opaque
//xops:failclosed
type RequestTTYMode uint8

const (
	RequestTTYUnset RequestTTYMode = iota // 未显式设置（零值）
	RequestTTYAuto                        // 自动：交互 Shell 且本机为 TTY 时分配 PTY
	RequestTTYYes                         // 本机为 TTY 时分配 PTY（对应 -t）
	RequestTTYNo                          // 禁止分配 PTY（对应 -T）
	RequestTTYForce                       // 强制分配远端 PTY，即使本机非 TTY（对应 -tt）
)

// ParseRequestTTYMode 严格解析 RequestTTY 文本（auto/yes/no/force）。
func ParseRequestTTYMode(raw string) (RequestTTYMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "auto":
		return RequestTTYAuto, nil
	case "yes", "true":
		return RequestTTYYes, nil
	case "no", "false":
		return RequestTTYNo, nil
	case "force":
		return RequestTTYForce, nil
	default:
		return RequestTTYUnset, fmt.Errorf("%w: %q", ErrInvalidRequestTTY, raw)
	}
}

// IsValid 报告 m 是否为已显式设置的合法 RequestTTYMode。
func (m RequestTTYMode) IsValid() bool { return m >= RequestTTYAuto && m <= RequestTTYForce }

// IsZero 报告 m 是否处于未设置零值态。
func (m RequestTTYMode) IsZero() bool { return m == RequestTTYUnset }

// String 返回规范小写名称；未设置返回 "unset"。
func (m RequestTTYMode) String() string {
	switch m {
	case RequestTTYAuto:
		return "auto"
	case RequestTTYYes:
		return "yes"
	case RequestTTYNo:
		return "no"
	case RequestTTYForce:
		return "force"
	default:
		return "unset"
	}
}

// AppendText 实现 encoding.TextAppender（值接收者）；对未设置/非法值失败关闭。
func (m RequestTTYMode) AppendText(b []byte) ([]byte, error) {
	if !m.IsValid() {
		return nil, fmt.Errorf("%w: %d", ErrInvalidRequestTTY, uint8(m))
	}
	return append(b, m.String()...), nil
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (m RequestTTYMode) MarshalText() ([]byte, error) { return m.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为 RequestTTYUnset。
func (m *RequestTTYMode) UnmarshalText(text []byte) error {
	if m == nil {
		return ErrInvalidRequestTTY
	}
	parsed, err := ParseRequestTTYMode(string(text))
	if err != nil {
		*m = RequestTTYUnset
		return err
	}
	*m = parsed
	return nil
}
