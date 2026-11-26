// Package session 实现 XOps v2 全量会话、提权、探测、持久 PTY、隧道转发与多路复用控制面用例服务
// （ADR-008 / ADR-009 / ADR-010 / ADR-011 / Plan P2.5-T2 & P3-T2）。
//
// 核心安全、并发与所有权不变量：
//   - 能力门控与连接池嵌套序恒为 gate.WithAuthorized[C] 包裹 pool.WithLease，严禁反序或绕过护栏，
//     并向 Authorized.ReportOutcome 上报强类型 ExecutionOutcome（确保 OutcomeUnknown 绝不降级）；
//   - 提权执行（sudo/su/doas）经 PrivilegeEscalationPort 与 security.CanonicalScopeEscalated 校验，
//     口令仅经 SecretVault.WithSecret 或 InteractionPort.PromptSecret 借用透传（本包 0 SecretBox.Use）；
//   - 两阶段远端 Shell 探针经 ShellProbePort 执行并严格失败关闭校验（拒绝非法/未知方言，零盲猜回退）；
//   - 跨请求持久 PTY、-L/-R/-D/StreamLocal/TUN 转发与 ControlMaster 一律经 pool.RegisterLeaseHandleWith
//     绑定池钉选可撤销 TransportConn，杜绝失效 *pool.Lease 复用与 //xops:borrowed 逃逸，吊销即止、0 泄漏；
//   - ControlMaster 控制面门控一律消费 ControlPolicy.EffectiveMaster() / EffectivePersist() 失败关闭投影；
//   - 全部后台协程受 core/conc.Nursery 监督（0 裸 go、0 goleak、0 time.Sleep），禁导 core/osfs 与 sshnet。
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
	ErrNilContext             = errors.New("usecase/session: context 不能为 nil")
	ErrInvalidConfig          = errors.New("usecase/session: 无效的 ServiceConfig 配置")
	ErrServiceNotInitialized  = errors.New("usecase/session: Service 未初始化")
	ErrInvalidRequest         = errors.New("usecase/session: 无效的会话执行请求")
	ErrInvalidRequestTTY      = errors.New("usecase/session: 无效的 RequestTTY 模式")
	ErrPortUnavailable        = errors.New("usecase/session: 必需的出站端口未配置")
	ErrInvalidProbeResult     = errors.New("usecase/session: 远端 Shell 探测结果无效")
	ErrEscalationScopeChanged = errors.New("usecase/session: 提权规范作用域校验失败或发生漂移")
	ErrPTYClosed              = errors.New("usecase/session: 持久 PTY 会话已关闭或已吊销")
	ErrControlMasterDisabled  = errors.New("usecase/session: ControlPolicy 生效投影已禁用多路复用")
	ErrMuxMasterUnavailable   = errors.New("usecase/session: ControlMaster 不可用或连接被拒绝")
	ErrMuxPersistExpired      = errors.New("usecase/session: ControlPersist 驻留超时已过期")
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
