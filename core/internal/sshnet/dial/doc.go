// Package dial 实现 XOps v2 基于 golang.org/x/crypto/ssh 的真实 SSH 拨号、传输连接与会话适配器
// （ports.DialerPort / ports.TransportConn / ports.RemoteSession，ADR-009 / ADR-015）。
//
// 核心安全与并发不变量：
//   - 全包 0 裸 go 语句，所有异步看门狗与数据面流泵均受 core/conc.Nursery（RunScoped/NewNursery）监督；
//   - 所有基于 ssh.Channel（无原生 SetDeadline）的多跳连接均封装为 watchedChannelConn，
//     在取消或截止时间到期时经 RunScoped 看门狗立即关闭通道唤醒阻塞读写（ADR-015）；
//   - 严禁给 ssh.Session.Stdin 赋值（规避 x/crypto/ssh 孤儿拷贝协程泄漏），统一经 StdinPipe/StdoutPipe/StderrPipe 接线；
//   - 严禁使用 ssh.InsecureIgnoreHostKey，所有服务端主机密钥均经 ports.HostTrustPort 强制核验；
//   - 全部明文凭据均通过 SecretVault.WithSecret + box.Use 或 secret.WithBytes 同步消费，全包零 nolint 豁免。
package dial

import (
	"context"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/ports"
)

const (
	defaultClientVersion          = "SSH-2.0-XOps-2.0"
	maxPrivateKeyFileBytes  int64 = 1 << 20 // 本地私钥文件读取上限（1 MiB）
	maxCertFileBytes        int64 = 1 << 20 // 本地证书文件读取上限（1 MiB）
	sessionCopyBufferBytes        = 32 * 1024
	defaultTOTPDigits             = 6
	defaultTOTPPeriodSecond int64 = 30
)

// DialContextFunc 定义底层流传输拨号函数签名（为空时默认使用 (&net.Dialer{}).DialContext）。
// 测试夹具可注入回环重定向函数将测试端点映射至进程内 127.0.0.1 SSH 桩，绝不连接外部真实主机。
type DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// RemoteFSFactory 为 Phase 4（P4-T2 sshnet/sftp）预留的 SFTP 客户端构造注入点。
type RemoteFSFactory func(ctx context.Context, client *ssh.Client) (ports.RemoteFSPort, error)

// Config 描述 Dialer 的显式出站依赖配置（全依赖注入，零全局单例与隐式环境变量）。
type Config struct {
	// HostTrust 是必填的主机密钥信任库端口（严禁缺省或降级为不校验模式）。
	HostTrust ports.HostTrustPort
	// Vault 可选注入凭据库，用于 Password、加密私钥口令及 Keyboard-Interactive 凭据/TOTP 消费。
	Vault ports.SecretVault
	// KeySigner 可选注入外部公钥签名器端口。
	KeySigner ports.KeySignerPort
	// Agent 可选注入本机 SSH Agent 端口。
	Agent ports.SSHAgentPort
	// ReadFS 可选注入操作员本地只读文件端口，用于按策略读取私钥与证书文件（绝不直接调用 os.Open）。
	ReadFS ports.OperatorReadFS
	// Process 可选注入子进程端口，用于执行 ProxyCommand（DialStdio）与 Keyboard-Interactive RuleCommand。
	Process ports.ProcessPort
	// Interaction 可选注入人工交互端口，用于 StrictHostKeyChecking=ask 确认及未知质询应答。
	Interaction ports.InteractionPort
	// Clock 可选注入时钟端口（用于 TOTP 窗口与通道截止时间判断，为空时回退系统时间）。
	Clock ports.Clock
	// Env 可选注入只读环境与本机身份信息端口，用于展开私钥路径 "~/" 与 ProxyCommand 令牌。
	Env ports.EnvPort
	// DialContext 可选覆盖底层 TCP 拨号器。
	DialContext DialContextFunc
	// OpenRemoteFS 可选注入 SFTP 子系统工厂（未配置时 TransportConn.OpenRemoteFS 返回 ErrUnsupported）。
	OpenRemoteFS RemoteFSFactory
	// ClientVersion 可选覆盖 SSH 客户端标识串（须以 "SSH-2.0-" 开头且不含换行）。
	ClientVersion string
}

// Dialer 是基于 golang.org/x/crypto/ssh 的真实多跳拨号适配器，实现 ports.DialerPort；零值恒失败关闭。
//
//xops:opaque
//xops:failclosed
type Dialer struct {
	hostTrust     ports.HostTrustPort
	vault         ports.SecretVault
	keySigner     ports.KeySignerPort
	agent         ports.SSHAgentPort
	readFS        ports.OperatorReadFS
	process       ports.ProcessPort
	interaction   ports.InteractionPort
	clock         ports.Clock
	env           ports.EnvPort
	dialContext   DialContextFunc
	openRemoteFS  RemoteFSFactory
	clientVersion string
	valid         bool
}

// NewDialer 校验必填 HostTrustPort 与可选客户端版本标识并构造不可变 Dialer。
func NewDialer(cfg Config) (*Dialer, error) {
	if cfg.HostTrust == nil {
		return nil, fmt.Errorf("%w: HostTrust 端口不能为 nil", ports.ErrInvalidArgument)
	}
	clientVer := cfg.ClientVersion
	if clientVer == "" {
		clientVer = defaultClientVersion
	}
	if !strings.HasPrefix(clientVer, "SSH-2.0-") || strings.ContainsAny(clientVer, "\r\n") {
		return nil, fmt.Errorf("%w: 非法 SSH ClientVersion %q", ports.ErrInvalidArgument, clientVer)
	}
	dialFn := cfg.DialContext
	if dialFn == nil {
		dialFn = (&net.Dialer{}).DialContext
	}
	return &Dialer{
		hostTrust:     cfg.HostTrust,
		vault:         cfg.Vault,
		keySigner:     cfg.KeySigner,
		agent:         cfg.Agent,
		readFS:        cfg.ReadFS,
		process:       cfg.Process,
		interaction:   cfg.Interaction,
		clock:         cfg.Clock,
		env:           cfg.Env,
		dialContext:   dialFn,
		openRemoteFS:  cfg.OpenRemoteFS,
		clientVersion: clientVer,
		valid:         true,
	}, nil
}
