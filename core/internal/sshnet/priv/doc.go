// Package priv 实现 XOps v2 的远端提权执行适配器（ports.PrivilegeEscalationPort，P4-T1）。
//
// 核心安全、协议与并发不变量：
//   - 随机化 `-p` 提权提示令牌与提权就绪帧（ready token）分离认证输入与命令输入：
//     口令仅在识别到合法提示帧后写入已验证的 (ports.RemoteSession).StdinPipe，普通 stdin 与脚本正文
//     在就绪帧抵达前绝不投递，防止口令混入命令流或命令输入误充口令；
//   - 双输出流严格维持无环因果序（次流 -> 主控流，非 PTY 模式主控流为 stderr、PTY 模式主控流为 stdout）：
//     仅主控流扫描提示帧与就绪帧，次流绝不扫描提示或就绪帧（阻断混淆代理口令泄露与输出串扰），
//     在主控流观测到 ready token 或到达 EOF 前有界暂存（<= 64 KiB）就绪前字节并按因果序释放；
//   - 输出流经 io.Pipe() 复用上游 RemoteSession 输出泵与弃写保护，并在握手超时、就绪后取消或半开黑洞下
//     O(1) 关闭管道解除阻塞；一旦已越过就绪帧后发生中止或超时，恒返回不可重试的 *execution.OutcomeUnknown；
//   - 完整兼容 POSIX sudo（含 sudo-rs 的 `[sudo: <token>] ...:` 封套、全角冒号与 `*` 回显抑制）、
//     su 与 doas，支持 NonInteractive（-n）失败关闭；
//   - 隶属 LayerCoreSSHNetPriv 明文白名单，严格复用 secrettaint/sinks_narrow.go:isAllowedPrivEscalationWrite
//     正向白名单，并支持双层嵌套 primaryBox.Use -> secondaryBox.Use 组合口令写入（全包零行内 nolint 豁免）；
//   - *secret.SecretBox 仅在调用方同步协程内消费（零跨协程借用逃逸），全部输出/输入泵均由
//     core/conc.Nursery 监督（0 裸 go，0 协程泄漏）。
package priv

import (
	"fmt"
	"time"

	"github.com/wentf9/xops-cli/core/ports"
)

const (
	defaultHandshakeTimeout = 30 * time.Second
	maxDiagBufferBytes      = 4096
	copyChunkBytes          = 32 * 1024
	nonceRawBytes           = 16
	maxPromptSignals        = 4
)

// Config 描述 Escalator 的显式运行期出站依赖配置（零全局单例与隐式状态）。
type Config struct {
	// Entropy 可选注入显式随机字节源用于生成随机 -p 提示令牌与就绪帧；为空时回退 crypto/rand.Reader。
	Entropy ports.Entropy
	// Clock 可选注入时钟端口用于控制提权握手超时定时器；为空时回退系统时钟。
	Clock ports.Clock
	// HandshakeTimeout 可选覆盖等待提权认证完成的最长超时时长（<= 0 时默认 30s）。
	HandshakeTimeout time.Duration
}

// Escalator 是基于随机化提示/就绪帧握手协议的 ports.PrivilegeEscalationPort 生产实现；零值恒失败关闭。
//
//xops:opaque
//xops:failclosed
type Escalator struct {
	entropy          ports.Entropy
	clock            ports.Clock
	handshakeTimeout time.Duration
	valid            bool
}

// NewEscalator 校验配置并构造不可变 Escalator 实例。
func NewEscalator(cfg Config) (*Escalator, error) {
	if cfg.HandshakeTimeout < 0 {
		return nil, fmt.Errorf("%w: HandshakeTimeout 不能为负", ports.ErrInvalidArgument)
	}
	hsTimeout := cfg.HandshakeTimeout
	if hsTimeout == 0 {
		hsTimeout = defaultHandshakeTimeout
	}
	return &Escalator{
		entropy:          cfg.Entropy,
		clock:            cfg.Clock,
		handshakeTimeout: hsTimeout,
		valid:            true,
	}, nil
}
