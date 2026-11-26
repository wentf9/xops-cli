// Package keysigner 实现 XOps v2 基于 golang.org/x/crypto/ssh 的私钥解析、指纹核验与签名器适配器
// （ports.KeySignerPort，ADR-011 / INV-F1）。
//
// 本包隶属 core/internal/sshnet/dial 明文消费白名单层（LayerCoreSSHNetDial），严格维持以下安全不变量：
//   - 所有私钥原始字节均经 OperatorReadFS 有界读取后立即装入 secret.WithBytes 同步闭包零化消费，
//     仅保留不透明 ssh.Signer 与公钥指纹，绝不将原始私钥材料持久化或暴露至日志/错误；
//   - 口令保护私钥经 SecretVault.WithSecret + 嵌套 keyBox.Use -> passBox.Use 解密并强制校验 INV-F1 指纹绑定；
//   - 全包零行内 nolint 豁免、0 裸 go 语句与 0 全局状态。
package keysigner

import (
	"fmt"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	// MaxPrivateKeyFileBytes 限制单个本地私钥文件的读取字节上限（1 MiB）。
	MaxPrivateKeyFileBytes int64 = 1 << 20
	// MaxCertFileBytes 限制单个本地用户证书文件的读取字节上限（1 MiB）。
	MaxCertFileBytes int64 = 1 << 20
)

// Config 描述 KeySigner 的显式出站依赖配置（全依赖注入，零全局单例与隐式环境变量）。
type Config struct {
	// ReadFS 提供操作员本地私钥与证书文件的受控只读能力（经 SymlinkFollowOperatorSource）。
	ReadFS ports.OperatorReadFS
	// Vault 可选注入凭据库，用于读取口令保护私钥绑定的解密口令。
	Vault ports.SecretVault
	// Agent 可选注入本机 SSH Agent 端口，用于 AuthAgent 变体列举与签名回退。
	Agent ports.SSHAgentPort
	// Env 可选注入本机身份信息端口，用于展开私钥/证书路径中的 "~/" 前缀。
	Env ports.EnvPort
	// Entropy 可选注入显式随机字节源供签名算法使用；为空时回退 crypto/rand.Reader。
	Entropy ports.Entropy
}

type agentKeyEntry struct {
	spec algebraic.Option[inventory.AgentSpec]
}

// KeySigner 实现 ports.KeySignerPort，提供并发安全的私钥加载、证书匹配、签名与指纹核验能力；零值恒失败关闭。
//
//xops:opaque
//xops:failclosed
type KeySigner struct {
	readFS  ports.OperatorReadFS
	vault   ports.SecretVault
	agent   ports.SSHAgentPort
	env     ports.EnvPort
	entropy ports.Entropy

	mu        sync.RWMutex
	signers   map[string]ssh.Signer
	agentKeys map[string]agentKeyEntry
	valid     bool
}

// NewKeySigner 校验至少注入 ReadFS 或 Agent 端口后构造不可变 KeySigner。
func NewKeySigner(cfg Config) (*KeySigner, error) {
	if cfg.ReadFS == nil && cfg.Agent == nil {
		return nil, fmt.Errorf("%w: KeySigner 需要至少注入 ReadFS 或 Agent 端口", ports.ErrInvalidArgument)
	}
	return &KeySigner{
		readFS:    cfg.ReadFS,
		vault:     cfg.Vault,
		agent:     cfg.Agent,
		env:       cfg.Env,
		entropy:   cfg.Entropy,
		signers:   make(map[string]ssh.Signer),
		agentKeys: make(map[string]agentKeyEntry),
		valid:     true,
	}, nil
}
