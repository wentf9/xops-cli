package agent

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/sys"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// Spec 是构造本机 SystemAgent 的显式入参规格（非持久化 DTO）。
type Spec struct {
	// Env 为可选环境变量端口；为 nil 时默认使用 sys.NewSystemEnv()。
	Env ports.EnvPort
}

// SystemAgent 实现 ports.SSHAgentPort，统一封装本机 Unix 套接字与 Windows 命名管道 SSH Agent 访问；
// 零值恒无效并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type SystemAgent struct {
	env   ports.EnvPort
	valid bool
}

// NewSystemAgent 构造可用的本机 SSH Agent 适配器实例。
func NewSystemAgent(spec Spec) *SystemAgent {
	env := spec.Env
	if env == nil {
		env = sys.NewSystemEnv()
	}
	return &SystemAgent{env: env, valid: true}
}

// DialAgent 按 spec 或环境变量解析目标 Agent 通道，并执行对端安全校验后返回双向连接。
func (a *SystemAgent) DialAgent(ctx context.Context, spec algebraic.Option[inventory.AgentSpec]) (net.Conn, error) {
	if err := a.checkBase(ctx); err != nil {
		return nil, err
	}
	target, err := a.resolveTarget(spec)
	if err != nil {
		return nil, err
	}
	return dialAgentPlatform(ctx, target)
}

// ListAgentKeys 连接本机 SSH Agent 并列举当前可用的已校验公钥清单。
func (a *SystemAgent) ListAgentKeys(ctx context.Context, spec algebraic.Option[inventory.AgentSpec]) ([]ports.PublicKeyInfo, error) {
	conn, err := a.DialAgent(ctx, spec)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	stop := bindConnCancel(ctx, conn)
	defer stop()

	rawKeys, err := sshagent.NewClient(conn).List()
	if err != nil {
		return nil, mapAgentOpError(ctx, err)
	}
	out := make([]ports.PublicKeyInfo, 0, len(rawKeys))
	for _, k := range rawKeys {
		info, pErr := agentKeyToPublicKeyInfo(k)
		if pErr != nil {
			continue
		}
		out = append(out, info)
	}
	return out, nil
}

// SignWithAgent 使用本机 SSH Agent 中与 key 指纹匹配的私钥按 algorithm 对 data 生成数字签名。
func (a *SystemAgent) SignWithAgent(
	ctx context.Context,
	spec algebraic.Option[inventory.AgentSpec],
	key inventory.KeyFingerprint,
	algorithm string,
	data []byte,
) (ports.Signature, error) {
	if err := a.checkBase(ctx); err != nil {
		return zeroVal[ports.Signature](), err
	}
	if !key.IsValid() || strings.TrimSpace(algorithm) == "" {
		return zeroVal[ports.Signature](), fmt.Errorf("%w: 公钥指纹与签名算法均须有效", ports.ErrInvalidArgument)
	}
	conn, err := a.DialAgent(ctx, spec)
	if err != nil {
		return zeroVal[ports.Signature](), err
	}
	defer func() { _ = conn.Close() }()
	stop := bindConnCancel(ctx, conn)
	defer stop()

	client := sshagent.NewClient(conn)
	matched, err := findMatchingAgentKey(ctx, client, key)
	if err != nil {
		return zeroVal[ports.Signature](), err
	}
	flags := signatureFlagsForAlgorithm(algorithm)
	sig, err := client.SignWithFlags(matched, data, flags)
	if err != nil {
		return zeroVal[ports.Signature](), mapAgentOpError(ctx, err)
	}
	return ports.NewSignature(sig.Format, sig.Blob)
}

func (a *SystemAgent) checkBase(ctx context.Context) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if a == nil || !a.valid {
		return fmt.Errorf("%w: SystemAgent 未初始化", ports.ErrInvalidArgument)
	}
	return nil
}

func (a *SystemAgent) resolveTarget(spec algebraic.Option[inventory.AgentSpec]) (string, error) {
	if sp, has := spec.Get(); has {
		if !sp.IsValid() {
			return "", fmt.Errorf("%w: AgentSpec 无效", ports.ErrInvalidArgument)
		}
		raw := sp.String()
		if strings.EqualFold(raw, agentKeywordNone) {
			return "", fmt.Errorf("%w: Agent 已被显式禁用", ports.ErrSignerUnavailable)
		}
		if !strings.EqualFold(raw, agentKeywordDefault) {
			return raw, nil
		}
	}
	if sock, ok := a.env.LookupEnv(envSSHAuthSock); ok && strings.TrimSpace(sock) != "" {
		return strings.TrimSpace(sock), nil
	}
	if def := defaultAgentTarget(); def != "" {
		return def, nil
	}
	return "", fmt.Errorf("%w: 未配置 %s 环境变量", ports.ErrSignerUnavailable, envSSHAuthSock)
}

func bindConnCancel(ctx context.Context, conn net.Conn) func() bool {
	return context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
}

func mapAgentOpError(ctx context.Context, err error) error {
	if cErr := ctx.Err(); cErr != nil {
		return cErr
	}
	return fmt.Errorf("%w: %w", ports.ErrSignerUnavailable, err)
}

func findMatchingAgentKey(ctx context.Context, client sshagent.ExtendedAgent, want inventory.KeyFingerprint) (ssh.PublicKey, error) {
	rawKeys, err := client.List()
	if err != nil {
		return nil, mapAgentOpError(ctx, err)
	}
	for _, k := range rawKeys {
		pub, pErr := ssh.ParsePublicKey(k.Marshal())
		if pErr != nil {
			continue
		}
		if fingerprintForPubKey(pub).Equal(want) {
			return k, nil
		}
	}
	return nil, fmt.Errorf("%w: SSH Agent 中未找到指定指纹的公钥", ports.ErrSignerUnavailable)
}

func agentKeyToPublicKeyInfo(k *sshagent.Key) (ports.PublicKeyInfo, error) {
	pub, err := ssh.ParsePublicKey(k.Marshal())
	if err != nil {
		return zeroVal[ports.PublicKeyInfo](), err
	}
	comment := truncateUTF8Bytes(security.SanitizePromptText(k.Comment), maxAgentCommentBytes)
	return ports.NewPublicKeyInfo(ports.PublicKeyInfoSpec{
		Algorithm:   pub.Type(),
		Fingerprint: fingerprintForPubKey(pub),
		WireBlob:    pub.Marshal(),
		Comment:     comment,
	})
}

func truncateUTF8Bytes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := 0
	for i := range s {
		if i > maxBytes {
			break
		}
		cut = i
	}
	if cut == 0 && utf8.RuneCountInString(s) > 0 {
		return ""
	}
	return s[:cut]
}

func fingerprintForPubKey(pub ssh.PublicKey) inventory.KeyFingerprint {
	return inventory.KeyFingerprintFromSHA256(sha256.Sum256(pub.Marshal()))
}

func signatureFlagsForAlgorithm(algorithm string) sshagent.SignatureFlags {
	switch algorithm {
	case ssh.KeyAlgoRSASHA256, ssh.CertAlgoRSASHA256v01:
		return sshagent.SignatureFlagRsaSha256
	case ssh.KeyAlgoRSASHA512, ssh.CertAlgoRSASHA512v01:
		return sshagent.SignatureFlagRsaSha512
	default:
		return 0
	}
}
