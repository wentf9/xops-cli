package dial

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/keysigner"
	"github.com/wentf9/xops-cli/core/ports"
)

// buildAuthMethods 将不可变封闭 inventory.AuthMethod 转换为 golang.org/x/crypto/ssh.AuthMethod 列表。
// 全部明文机密仅经 SecretVault.WithSecret + box.Use 或 secret.WithBytes 在同步闭包内消费（零 nolint 豁免）。
func (d *Dialer) buildAuthMethods(ctx context.Context, hop plan.HopSpec) ([]ssh.AuthMethod, error) {
	loginPassRef := findLoginPasswordRef(hop.Auth())
	methods, err := d.compileAuthMethod(ctx, hop, hop.Auth(), loginPassRef)
	if err != nil {
		return nil, err
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("%w: 未构建出任何可用的 SSH 认证方法", ports.ErrAuthFailed)
	}
	return methods, nil
}

func (d *Dialer) compileAuthMethod(ctx context.Context, hop plan.HopSpec, auth inventory.AuthMethod, loginPassRef algebraic.Option[secret.Ref]) ([]ssh.AuthMethod, error) {
	if auth == nil || !auth.IsValid() {
		return nil, fmt.Errorf("%w: 无效 AuthMethod", ports.ErrAuthFailed)
	}
	switch v := auth.(type) {
	case *inventory.AuthPassword:
		m, err := d.buildPasswordAuth(ctx, v.PasswordRef())
		if err != nil {
			return nil, err
		}
		return []ssh.AuthMethod{m}, nil
	case *inventory.AuthPrivateKey:
		return d.buildPrivateKeyAuth(ctx, hop, v)
	case *inventory.AuthAgent:
		return d.buildAgentAuth(ctx, v.Spec())
	case *inventory.AuthKeyboardInteractive:
		return []ssh.AuthMethod{d.buildKeyboardInteractiveAuth(ctx, hop, v, loginPassRef)}, nil
	case *inventory.AuthComposite:
		return d.buildCompositeAuth(ctx, hop, v, loginPassRef)
	default:
		return nil, fmt.Errorf("%w: 不支持的认证变体 %T", ports.ErrAuthFailed, auth)
	}
}

// buildCompositeAuth 编译组合认证链路：当单个子认证仅因签名源不可用（ErrSignerUnavailable）跳过时继续尝试后续方法；
// 凡安全/凭据硬错误（INV-F1 指纹失配、Vault 锁定、软链拒绝、坏 PEM/错口令）或上下文取消均立即失败关闭。
func (d *Dialer) buildCompositeAuth(ctx context.Context, hop plan.HopSpec, comp *inventory.AuthComposite, loginPassRef algebraic.Option[secret.Ref]) ([]ssh.AuthMethod, error) {
	var all []ssh.AuthMethod
	var lastUnavailable error
	for _, sub := range comp.Methods() {
		ms, err := d.compileAuthMethod(ctx, hop, sub, loginPassRef)
		if err != nil {
			if ctx.Err() == nil && errors.Is(err, ports.ErrSignerUnavailable) {
				lastUnavailable = err
				continue
			}
			return nil, err
		}
		all = append(all, ms...)
	}
	if len(all) == 0 && lastUnavailable != nil {
		return nil, lastUnavailable
	}
	return all, nil
}

func (d *Dialer) buildPasswordAuth(ctx context.Context, ref secret.Ref) (ssh.AuthMethod, error) {
	if d.vault == nil {
		return nil, fmt.Errorf("%w: 密码认证需要注入 SecretVault", ports.ErrAuthFailed)
	}
	var method ssh.AuthMethod
	err := d.vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
		return box.Use(func(plain []byte) error {
			method = ssh.Password(string(plain))
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("%w: 读取密码凭据失败: %w", ports.ErrAuthFailed, err)
	}
	return method, nil
}

func (d *Dialer) buildAgentAuth(ctx context.Context, spec algebraic.Option[inventory.AgentSpec]) ([]ssh.AuthMethod, error) {
	if d.agent == nil {
		return nil, fmt.Errorf("%w: 未注入 SSHAgentPort", ports.ErrSignerUnavailable)
	}
	keys, err := d.agent.ListAgentKeys(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ports.ErrSignerUnavailable, err)
	}
	signers, err := keysigner.WrapPortSigners(keys, func(fp inventory.KeyFingerprint, algo string, data []byte) (ports.Signature, error) {
		return d.agent.SignWithAgent(ctx, spec, fp, algo, data)
	})
	if err != nil {
		return nil, err
	}
	return []ssh.AuthMethod{ssh.PublicKeys(signers...)}, nil
}

func (d *Dialer) buildPrivateKeyAuth(ctx context.Context, hop plan.HopSpec, v *inventory.AuthPrivateKey) ([]ssh.AuthMethod, error) {
	var signers []ssh.Signer
	if d.keySigner != nil {
		ks, err := d.loadSignersFromKeyPort(ctx, v)
		if err == nil {
			signers = append(signers, ks...)
		} else if ctx.Err() != nil || !errors.Is(err, ports.ErrSignerUnavailable) || d.readFS == nil {
			return nil, err
		}
	}
	if len(signers) == 0 && d.readFS != nil {
		fsSigners, err := d.loadSignersFromReadFS(ctx, hop, v)
		if err != nil {
			return nil, err
		}
		signers = append(signers, fsSigners...)
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("%w: 无可用私钥签名器（请注入 KeySignerPort 或 OperatorReadFS）", ports.ErrSignerUnavailable)
	}
	return []ssh.AuthMethod{ssh.PublicKeys(signers...)}, nil
}

func (d *Dialer) loadSignersFromKeyPort(ctx context.Context, v *inventory.AuthPrivateKey) ([]ssh.Signer, error) {
	keys, err := d.keySigner.ListPublicKeys(ctx, v)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ports.ErrSignerUnavailable, err)
	}
	return keysigner.WrapPortSigners(keys, func(fp inventory.KeyFingerprint, algo string, data []byte) (ports.Signature, error) {
		return d.keySigner.Sign(ctx, fp, algo, data)
	})
}

func (d *Dialer) loadSignersFromReadFS(ctx context.Context, hop plan.HopSpec, v *inventory.AuthPrivateKey) ([]ssh.Signer, error) {
	tc := d.buildHopTokenContext(hop)
	certs, err := keysigner.LoadCertificates(ctx, d.readFS, d.env, tc, v.CertPaths())
	if err != nil {
		return nil, err
	}
	skipNotFound := v.Passphrase().IsNone()
	var signers []ssh.Signer
	for _, kp := range v.KeyPaths().Slice() {
		s, lErr := keysigner.LoadPrivateKeyFile(ctx, d.readFS, d.vault, d.env, tc, kp, v.Passphrase())
		if lErr != nil {
			if skipNotFound && ctx.Err() == nil && errors.Is(lErr, ports.ErrNotFound) {
				continue
			}
			return nil, lErr
		}
		signers = append(signers, keysigner.AttachMatchingCert(s, certs))
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("%w: %w: 未找到任何可用私钥文件", ports.ErrAuthFailed, ports.ErrSignerUnavailable)
	}
	return signers, nil
}
