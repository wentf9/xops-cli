package dial

import (
	"context"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
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
		return nil, domi18n.EF(ports.ErrAuthFailed, domi18n.KeyDialNoAuthMethods)
	}
	return methods, nil
}

func (d *Dialer) compileAuthMethod(ctx context.Context, hop plan.HopSpec, auth inventory.AuthMethod, loginPassRef algebraic.Option[secret.Ref]) ([]ssh.AuthMethod, error) {
	if auth == nil || !auth.IsValid() {
		return nil, domi18n.WrapSentinel(ports.ErrAuthFailed, domi18n.E(domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "AuthMethod")))
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
		return nil, domi18n.EF(ports.ErrAuthFailed, domi18n.KeyCommonUnsupportedVariant, domi18n.Str("type", "AuthMethod"))
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
		return nil, domi18n.EF(ports.ErrAuthFailed, domi18n.KeyCommonMissingDep, domi18n.Str("component", "SecretVault"))
	}
	var method ssh.AuthMethod
	err := d.vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
		return box.Use(func(plain []byte) error {
			method = ssh.Password(string(plain))
			return nil
		})
	})
	if err != nil {
		return nil, domi18n.WrapS(ports.ErrAuthFailed, err, domi18n.KeyDialReadPasswordFailed)
	}
	return method, nil
}

func (d *Dialer) buildAgentAuth(ctx context.Context, spec algebraic.Option[inventory.AgentSpec]) ([]ssh.AuthMethod, error) {
	if d.agent == nil {
		return nil, domi18n.EF(ports.ErrSignerUnavailable, domi18n.KeyCommonMissingDep, domi18n.Str("component", "SSHAgentPort"))
	}
	keys, err := d.agent.ListAgentKeys(ctx, spec)
	if err != nil {
		if ctx.Err() != nil {
			return nil, err
		}
		return nil, domi18n.WrapSentinel(ports.ErrSignerUnavailable, err)
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
	// 当密钥或证书路径包含跳板级 % 令牌（如 %h/%p/%r/%n/%C）且注入了 ReadFS 时，
	// 直接走带 hop TokenContext 的 ReadFS 加载路径，避免经无 hop 上下文的 KeySigner 重复加载或展开缺失。
	useReadFSDirectly := d.readFS != nil && privateKeyUsesHopTokens(v)
	var signers []ssh.Signer
	if !useReadFSDirectly && d.keySigner != nil {
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
		return nil, domi18n.EF(ports.ErrSignerUnavailable, domi18n.KeyCommonEitherMissingDep, domi18n.Str("first", "KeySignerPort"), domi18n.Str("second", "OperatorReadFS"))
	}
	return []ssh.AuthMethod{ssh.PublicKeys(signers...)}, nil
}

func privateKeyUsesHopTokens(v *inventory.AuthPrivateKey) bool {
	for _, kp := range v.KeyPaths().Slice() {
		if strings.Contains(kp.String(), "%") {
			return true
		}
	}
	for _, cp := range v.CertPaths() {
		if strings.Contains(cp.String(), "%") {
			return true
		}
	}
	return false
}

// loadSignersFromKeyPort 保留 KeySignerPort 返回的原始安全错误语义（INV-F1 / Vault 锁定 / 软链拒绝等），
// 绝不无条件包装为 ErrSignerUnavailable，确保 AuthComposite 对硬安全错误严格失败关闭。
func (d *Dialer) loadSignersFromKeyPort(ctx context.Context, v *inventory.AuthPrivateKey) ([]ssh.Signer, error) {
	keys, err := d.keySigner.ListPublicKeys(ctx, v)
	if err != nil {
		return nil, err
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
	var rawSigners []ssh.Signer
	for _, kp := range v.KeyPaths().Slice() {
		s, lErr := keysigner.LoadPrivateKeyFile(ctx, d.readFS, d.vault, d.env, tc, kp, v.Passphrase())
		if lErr != nil {
			if skipNotFound && ctx.Err() == nil && errors.Is(lErr, ports.ErrNotFound) {
				continue
			}
			return nil, lErr
		}
		rawSigners = append(rawSigners, s)
	}
	if len(rawSigners) == 0 {
		return nil, domi18n.WrapS(ports.ErrAuthFailed, ports.ErrSignerUnavailable, domi18n.KeyKeySignerNoKeysFound)
	}
	if err := keysigner.VerifyPassphraseBindingLoaded(rawSigners, v.Passphrase()); err != nil {
		return nil, err
	}
	signers := make([]ssh.Signer, 0, len(rawSigners))
	for _, s := range rawSigners {
		signers = append(signers, keysigner.AttachMatchingCert(s, certs))
	}
	return signers, nil
}
