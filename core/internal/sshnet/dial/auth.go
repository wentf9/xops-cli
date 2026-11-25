package dial

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/secret"
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
	signers, err := wrapPortSigners(keys, func(fp inventory.KeyFingerprint, algo string, data []byte) (ports.Signature, error) {
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
	return wrapPortSigners(keys, func(fp inventory.KeyFingerprint, algo string, data []byte) (ports.Signature, error) {
		return d.keySigner.Sign(ctx, fp, algo, data)
	})
}

func (d *Dialer) loadSignersFromReadFS(ctx context.Context, hop plan.HopSpec, v *inventory.AuthPrivateKey) ([]ssh.Signer, error) {
	certs, err := d.loadCertificates(ctx, hop, v.CertPaths())
	if err != nil {
		return nil, err
	}
	skipNotFound := v.Passphrase().IsNone()
	var signers []ssh.Signer
	for _, kp := range v.KeyPaths().Slice() {
		s, err := d.loadSinglePrivateKey(ctx, hop, kp, v.Passphrase())
		if err != nil {
			if skipNotFound && ctx.Err() == nil && errors.Is(err, ports.ErrNotFound) {
				continue
			}
			return nil, err
		}
		signers = append(signers, attachMatchingCert(s, certs))
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("%w: %w: 未找到任何可用私钥文件", ports.ErrAuthFailed, ports.ErrSignerUnavailable)
	}
	return signers, nil
}

func (d *Dialer) loadSinglePrivateKey(ctx context.Context, hop plan.HopSpec, kp inventory.KeyPathSpec, passOpt algebraic.Option[inventory.KeyPassphraseBinding]) (ssh.Signer, error) {
	srcPath, err := d.resolveLocalFilePath(hop, kp.String())
	if err != nil {
		return nil, err
	}
	raw, err := d.readBoundedFile(ctx, srcPath, maxPrivateKeyFileBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: 读取私钥 %q 失败: %w", ports.ErrAuthFailed, kp.String(), err)
	}
	var signer ssh.Signer
	err = secret.WithBytes(raw, func(keyBox *secret.SecretBox) error {
		return keyBox.Use(func(keyBytes []byte) error {
			var pErr error
			signer, pErr = d.parsePrivateKeyBytes(ctx, keyBytes, passOpt)
			return pErr
		})
	})
	if err != nil {
		return nil, err
	}
	return signer, nil
}

// parsePrivateKeyBytes 在同步明文作用域内解析未加密或口令保护私钥，并强制校验 INV-F1 口令指纹绑定。
//
//xops:secretuse
func (d *Dialer) parsePrivateKeyBytes(ctx context.Context, keyBytes []byte, passOpt algebraic.Option[inventory.KeyPassphraseBinding]) (ssh.Signer, error) {
	s, err := ssh.ParsePrivateKey(keyBytes)
	if err == nil {
		return s, nil
	}
	var missingErr *ssh.PassphraseMissingError
	if !errors.As(err, &missingErr) {
		return nil, fmt.Errorf("%w: 解析私钥失败: %w", ports.ErrAuthFailed, err)
	}
	binding, hasPass := passOpt.Get()
	if !hasPass || d.vault == nil {
		return nil, fmt.Errorf("%w: 私钥受口令保护且缺少绑定口令凭据", ports.ErrAuthFailed)
	}
	var decrypted ssh.Signer
	vErr := d.vault.WithSecret(ctx, binding.PassphraseRef(), func(passBox *secret.SecretBox) error {
		return passBox.Use(func(passBytes []byte) error {
			var decErr error
			decrypted, decErr = ssh.ParsePrivateKeyWithPassphrase(keyBytes, passBytes)
			return decErr
		})
	})
	if vErr != nil {
		return nil, fmt.Errorf("%w: 解密私钥失败: %w", ports.ErrAuthFailed, vErr)
	}
	if !fingerprintOfSSHKey(decrypted.PublicKey()).Equal(binding.KeyFingerprint()) {
		return nil, fmt.Errorf("%w: 解密后私钥指纹与 KeyPassphraseBinding 不匹配 (INV-F1)", ports.ErrAuthFailed)
	}
	return decrypted, nil
}

func (d *Dialer) loadCertificates(ctx context.Context, hop plan.HopSpec, certPaths []inventory.CertPathSpec) ([]*ssh.Certificate, error) {
	if len(certPaths) == 0 {
		return nil, nil
	}
	out := make([]*ssh.Certificate, 0, len(certPaths))
	for _, cp := range certPaths {
		srcPath, err := d.resolveLocalFilePath(hop, cp.String())
		if err != nil {
			return nil, err
		}
		raw, err := d.readBoundedFile(ctx, srcPath, maxCertFileBytes)
		if err != nil {
			if ctx.Err() == nil && errors.Is(err, ports.ErrNotFound) {
				continue
			}
			return nil, fmt.Errorf("%w: 读取证书 %q 失败: %w", ports.ErrAuthFailed, cp.String(), err)
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: 解析证书 %q 失败: %w", ports.ErrAuthFailed, cp.String(), err)
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok {
			return nil, fmt.Errorf("%w: 文件 %q 不是有效的 SSH 证书", ports.ErrAuthFailed, cp.String())
		}
		out = append(out, cert)
	}
	return out, nil
}

func attachMatchingCert(signer ssh.Signer, certs []*ssh.Certificate) ssh.Signer {
	fp := fingerprintOfSSHKey(signer.PublicKey())
	for _, cert := range certs {
		if fingerprintOfSSHKey(cert.Key).Equal(fp) {
			if wrapped, err := ssh.NewCertSigner(cert, signer); err == nil {
				return wrapped
			}
		}
	}
	return signer
}

func (d *Dialer) readBoundedFile(ctx context.Context, path pathalg.LocalSourcePath, maxBytes int64) ([]byte, error) {
	var data []byte
	err := d.readFS.WithOperatorRead(ctx, path, pathalg.SymlinkFollowOperatorSource, func(r ports.BoundedReadHandle, size int64) error {
		if size > maxBytes {
			return ports.ErrLimitExceeded
		}
		var rErr error
		data, rErr = io.ReadAll(io.LimitReader(r, maxBytes+1))
		if rErr != nil {
			clear(data)
			data = nil
			return rErr
		}
		if int64(len(data)) > maxBytes {
			clear(data)
			data = nil
			return ports.ErrLimitExceeded
		}
		return nil
	})
	return data, err
}

func (d *Dialer) resolveLocalFilePath(hop plan.HopSpec, raw string) (pathalg.LocalSourcePath, error) {
	var zero pathalg.LocalSourcePath
	expanded := raw
	if strings.ContainsRune(expanded, '%') {
		out, err := option.ExpandPathTokens(expanded, d.buildHopTokenContext(hop))
		if err != nil {
			return zero, fmt.Errorf("%w: 展开路径模板 %q 失败: %w", ports.ErrInvalidArgument, raw, err)
		}
		expanded = out
	}
	if strings.HasPrefix(expanded, "~/") || strings.HasPrefix(expanded, `~\`) {
		if d.env == nil {
			return zero, fmt.Errorf("%w: 展开 %q 需要注入 EnvPort", ports.ErrInvalidArgument, raw)
		}
		id, err := d.env.LookupLocalIdentity()
		if err != nil {
			return zero, fmt.Errorf("%w: 获取主目录失败: %w", ports.ErrInvalidArgument, err)
		}
		expanded = strings.TrimRight(id.HomeDir(), `/\`) + "/" + expanded[2:]
	}
	return pathalg.ParseLocalSourcePath(expanded)
}

type portSignFunc func(fp inventory.KeyFingerprint, algorithm string, data []byte) (ports.Signature, error)

// portSignerAdapter 将协议库无关的 ports.PublicKeyInfo 与签名回调适配为 ssh.AlgorithmSigner。
type portSignerAdapter struct {
	pub  ssh.PublicKey
	fp   inventory.KeyFingerprint
	sign portSignFunc
}

func wrapPortSigners(keys []ports.PublicKeyInfo, signFn portSignFunc) ([]ssh.Signer, error) {
	out := make([]ssh.Signer, 0, len(keys))
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.WireBlob())
		if err != nil {
			return nil, fmt.Errorf("%w: 解析端口公钥失败: %w", ports.ErrSignerUnavailable, err)
		}
		out = append(out, &portSignerAdapter{pub: pub, fp: k.Fingerprint(), sign: signFn})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: 签名器未提供任何可用公钥", ports.ErrSignerUnavailable)
	}
	return out, nil
}

func (s *portSignerAdapter) PublicKey() ssh.PublicKey { return s.pub }

func (s *portSignerAdapter) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(nil, data, s.pub.Type())
}

func (s *portSignerAdapter) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	if algorithm == "" {
		algorithm = s.pub.Type()
	}
	sig, err := s.sign(s.fp, algorithm, data)
	if err != nil {
		return nil, err
	}
	return &ssh.Signature{Format: sig.Format(), Blob: sig.Blob()}, nil
}
