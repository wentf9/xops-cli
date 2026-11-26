package keysigner

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
)

// PublicKeyInfoFromSSH 将 golang.org/x/crypto/ssh.PublicKey 转换为协议库无关的不可变 ports.PublicKeyInfo。
func PublicKeyInfoFromSSH(key ssh.PublicKey) (ports.PublicKeyInfo, error) {
	if key == nil {
		var zero ports.PublicKeyInfo
		return zero, fmt.Errorf("%w: 公钥不能为 nil", ports.ErrInvalidArgument)
	}
	blob := key.Marshal()
	fp := inventory.KeyFingerprintFromSHA256(sha256.Sum256(blob))
	return ports.NewPublicKeyInfo(ports.PublicKeyInfoSpec{
		Algorithm:   key.Type(),
		Fingerprint: fp,
		WireBlob:    blob,
	})
}

// FingerprintOfSSHKey 计算 ssh.PublicKey 的 SHA-256 规范指纹；nil 公钥返回无效零值。
func FingerprintOfSSHKey(key ssh.PublicKey) inventory.KeyFingerprint {
	if key == nil {
		var zero inventory.KeyFingerprint
		return zero
	}
	return inventory.KeyFingerprintFromSHA256(sha256.Sum256(key.Marshal()))
}

// LoadPrivateKeyFile 通过 OperatorReadFS 读取有界私钥文件并在同步 SecretBox 闭包内解密为不透明 ssh.Signer。
// 强制执行 INV-F1：当绑定口令凭据时，解密后公钥指纹必须与 KeyPassphraseBinding.KeyFingerprint 一致。
func LoadPrivateKeyFile(
	ctx context.Context,
	readFS ports.OperatorReadFS,
	vault ports.SecretVault,
	env ports.EnvPort,
	tokenCtx option.TokenContext,
	kp inventory.KeyPathSpec,
	passOpt algebraic.Option[inventory.KeyPassphraseBinding],
) (ssh.Signer, error) {
	if readFS == nil {
		return nil, fmt.Errorf("%w: 读取私钥需要注入 OperatorReadFS", ports.ErrSignerUnavailable)
	}
	srcPath, err := ResolveLocalFilePath(env, tokenCtx, kp.String())
	if err != nil {
		return nil, err
	}
	raw, err := ReadBoundedFile(ctx, readFS, srcPath, MaxPrivateKeyFileBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: 读取私钥 %q 失败: %w", ports.ErrAuthFailed, kp.String(), err)
	}
	var signer ssh.Signer
	err = secret.WithBytes(raw, func(keyBox *secret.SecretBox) error {
		return keyBox.Use(func(keyBytes []byte) error {
			var pErr error
			signer, pErr = ParsePrivateKeyBytes(ctx, vault, keyBytes, passOpt)
			return pErr
		})
	})
	if err != nil {
		return nil, err
	}
	return signer, nil
}

// ParsePrivateKeyBytes 在同步明文作用域内解析未加密或口令保护私钥，并强制校验 INV-F1 口令指纹绑定。
//
//xops:secretuse
func ParsePrivateKeyBytes(
	ctx context.Context,
	vault ports.SecretVault,
	keyBytes []byte,
	passOpt algebraic.Option[inventory.KeyPassphraseBinding],
) (ssh.Signer, error) {
	s, err := ssh.ParsePrivateKey(keyBytes)
	if err == nil {
		return s, nil
	}
	var missingErr *ssh.PassphraseMissingError
	if !errors.As(err, &missingErr) {
		return nil, fmt.Errorf("%w: 解析私钥失败: %w", ports.ErrAuthFailed, err)
	}
	binding, hasPass := passOpt.Get()
	if !hasPass || vault == nil {
		return nil, fmt.Errorf("%w: 私钥受口令保护且缺少绑定口令凭据", ports.ErrAuthFailed)
	}
	decrypted, err := decryptKeyWithVaultRef(ctx, vault, keyBytes, binding.PassphraseRef())
	if err != nil {
		return nil, err
	}
	if !FingerprintOfSSHKey(decrypted.PublicKey()).Equal(binding.KeyFingerprint()) {
		return nil, fmt.Errorf("%w: 解密后私钥指纹与 KeyPassphraseBinding 不匹配 (INV-F1)", ports.ErrAuthFailed)
	}
	return decrypted, nil
}

// decryptKeyWithVaultRef 在外层明文作用域内嵌套 SecretVault.WithSecret + passBox.Use 解密受保护私钥。
//
//xops:secretuse
func decryptKeyWithVaultRef(ctx context.Context, vault ports.SecretVault, keyBytes []byte, ref secret.Ref) (ssh.Signer, error) {
	var decrypted ssh.Signer
	vErr := vault.WithSecret(ctx, ref, func(passBox *secret.SecretBox) error {
		return passBox.Use(func(passBytes []byte) error {
			var decErr error
			decrypted, decErr = ssh.ParsePrivateKeyWithPassphrase(keyBytes, passBytes)
			return decErr
		})
	})
	if vErr != nil {
		return nil, fmt.Errorf("%w: 解密私钥失败: %w", ports.ErrAuthFailed, vErr)
	}
	return decrypted, nil
}

// LoadCertificates 按路径清单读取并解析本地 OpenSSH 用户证书（缺失的证书文件按 OpenSSH 惯例静默跳过）。
func LoadCertificates(
	ctx context.Context,
	readFS ports.OperatorReadFS,
	env ports.EnvPort,
	tokenCtx option.TokenContext,
	certPaths []inventory.CertPathSpec,
) ([]*ssh.Certificate, error) {
	if len(certPaths) == 0 || readFS == nil {
		return nil, nil
	}
	out := make([]*ssh.Certificate, 0, len(certPaths))
	for _, cp := range certPaths {
		srcPath, err := ResolveLocalFilePath(env, tokenCtx, cp.String())
		if err != nil {
			return nil, err
		}
		raw, err := ReadBoundedFile(ctx, readFS, srcPath, MaxCertFileBytes)
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

// AttachMatchingCert 若 certs 中存在公钥指纹与 signer 匹配的 SSH 证书，则返回证书签名包装器，否则原样返回。
func AttachMatchingCert(signer ssh.Signer, certs []*ssh.Certificate) ssh.Signer {
	fp := FingerprintOfSSHKey(signer.PublicKey())
	for _, cert := range certs {
		if FingerprintOfSSHKey(cert.Key).Equal(fp) {
			if wrapped, err := ssh.NewCertSigner(cert, signer); err == nil {
				return wrapped
			}
		}
	}
	return signer
}

// ReadBoundedFile 经 OperatorReadFS 在 maxBytes 上限内安全读取单个文件字节（失败或超限时立即 clear 局部缓冲）。
func ReadBoundedFile(ctx context.Context, readFS ports.OperatorReadFS, path pathalg.LocalSourcePath, maxBytes int64) ([]byte, error) {
	var data []byte
	err := readFS.WithOperatorRead(ctx, path, pathalg.SymlinkFollowOperatorSource, func(r ports.BoundedReadHandle, size int64) error {
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

// ResolveLocalFilePath 展开路径模板中的 OpenSSH 令牌与 "~/" 主目录前缀，并解析为不可变 LocalSourcePath。
func ResolveLocalFilePath(env ports.EnvPort, tokenCtx option.TokenContext, raw string) (pathalg.LocalSourcePath, error) {
	var zero pathalg.LocalSourcePath
	expanded := raw
	if strings.ContainsRune(expanded, '%') {
		out, err := option.ExpandPathTokens(expanded, tokenCtx)
		if err != nil {
			return zero, fmt.Errorf("%w: 展开路径模板 %q 失败: %w", ports.ErrInvalidArgument, raw, err)
		}
		expanded = out
	}
	if strings.HasPrefix(expanded, "~/") || strings.HasPrefix(expanded, `~\`) {
		if env == nil {
			return zero, fmt.Errorf("%w: 展开 %q 需要注入 EnvPort", ports.ErrInvalidArgument, raw)
		}
		id, err := env.LookupLocalIdentity()
		if err != nil {
			return zero, fmt.Errorf("%w: 获取主目录失败: %w", ports.ErrInvalidArgument, err)
		}
		expanded = strings.TrimRight(id.HomeDir(), `/\`) + "/" + expanded[2:]
	}
	return pathalg.ParseLocalSourcePath(expanded)
}

// PortSignFunc 是适配外部 KeySignerPort / SSHAgentPort 签名回调的函数类型。
type PortSignFunc func(fp inventory.KeyFingerprint, algorithm string, data []byte) (ports.Signature, error)

// portSignerAdapter 将协议库无关的 ports.PublicKeyInfo 与签名回调适配为 ssh.AlgorithmSigner。
type portSignerAdapter struct {
	pub  ssh.PublicKey
	fp   inventory.KeyFingerprint
	sign PortSignFunc
}

// WrapPortSigners 将一组 ports.PublicKeyInfo 包装为可传入 ssh.PublicKeys 的 ssh.Signer 列表。
func WrapPortSigners(keys []ports.PublicKeyInfo, signFn PortSignFunc) ([]ssh.Signer, error) {
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
