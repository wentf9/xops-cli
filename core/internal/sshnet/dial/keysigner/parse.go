package keysigner

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
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
		return zero, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldNil, domi18n.Str("field", "public_key"))
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
		return nil, domi18n.EF(ports.ErrSignerUnavailable, domi18n.KeyCommonMissingDep, domi18n.Str("component", "OperatorReadFS"))
	}
	srcPath, err := ResolveLocalFilePath(env, tokenCtx, kp.String())
	if err != nil {
		return nil, err
	}
	raw, err := ReadBoundedFile(ctx, readFS, srcPath, MaxPrivateKeyFileBytes)
	if err != nil {
		return nil, domi18n.WrapS(ports.ErrAuthFailed, err, domi18n.KeyKeySignerReadKeyFailed, domi18n.BoundStr("target", kp.String()))
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
		return nil, domi18n.WrapS(ports.ErrAuthFailed, err, domi18n.KeyKeySignerParseKeyFailed)
	}
	binding, hasPass := passOpt.Get()
	if !hasPass || vault == nil {
		return nil, domi18n.EF(ports.ErrAuthFailed, domi18n.KeyKeySignerPassphraseReq)
	}
	// OpenSSH 加密私钥格式在解密前即携带明文公钥，先做 INV-F1 指纹预校验，避免对失配密钥无谓读取 Vault/KDF。
	if missingErr.PublicKey != nil && !FingerprintOfSSHKey(missingErr.PublicKey).Equal(binding.KeyFingerprint()) {
		return nil, domi18n.EF(ports.ErrAuthFailed, domi18n.KeyKeySignerFPMismatch)
	}
	decrypted, err := decryptKeyWithVaultRef(ctx, vault, keyBytes, binding.PassphraseRef())
	if err != nil {
		return nil, err
	}
	if !FingerprintOfSSHKey(decrypted.PublicKey()).Equal(binding.KeyFingerprint()) {
		return nil, domi18n.EF(ports.ErrAuthFailed, domi18n.KeyKeySignerFPMismatch)
	}
	return decrypted, nil
}

// VerifyPassphraseBindingLoaded 强制校验 INV-F1 防掉包不变式：
// 当 AuthPrivateKey 声明了 KeyPassphraseBinding 时，必须在附加证书前确认已加载的原始私钥集合中
// 至少包含一枚与 binding.KeyFingerprint 一致的私钥，彻底阻断将加密私钥静默替换为未加密伪造私钥的绕过攻击。
func VerifyPassphraseBindingLoaded(rawSigners []ssh.Signer, passOpt algebraic.Option[inventory.KeyPassphraseBinding]) error {
	binding, hasPass := passOpt.Get()
	if !hasPass {
		return nil
	}
	for _, s := range rawSigners {
		if s != nil && FingerprintOfSSHKey(s.PublicKey()).Equal(binding.KeyFingerprint()) {
			return nil
		}
	}
	return domi18n.EF(ports.ErrAuthFailed, domi18n.KeyKeySignerFPMismatch)
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
		return nil, domi18n.WrapS(ports.ErrAuthFailed, vErr, domi18n.KeyKeySignerDecryptKeyFailed)
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
			return nil, domi18n.WrapS(ports.ErrAuthFailed, err, domi18n.KeyKeySignerReadCertFailed, domi18n.BoundStr("target", cp.String()))
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(raw)
		if err != nil {
			return nil, domi18n.WrapS(ports.ErrAuthFailed, err, domi18n.KeyKeySignerParseCertFailed, domi18n.BoundStr("target", cp.String()))
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok {
			return nil, domi18n.EF(ports.ErrAuthFailed, domi18n.KeyKeySignerInvalidCert, domi18n.BoundStr("path", cp.String()))
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
			return zero, domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonPathTemplateFailed, domi18n.BoundStr("target", raw))
		}
		expanded = out
	}
	if strings.HasPrefix(expanded, "~/") || strings.HasPrefix(expanded, `~\`) {
		if env == nil {
			return zero, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonMissingDep, domi18n.Str("component", "EnvPort"))
		}
		id, err := env.LookupLocalIdentity()
		if err != nil {
			return zero, domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyKeySignerResolveHomeFailed)
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
			return nil, domi18n.WrapS(ports.ErrSignerUnavailable, err, domi18n.KeyKeySignerParsePubKeyFailed)
		}
		out = append(out, &portSignerAdapter{pub: pub, fp: k.Fingerprint(), sign: signFn})
	}
	if len(out) == 0 {
		return nil, domi18n.EF(ports.ErrSignerUnavailable, domi18n.KeyKeySignerNoKeysFound)
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
