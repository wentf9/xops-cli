package keysigner

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
)

// ListPublicKeys 根据认证方式加载并缓存不透明签名器，返回协议库无关的公钥元数据列表。
func (k *KeySigner) ListPublicKeys(ctx context.Context, auth inventory.AuthMethod) ([]ports.PublicKeyInfo, error) {
	if err := k.checkBase(ctx); err != nil {
		return nil, err
	}
	if auth == nil || !auth.IsValid() {
		return nil, fmt.Errorf("%w: 无效 AuthMethod", ports.ErrInvalidArgument)
	}
	return k.listForAuth(ctx, auth)
}

func (k *KeySigner) listForAuth(ctx context.Context, auth inventory.AuthMethod) ([]ports.PublicKeyInfo, error) {
	switch v := auth.(type) {
	case *inventory.AuthPrivateKey:
		return k.listPrivateKeys(ctx, v)
	case *inventory.AuthAgent:
		return k.listAgentKeys(ctx, v.Spec())
	case *inventory.AuthComposite:
		return k.listCompositeKeys(ctx, v)
	case *inventory.AuthPassword, *inventory.AuthKeyboardInteractive:
		return nil, nil
	default:
		return nil, fmt.Errorf("%w: 不支持的认证方式变体 %T", ports.ErrInvalidArgument, auth)
	}
}

func (k *KeySigner) listPrivateKeys(ctx context.Context, v *inventory.AuthPrivateKey) ([]ports.PublicKeyInfo, error) {
	if k.readFS == nil {
		return nil, fmt.Errorf("%w: 列举本地私钥需要注入 OperatorReadFS", ports.ErrSignerUnavailable)
	}
	tc := k.baseTokenContext()
	certs, err := LoadCertificates(ctx, k.readFS, k.env, tc, v.CertPaths())
	if err != nil {
		return nil, err
	}
	skipNotFound := v.Passphrase().IsNone()
	var rawSigners []ssh.Signer
	for _, kp := range v.KeyPaths().Slice() {
		signer, lErr := LoadPrivateKeyFile(ctx, k.readFS, k.vault, k.env, tc, kp, v.Passphrase())
		if lErr != nil {
			if skipNotFound && ctx.Err() == nil && errors.Is(lErr, ports.ErrNotFound) {
				continue
			}
			return nil, lErr
		}
		rawSigners = append(rawSigners, signer)
	}
	if len(rawSigners) == 0 {
		return nil, fmt.Errorf("%w: 未找到任何可用本地私钥", ports.ErrSignerUnavailable)
	}
	if err := VerifyPassphraseBindingLoaded(rawSigners, v.Passphrase()); err != nil {
		return nil, err
	}
	out := make([]ports.PublicKeyInfo, 0, len(rawSigners))
	for _, signer := range rawSigners {
		attached := AttachMatchingCert(signer, certs)
		pubInfo, pErr := PublicKeyInfoFromSSH(attached.PublicKey())
		if pErr != nil {
			return nil, pErr
		}
		k.registerSigner(pubInfo.Fingerprint(), attached)
		out = append(out, pubInfo)
	}
	return out, nil
}

func (k *KeySigner) listAgentKeys(ctx context.Context, spec algebraic.Option[inventory.AgentSpec]) ([]ports.PublicKeyInfo, error) {
	if k.agent == nil {
		return nil, fmt.Errorf("%w: 未注入 SSHAgentPort", ports.ErrSignerUnavailable)
	}
	keys, err := k.agent.ListAgentKeys(ctx, spec)
	if err != nil {
		if ctx.Err() != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ports.ErrSignerUnavailable, err)
	}
	k.mu.Lock()
	for _, pk := range keys {
		if pk.IsValid() {
			k.agentKeys[pk.Fingerprint().String()] = agentKeyEntry{spec: spec}
		}
	}
	k.mu.Unlock()
	return keys, nil
}

func (k *KeySigner) listCompositeKeys(ctx context.Context, comp *inventory.AuthComposite) ([]ports.PublicKeyInfo, error) {
	var out []ports.PublicKeyInfo
	var lastUnavailable error
	for _, sub := range comp.Methods() {
		keys, err := k.listForAuth(ctx, sub)
		if err != nil {
			if ctx.Err() == nil && errors.Is(err, ports.ErrSignerUnavailable) {
				lastUnavailable = err
				continue
			}
			return nil, err
		}
		out = append(out, keys...)
	}
	if len(out) == 0 && lastUnavailable != nil {
		return nil, lastUnavailable
	}
	return out, nil
}

// Sign 使用已加载的本地不透明 ssh.Signer 或已登记的 Agent 公钥对 data 执行指定算法签名。
func (k *KeySigner) Sign(ctx context.Context, key inventory.KeyFingerprint, algorithm string, data []byte) (ports.Signature, error) {
	var zero ports.Signature
	if err := k.checkBase(ctx); err != nil {
		return zero, err
	}
	if !key.IsValid() || len(data) == 0 {
		return zero, fmt.Errorf("%w: 签名指纹或待签数据无效", ports.ErrInvalidArgument)
	}
	fpKey := key.String()
	k.mu.RLock()
	signer, hasLocal := k.signers[fpKey]
	agEntry, hasAgent := k.agentKeys[fpKey]
	k.mu.RUnlock()
	if hasLocal {
		return k.signWithLocal(signer, algorithm, data)
	}
	if hasAgent && k.agent != nil {
		return k.agent.SignWithAgent(ctx, agEntry.spec, key, algorithm, data)
	}
	return zero, fmt.Errorf("%w: 未找到指纹 %s 对应的签名器", ports.ErrSignerUnavailable, fpKey)
}

func (k *KeySigner) signWithLocal(signer ssh.Signer, algorithm string, data []byte) (ports.Signature, error) {
	var zero ports.Signature
	rnd := k.randReader()
	if _, isCert := signer.PublicKey().(*ssh.Certificate); isCert && algorithm != "" {
		// x/crypto/ssh 的 certSigner.SignWithAlgorithm 将算法原样透传给底层密钥签名器，
		// 需将 OpenSSH 证书算法名规范化为对应的底层签名算法名（RFC / PROTOCOL.certkeys）。
		algorithm = underlyingCertSignAlgo(algorithm)
	}
	var (
		sig *ssh.Signature
		err error
	)
	if algSigner, ok := signer.(ssh.AlgorithmSigner); ok && algorithm != "" {
		sig, err = algSigner.SignWithAlgorithm(rnd, data, algorithm)
	} else {
		sig, err = signer.Sign(rnd, data)
	}
	if err != nil {
		return zero, fmt.Errorf("%w: SSH 私钥签名失败: %w", ports.ErrSignerUnavailable, err)
	}
	return ports.NewSignature(sig.Format, sig.Blob)
}

func underlyingCertSignAlgo(algorithm string) string {
	switch algorithm {
	case ssh.CertAlgoRSAv01:
		return ssh.KeyAlgoRSA
	case ssh.CertAlgoRSASHA256v01:
		return ssh.KeyAlgoRSASHA256
	case ssh.CertAlgoRSASHA512v01:
		return ssh.KeyAlgoRSASHA512
	case ssh.CertAlgoECDSA256v01:
		return ssh.KeyAlgoECDSA256
	case ssh.CertAlgoECDSA384v01:
		return ssh.KeyAlgoECDSA384
	case ssh.CertAlgoECDSA521v01:
		return ssh.KeyAlgoECDSA521
	case ssh.CertAlgoED25519v01:
		return ssh.KeyAlgoED25519
	case ssh.CertAlgoSKECDSA256v01:
		return ssh.KeyAlgoSKECDSA256
	case ssh.CertAlgoSKED25519v01:
		return ssh.KeyAlgoSKED25519
	default:
		return algorithm
	}
}

// InspectPrivateKeyFingerprint 读取并核验未加密或口令保护私钥文件的 SHA-256 公钥指纹（支撑加密私钥原子登记）。
func (k *KeySigner) InspectPrivateKeyFingerprint(
	ctx context.Context,
	keyPath inventory.KeyPathSpec,
	passphrase algebraic.Option[secret.Ref],
) (inventory.KeyFingerprint, error) {
	var zero inventory.KeyFingerprint
	if err := k.checkBase(ctx); err != nil {
		return zero, err
	}
	if !keyPath.IsValid() {
		return zero, fmt.Errorf("%w: KeyPathSpec 无效", ports.ErrInvalidArgument)
	}
	passRef, hasPass := passphrase.Get()
	if hasPass && !passRef.IsValid() {
		return zero, fmt.Errorf("%w: 口令凭据引用无效", ports.ErrInvalidArgument)
	}
	if k.readFS == nil {
		return zero, fmt.Errorf("%w: 核验私钥指纹需要注入 OperatorReadFS", ports.ErrSignerUnavailable)
	}
	srcPath, err := ResolveLocalFilePath(k.env, k.baseTokenContext(), keyPath.String())
	if err != nil {
		return zero, err
	}
	raw, err := ReadBoundedFile(ctx, k.readFS, srcPath, MaxPrivateKeyFileBytes)
	if err != nil {
		return zero, fmt.Errorf("%w: 读取私钥 %q 失败: %w", ports.ErrAuthFailed, keyPath.String(), err)
	}
	var fp inventory.KeyFingerprint
	err = secret.WithBytes(raw, func(keyBox *secret.SecretBox) error {
		return keyBox.Use(func(keyBytes []byte) error {
			signer, pErr := k.parseInspectKeyBytes(ctx, keyBytes, passRef, hasPass)
			if pErr != nil {
				return pErr
			}
			fp = FingerprintOfSSHKey(signer.PublicKey())
			return nil
		})
	})
	if err != nil {
		return zero, err
	}
	if !fp.IsValid() {
		return zero, fmt.Errorf("%w: 解析出的私钥指纹无效", ports.ErrAuthFailed)
	}
	return fp, nil
}

// parseInspectKeyBytes 在明文作用域内解析待核验私钥（显式提供口令引用时强制经 Vault 解密校验）。
//
//xops:secretuse
func (k *KeySigner) parseInspectKeyBytes(ctx context.Context, keyBytes []byte, passRef secret.Ref, hasPass bool) (ssh.Signer, error) {
	if hasPass {
		if k.vault == nil {
			return nil, fmt.Errorf("%w: 解密私钥口令需要注入 SecretVault", ports.ErrAuthFailed)
		}
		return decryptKeyWithVaultRef(ctx, k.vault, keyBytes, passRef)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: 解析私钥失败: %w", ports.ErrAuthFailed, err)
	}
	return signer, nil
}

func (k *KeySigner) checkBase(ctx context.Context) error {
	if k == nil || !k.valid {
		return fmt.Errorf("%w: KeySigner 未初始化", ports.ErrInvalidArgument)
	}
	if ctx == nil {
		return ports.ErrNilContext
	}
	return ctx.Err()
}

func (k *KeySigner) registerSigner(fp inventory.KeyFingerprint, signer ssh.Signer) {
	if !fp.IsValid() || signer == nil {
		return
	}
	k.mu.Lock()
	k.signers[fp.String()] = signer
	k.mu.Unlock()
}

func (k *KeySigner) randReader() io.Reader {
	if k.entropy != nil {
		return k.entropy
	}
	return rand.Reader
}

func (k *KeySigner) baseTokenContext() option.TokenContext {
	var tc option.TokenContext
	if k.env != nil {
		if id, err := k.env.LookupLocalIdentity(); err == nil {
			tc = id.ApplyToTokenContext(tc)
		}
	}
	return tc
}
