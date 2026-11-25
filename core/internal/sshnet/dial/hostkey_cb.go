package dial

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
)

// publicKeyInfoFromSSH 将 golang.org/x/crypto/ssh.PublicKey 转换为协议库无关的不可变 ports.PublicKeyInfo。
func publicKeyInfoFromSSH(key ssh.PublicKey) (ports.PublicKeyInfo, error) {
	if key == nil {
		var zero ports.PublicKeyInfo
		return zero, fmt.Errorf("%w: 服务端未呈递有效主机公钥", ports.ErrInvalidArgument)
	}
	blob := key.Marshal()
	fp := inventory.KeyFingerprintFromSHA256(sha256.Sum256(blob))
	return ports.NewPublicKeyInfo(ports.PublicKeyInfoSpec{
		Algorithm:   key.Type(),
		Fingerprint: fp,
		WireBlob:    blob,
	})
}

func fingerprintOfSSHKey(key ssh.PublicKey) inventory.KeyFingerprint {
	if key == nil {
		var zero inventory.KeyFingerprint
		return zero
	}
	return inventory.KeyFingerprintFromSHA256(sha256.Sum256(key.Marshal()))
}

// buildHostKeyCallback 构造严格经 ports.HostTrustPort 裁决的 ssh.HostKeyCallback（绝不使用 InsecureIgnoreHostKey）。
func (d *Dialer) buildHostKeyCallback(ctx context.Context, hop plan.HopSpec) ssh.HostKeyCallback {
	tp := hop.Transport()
	mode := tp.StrictHostKeyChecking()
	knownHosts := tp.UserKnownHostsFiles()
	ep := hop.Endpoint()
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		pubInfo, err := publicKeyInfoFromSSH(key)
		if err != nil {
			return err
		}
		req, err := ports.NewHostTrustRequest(ports.HostTrustRequestSpec{
			Endpoint:   ep,
			Presented:  pubInfo,
			Mode:       mode,
			KnownHosts: knownHosts,
		})
		if err != nil {
			return err
		}
		chk, err := d.hostTrust.VerifyHostKey(ctx, req)
		if err != nil {
			return err
		}
		return d.enforceHostTrustCheck(ctx, hop, pubInfo, chk)
	}
}

func (d *Dialer) enforceHostTrustCheck(ctx context.Context, hop plan.HopSpec, pub ports.PublicKeyInfo, chk ports.HostTrustCheck) error {
	if strings.HasSuffix(pub.Algorithm(), "-cert-v01@openssh.com") {
		return enforceHostCertTrustCheck(hop, pub, chk)
	}
	switch chk.Status() {
	case ports.HostTrustTrusted:
		return nil
	case ports.HostTrustRevoked:
		return fmt.Errorf("%w: %s (%s)", ports.ErrHostKeyRevoked, hop.Endpoint(), pub.Fingerprint())
	case ports.HostTrustMismatch:
		return d.handleHostKeyMismatch(hop, pub)
	case ports.HostTrustUnknown:
		return d.handleUnknownHostKey(ctx, hop, pub)
	default:
		return fmt.Errorf("%w: 无效主机密钥核验状态 %s", ports.ErrHostKeyUnknown, chk.Status())
	}
}

// enforceHostCertTrustCheck 对 SSH 主机证书在全部模式（含 accept-new/ask/no）下严格失败关闭：
// 仅放行经 @cert-authority 完整验签且未吊销的 HostTrustTrusted 证书，严禁 TOFU 放行或落盘未验证证书。
func enforceHostCertTrustCheck(hop plan.HopSpec, pub ports.PublicKeyInfo, chk ports.HostTrustCheck) error {
	switch chk.Status() {
	case ports.HostTrustTrusted:
		return nil
	case ports.HostTrustRevoked:
		return fmt.Errorf("%w: %s (%s)", ports.ErrHostKeyRevoked, hop.Endpoint(), pub.Fingerprint())
	case ports.HostTrustMismatch:
		return fmt.Errorf("%w: %s 呈递主机证书未通过校验 (%s): %s", ports.ErrHostKeyMismatch, hop.Endpoint(), pub.Fingerprint(), chk.Reason())
	case ports.HostTrustUnknown:
		return fmt.Errorf("%w: %s 主机证书缺少可信 @cert-authority (%s)", ports.ErrHostKeyUnknown, hop.Endpoint(), pub.Fingerprint())
	default:
		return fmt.Errorf("%w: 无效主机证书核验状态 %s", ports.ErrHostKeyUnknown, chk.Status())
	}
}

// handleHostKeyMismatch 严格拦截主机密钥变更；仅在显式 StrictHostKeyChecking=no 且认证不含密码/质询凭据时放行，
// 防止凭据暴露给潜在中间人（遵循 OpenSSH 原生安全边界）。
func (d *Dialer) handleHostKeyMismatch(hop plan.HopSpec, pub ports.PublicKeyInfo) error {
	if hop.Transport().StrictHostKeyChecking() == option.StrictHostKeyCheckingNo && authAllowsInsecureMismatch(hop.Auth()) {
		return nil
	}
	return fmt.Errorf("%w: %s 呈递指纹 %s 与 known_hosts 冲突", ports.ErrHostKeyMismatch, hop.Endpoint(), pub.Fingerprint())
}

func (d *Dialer) handleUnknownHostKey(ctx context.Context, hop plan.HopSpec, pub ports.PublicKeyInfo) error {
	tp := hop.Transport()
	switch tp.StrictHostKeyChecking() {
	case option.StrictHostKeyCheckingAcceptNew:
		if err := d.hostTrust.RecordHostKey(ctx, hop.Endpoint(), pub, tp.UserKnownHostsFiles()); err != nil {
			return fmt.Errorf("记录新主机密钥失败: %w", err)
		}
		return nil
	case option.StrictHostKeyCheckingNo:
		_ = d.hostTrust.RecordHostKey(ctx, hop.Endpoint(), pub, tp.UserKnownHostsFiles())
		return nil
	case option.StrictHostKeyCheckingAsk:
		return d.confirmAndRecordUnknownHostKey(ctx, hop, pub)
	case option.StrictHostKeyCheckingYes, option.StrictHostKeyCheckingUnset:
		return fmt.Errorf("%w: %s (%s)", ports.ErrHostKeyUnknown, hop.Endpoint(), pub.Fingerprint())
	default:
		return fmt.Errorf("%w: %s (%s)", ports.ErrHostKeyUnknown, hop.Endpoint(), pub.Fingerprint())
	}
}

func (d *Dialer) confirmAndRecordUnknownHostKey(ctx context.Context, hop plan.HopSpec, pub ports.PublicKeyInfo) error {
	tp := hop.Transport()
	if tp.BatchMode() || d.interaction == nil || !d.interaction.CanInteract() {
		return fmt.Errorf("%w: %s (%s)", ports.ErrHostKeyUnknown, hop.Endpoint(), pub.Fingerprint())
	}
	msg := fmt.Sprintf("Trust unknown SSH host key %s (%s) for %s?", pub.Algorithm(), pub.Fingerprint(), hop.Endpoint())
	req, err := ports.NewConfirmRequest(ports.ConfirmRequestSpec{
		Title:   "SSH Host Key Verification",
		Message: msg,
		Subject: hop.Endpoint().String(),
		Risk:    security.RiskModerate,
	})
	if err != nil {
		return err
	}
	verdict, err := d.interaction.Confirm(ctx, req)
	if err != nil {
		return fmt.Errorf("%w: %w", ports.ErrHostKeyUnknown, err)
	}
	if !verdict.Allowed() {
		return fmt.Errorf("%w: 操作员拒绝信任 %s (%s)", ports.ErrHostKeyUnknown, hop.Endpoint(), pub.Fingerprint())
	}
	if err := d.hostTrust.RecordHostKey(ctx, hop.Endpoint(), pub, tp.UserKnownHostsFiles()); err != nil {
		return fmt.Errorf("记录已确认主机密钥失败: %w", err)
	}
	return nil
}

// authAllowsInsecureMismatch 仅对非密码/非质询的纯公钥或 Agent 认证放行 Mismatch 豁免，其余及未知变体一律失败关闭。
func authAllowsInsecureMismatch(m inventory.AuthMethod) bool {
	if m == nil || !m.IsValid() {
		return false
	}
	switch v := m.(type) {
	case *inventory.AuthPrivateKey, *inventory.AuthAgent:
		return true
	case *inventory.AuthPassword, *inventory.AuthKeyboardInteractive:
		return false
	case *inventory.AuthComposite:
		methods := v.Methods()
		return len(methods) > 0 && !slices.ContainsFunc(methods, func(sub inventory.AuthMethod) bool {
			return !authAllowsInsecureMismatch(sub)
		})
	default:
		return false
	}
}

// orderHostKeyAlgorithms 将信任库偏好算法（在 allowed 策略允许范围内）前置，其余允许算法按原策略顺序保留。
func orderHostKeyAlgorithms(allowed, preferred []string) []string {
	if len(preferred) == 0 {
		return slices.Clone(allowed)
	}
	out := make([]string, 0, len(allowed))
	for _, p := range preferred {
		for _, expanded := range expandPreferredHostKeyAlgo(p) {
			if slices.Contains(allowed, expanded) && !slices.Contains(out, expanded) {
				out = append(out, expanded)
			}
		}
	}
	for _, a := range allowed {
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

func expandPreferredHostKeyAlgo(algo string) []string {
	if algo == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{algo}
}
