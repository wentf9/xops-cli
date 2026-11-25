package hostkey

import (
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/ports"
)

// isHostCertificateAlgorithm 判断主机密钥算法是否属于 OpenSSH 主机证书族（*-cert-v01@openssh.com）。
func isHostCertificateAlgorithm(algo string) bool {
	return strings.HasSuffix(algo, "-cert-v01@openssh.com")
}

// hostCertPreferredAlgorithms 返回匹配 @cert-authority 时优先向服务端协商的主机证书算法顺序。
func hostCertPreferredAlgorithms() []string {
	return []string{
		ssh.CertAlgoED25519v01,
		ssh.CertAlgoECDSA256v01,
		ssh.CertAlgoECDSA384v01,
		ssh.CertAlgoECDSA521v01,
		ssh.CertAlgoRSASHA512v01,
		ssh.CertAlgoRSASHA256v01,
		ssh.CertAlgoRSAv01,
	}
}

// evaluateHostCertTrust 严格执行 OpenSSH 主机证书核验（防 @revoked 绕过与未验签证书 TOFU 投毒）：
//  1. 强解析 wire blob 为 *ssh.Certificate（失败即失败关闭）；
//  2. 对匹配端点的 @revoked 条目同时比对证书本体、底层主机公钥 cert.Key 与签发 CA 公钥 cert.SignatureKey；
//  3. 强制校验 cert.CertType == ssh.HostCert、空 CriticalOptions、匹配 @cert-authority CA 信任链、
//     有效期（绑定 Clock）与 Principal（支持 OpenSSH 空 ValidPrincipals 由 known_hosts CA 主机模式授权）。
func evaluateHostCertTrust(
	ep netaddr.Endpoint,
	presented ports.PublicKeyInfo,
	entries []parsedEntry,
	nowFn func() time.Time,
) ports.HostTrustCheckSpec {
	spec := ports.HostTrustCheckSpec{
		Endpoint:  ep,
		Presented: presented,
		Status:    ports.HostTrustUnknown,
		Reason:    "untrusted SSH host certificate",
	}
	cert, err := parseHostCertificate(presented.WireBlob())
	if err != nil {
		spec.Status = ports.HostTrustMismatch
		spec.Reason = "invalid SSH host certificate"
		return spec
	}
	caBlobs, revoked := collectCertAuthoritiesAndCheckRevoked(ep, presented.WireBlob(), cert, entries, &spec)
	if revoked {
		spec.Status = ports.HostTrustRevoked
		spec.Reason = "host certificate, host key, or CA key is explicitly marked @revoked"
		return spec
	}
	if cert.CertType != ssh.HostCert {
		spec.Status = ports.HostTrustMismatch
		spec.Reason = "SSH certificate is not a host certificate"
		return spec
	}
	if len(cert.CriticalOptions) > 0 {
		spec.Status = ports.HostTrustMismatch
		spec.Reason = "SSH host certificate contains unsupported critical options"
		return spec
	}
	if len(caBlobs) == 0 {
		spec.Status = ports.HostTrustUnknown
		spec.Reason = "no matching @cert-authority for SSH host certificate"
		return spec
	}
	return verifyHostCertAgainstAuthorities(ep, cert, caBlobs, nowFn, spec)
}

func parseHostCertificate(wireBlob []byte) (*ssh.Certificate, error) {
	pub, err := ssh.ParsePublicKey(wireBlob)
	if err != nil {
		return nil, err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok || cert == nil || cert.Key == nil || cert.SignatureKey == nil {
		return nil, ports.ErrInvalidArgument
	}
	return cert, nil
}

func collectCertAuthoritiesAndCheckRevoked(
	ep netaddr.Endpoint,
	certWire []byte,
	cert *ssh.Certificate,
	entries []parsedEntry,
	spec *ports.HostTrustCheckSpec,
) ([][]byte, bool) {
	hostKeyWire := cert.Key.Marshal()
	caKeyWire := cert.SignatureKey.Marshal()
	var caBlobs [][]byte
	for _, e := range entries {
		if !e.matchesEndpoint(ep) {
			continue
		}
		switch e.marker {
		case markerRevoked:
			if keyBlobEqual(e.wireBlob, certWire) || keyBlobEqual(e.wireBlob, hostKeyWire) || keyBlobEqual(e.wireBlob, caKeyWire) {
				return nil, true
			}
		case markerCertAuthority:
			caBlobs = append(caBlobs, e.wireBlob)
		case markerRegular:
			if !slices.ContainsFunc(spec.ExpectedFingerprints, e.fingerprint.Equal) {
				spec.ExpectedFingerprints = append(spec.ExpectedFingerprints, e.fingerprint)
			}
		}
	}
	return caBlobs, false
}

func verifyHostCertAgainstAuthorities(
	ep netaddr.Endpoint,
	cert *ssh.Certificate,
	caBlobs [][]byte,
	nowFn func() time.Time,
	spec ports.HostTrustCheckSpec,
) ports.HostTrustCheckSpec {
	sigKeyWire := cert.SignatureKey.Marshal()
	if !slices.ContainsFunc(caBlobs, func(b []byte) bool { return keyBlobEqual(b, sigKeyWire) }) {
		spec.Status = ports.HostTrustMismatch
		spec.Reason = "host certificate CA is not trusted by matching @cert-authority"
		return spec
	}
	checker := &ssh.CertChecker{Clock: nowFn}
	if err := checker.CheckCert(ep.Host().String(), cert); err != nil {
		spec.Status = ports.HostTrustMismatch
		spec.Reason = "host certificate verification failed: " + err.Error()
		return spec
	}
	spec.Status = ports.HostTrustTrusted
	spec.Reason = ""
	return spec
}
