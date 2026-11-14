package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	logger "github.com/wentf9/xops-cli/core/log"
	cryptoSSH "golang.org/x/crypto/ssh"
)

const (
	openSSHCertAlgoSuffix = "-cert-v01@openssh.com"
	goCertAlgoSuffix      = "-cert-v01@golang.org"
	dsaCertAlgoV01        = "ssh-dss-cert-v01@openssh.com"
	dsaKeyAlgo            = "ssh-dss"
)

// isCertAlgorithm reports whether alg is an SSH certificate public-key or
// signature algorithm name (covering OpenSSH *-cert-v01@openssh.com and Go
// ML-DSA *-cert-v01@golang.org certificate algorithms).
func isCertAlgorithm(alg string) bool {
	switch alg {
	case cryptoSSH.CertAlgoRSAv01,
		cryptoSSH.CertAlgoRSASHA256v01,
		cryptoSSH.CertAlgoRSASHA512v01,
		dsaCertAlgoV01,
		cryptoSSH.CertAlgoECDSA256v01,
		cryptoSSH.CertAlgoECDSA384v01,
		cryptoSSH.CertAlgoECDSA521v01,
		cryptoSSH.CertAlgoSKECDSA256v01,
		cryptoSSH.CertAlgoED25519v01,
		cryptoSSH.CertAlgoSKED25519v01,
		cryptoSSH.CertAlgoMLDSA44v01Go,
		cryptoSSH.CertAlgoMLDSA65v01Go,
		cryptoSSH.CertAlgoMLDSA87v01Go:
		return true
	default:
		return (len(alg) > len(openSSHCertAlgoSuffix) && strings.HasSuffix(alg, openSSHCertAlgoSuffix)) ||
			(len(alg) > len(goCertAlgoSuffix) && strings.HasSuffix(alg, goCertAlgoSuffix))
	}
}

// normalizeCertSignAlgorithm maps SSH certificate signature algorithm names
// (such as "rsa-sha2-256-cert-v01@openssh.com" or "ssh-mldsa-65-cert-v01@golang.org")
// to the underlying private-key signature algorithm expected by
// cryptoSSH.AlgorithmSigner implementations.
func normalizeCertSignAlgorithm(algorithm string) string {
	switch algorithm {
	case cryptoSSH.CertAlgoRSAv01:
		return cryptoSSH.KeyAlgoRSA
	case cryptoSSH.CertAlgoRSASHA256v01:
		return cryptoSSH.KeyAlgoRSASHA256
	case cryptoSSH.CertAlgoRSASHA512v01:
		return cryptoSSH.KeyAlgoRSASHA512
	case dsaCertAlgoV01:
		return dsaKeyAlgo
	case cryptoSSH.CertAlgoECDSA256v01:
		return cryptoSSH.KeyAlgoECDSA256
	case cryptoSSH.CertAlgoECDSA384v01:
		return cryptoSSH.KeyAlgoECDSA384
	case cryptoSSH.CertAlgoECDSA521v01:
		return cryptoSSH.KeyAlgoECDSA521
	case cryptoSSH.CertAlgoSKECDSA256v01:
		return cryptoSSH.KeyAlgoSKECDSA256
	case cryptoSSH.CertAlgoED25519v01:
		return cryptoSSH.KeyAlgoED25519
	case cryptoSSH.CertAlgoSKED25519v01:
		return cryptoSSH.KeyAlgoSKED25519
	case cryptoSSH.CertAlgoMLDSA44v01Go:
		return cryptoSSH.KeyAlgoMLDSA44
	case cryptoSSH.CertAlgoMLDSA65v01Go:
		return cryptoSSH.KeyAlgoMLDSA65
	case cryptoSSH.CertAlgoMLDSA87v01Go:
		return cryptoSSH.KeyAlgoMLDSA87
	default:
		return algorithm
	}
}

// certLazySigner implements cryptoSSH.AlgorithmSigner over an OpenSSH user certificate
// backed by a passphrase-protected lazySigner. PublicKey() returns the certificate
// immediately without unlocking the private key; decryption occurs only when the
// remote SSH server accepts the certificate and challenges Sign/SignWithAlgorithm.
type certLazySigner struct {
	cert *cryptoSSH.Certificate
	base *lazySigner
}

var _ cryptoSSH.AlgorithmSigner = (*certLazySigner)(nil)

func (s *certLazySigner) PublicKey() cryptoSSH.PublicKey {
	return s.cert
}

func (s *certLazySigner) Sign(rand io.Reader, data []byte) (*cryptoSSH.Signature, error) {
	return s.SignWithAlgorithm(rand, data, "")
}

func (s *certLazySigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*cryptoSSH.Signature, error) {
	unlocked, err := s.base.getDecryptedSigner()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(s.cert.Key.Marshal(), unlocked.PublicKey().Marshal()) {
		return nil, errors.New("ssh: certificate public key does not match unlocked private key")
	}
	certSigner, err := cryptoSSH.NewCertSigner(s.cert, unlocked)
	if err != nil {
		return nil, err
	}
	return signCertWithNormalizedAlgorithm(s.cert, certSigner, rand, data, algorithm)
}

func signCertWithNormalizedAlgorithm(
	cert *cryptoSSH.Certificate,
	certSigner cryptoSSH.Signer,
	rand io.Reader,
	data []byte,
	algorithm string,
) (*cryptoSSH.Signature, error) {
	normAlgo := normalizeCertSignAlgorithm(algorithm)
	if normAlgo == "" {
		return certSigner.Sign(rand, data)
	}
	if algoSigner, ok := certSigner.(cryptoSSH.AlgorithmSigner); ok {
		return algoSigner.SignWithAlgorithm(rand, data, normAlgo)
	}
	var keyFormat string
	if cert != nil && cert.Key != nil {
		keyFormat = cert.Key.Type()
	}
	if normAlgo != keyFormat {
		return nil, fmt.Errorf("ssh: certificate signer does not support signature algorithm %q (key type %q)", normAlgo, keyFormat)
	}
	return certSigner.Sign(rand, data)
}

// normalizedCertSigner wraps cryptoSSH.NewCertSigner so direct callers passing
// SSH certificate algorithm names (*-cert-v01@openssh.com or *-cert-v01@golang.org)
// to SignWithAlgorithm are normalized to the underlying key signature algorithm
// (e.g. rsa-sha2-256, rsa-sha2-512, or ssh-mldsa-65).
type normalizedCertSigner struct {
	cert       *cryptoSSH.Certificate
	certSigner cryptoSSH.Signer
}

var _ cryptoSSH.AlgorithmSigner = (*normalizedCertSigner)(nil)

// normalizedMultiAlgoCertSigner preserves MultiAlgorithmSigner restrictions
// (such as RSA signers constrained to rsa-sha2-512) so x/crypto/ssh negotiates
// only algorithms supported by the underlying signer.
type normalizedMultiAlgoCertSigner struct {
	normalizedCertSigner
	algos []string
}

var _ cryptoSSH.MultiAlgorithmSigner = (*normalizedMultiAlgoCertSigner)(nil)

func (s *normalizedMultiAlgoCertSigner) Algorithms() []string {
	return slices.Clone(s.algos)
}

type plainKeyOverrideSigner struct {
	inner cryptoSSH.Signer
	pub   cryptoSSH.PublicKey
}

func (s *plainKeyOverrideSigner) PublicKey() cryptoSSH.PublicKey {
	return s.pub
}

func (s *plainKeyOverrideSigner) Sign(rand io.Reader, data []byte) (*cryptoSSH.Signature, error) {
	return s.inner.Sign(rand, data)
}

type plainKeyOverrideAlgoSigner struct {
	plainKeyOverrideSigner
	algo cryptoSSH.AlgorithmSigner
}

func (s *plainKeyOverrideAlgoSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*cryptoSSH.Signature, error) {
	return s.algo.SignWithAlgorithm(rand, data, algorithm)
}

type plainKeyOverrideMultiAlgoSigner struct {
	plainKeyOverrideAlgoSigner
	multi cryptoSSH.MultiAlgorithmSigner
}

func (s *plainKeyOverrideMultiAlgoSigner) Algorithms() []string {
	return s.multi.Algorithms()
}

func adaptPlainKeySigner(base cryptoSSH.Signer, wantPub cryptoSSH.PublicKey) cryptoSSH.Signer {
	if base == nil || wantPub == nil || bytes.Equal(base.PublicKey().Marshal(), wantPub.Marshal()) {
		return base
	}
	baseWrap := plainKeyOverrideSigner{inner: base, pub: wantPub}
	if mas, ok := base.(cryptoSSH.MultiAlgorithmSigner); ok {
		return &plainKeyOverrideMultiAlgoSigner{
			plainKeyOverrideAlgoSigner: plainKeyOverrideAlgoSigner{plainKeyOverrideSigner: baseWrap, algo: mas},
			multi:                      mas,
		}
	}
	if as, ok := base.(cryptoSSH.AlgorithmSigner); ok {
		return &plainKeyOverrideAlgoSigner{plainKeyOverrideSigner: baseWrap, algo: as}
	}
	return &baseWrap
}

func extractCertFromPublicKey(pub cryptoSSH.PublicKey) (*cryptoSSH.Certificate, bool) {
	if pub == nil {
		return nil, false
	}
	if cert, ok := pub.(*cryptoSSH.Certificate); ok && cert.Key != nil {
		return cert, true
	}
	if !isCertAlgorithm(pub.Type()) {
		return nil, false
	}
	parsed, err := cryptoSSH.ParsePublicKey(pub.Marshal())
	if err != nil {
		return nil, false
	}
	cert, ok := parsed.(*cryptoSSH.Certificate)
	return cert, ok && cert.Key != nil
}

func sidecarCertPath(keyPath string) string {
	if keyPath == "" {
		return ""
	}
	return strings.TrimSuffix(keyPath, ".pub") + "-cert.pub"
}

func newWrappedCertSigner(cert *cryptoSSH.Certificate, base cryptoSSH.Signer) (cryptoSSH.Signer, error) {
	if cert == nil {
		return nil, errors.New("ssh: certificate is nil")
	}
	if lazy, ok := base.(*lazySigner); ok {
		if lazy.pubKey != nil && !bytes.Equal(cert.Key.Marshal(), lazy.pubKey.Marshal()) {
			return nil, errors.New("ssh: signer and cert have different public key")
		}
		return &certLazySigner{cert: cert, base: lazy}, nil
	}
	if base != nil && cert.Key != nil {
		if baseCert, ok := extractCertFromPublicKey(base.PublicKey()); ok && bytes.Equal(baseCert.Key.Marshal(), cert.Key.Marshal()) {
			base = adaptPlainKeySigner(base, cert.Key)
		}
	}
	cs, err := cryptoSSH.NewCertSigner(cert, base)
	if err != nil {
		return nil, err
	}
	wrapped := normalizedCertSigner{cert: cert, certSigner: cs}
	if mas, ok := cs.(cryptoSSH.MultiAlgorithmSigner); ok {
		return &normalizedMultiAlgoCertSigner{normalizedCertSigner: wrapped, algos: mas.Algorithms()}, nil
	}
	if _, ok := cs.(cryptoSSH.AlgorithmSigner); !ok && cert.Key != nil {
		return &normalizedMultiAlgoCertSigner{
			normalizedCertSigner: wrapped,
			algos:                []string{cert.Key.Type()},
		}, nil
	}
	return &wrapped, nil
}

func (s *normalizedCertSigner) PublicKey() cryptoSSH.PublicKey {
	return s.cert
}

func (s *normalizedCertSigner) Sign(rand io.Reader, data []byte) (*cryptoSSH.Signature, error) {
	return s.certSigner.Sign(rand, data)
}

func (s *normalizedCertSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*cryptoSSH.Signature, error) {
	return signCertWithNormalizedAlgorithm(s.cert, s.certSigner, rand, data, algorithm)
}

type loadedUserCert struct {
	path   string
	cert   *cryptoSSH.Certificate
	keyRaw string
}

func parseUserCertFile(certPath string, silentIfMissing bool, l logger.DebugLogger) (*loadedUserCert, bool) {
	if l == nil {
		l = logger.NopLogger
	}
	if certPath == "" {
		return nil, false
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		if !silentIfMissing || !errors.Is(err, os.ErrNotExist) {
			l.Debugf("Failed to read SSH certificate %q: %v", certPath, err)
		}
		return nil, false
	}
	pubKey, _, _, _, err := cryptoSSH.ParseAuthorizedKey(data)
	if err != nil {
		l.Debugf("Failed to parse SSH certificate %q: %v", certPath, err)
		return nil, false
	}
	cert, ok := pubKey.(*cryptoSSH.Certificate)
	if !ok || cert.Key == nil {
		l.Debugf("SSH certificate file %q does not contain a valid certificate (got %T)", certPath, pubKey)
		return nil, false
	}
	if cert.CertType != cryptoSSH.UserCert {
		l.Debugf("Skipping SSH certificate %q: CertType=%d is not UserCert (%d)", certPath, cert.CertType, cryptoSSH.UserCert)
		return nil, false
	}
	return &loadedUserCert{
		path:   certPath,
		cert:   cert,
		keyRaw: string(cert.Key.Marshal()),
	}, true
}

func collectExplicitUserCerts(
	sshOpts *Options,
	env Environment,
	target TargetContext,
	resolve func(string) string,
	l logger.DebugLogger,
) ([]loadedUserCert, bool) {
	if l == nil {
		l = logger.NopLogger
	}
	rawCerts := sshOpts.CertificateFiles()
	if len(rawCerts) == 0 {
		return nil, false
	}

	var loaded []loadedUserCert
	seenPaths := make(map[string]struct{}, len(rawCerts))
	hasExplicit := false
	for _, raw := range rawCerts {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		hasExplicit = true
		if strings.EqualFold(trimmed, "none") {
			continue
		}
		expanded, err := expandIdentityKeyPath(trimmed, env, target, resolve)
		if err != nil {
			l.Debugf("Failed to expand CertificateFile %q: %v", raw, err)
			continue
		}
		if expanded == "" {
			continue
		}
		if _, dup := seenPaths[expanded]; dup {
			continue
		}
		seenPaths[expanded] = struct{}{}
		if cert, ok := parseUserCertFile(expanded, false, l); ok {
			loaded = append(loaded, *cert)
		}
	}
	return loaded, hasExplicit
}

func matchCertsForKey(
	keyPath string,
	pubKey cryptoSSH.PublicKey,
	explicitCerts []loadedUserCert,
	hasExplicitCerts bool,
	l logger.DebugLogger,
) []loadedUserCert {
	if pubKey == nil {
		return nil
	}
	pubRaw := string(pubKey.Marshal())
	if hasExplicitCerts {
		var matched []loadedUserCert
		for _, c := range explicitCerts {
			if c.keyRaw == pubRaw {
				matched = append(matched, c)
			}
		}
		return matched
	}
	if keyPath == "" {
		return nil
	}
	if sidecar, ok := parseUserCertFile(sidecarCertPath(keyPath), true, l); ok {
		if sidecar.keyRaw == pubRaw {
			return []loadedUserCert{*sidecar}
		}
		l.Debugf("Skipping SSH certificate %q: certificate public key does not match private key %q", sidecar.path, keyPath)
	}
	return nil
}
