package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	logger "github.com/wentf9/xops-cli/core/log"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// normalizeCertSignAlgorithm maps OpenSSH certificate signature algorithm names
// (such as "rsa-sha2-256-cert-v01@openssh.com") to the underlying private-key
// signature algorithm expected by cryptoSSH.AlgorithmSigner implementations.
func normalizeCertSignAlgorithm(algorithm string) string {
	switch algorithm {
	case cryptoSSH.CertAlgoRSAv01:
		return cryptoSSH.KeyAlgoRSA
	case cryptoSSH.CertAlgoRSASHA256v01:
		return cryptoSSH.KeyAlgoRSASHA256
	case cryptoSSH.CertAlgoRSASHA512v01:
		return cryptoSSH.KeyAlgoRSASHA512
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
// *-cert-v01@openssh.com algorithm names to SignWithAlgorithm are normalized to
// the underlying key signature algorithm (e.g. rsa-sha2-256 / rsa-sha2-512).
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
	multi cryptoSSH.MultiAlgorithmSigner
}

var _ cryptoSSH.MultiAlgorithmSigner = (*normalizedMultiAlgoCertSigner)(nil)

func (s *normalizedMultiAlgoCertSigner) Algorithms() []string {
	return s.multi.Algorithms()
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
	cs, err := cryptoSSH.NewCertSigner(cert, base)
	if err != nil {
		return nil, err
	}
	wrapped := normalizedCertSigner{cert: cert, certSigner: cs}
	if mas, ok := cs.(cryptoSSH.MultiAlgorithmSigner); ok {
		return &normalizedMultiAlgoCertSigner{normalizedCertSigner: wrapped, multi: mas}, nil
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
	if sidecar, ok := parseUserCertFile(keyPath+"-cert.pub", true, l); ok {
		if sidecar.keyRaw == pubRaw {
			return []loadedUserCert{*sidecar}
		}
		l.Debugf("Skipping SSH certificate %q: certificate public key does not match private key %q", sidecar.path, keyPath)
	}
	return nil
}
