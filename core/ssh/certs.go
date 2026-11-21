package ssh

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

	maxUserCertFileBytes int64 = 256 * 1024
	maxKeyFileBytes      int64 = 1024 * 1024
)

// readBoundedRegularFile reads a regular file bounded to maxBytes. It inspects
// the path with os.Stat before opening so non-regular files (FIFOs, devices,
// sockets, directories) are rejected without blocking, then re-checks f.Stat()
// on the opened descriptor and enforces maxBytes via io.LimitReader.
func readBoundedRegularFile(path string, maxBytes int64) ([]byte, error) {
	if path == "" {
		return nil, errors.New("file path is empty")
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("invalid maximum file size %d", maxBytes)
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing non-regular file %q (mode %s)", path, st.Mode().Type())
	}
	if st.Size() > maxBytes {
		return nil, fmt.Errorf("file %q exceeds maximum size %d bytes", path, maxBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fst, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fst.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing non-regular file %q (mode %s)", path, fst.Mode().Type())
	}
	if fst.Size() > maxBytes {
		return nil, fmt.Errorf("file %q exceeds maximum size %d bytes", path, maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file %q exceeds maximum size %d bytes", path, maxBytes)
	}
	return data, nil
}

type admittedMaterialPolicy struct {
	enforceCerts  bool
	certs         map[string]AdmittedCertificate
	conflictCerts map[string]struct{}
	enforceKeys   bool
	keys          map[string]AdmittedKeyDigest
	conflictKeys  map[string]struct{}
}

func canonicalAdmittedPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	return filepath.Clean(filepath.FromSlash(path))
}

func equalSHA256Hex(data []byte, wantHex string) bool {
	normWant := strings.ToLower(strings.TrimSpace(wantHex))
	if len(normWant) != sha256.Size*2 {
		return false
	}
	sum := sha256.Sum256(data)
	gotHex := hex.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(gotHex), []byte(normWant)) == 1
}

func newAdmittedMaterialPolicy(
	enforceCerts bool,
	admittedCerts []AdmittedCertificate,
	enforceKeys bool,
	admittedKeys []AdmittedKeyDigest,
) *admittedMaterialPolicy {
	if !enforceCerts && !enforceKeys {
		return nil
	}
	p := &admittedMaterialPolicy{
		enforceCerts: enforceCerts,
		enforceKeys:  enforceKeys,
	}
	if enforceCerts {
		p.certs = make(map[string]AdmittedCertificate, len(admittedCerts))
		for _, entry := range admittedCerts {
			key := canonicalAdmittedPath(entry.Path)
			if key == "" {
				continue
			}
			if prev, exists := p.certs[key]; exists {
				if !equalAdmittedCertificateMeta(prev, entry) {
					if p.conflictCerts == nil {
						p.conflictCerts = make(map[string]struct{})
					}
					p.conflictCerts[key] = struct{}{}
				}
				continue
			}
			cloned := entry
			cloned.RawBytes = slices.Clone(entry.RawBytes)
			p.certs[key] = cloned
		}
	}
	if enforceKeys {
		p.keys = make(map[string]AdmittedKeyDigest, len(admittedKeys))
		for _, entry := range admittedKeys {
			key := canonicalAdmittedPath(entry.Path)
			if key == "" {
				continue
			}
			if prev, exists := p.keys[key]; exists {
				if prev != entry {
					if p.conflictKeys == nil {
						p.conflictKeys = make(map[string]struct{})
					}
					p.conflictKeys[key] = struct{}{}
				}
				continue
			}
			p.keys[key] = entry
		}
	}
	return p
}

func newAdmittedMaterialPolicyFromConfig(cfg *ClientConfig) *admittedMaterialPolicy {
	if cfg == nil {
		return nil
	}
	return newAdmittedMaterialPolicy(
		cfg.EnforceAdmittedCertificates,
		cfg.AdmittedCertificates,
		cfg.EnforceAdmittedKeyDigests,
		cfg.AdmittedKeyDigests,
	)
}

func firstAdmittedPolicy(policies []*admittedMaterialPolicy) *admittedMaterialPolicy {
	if len(policies) > 0 {
		return policies[0]
	}
	return nil
}

func (p *admittedMaterialPolicy) lookupCert(certPath string) (AdmittedCertificate, bool) {
	if p == nil || !p.enforceCerts {
		return AdmittedCertificate{}, false
	}
	key := canonicalAdmittedPath(certPath)
	if key == "" {
		return AdmittedCertificate{}, false
	}
	if _, conflicted := p.conflictCerts[key]; conflicted {
		return AdmittedCertificate{}, false
	}
	entry, ok := p.certs[key]
	return entry, ok
}

func (p *admittedMaterialPolicy) readKeyFile(keyPath string, explicit bool) (data []byte, absentAllowed bool, err error) {
	if p == nil || !p.enforceKeys {
		data, err = readBoundedRegularFile(keyPath, maxKeyFileBytes)
		return data, false, err
	}
	key := canonicalAdmittedPath(keyPath)
	if key == "" {
		return nil, false, fmt.Errorf("%w: empty SSH key path is not admitted", ErrSnapshotMismatch)
	}
	if _, conflicted := p.conflictKeys[key]; conflicted {
		return nil, false, fmt.Errorf("%w: conflicting admitted key digest entries for %q", ErrSnapshotMismatch, keyPath)
	}
	entry, ok := p.keys[key]
	if !ok {
		if !explicit {
			if _, statErr := os.Stat(keyPath); errors.Is(statErr, os.ErrNotExist) {
				return nil, true, nil
			}
		}
		return nil, false, fmt.Errorf("%w: SSH key %q is not in admitted key digests", ErrSnapshotMismatch, keyPath)
	}
	if entry.Missing {
		_, statErr := os.Stat(keyPath)
		if errors.Is(statErr, os.ErrNotExist) {
			return nil, true, nil
		}
		if statErr == nil {
			return nil, false, fmt.Errorf("%w: SSH key %q appeared after connection plan admission", ErrSnapshotMismatch, keyPath)
		}
		return nil, false, fmt.Errorf("%w: stat admitted-missing SSH key %q failed: %w", ErrSnapshotMismatch, keyPath, statErr)
	}
	if entry.NonRegular {
		return nil, false, fmt.Errorf("%w: SSH key %q was non-regular at connection plan admission", ErrSnapshotMismatch, keyPath)
	}
	if len(strings.TrimSpace(entry.SHA256)) != sha256.Size*2 {
		return nil, false, fmt.Errorf("%w: SSH key %q has invalid admitted SHA-256 digest", ErrSnapshotMismatch, keyPath)
	}
	data, err = readBoundedRegularFile(keyPath, maxKeyFileBytes)
	if err != nil {
		return nil, false, fmt.Errorf("%w: read admitted SSH key %q failed: %w", ErrSnapshotMismatch, keyPath, err)
	}
	if !equalSHA256Hex(data, entry.SHA256) {
		return nil, false, fmt.Errorf("%w: SSH key %q SHA-256 digest changed after connection plan admission", ErrSnapshotMismatch, keyPath)
	}
	return data, false, nil
}

func (p *admittedMaterialPolicy) readOptionalAdmittedPubFile(pubPath string) ([]byte, bool) {
	if p == nil || !p.enforceKeys {
		data, err := readBoundedRegularFile(pubPath, maxKeyFileBytes)
		return data, err == nil
	}
	key := canonicalAdmittedPath(pubPath)
	if key == "" {
		return nil, false
	}
	if _, conflicted := p.conflictKeys[key]; conflicted {
		return nil, false
	}
	entry, ok := p.keys[key]
	if !ok || entry.Missing || entry.NonRegular {
		return nil, false
	}
	data, err := readBoundedRegularFile(pubPath, maxKeyFileBytes)
	if err != nil || !equalSHA256Hex(data, entry.SHA256) {
		return nil, false
	}
	return data, true
}

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

func parseUserCertData(certPath string, data []byte, l logger.DebugLogger) (*loadedUserCert, bool) {
	if l == nil {
		l = logger.NopLogger
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

func parseUserCertFile(certPath string, silentIfMissing bool, l logger.DebugLogger, policies ...*admittedMaterialPolicy) (*loadedUserCert, bool) {
	if l == nil {
		l = logger.NopLogger
	}
	if certPath == "" {
		return nil, false
	}
	policy := firstAdmittedPolicy(policies)
	if policy != nil && policy.enforceCerts {
		entry, ok := policy.lookupCert(certPath)
		if !ok {
			if !silentIfMissing {
				l.Debugf("Refusing un-admitted SSH certificate %q", certPath)
			}
			return nil, false
		}
		if entry.Missing || entry.NonRegular {
			if !silentIfMissing || entry.NonRegular {
				l.Debugf("Refusing SSH certificate %q admitted as missing=%v non_regular=%v", certPath, entry.Missing, entry.NonRegular)
			}
			return nil, false
		}
		if len(entry.RawBytes) > 0 {
			if int64(len(entry.RawBytes)) > maxUserCertFileBytes {
				l.Debugf("Refusing SSH certificate %q: admitted RawBytes exceed %d bytes", certPath, maxUserCertFileBytes)
				return nil, false
			}
			if !equalSHA256Hex(entry.RawBytes, entry.SHA256) {
				l.Debugf("Refusing SSH certificate %q: admitted RawBytes SHA-256 mismatch", certPath)
				return nil, false
			}
			return parseUserCertData(certPath, entry.RawBytes, l)
		}
		data, err := readBoundedRegularFile(certPath, maxUserCertFileBytes)
		if err != nil {
			l.Debugf("Failed to read admitted SSH certificate %q: %v", certPath, err)
			return nil, false
		}
		if !equalSHA256Hex(data, entry.SHA256) {
			l.Debugf("Refusing SSH certificate %q: file SHA-256 does not match admitted digest", certPath)
			return nil, false
		}
		return parseUserCertData(certPath, data, l)
	}

	data, err := readBoundedRegularFile(certPath, maxUserCertFileBytes)
	if err != nil {
		if !silentIfMissing || !errors.Is(err, os.ErrNotExist) {
			l.Debugf("Failed to read SSH certificate %q: %v", certPath, err)
		}
		return nil, false
	}
	return parseUserCertData(certPath, data, l)
}

func collectExplicitUserCerts(
	sshOpts *Options,
	env Environment,
	target TargetContext,
	resolve func(string) string,
	l logger.DebugLogger,
	policies ...*admittedMaterialPolicy,
) ([]loadedUserCert, bool) {
	if l == nil {
		l = logger.NopLogger
	}
	rawCerts := sshOpts.CertificateFiles()
	if len(rawCerts) == 0 {
		return nil, false
	}
	policy := firstAdmittedPolicy(policies)

	var loaded []loadedUserCert
	seenPaths := make(map[string]struct{}, len(rawCerts))
	hasExplicit := false
	for _, raw := range rawCerts {
		if hasControlOrLineSepChar(raw) {
			l.Debugf("Failed to expand CertificateFile %q: contains invalid control character", raw)
			continue
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		hasExplicit = true
		if IsNoneValue(trimmed) {
			break
		}
		expanded, err := expandIdentityKeyPath(raw, env, target, resolve)
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
		if cert, ok := parseUserCertFile(expanded, false, l, policy); ok {
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
	policies ...*admittedMaterialPolicy,
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
	policy := firstAdmittedPolicy(policies)
	if sidecar, ok := parseUserCertFile(sidecarCertPath(keyPath), true, l, policy); ok {
		if sidecar.keyRaw == pubRaw {
			return []loadedUserCert{*sidecar}
		}
		l.Debugf("Skipping SSH certificate %q: certificate public key does not match private key %q", sidecar.path, keyPath)
	}
	return nil
}
