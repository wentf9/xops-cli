package ssh

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	logger "github.com/wentf9/xops-cli/core/log"
	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func (c *Connector) getHostKeyOptionsWithState(
	ctx context.Context,
	coordinator *handshakeCoordinator,
	cfg *ClientConfig,
	hostKeyChanged *atomic.Bool,
	initialHandshakeDone *atomic.Bool,
) (cryptoSSH.HostKeyCallback, []string, error) {
	callback, err := c.getHostKeyCallbackWithState(ctx, coordinator, cfg, hostKeyChanged, initialHandshakeDone)
	if err != nil {
		return nil, nil, fmt.Errorf("get host key callback failed: %w", err)
	}
	algorithms, err := c.getHostKeyAlgorithms(ctx, coordinator, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("select host key algorithms failed: %w", err)
	}
	return callback, algorithms, nil
}

func (c *Connector) getHostKeyAlgorithms(ctx context.Context, coordinator *handshakeCoordinator, cfg *ClientConfig) ([]string, error) {
	var optionAlgos []string
	if cfg != nil && cfg.Options != nil && cfg.Options.HostKeyAlgorithms() != "" {
		algos, err := ResolveAlgorithmList(cfg.Options.HostKeyAlgorithms(), cryptoSSH.SupportedAlgorithms().HostKeys)
		if err != nil {
			return nil, fmt.Errorf("resolve HostKeyAlgorithms option: %w", err)
		}
		optionAlgos = algos
	}
	if c.hostKeyVerifier == nil {
		if len(optionAlgos) > 0 {
			return optionAlgos, nil
		}
		return c.defaultKnownHostsHostKeyAlgorithms(cfg), nil
	}
	source, ok := c.hostKeyVerifier.(HostKeyAlgorithmSource)
	if !ok {
		return optionAlgos, nil
	} // Existing verifiers retain the SSH library defaults (or optionAlgos when specified).
	if coordinator != nil {
		ctx = coordinator.Context()
	}
	selection, cancel := context.WithTimeout(ctx, c.getNodeHandshakeTimeout(cfg))
	defer cancel()
	if err := selection.Err(); err != nil {
		return nil, err
	}
	request := HostKeyRequest{NodeID: cfg.NodeID, Host: cfg.Address, Port: cfg.Port, User: cfg.User, VersionToken: cfg.TrustVersion}
	algorithms, err := source.HostKeyAlgorithms(selection, request)
	if err != nil {
		return nil, fmt.Errorf("resolve host key algorithms: %w", err)
	}
	if err := selection.Err(); err != nil {
		return nil, err
	}
	if len(algorithms) == 0 {
		return nil, errors.New("host key algorithm source returned no algorithms")
	}
	for _, algorithm := range algorithms {
		if !slices.Contains(cryptoSSH.SupportedAlgorithms().HostKeys, algorithm) {
			return nil, fmt.Errorf("host key algorithm source returned unsupported algorithm %q", algorithm)
		}
	}
	if len(optionAlgos) > 0 {
		var intersected []string
		for _, alg := range optionAlgos {
			if slices.Contains(algorithms, alg) {
				intersected = append(intersected, alg)
			}
		}
		if len(intersected) == 0 {
			return nil, errors.New("no host key algorithms in common between HostKeyAlgorithms option and pinned host key verifier")
		}
		return intersected, nil
	}
	return slices.Clone(algorithms), nil
}

// defaultKnownHostsHostKeyAlgorithms mirrors OpenSSH order_hostkeyalgs when no
// custom HostKeyVerifier or explicit HostKeyAlgorithms option is configured:
// unless a non-revoked @cert-authority in known_hosts matches the target host,
// plain host key algorithms (prioritizing any pinned key types for the host)
// are ordered ahead of *-cert-v01@openssh.com so servers configured with both a
// pinned plain HostKey and an untrusted HostCertificate negotiate the plain key.
func (c *Connector) defaultKnownHostsHostKeyAlgorithms(cfg *ClientConfig) []string {
	if cfg == nil || strings.TrimSpace(cfg.Address) == "" {
		return nil
	}
	db := c.loadReadOnlyKnownHostsDB(cfg)
	port := cfg.Port
	if port <= 0 {
		port = 22
	}
	targetAddr := khAddr{
		host: normalizeHostAddress(cfg.Address),
		port: strconv.Itoa(port),
	}
	hasCertAuthority, pinnedPlainTypes := db.matchingHostKeyTypes(targetAddr)
	if hasCertAuthority {
		return nil
	}

	supported := cryptoSSH.SupportedAlgorithms().HostKeys
	ordered := make([]string, 0, len(supported))
	appendUnique := func(alg string) {
		if slices.Contains(supported, alg) && !slices.Contains(ordered, alg) {
			ordered = append(ordered, alg)
		}
	}
	for _, kt := range pinnedPlainTypes {
		for _, sigAlg := range hostKeySigAlgsForKeyType(kt) {
			appendUnique(sigAlg)
		}
	}
	for _, alg := range supported {
		if !strings.HasSuffix(alg, "-cert-v01@openssh.com") {
			appendUnique(alg)
		}
	}
	for _, alg := range supported {
		if strings.HasSuffix(alg, "-cert-v01@openssh.com") {
			appendUnique(alg)
		}
	}
	return ordered
}

func hostKeySigAlgsForKeyType(keyType string) []string {
	if keyType == cryptoSSH.KeyAlgoRSA {
		return []string{cryptoSSH.KeyAlgoRSASHA512, cryptoSSH.KeyAlgoRSASHA256, cryptoSSH.KeyAlgoRSA}
	}
	return []string{keyType}
}

func (c *Connector) loadReadOnlyKnownHostsDB(cfg *ClientConfig) *knownHostsDB {
	db := newKnownHostsDB()
	target := knownHostsTarget(cfg)
	_, userKH, _ := extractHostKeyPolicy(cfg)

	var userFiles []string
	switch {
	case strings.EqualFold(userKH, "none") || userKH == "/dev/null":
	case userKH != "":
		for _, tokenPath := range strings.Fields(userKH) {
			if strings.EqualFold(tokenPath, "none") || tokenPath == "/dev/null" {
				continue
			}
			expanded, err := expandKnownHostsPath(tokenPath, c.environment, target)
			if err != nil || expanded == "" || strings.EqualFold(expanded, "none") || expanded == "/dev/null" {
				continue
			}
			if isReadableRegularFile(expanded) && !slices.Contains(userFiles, expanded) {
				userFiles = append(userFiles, expanded)
			}
		}
	default:
		if p := strings.TrimSpace(c.environment.KnownHostsFile); p != "" && isReadableRegularFile(p) {
			userFiles = append(userFiles, p)
		}
	}

	globalFiles, _, err := c.resolveGlobalKnownHostsFiles(cfg, target, userFiles)
	if err != nil {
		globalFiles = nil
	}
	for _, f := range userFiles {
		db.parseFileLenient(f, logger.NopLogger)
	}
	for _, f := range globalFiles {
		db.parseFileLenient(f, logger.NopLogger)
	}
	return db
}

const (
	khMarkerCert      = "@cert-authority"
	khMarkerRevoked   = "@revoked"
	khSHA1HashVersion = "1"
)

type khAddr struct {
	host string
	port string
}

func (a khAddr) String() string {
	h := a.host
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return h + ":" + a.port
}

type khMatcher interface {
	match(khAddr) bool
}

type khHostPattern struct {
	negate bool
	addr   khAddr
}

func (p khHostPattern) match(a khAddr) bool {
	return khWildcardMatch([]byte(p.addr.host), []byte(a.host)) && p.addr.port == a.port
}

type khHostPatterns []khHostPattern

func (ps khHostPatterns) match(a khAddr) bool {
	matched := false
	for _, p := range ps {
		if !p.match(a) {
			continue
		}
		if p.negate {
			return false
		}
		matched = true
	}
	return matched
}

func khWildcardMatch(pat, str []byte) bool {
	for {
		if len(pat) == 0 {
			return len(str) == 0
		}
		if len(str) == 0 {
			return false
		}
		if pat[0] == '*' {
			if len(pat) == 1 {
				return true
			}
			for j := range str {
				if khWildcardMatch(pat[1:], str[j:]) {
					return true
				}
			}
			return false
		}
		if pat[0] == '?' || pat[0] == str[0] {
			pat = pat[1:]
			str = str[1:]
		} else {
			return false
		}
	}
}

type khHashedHost struct {
	salt []byte
	hash []byte
}

func newKHHashedHost(encoded string) (*khHashedHost, error) {
	if len(encoded) == 0 || encoded[0] != '|' {
		return nil, errors.New("knownhosts: hashed host must start with '|'")
	}
	components := strings.Split(encoded, "|")
	if len(components) != 4 {
		return nil, fmt.Errorf("knownhosts: got %d components, want 3", len(components))
	}
	if components[1] != khSHA1HashVersion {
		return nil, fmt.Errorf("knownhosts: got hash type %s, must be '1'", components[1])
	}
	salt, err := base64.StdEncoding.DecodeString(components[2])
	if err != nil {
		return nil, err
	}
	hash, err := base64.StdEncoding.DecodeString(components[3])
	if err != nil {
		return nil, err
	}
	return &khHashedHost{salt: salt, hash: hash}, nil
}

func (h *khHashedHost) match(a khAddr) bool {
	mac := hmac.New(sha1.New, h.salt)
	_, _ = mac.Write([]byte(knownhosts.Normalize(a.String())))
	return hmac.Equal(mac.Sum(nil), h.hash)
}

type khDBLine struct {
	cert     bool
	matcher  khMatcher
	knownKey knownhosts.KnownKey
}

type knownHostsDB struct {
	revoked map[string]*knownhosts.KnownKey
	lines   []khDBLine
}

func newKnownHostsDB() *knownHostsDB {
	return &knownHostsDB{
		revoked: make(map[string]*knownhosts.KnownKey),
	}
}

func khPlainKeyBlob(key cryptoSSH.PublicKey) string {
	if cert, ok := key.(*cryptoSSH.Certificate); ok && cert.Key != nil {
		return string(cert.Key.Marshal())
	}
	return string(key.Marshal())
}

func (db *knownHostsDB) matchingHostKeyTypes(a khAddr) (hasCertAuthority bool, pinnedPlainTypes []string) {
	for _, l := range db.lines {
		if l.knownKey.Key == nil {
			continue
		}
		if _, revoked := db.revoked[khPlainKeyBlob(l.knownKey.Key)]; revoked {
			continue
		}
		if !l.matcher.match(a) {
			continue
		}
		if l.cert {
			hasCertAuthority = true
			continue
		}
		kt := l.knownKey.Key.Type()
		if !slices.Contains(pinnedPlainTypes, kt) {
			pinnedPlainTypes = append(pinnedPlainTypes, kt)
		}
	}
	return hasCertAuthority, pinnedPlainTypes
}

func (db *knownHostsDB) isHostAuthority(remote cryptoSSH.PublicKey, address string) bool {
	h, p, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	a := khAddr{host: h, port: p}
	for _, l := range db.lines {
		if l.cert && bytes.Equal(l.knownKey.Key.Marshal(), remote.Marshal()) && l.matcher.match(a) {
			return true
		}
	}
	return false
}

func (db *knownHostsDB) isRevoked(cert *cryptoSSH.Certificate) bool {
	if cert == nil {
		return false
	}
	if cert.Key != nil {
		if _, ok := db.revoked[khPlainKeyBlob(cert)]; ok {
			return true
		}
	}
	if cert.SignatureKey != nil {
		if _, ok := db.revoked[khPlainKeyBlob(cert.SignatureKey)]; ok {
			return true
		}
	}
	return false
}

func (db *knownHostsDB) check(address string, remote net.Addr, remoteKey cryptoSSH.PublicKey) error {
	if revoked := db.revoked[khPlainKeyBlob(remoteKey)]; revoked != nil {
		return &knownhosts.RevokedError{Revoked: *revoked}
	}
	host, port, err := net.SplitHostPort(remote.String())
	if err != nil {
		return fmt.Errorf("knownhosts: SplitHostPort(%s): %w", remote, err)
	}
	hostToCheck := khAddr{host: host, port: port}
	if address != "" {
		host, port, err = net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("knownhosts: SplitHostPort(%s): %w", address, err)
		}
		hostToCheck = khAddr{host: host, port: port}
	}
	keyErr := &knownhosts.KeyError{}
	for _, l := range db.lines {
		if !l.matcher.match(hostToCheck) {
			continue
		}
		keyErr.Want = append(keyErr.Want, l.knownKey)
		if bytes.Equal(l.knownKey.Key.Marshal(), remoteKey.Marshal()) {
			return nil
		}
	}
	return keyErr
}

func (db *knownHostsDB) hostKeyCallback() cryptoSSH.HostKeyCallback {
	certChecker := cryptoSSH.CertChecker{
		IsHostAuthority: db.isHostAuthority,
		IsRevoked:       db.isRevoked,
		HostKeyFallback: db.check,
	}
	return wrapNilRemoteHostKeyCallback(certChecker.CheckHostKey)
}

func wrapNilRemoteHostKeyCallback(cb cryptoSSH.HostKeyCallback) cryptoSSH.HostKeyCallback {
	return func(hostname string, remote net.Addr, key cryptoSSH.PublicKey) error {
		if remote == nil {
			remote = proxyEndpointAddr("0.0.0.0:22")
		}
		return cb(hostname, remote, key)
	}
}

func (db *knownHostsDB) parseFileStrict(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return db.readLines(f, filename, nil)
}

func (db *knownHostsDB) parseFileLenient(filename string, l logger.DebugLogger) {
	if l == nil {
		l = logger.NopLogger
	}
	f, err := os.Open(filename)
	if err != nil {
		l.Debugf("skipping global known_hosts file %q: %v", filename, err)
		return
	}
	defer func() { _ = f.Close() }()
	_ = db.readLines(f, filename, l)
}

func (db *knownHostsDB) readLines(r io.Reader, filename string, lenientLogger logger.DebugLogger) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := bytes.Trim(scanner.Bytes(), " \t")
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if err := db.parseLine(line, filename, lineNum); err != nil {
			if lenientLogger != nil {
				lenientLogger.Debugf("skipping malformed global known_hosts line %s:%d: %v", filename, lineNum, err)
				continue
			}
			return fmt.Errorf("knownhosts: %s:%d: %w", filename, lineNum, err)
		}
	}
	if err := scanner.Err(); err != nil && lenientLogger == nil {
		return err
	}
	return nil
}

func khNextWord(line []byte) (string, []byte) {
	i := bytes.IndexAny(line, "\t ")
	if i == -1 {
		return string(line), nil
	}
	return string(line[:i]), bytes.Trim(line[i:], " \t")
}

func parseKHLineFields(line []byte) (marker, host string, key cryptoSSH.PublicKey, err error) {
	if w, next := khNextWord(line); w == khMarkerCert || w == khMarkerRevoked {
		marker = w
		line = next
	}
	host, line = khNextWord(line)
	if len(host) > 0 && host[0] == '@' {
		return "", "", nil, fmt.Errorf("knownhosts: unexpected marker: %q", host)
	}
	if len(line) == 0 {
		return "", "", nil, errors.New("knownhosts: missing host pattern")
	}
	wantType, line := khNextWord(line)
	if len(line) == 0 {
		return "", "", nil, errors.New("knownhosts: missing key type pattern")
	}
	keyBlob, _ := khNextWord(line)
	keyBytes, err := base64.StdEncoding.DecodeString(keyBlob)
	if err != nil {
		return "", "", nil, err
	}
	key, err = cryptoSSH.ParsePublicKey(keyBytes)
	if err != nil {
		return "", "", nil, err
	}
	if key.Type() != wantType {
		return "", "", nil, fmt.Errorf("knownhosts: key type mismatch: found %q, want %q", key.Type(), wantType)
	}
	return marker, host, key, nil
}

func (db *knownHostsDB) parseLine(line []byte, filename string, linenum int) error {
	marker, pattern, key, err := parseKHLineFields(line)
	if err != nil {
		return err
	}
	if marker == khMarkerRevoked {
		db.revoked[khPlainKeyBlob(key)] = &knownhosts.KnownKey{
			Key:      key,
			Filename: filename,
			Line:     linenum,
		}
		return nil
	}
	entry := khDBLine{
		cert: marker == khMarkerCert,
		knownKey: knownhosts.KnownKey{
			Filename: filename,
			Line:     linenum,
			Key:      key,
		},
	}
	if pattern[0] == '|' {
		entry.matcher, err = newKHHashedHost(pattern)
	} else {
		entry.matcher, err = newKHHostnameMatcher(pattern)
	}
	if err != nil {
		return err
	}
	db.lines = append(db.lines, entry)
	return nil
}

func newKHHostnameMatcher(pattern string) (khMatcher, error) {
	var hps khHostPatterns
	for p := range strings.SplitSeq(pattern, ",") {
		if len(p) == 0 {
			continue
		}
		var a khAddr
		var negate bool
		if p[0] == '!' {
			negate = true
			p = p[1:]
		}
		if len(p) == 0 {
			return nil, errors.New("knownhosts: negation without following hostname")
		}
		var err error
		if p[0] == '[' {
			a.host, a.port, err = net.SplitHostPort(p)
			if err != nil {
				return nil, err
			}
		} else {
			a.host, a.port, err = net.SplitHostPort(p)
			if err != nil {
				a.host = p
				a.port = "22"
			}
		}
		hps = append(hps, khHostPattern{negate: negate, addr: a})
	}
	return hps, nil
}
