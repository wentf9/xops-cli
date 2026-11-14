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

func isRelativeAlgorithmSpec(spec string) bool {
	return len(spec) > 0 && (spec[0] == '+' || spec[0] == '-' || spec[0] == '^')
}

func (c *Connector) getHostKeyAlgorithms(ctx context.Context, coordinator *handshakeCoordinator, cfg *ClientConfig) ([]string, error) {
	rawSpec := ""
	if cfg != nil && cfg.Options != nil {
		rawSpec = strings.TrimSpace(cfg.Options.HostKeyAlgorithms())
	}
	if c.hostKeyVerifier != nil {
		return c.getVerifierHostKeyAlgorithms(ctx, coordinator, cfg, rawSpec)
	}
	if rawSpec == "" {
		return c.defaultKnownHostsHostKeyAlgorithms(cfg), nil
	}
	if isRelativeAlgorithmSpec(rawSpec) {
		pool, err := ResolveAlgorithmList(rawSpec, cryptoSSH.SupportedAlgorithms().HostKeys)
		if err != nil {
			return nil, fmt.Errorf("resolve HostKeyAlgorithms option: %w", err)
		}
		ordered := c.orderKnownHostsHostKeyAlgorithms(cfg, pool)
		if strings.HasPrefix(rawSpec, "^") {
			algos, err := ResolveAlgorithmList(rawSpec, ordered)
			if err != nil {
				return nil, fmt.Errorf("resolve HostKeyAlgorithms option: %w", err)
			}
			return algos, nil
		}
		return ordered, nil
	}
	algos, err := ResolveAlgorithmList(rawSpec, cryptoSSH.SupportedAlgorithms().HostKeys)
	if err != nil {
		return nil, fmt.Errorf("resolve HostKeyAlgorithms option: %w", err)
	}
	return algos, nil
}

func (c *Connector) getVerifierHostKeyAlgorithms(
	ctx context.Context,
	coordinator *handshakeCoordinator,
	cfg *ClientConfig,
	rawSpec string,
) ([]string, error) {
	source, ok := c.hostKeyVerifier.(HostKeyAlgorithmSource)
	if !ok {
		if rawSpec == "" {
			return nil, nil
		}
		algos, err := ResolveAlgorithmList(rawSpec, cryptoSSH.SupportedAlgorithms().HostKeys)
		if err != nil {
			return nil, fmt.Errorf("resolve HostKeyAlgorithms option: %w", err)
		}
		return algos, nil
	} // Existing verifiers retain the SSH library defaults (or resolved rawSpec when specified).
	if coordinator != nil {
		ctx = coordinator.Context()
	}
	selection, cancel := context.WithTimeout(ctx, c.getNodeHandshakeTimeout(cfg))
	defer cancel()
	if err := selection.Err(); err != nil {
		return nil, err
	}
	var request HostKeyRequest
	if cfg != nil {
		request = HostKeyRequest{NodeID: cfg.NodeID, Host: cleanHostLiteral(cfg.Address), Port: cfg.Port, User: cfg.User, VersionToken: cfg.TrustVersion}
	}
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
	if rawSpec == "" {
		return slices.Clone(algorithms), nil
	}
	return intersectVerifierHostKeyAlgorithms(rawSpec, algorithms)
}

func intersectVerifierHostKeyAlgorithms(rawSpec string, verifierAlgos []string) ([]string, error) {
	optionAlgos, err := ResolveAlgorithmList(rawSpec, verifierAlgos)
	if err != nil {
		return nil, fmt.Errorf("resolve HostKeyAlgorithms option: %w", err)
	}
	var intersected []string
	for _, alg := range optionAlgos {
		if slices.Contains(verifierAlgos, alg) {
			intersected = append(intersected, alg)
		}
	}
	if len(intersected) == 0 {
		return nil, errors.New("no host key algorithms in common between HostKeyAlgorithms option and pinned host key verifier")
	}
	return intersected, nil
}

// defaultKnownHostsHostKeyAlgorithms mirrors OpenSSH order_hostkeyalgs when no
// custom HostKeyVerifier or HostKeyAlgorithms option is set: the returned list is
// always built strictly from SupportedAlgorithms().HostKeys (never nil, which would
// re-enable SHA-1/DSA defaults in x/crypto/ssh).
func (c *Connector) defaultKnownHostsHostKeyAlgorithms(cfg *ClientConfig) []string {
	return c.orderKnownHostsHostKeyAlgorithms(cfg, cryptoSSH.SupportedAlgorithms().HostKeys)
}

// orderKnownHostsHostKeyAlgorithms orders the candidate algorithm pool against
// matching non-revoked entries in known_hosts (matching OpenSSH order_hostkeyalgs):
// when an @cert-authority matches the target host, certificate algorithms in pool
// come first followed by pinned plain key types and remaining plain algorithms in
// pool; otherwise plain algorithms in pool (with pinned types first) precede
// certificate algorithms.
func (c *Connector) orderKnownHostsHostKeyAlgorithms(cfg *ClientConfig, pool []string) []string {
	if cfg == nil || cleanHostLiteral(cfg.Address) == "" {
		return slices.Clone(pool)
	}
	db := c.loadReadOnlyKnownHostsDB(cfg)
	port := cfg.Port
	if port <= 0 {
		port = 22
	}
	targetAddr := khAddr{
		host: cleanHostLiteral(cfg.Address),
		port: strconv.Itoa(port),
	}
	hasCertAuthority, pinnedPlainTypes := db.matchingHostKeyTypes(targetAddr)

	ordered := make([]string, 0, len(pool))
	appendUnique := func(alg string) {
		if slices.Contains(pool, alg) && !slices.Contains(ordered, alg) {
			ordered = append(ordered, alg)
		}
	}
	appendCerts := func() {
		for _, alg := range pool {
			if isCertAlgorithm(alg) {
				appendUnique(alg)
			}
		}
	}
	appendPlain := func() {
		for _, kt := range pinnedPlainTypes {
			for _, sigAlg := range hostKeySigAlgsForKeyType(kt) {
				appendUnique(sigAlg)
			}
		}
		for _, alg := range pool {
			if !isCertAlgorithm(alg) {
				appendUnique(alg)
			}
		}
	}
	if hasCertAuthority {
		appendCerts()
		appendPlain()
	} else {
		appendPlain()
		appendCerts()
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

	globalFiles, err := c.resolveGlobalKnownHostsFiles(cfg, target, userFiles)
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
	return khWildcardMatch([]byte(p.addr.host), []byte(strings.ToLower(a.host))) &&
		khWildcardMatch([]byte(p.addr.port), []byte(a.port))
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
	p, s := 0, 0
	starIdx := -1
	matchIdx := 0
	for s < len(str) {
		if p < len(pat) && (pat[p] == '?' || pat[p] == str[s]) {
			p++
			s++
		} else if p < len(pat) && pat[p] == '*' {
			starIdx = p
			matchIdx = s
			p++
		} else if starIdx != -1 {
			p = starIdx + 1
			matchIdx++
			s = matchIdx
		} else {
			return false
		}
	}
	for p < len(pat) && pat[p] == '*' {
		p++
	}
	return p == len(pat)
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
	lower := khAddr{host: strings.ToLower(a.host), port: a.port}
	mac := hmac.New(sha1.New, h.salt)
	_, _ = mac.Write([]byte(knownhosts.Normalize(lower.String())))
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
		if !l.cert && bytes.Equal(l.knownKey.Key.Marshal(), remoteKey.Marshal()) {
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
	return wrapNilRemoteHostKeyCallback(func(hostname string, remote net.Addr, key cryptoSSH.PublicKey) error {
		if h, p, err := net.SplitHostPort(hostname); err == nil {
			hostname = net.JoinHostPort(strings.ToLower(h), p)
		}
		return certChecker.CheckHostKey(hostname, remote, key)
	})
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
		p = strings.ToLower(p)
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
