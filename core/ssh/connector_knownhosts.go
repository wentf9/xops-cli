package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var knownHostsFileMutex sync.Mutex

func (c *Connector) getHostKeyCallback(ctx context.Context, coordinator *handshakeCoordinator, cfg *ClientConfig, hostKeyChangedFlags ...*atomic.Bool) (ssh.HostKeyCallback, error) {
	var hostKeyChanged *atomic.Bool
	if len(hostKeyChangedFlags) > 0 {
		hostKeyChanged = hostKeyChangedFlags[0]
	}
	return c.getHostKeyCallbackWithState(ctx, coordinator, cfg, hostKeyChanged, nil)
}

func (c *Connector) getHostKeyCallbackWithState(
	ctx context.Context,
	coordinator *handshakeCoordinator,
	cfg *ClientConfig,
	hostKeyChanged *atomic.Bool,
	initialHandshakeDone *atomic.Bool,
) (ssh.HostKeyCallback, error) {
	if c.hostKeyVerifier != nil {
		return c.verifierHostKeyCallback(ctx, coordinator, cfg, initialHandshakeDone), nil
	}

	strictMode, userKH, batchMode := extractHostKeyPolicy(cfg)
	knownHostsFile, noKnownHostsFile, hostKeyCallback, err := c.openKnownHostsCallback(userKH, cfg)
	if err != nil {
		return nil, err
	}

	var acceptedMu sync.Mutex
	var acceptedHost string
	var acceptedKey []byte
	var verifiedOnce bool

	isRekey := func() bool {
		if initialHandshakeDone != nil && initialHandshakeDone.Load() {
			return true
		}
		acceptedMu.Lock()
		done := verifiedOnce
		acceptedMu.Unlock()
		return done
	}
	recordAccepted := func(hostname string, key ssh.PublicKey) {
		acceptedMu.Lock()
		verifiedOnce = true
		if key != nil {
			acceptedHost = hostname
			acceptedKey = slices.Clone(key.Marshal())
		}
		acceptedMu.Unlock()
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) (retErr error) {
		if remote == nil {
			remote = proxyEndpointAddr("0.0.0.0:22")
		}
		rekey := isRekey()
		err := hostKeyCallback(hostname, remote, key)
		if err == nil {
			if !rekey {
				recordAccepted(hostname, key)
			}
			return nil
		}

		if rekey {
			if _, ok := errors.AsType[*knownhosts.KeyError](err); !ok {
				return err
			}
			if _, isCert := key.(*ssh.Certificate); isCert {
				return fmt.Errorf("%w: untrusted host certificate presented during transport rekey for %s: %w", ErrHostKeyMismatch, hostname, err)
			}
			acceptedMu.Lock()
			sameKey := key != nil && acceptedKey != nil && hostname == acceptedHost && bytes.Equal(key.Marshal(), acceptedKey)
			acceptedMu.Unlock()
			if sameKey {
				return nil
			}
			return fmt.Errorf("%w: remote host key changed during transport rekey for %s", ErrHostKeyMismatch, hostname)
		}

		if keyErr, ok := errors.AsType[*knownhosts.KeyError](err); ok {
			if handleErr := c.handleKnownHostsKeyError(ctx, coordinator, cfg, keyErr, strictMode, batchMode, noKnownHostsFile, knownHostsFile, hostname, remote, key, hostKeyChanged, initialHandshakeDone); handleErr != nil {
				return handleErr
			}
			recordAccepted(hostname, key)
			return nil
		}
		return err
	}, nil
}

func (c *Connector) verifierHostKeyCallback(ctx context.Context, coordinator *handshakeCoordinator, cfg *ClientConfig, initialHandshakeDone ...*atomic.Bool) ssh.HostKeyCallback {
	var handshakeDone *atomic.Bool
	if len(initialHandshakeDone) > 0 {
		handshakeDone = initialHandshakeDone[0]
	}
	request := HostKeyRequest{NodeID: cfg.NodeID, Host: cleanHostLiteral(cfg.Address), Port: cfg.Port, User: cfg.User, VersionToken: cfg.TrustVersion}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		verificationParent := ctx
		if verificationParent == nil {
			verificationParent = c.lifecycleCtx
		}
		if coordinator != nil && (handshakeDone == nil || !handshakeDone.Load()) {
			verificationParent = coordinator.Context()
		}
		verification, cancel := context.WithTimeout(verificationParent, c.getNodeHandshakeTimeout(cfg))
		defer cancel()
		if err := verification.Err(); err != nil {
			return err
		}
		requestCopy := request
		requestCopy.Hostname, requestCopy.Remote = hostname, remote
		return c.hostKeyVerifier.Verify(verification, requestCopy, key)
	}
}

func extractHostKeyPolicy(cfg *ClientConfig) (strictMode string, userKH string, batchMode bool) {
	strictMode = StrictHostKeyCheckingAsk
	if cfg != nil && cfg.Options != nil {
		if m := cfg.Options.StrictHostKeyChecking(); m != "" {
			strictMode = m
		}
		userKH = strings.TrimSpace(cfg.Options.UserKnownHostsFile())
		batchMode = cfg.Options.BatchMode()
	}
	return strictMode, userKH, batchMode
}

// openKnownHostsCallback returns the single writable user known_hosts file (only
// ever derived from UserKnownHostsFile), whether writes are disabled, and a
// callback that verifies against user files followed by read-only global files.
func (c *Connector) openKnownHostsCallback(userKH string, cfg *ClientConfig) (string, bool, ssh.HostKeyCallback, error) {
	target := knownHostsTarget(cfg)

	db := newKnownHostsDB()
	primaryWriteFile, userFiles, err := c.loadUserKnownHosts(userKH, target, db)
	if err != nil {
		return "", false, nil, err
	}
	noWrite := primaryWriteFile == ""

	globalFiles, err := c.resolveGlobalKnownHostsFiles(cfg, target, userFiles)
	if err != nil {
		return "", false, nil, err
	}
	for _, gf := range globalFiles {
		db.parseFileLenient(gf, c.getLogger())
	}
	return primaryWriteFile, noWrite, db.hostKeyCallback(), nil
}

func (c *Connector) loadUserKnownHosts(userKH string, target TargetContext, db *knownHostsDB) (string, []string, error) {
	knownHostsFileMutex.Lock()
	defer knownHostsFileMutex.Unlock()

	var primaryWriteFile string
	var userFiles []string
	switch {
	case strings.EqualFold(userKH, "none") || isKnownHostsDevNull(userKH):
	case userKH != "":
		var err error
		primaryWriteFile, userFiles, err = c.resolveCustomKnownHostsFiles(userKH, target)
		if err != nil {
			return "", nil, err
		}
	default:
		if err := validateEnvironment(c.environment); err != nil {
			return "", nil, err
		}
		primaryWriteFile = c.environment.KnownHostsFile
		f, openErr := openKnownHostsFileNoFollow(primaryWriteFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if errors.Is(openErr, os.ErrNotExist) {
			if mkdirErr := os.MkdirAll(filepath.Dir(primaryWriteFile), 0700); mkdirErr != nil {
				return "", nil, fmt.Errorf("create .ssh directory failed: %w", mkdirErr)
			}
			f, openErr = openKnownHostsFileNoFollow(primaryWriteFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		}
		if openErr == nil {
			if closeErr := f.Close(); closeErr != nil {
				return "", nil, fmt.Errorf("create known_hosts file failed: %w", closeErr)
			}
			if hardenErr := hardenNewKnownHostsFile(primaryWriteFile); hardenErr != nil {
				_ = os.Remove(primaryWriteFile)
				return "", nil, fmt.Errorf("harden known_hosts file failed: %w", hardenErr)
			}
		} else if !errors.Is(openErr, os.ErrExist) {
			return "", nil, fmt.Errorf("create known_hosts file failed: %w", openErr)
		}
		userFiles = []string{primaryWriteFile}
	}

	for _, uf := range userFiles {
		if parseErr := db.parseFileStrict(uf); parseErr != nil {
			return "", nil, fmt.Errorf("parse known_hosts file failed: %w", parseErr)
		}
	}
	return primaryWriteFile, userFiles, nil
}

func knownHostsTarget(cfg *ClientConfig) TargetContext {
	if cfg == nil {
		return TargetContext{}
	}
	return TargetContext{
		Host:         cleanHostLiteral(cfg.Address),
		Port:         cfg.Port,
		User:         cfg.User,
		OriginalHost: effectiveOriginalHost(cfg.OriginalHost, cfg.NodeID),
		JumpHost:     NormalizeProxyJump(cfg.ProxyJump),
	}
}

func (c *Connector) resolveCustomKnownHostsFiles(userKH string, target TargetContext) (string, []string, error) {
	var existingFiles []string
	var primaryWriteFile string
	for idx, tokenPath := range strings.Fields(userKH) {
		if strings.EqualFold(tokenPath, "none") || isKnownHostsDevNull(tokenPath) {
			continue
		}
		expanded, expErr := expandKnownHostsPath(tokenPath, c.environment, target)
		if expErr != nil {
			return "", nil, fmt.Errorf("expand UserKnownHostsFile %q failed: %w", tokenPath, expErr)
		}
		if expanded == "" || strings.EqualFold(expanded, "none") || isKnownHostsDevNull(expanded) {
			continue
		}
		if idx == 0 {
			primaryWriteFile = expanded
		}
		st, err := os.Lstat(expanded)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return "", nil, fmt.Errorf("stat UserKnownHostsFile %q failed: %w", expanded, err)
			}
			continue
		}
		if st.IsDir() {
			return "", nil, fmt.Errorf("UserKnownHostsFile %q is a directory", expanded)
		}
		if !st.Mode().IsRegular() {
			return "", nil, fmt.Errorf("UserKnownHostsFile %q is not a regular file (mode %s)", expanded, st.Mode().Type())
		}
		existingFiles = append(existingFiles, expanded)
	}
	return primaryWriteFile, existingFiles, nil
}

// resolveGlobalKnownHostsFiles returns existing, readable, regular global
// known_hosts files. Global files are verification-only: never created or
// written. Missing or unreadable global files are skipped with a debug log,
// while valid @revoked/@cert-authority/host entries in partially malformed
// global files are preserved via knownHostsDB.parseFileLenient; UserKnownHostsFile
// parsing remains strict.
func (c *Connector) resolveGlobalKnownHostsFiles(cfg *ClientConfig, target TargetContext, userFiles []string) ([]string, error) {
	var candidates []string
	spec := ""
	if cfg != nil && cfg.Options != nil {
		spec = cfg.Options.GlobalKnownHostsFile()
	}
	switch {
	case strings.EqualFold(spec, "none"):
		return nil, nil
	case spec != "":
		for _, tokenPath := range strings.Fields(spec) {
			if strings.EqualFold(tokenPath, "none") || isKnownHostsDevNull(tokenPath) {
				continue
			}
			expanded, err := expandKnownHostsPath(tokenPath, c.environment, target)
			if err != nil {
				return nil, fmt.Errorf("expand GlobalKnownHostsFile %q failed: %w", tokenPath, err)
			}
			if expanded == "" || strings.EqualFold(expanded, "none") || isKnownHostsDevNull(expanded) {
				continue
			}
			candidates = append(candidates, expanded)
		}
	default:
		for _, path := range c.environment.GlobalKnownHostsFiles {
			if path = strings.TrimSpace(path); path != "" {
				candidates = append(candidates, filepath.Clean(path))
			}
		}
	}

	var files []string
	for _, path := range candidates {
		if path == "" || slices.Contains(userFiles, path) || slices.Contains(files, path) {
			continue
		}
		if !isReadableRegularFile(path) {
			c.getLogger().Debugf("skipping global known_hosts file %q: missing, unreadable, or not a regular file", path)
			continue
		}
		files = append(files, path)
	}
	return files, nil
}

func isReadableRegularFile(path string) bool {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	f, err := openKnownHostsReadOnlyFollow(path)
	if err != nil {
		return false
	}
	fst, statErr := f.Stat()
	_ = f.Close()
	return statErr == nil && fst.Mode().IsRegular()
}

func expandKnownHostsPath(pattern string, env Environment, target TargetContext) (string, error) {
	expanded, err := ExpandControlPath(pattern, env, target)
	if err != nil || expanded == "" || strings.EqualFold(expanded, "none") || isKnownHostsDevNull(expanded) {
		return expanded, err
	}
	return filepath.Clean(filepath.FromSlash(expanded)), nil
}

func (c *Connector) handleKnownHostsKeyError(
	ctx context.Context,
	coordinator *handshakeCoordinator,
	cfg *ClientConfig,
	keyErr *knownhosts.KeyError,
	strictMode string,
	batchMode bool,
	noKnownHostsFile bool,
	knownHostsFile string,
	hostname string,
	remote net.Addr,
	key ssh.PublicKey,
	hostKeyChanged *atomic.Bool,
	initialHandshakeDone ...*atomic.Bool,
) error {
	if _, isCert := key.(*ssh.Certificate); isCert {
		return fmt.Errorf("%w: untrusted host certificate for %s: %w", ErrHostKeyMismatch, hostname, keyErr)
	}

	// A conflicting known key always wins over DNS evidence.
	if len(keyErr.Want) > 0 {
		if strictMode == StrictHostKeyCheckingNo {
			if hostKeyChanged != nil {
				hostKeyChanged.Store(true)
			}
			c.getLogger().Debugf("host key verification: remote host identification changed for %s; continuing due to StrictHostKeyChecking=no with password and keyboard-interactive authentication disabled", hostname)
			return nil
		}
		return fmt.Errorf("%w: remote host identification has changed for %s: %w", ErrHostKeyMismatch, hostname, keyErr)
	}

	hashHosts := cfg != nil && cfg.Options.HashKnownHosts()
	record := func() error {
		if noKnownHostsFile || knownHostsFile == "" {
			return nil
		}
		return appendKnownHost(knownHostsFile, hostname, key, hashHosts)
	}

	switch strictMode {
	case StrictHostKeyCheckingYes:
		return fmt.Errorf("%w: no host key is known for %s and StrictHostKeyChecking=yes", ErrHostKeyMismatch, hostname)
	case StrictHostKeyCheckingNo:
		// Explicit opt-out (matching OpenSSH): unknown keys are accepted and
		// recorded without consulting SSHFP DNS records.
		_ = record()
		return nil
	default:
		return c.handleUnknownHostKey(ctx, coordinator, cfg, strictMode, batchMode, hostname, remote, key, record, initialHandshakeDone...)
	}
}

// handleUnknownHostKey applies StrictHostKeyChecking=ask/accept-new with the
// VerifyHostKeyDNS fail-closed matrix (StrictHostKeyChecking=yes/no return in
// handleKnownHostsKeyError before reaching DNS lookup, matching OpenSSH opt-out
// semantics for StrictHostKeyChecking=no):
//   - only an AD=1 SHA-256 match under VerifyHostKeyDNS=yes skips the prompt;
//   - under ask/accept-new, an SSHFP mismatch is never auto-accepted (not even
//     by accept-new or AcceptNewHostKey) and fails closed when no interactive
//     prompt is possible;
//   - unverified matches and VerifyHostKeyDNS=ask only annotate the prompt.
func (c *Connector) handleUnknownHostKey(
	ctx context.Context,
	coordinator *handshakeCoordinator,
	cfg *ClientConfig,
	strictMode string,
	batchMode bool,
	hostname string,
	remote net.Addr,
	key ssh.PublicKey,
	record func() error,
	initialHandshakeDone ...*atomic.Bool,
) (retErr error) {
	dnsMode := ""
	if cfg != nil {
		dnsMode = cfg.Options.VerifyHostKeyDNS()
	}
	status := c.lookupSSHFPStatus(ctx, coordinator, cfg, key, initialHandshakeDone...)
	if status == SSHFPStatusMatchedVerified && dnsMode == VerifyHostKeyDNSYes {
		c.getLogger().Debugf("host key for %s accepted via DNSSEC-authenticated SSHFP record", hostname)
		if strictMode == StrictHostKeyCheckingAcceptNew {
			return record()
		}
		return nil
	}
	if strictMode == StrictHostKeyCheckingAcceptNew && status != SSHFPStatusMismatch {
		return record()
	}
	if status == SSHFPStatusMismatch && (batchMode || c.AcceptNewHostKey.Load()) {
		return fmt.Errorf("%w: SSHFP DNS records for %s do not match the presented %s host key", ErrHostKeyMismatch, hostname, key.Type())
	}
	if batchMode && !c.AcceptNewHostKey.Load() {
		return ErrInteractionRequired
	}
	if coordinator != nil {
		if pauseErr := coordinator.Pause(); pauseErr != nil {
			return pauseErr
		}
		defer func() {
			if resumeErr := coordinator.Resume(); resumeErr != nil {
				retErr = errors.Join(retErr, resumeErr)
			}
		}()
	}

	if promptErr := c.promptHostKeyVerification(ctx, hostname, remote, key, status); promptErr != nil {
		return promptErr
	}
	return record()
}

func (c *Connector) promptHostKeyVerification(ctx context.Context, hostname string, remote net.Addr, key ssh.PublicKey, sshfpStatus SSHFPVerifyStatus) error {
	if c.AcceptNewHostKey.Load() && sshfpStatus != SSHFPStatusMismatch {
		return nil
	}

	var remoteAddr string
	if remote != nil {
		remoteAddr = remote.String()
	}
	fingerprint := ssh.FingerprintSHA256(key)

	promptCtx, cancel := c.interactionContext(ctx)
	defer cancel()

	agreed, err := c.hostKeyConfirmer.ConfirmHostKey(promptCtx, HostKeyConfirmation{
		Hostname:      hostname,
		RemoteAddress: remoteAddr,
		Algorithm:     key.Type(),
		Fingerprint:   fingerprint,
		SSHFPStatus:   sshfpStatus,
	})
	if err != nil {
		return fmt.Errorf("read response failed: %w", err)
	}

	if agreed {
		return nil
	}
	return ErrHostKeyMismatch
}

// appendKnownHost appends one known_hosts line. With hash, the normalized host
// ("host" or "[host]:port" for non-22 ports) is written as an HMAC-SHA1 |1| entry.
func appendKnownHost(knownHostsFile, hostname string, key ssh.PublicKey, hash bool) (err error) {
	if _, isCert := key.(*ssh.Certificate); isCert {
		return fmt.Errorf("%w: refusing to persist host certificate for %s to known_hosts", ErrHostKeyMismatch, hostname)
	}
	if isKnownHostsDevNull(knownHostsFile) {
		return nil
	}
	knownHostsFileMutex.Lock()
	defer knownHostsFileMutex.Unlock()

	if mkdirErr := os.MkdirAll(filepath.Dir(knownHostsFile), 0700); mkdirErr != nil {
		return fmt.Errorf("create known_hosts directory failed: %w", mkdirErr)
	}

	f, created, openErr := openKnownHostsForAppend(knownHostsFile)
	if openErr != nil {
		return openErr
	}
	closed := false
	defer func() {
		if closed {
			return
		}
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close known_hosts file failed: %w", closeErr)
		}
	}()

	if err := verifyRegularKnownHostsHandle(f, knownHostsFile); err != nil {
		return err
	}

	if created {
		if hardenErr := hardenNewKnownHostsFile(knownHostsFile); hardenErr != nil {
			closed = true
			_ = f.Close()
			_ = os.Remove(knownHostsFile)
			return fmt.Errorf("harden known_hosts file failed: %w", hardenErr)
		}
	}

	if lockErr := lockKnownHostsFile(f, true); lockErr != nil {
		return fmt.Errorf("lock known_hosts file failed: %w", lockErr)
	}
	defer func() {
		if unlockErr := unlockKnownHostsFile(f); unlockErr != nil && err == nil {
			err = fmt.Errorf("unlock known_hosts file failed: %w", unlockErr)
		}
	}()

	prefix, prefixErr := knownHostsTrailingNewlinePrefix(f, knownHostsFile)
	if prefixErr != nil {
		return prefixErr
	}

	line := formatKnownHostEntry(hostname, key, hash)
	if _, writeErr := f.WriteString(prefix + line + "\n"); writeErr != nil {
		return fmt.Errorf("write known_hosts file failed: %w", writeErr)
	}
	return nil
}

func verifyRegularKnownHostsHandle(f *os.File, knownHostsFile string) error {
	fst, statErr := f.Stat()
	if statErr != nil {
		return fmt.Errorf("stat known_hosts file failed: %w", statErr)
	}
	if !fst.Mode().IsRegular() {
		return fmt.Errorf("open known_hosts file failed: refusing non-regular file %q (mode %s)", knownHostsFile, fst.Mode().Type())
	}
	return nil
}

// knownHostsTrailingNewlinePrefix re-stats f under the exclusive file lock so
// st.Size() reflects any concurrent process's write completed before locking.
func knownHostsTrailingNewlinePrefix(f *os.File, knownHostsFile string) (string, error) {
	st, statErr := f.Stat()
	if statErr != nil {
		return "", fmt.Errorf("stat known_hosts file failed: %w", statErr)
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("open known_hosts file failed: refusing non-regular file %q (mode %s)", knownHostsFile, st.Mode().Type())
	}
	if st.Size() == 0 {
		return "", nil
	}
	var last [1]byte
	if _, readErr := f.ReadAt(last[:], st.Size()-1); readErr != nil {
		return "", fmt.Errorf("read known_hosts trailing byte failed: %w", readErr)
	}
	if last[0] != '\n' {
		return "\n", nil
	}
	return "", nil
}

func formatKnownHostEntry(hostname string, key ssh.PublicKey, hash bool) string {
	var host string
	if h, p, splitErr := net.SplitHostPort(hostname); splitErr == nil {
		host = khOpenSSHHostPort(khAddr{host: h, port: p})
	} else {
		host = lowercaseSSHHostPreservingZone(knownhosts.Normalize(hostname))
	}
	if hash {
		host = knownhosts.HashHostname(host)
	}
	return knownhosts.Line([]string{host}, key)
}

func openKnownHostsForAppend(knownHostsFile string) (*os.File, bool, error) {
	needCreate := false
	if st, lstatErr := os.Lstat(knownHostsFile); lstatErr == nil {
		if !st.Mode().IsRegular() {
			return nil, false, fmt.Errorf("open known_hosts file failed: refusing non-regular file %q (mode %s)", knownHostsFile, st.Mode().Type())
		}
	} else if errors.Is(lstatErr, os.ErrNotExist) {
		needCreate = true
	} else {
		return nil, false, fmt.Errorf("stat known_hosts file failed: %w", lstatErr)
	}

	if needCreate {
		f, err := openKnownHostsFileNoFollow(knownHostsFile, os.O_CREATE|os.O_EXCL|os.O_APPEND|os.O_RDWR, 0600)
		if err == nil {
			return f, true, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, false, fmt.Errorf("open known_hosts file failed: %w", err)
		}
	}

	f, err := openKnownHostsFileNoFollow(knownHostsFile, os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, false, fmt.Errorf("open known_hosts file failed: %w", err)
	}
	return f, false, nil
}
