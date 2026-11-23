package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/core/verdict"
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
	callback, _, err := c.getHostKeyCallbackWithDB(ctx, coordinator, cfg, hostKeyChanged, initialHandshakeDone)
	return callback, err
}

func (c *Connector) getHostKeyCallbackWithDB(
	ctx context.Context,
	coordinator *handshakeCoordinator,
	cfg *ClientConfig,
	hostKeyChanged *atomic.Bool,
	initialHandshakeDone *atomic.Bool,
) (ssh.HostKeyCallback, *knownHostsDB, error) {
	if c.hostKeyVerifier != nil {
		return c.verifierHostKeyCallback(ctx, coordinator, cfg, initialHandshakeDone), nil, nil
	}

	strictMode, userKH, batchMode := extractHostKeyPolicy(cfg)
	knownHostsFile, noKnownHostsFile, db, err := c.openKnownHostsDB(userKH, cfg)
	if err != nil {
		return nil, nil, err
	}
	hostKeyCallback := db.hostKeyCallback()

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
	}, db, nil
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
	primaryWriteFile, noWrite, db, err := c.openKnownHostsDB(userKH, cfg)
	if err != nil {
		return "", false, nil, err
	}
	return primaryWriteFile, noWrite, db.hostKeyCallback(), nil
}

// openKnownHostsDB loads the locked, handle-verified user known_hosts files
// followed by read-only global known_hosts files into a single immutable
// snapshot shared by HostKeyCallback and HostKeyAlgorithms ordering.
func (c *Connector) openKnownHostsDB(userKH string, cfg *ClientConfig) (string, bool, *knownHostsDB, error) {
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
	return primaryWriteFile, noWrite, db, nil
}

func (c *Connector) loadUserKnownHosts(userKH string, target TargetContext, db *knownHostsDB) (string, []string, error) {
	knownHostsFileMutex.Lock()
	defer knownHostsFileMutex.Unlock()

	var primaryWriteFile string
	var userFiles []string
	allowMissing := false
	switch {
	case strings.EqualFold(userKH, "none") || isKnownHostsDevNull(userKH):
	case userKH != "":
		var err error
		primaryWriteFile, userFiles, err = c.resolveCustomKnownHostsFiles(userKH, target)
		if err != nil {
			return "", nil, err
		}
		allowMissing = true
	default:
		if err := validateEnvironment(c.environment); err != nil {
			return "", nil, err
		}
		primaryWriteFile = c.environment.KnownHostsFile
		f, openErr := fsx.CreateExclusive(primaryWriteFile, fsx.OwnerOnlyPerm)
		if errors.Is(openErr, os.ErrNotExist) {
			if mkdirErr := os.MkdirAll(filepath.Dir(primaryWriteFile), 0o700); mkdirErr != nil {
				return "", nil, fmt.Errorf("create .ssh directory failed: %w", mkdirErr)
			}
			f, openErr = fsx.CreateExclusive(primaryWriteFile, fsx.OwnerOnlyPerm)
		}
		if openErr == nil {
			if closeErr := f.Close(); closeErr != nil {
				return "", nil, fmt.Errorf("create known_hosts file failed: %w", closeErr)
			}
		} else if !errors.Is(openErr, os.ErrExist) {
			return "", nil, fmt.Errorf("create known_hosts file failed: %w", openErr)
		}
		userFiles = []string{primaryWriteFile}
	}

	for _, uf := range userFiles {
		if parseErr := db.parseFileStrict(uf); parseErr != nil {
			if allowMissing && errors.Is(parseErr, os.ErrNotExist) {
				continue
			}
			if allowMissing {
				return "", nil, wrapCustomKnownHostsParseError(uf, parseErr)
			}
			return "", nil, fmt.Errorf("parse known_hosts file failed: %w", parseErr)
		}
	}
	return primaryWriteFile, userFiles, nil
}

func wrapCustomKnownHostsParseError(path string, err error) error {
	if errors.Is(err, fsx.ErrNonRegular) {
		if st, statErr := os.Lstat(path); statErr == nil && st.IsDir() {
			return fmt.Errorf("UserKnownHostsFile %q is a directory: %w", path, err)
		}
	}
	return fmt.Errorf("parse known_hosts file failed: %w", err)
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
	var candidateFiles []string
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
		if !slices.Contains(candidateFiles, expanded) {
			candidateFiles = append(candidateFiles, expanded)
		}
	}
	return primaryWriteFile, candidateFiles, nil
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
		if v, err := isReadableRegularFile(path); err != nil || !v.Allowed() {
			c.getLogger().Debugf("skipping global known_hosts file %q: %v", path, err)
			continue
		}
		files = append(files, path)
	}
	return files, nil
}

func isReadableRegularFile(path string) (verdict.Verdict, error) {
	rc, err := openGlobalKnownHostsFile(path, maxKnownHostsFileBytes)
	if err != nil {
		return verdict.Deny, err
	}
	_ = rc.Close()
	return verdict.Allow, nil
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

	if mkdirErr := os.MkdirAll(filepath.Dir(knownHostsFile), 0o700); mkdirErr != nil {
		return fmt.Errorf("create known_hosts directory failed: %w", mkdirErr)
	}

	lf, openErr := fsx.OpenLocked(knownHostsFile, fsx.LockExclusive, true, fsx.OwnerOnlyPerm)
	if openErr != nil {
		return fmt.Errorf("open known_hosts file failed: %w", openErr)
	}
	defer func() {
		if closeErr := lf.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close known_hosts file failed: %w", closeErr)
		}
	}()

	prefix, prefixErr := knownHostsTrailingNewlinePrefix(lf, knownHostsFile)
	if prefixErr != nil {
		return prefixErr
	}
	if _, seekErr := lf.Seek(0, io.SeekEnd); seekErr != nil {
		return fmt.Errorf("seek known_hosts file failed: %w", seekErr)
	}

	line := formatKnownHostEntry(hostname, key, hash)
	if _, writeErr := lf.Write([]byte(prefix + line + "\n")); writeErr != nil {
		return fmt.Errorf("write known_hosts file failed: %w", writeErr)
	}
	return nil
}

// knownHostsTrailingNewlinePrefix re-stats lf under the exclusive file lock so
// st.Size() reflects any concurrent process's write completed before locking.
func knownHostsTrailingNewlinePrefix(lf *fsx.LockedFile, knownHostsFile string) (string, error) {
	st, statErr := lf.Stat()
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
	if _, readErr := lf.ReadAt(last[:], st.Size()-1); readErr != nil {
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
