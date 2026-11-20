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

	var primaryWriteFile string
	var userFiles []string
	switch {
	case strings.EqualFold(userKH, "none") || userKH == "/dev/null":
	case userKH != "":
		var err error
		primaryWriteFile, userFiles, err = c.resolveCustomKnownHostsFiles(userKH, target)
		if err != nil {
			return "", false, nil, err
		}
	default:
		if err := validateEnvironment(c.environment); err != nil {
			return "", false, nil, err
		}
		primaryWriteFile = c.environment.KnownHostsFile
		if _, err := os.Stat(primaryWriteFile); os.IsNotExist(err) {
			if mkdirErr := os.MkdirAll(filepath.Dir(primaryWriteFile), 0700); mkdirErr != nil {
				return "", false, nil, fmt.Errorf("create .ssh directory failed: %w", mkdirErr)
			}
			if writeErr := os.WriteFile(primaryWriteFile, []byte(""), 0600); writeErr != nil {
				return "", false, nil, fmt.Errorf("create known_hosts file failed: %w", writeErr)
			}
		}
		userFiles = []string{primaryWriteFile}
	}
	noWrite := primaryWriteFile == ""

	globalFiles, err := c.resolveGlobalKnownHostsFiles(cfg, target, userFiles)
	if err != nil {
		return "", false, nil, err
	}
	db := newKnownHostsDB()
	for _, uf := range userFiles {
		if parseErr := db.parseFileStrict(uf); parseErr != nil {
			return "", false, nil, fmt.Errorf("parse known_hosts file failed: %w", parseErr)
		}
	}
	for _, gf := range globalFiles {
		db.parseFileLenient(gf, c.getLogger())
	}
	return primaryWriteFile, noWrite, db.hostKeyCallback(), nil
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
		if strings.EqualFold(tokenPath, "none") || tokenPath == "/dev/null" {
			continue
		}
		expanded, expErr := expandKnownHostsPath(tokenPath, c.environment, target)
		if expErr != nil {
			return "", nil, fmt.Errorf("expand UserKnownHostsFile %q failed: %w", tokenPath, expErr)
		}
		if expanded == "" || strings.EqualFold(expanded, "none") || expanded == "/dev/null" {
			continue
		}
		if idx == 0 {
			primaryWriteFile = expanded
		}
		st, err := os.Stat(expanded)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return "", nil, fmt.Errorf("stat UserKnownHostsFile %q failed: %w", expanded, err)
			}
			continue
		}
		if st.IsDir() {
			return "", nil, fmt.Errorf("UserKnownHostsFile %q is a directory", expanded)
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
			if strings.EqualFold(tokenPath, "none") || tokenPath == "/dev/null" {
				continue
			}
			expanded, err := expandKnownHostsPath(tokenPath, c.environment, target)
			if err != nil {
				return nil, fmt.Errorf("expand GlobalKnownHostsFile %q failed: %w", tokenPath, err)
			}
			if expanded == "" || strings.EqualFold(expanded, "none") || expanded == "/dev/null" {
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
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func expandKnownHostsPath(pattern string, env Environment, target TargetContext) (string, error) {
	expanded, err := ExpandControlPath(pattern, env, target)
	if err != nil || expanded == "" || strings.EqualFold(expanded, "none") || expanded == "/dev/null" {
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
	knownHostsFileMutex.Lock()
	defer knownHostsFileMutex.Unlock()

	if mkdirErr := os.MkdirAll(filepath.Dir(knownHostsFile), 0700); mkdirErr != nil {
		return fmt.Errorf("create known_hosts directory failed: %w", mkdirErr)
	}

	f, openErr := os.OpenFile(knownHostsFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if openErr != nil {
		return fmt.Errorf("open known_hosts file failed: %w", openErr)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close known_hosts file failed: %w", closeErr)
		}
	}()

	var host string
	if h, p, splitErr := net.SplitHostPort(hostname); splitErr == nil {
		host = khOpenSSHHostPort(khAddr{host: h, port: p})
	} else {
		host = lowercaseSSHHostPreservingZone(knownhosts.Normalize(hostname))
	}
	if hash {
		host = knownhosts.HashHostname(host)
	}
	line := knownhosts.Line([]string{host}, key)
	if _, writeErr := f.WriteString(line + "\n"); writeErr != nil {
		return fmt.Errorf("write known_hosts file failed: %w", writeErr)
	}
	return nil
}
