package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	corelog "github.com/wentf9/xops-cli/core/log"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// SFTPStream represents an active binary stream connected to a remote SFTP subsystem
// or elevated sftp-server binary.
type SFTPStream struct {
	Reader      io.Reader
	WriteCloser io.WriteCloser
	Stderr      io.Reader
	closer      func() error
}

func (s *SFTPStream) Close() error {
	if s == nil || s.closer == nil {
		return nil
	}
	return s.closer()
}

func (s *SFTPStream) Read(p []byte) (int, error) {
	if s == nil || s.Reader == nil {
		return 0, io.EOF
	}
	return s.Reader.Read(p)
}

func (s *SFTPStream) Write(p []byte) (int, error) {
	if s == nil || s.WriteCloser == nil {
		return 0, io.ErrClosedPipe
	}
	return s.WriteCloser.Write(p)
}

type sftpStderrBuffer struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    bytes.Buffer
	err    error
	closed bool
}

func newSFTPStderrBuffer() *sftpStderrBuffer {
	b := &sftpStderrBuffer{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

const maxSFTPStderrCapacity = 256 * 1024

func (b *sftpStderrBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	origLen := len(p)
	if b.buf.Len()+len(p) > maxSFTPStderrCapacity {
		excess := (b.buf.Len() + len(p)) - maxSFTPStderrCapacity
		if excess >= b.buf.Len() {
			b.buf.Reset()
			if len(p) > maxSFTPStderrCapacity {
				p = p[len(p)-maxSFTPStderrCapacity:]
			}
		} else {
			retained := append([]byte(nil), b.buf.Bytes()[excess:]...)
			b.buf.Reset()
			_, _ = b.buf.Write(retained)
		}
	}
	_, err := b.buf.Write(p)
	if err != nil {
		return 0, err
	}
	b.cond.Broadcast()
	return origLen, nil
}

func (b *sftpStderrBuffer) CloseWithError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	b.err = err
	b.cond.Broadcast()
}

func (b *sftpStderrBuffer) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.buf.Len() == 0 {
		if b.closed {
			if b.err != nil {
				return 0, b.err
			}
			return 0, io.EOF
		}
		b.cond.Wait()
	}
	return b.buf.Read(p)
}

func (b *sftpStderrBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (c *Client) resolveSFTPPrivilegeMode(ctx context.Context) (SudoMode, bool, error) {
	if c.isNonPOSIXExecution() {
		return "", false, fmt.Errorf("%w: sudo SFTP is unsupported on non-POSIX platforms", ErrExecutionValidation)
	}

	connCfg := c.ConnectionConfig()
	if connCfg.SudoMode == SudoModeRoot || (connCfg.User == "root" && (connCfg.SudoMode == "" || connCfg.SudoMode == SudoModeAuto)) {
		c.observePrivilege(SudoModeRoot, "mode_selected", 1, 0)
		c.observePrivilege(SudoModeRoot, "escalation_not_required", 1, 0)
		return SudoModeRoot, true, nil
	}

	if err := c.maybeDetectSudoMode(ctx); err != nil {
		return "", false, err
	}

	mode := c.ConnectionConfig().SudoMode
	if mode == SudoModeRoot {
		return SudoModeRoot, true, nil
	}
	if mode != SudoModeSudoer && mode != SudoModeSudo && mode != SudoModeSu {
		return "", false, fmt.Errorf("privilege escalation is unsupported for sudo mode %q", mode)
	}
	return mode, false, nil
}

// OpenSFTPStream opens a binary SFTP stdio stream. When sudo is false, it requests
// the standard "sftp" subsystem. When sudo is true, it detects privilege escalation,
// executes an elevated sftp-server binary on the remote host (or uses the standard
// subsystem if the remote user is root), and performs a clean binary stream handoff.
func (c *Client) OpenSFTPStream(ctx context.Context, sudo bool) (*SFTPStream, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}
	if c == nil || c.sshClient == nil {
		return nil, fmt.Errorf("ssh client is not connected")
	}
	if !sudo {
		return c.openSubsystemSFTPStream(ctx)
	}

	mode, isRoot, err := c.resolveSFTPPrivilegeMode(ctx)
	if err != nil {
		return nil, err
	}
	if isRoot {
		return c.openSubsystemSFTPStream(ctx)
	}

	preResolved, err := c.maybeProbeExecutionForPrivilege(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if preResolved != nil {
			preResolved.Zero()
			preResolved = nil
		}
	}()

	var retErr error
	defer func() { c.observePrivilegeResult(ctx, mode, retErr) }()

	for attempt := 0; attempt < 3; attempt++ {
		c.observePrivilege(mode, "attempt_started", 1, attempt+1)
		stream, err := c.runSFTPStreamAttempt(ctx, mode, attempt > 0, preResolved)
		preResolved = nil
		if err == nil {
			return stream, nil
		}
		retErr = err
		if mode != SudoModeSu || !errors.Is(err, errPrivilegeAuthenticationRejected) || credentialRecoveryPrompter(c.prompter) == nil || attempt == 2 {
			return nil, err
		}
		c.observePrivilege(mode, "exchange_retry", 1, attempt+2)
	}
	return nil, retErr
}

func (c *Client) openSubsystemSFTPStream(ctx context.Context) (*SFTPStream, error) {
	setupCtx, cancelSetup := withTimeoutOrDefault(ctx, c.handshakeTimeout, defaultSSHHandshakeTimeout)
	defer cancelSetup()

	session, err := c.newSessionContext(setupCtx)
	if err != nil {
		return nil, fmt.Errorf("create SSH session failed: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("create SFTP stdin pipe failed: %w", err), c.closeSessionBounded(session))
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("create SFTP stdout pipe failed: %w", err), c.closeSessionBounded(session))
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("create SFTP stderr pipe failed: %w", err), c.closeSessionBounded(session))
	}

	if err := c.sessionRequest(setupCtx, session, "sftp subsystem", func() error {
		return session.RequestSubsystem("sftp")
	}); err != nil {
		return nil, errors.Join(fmt.Errorf("request SFTP subsystem failed: %w", err), c.closeSessionBounded(session))
	}

	closer := sync.OnceValue(func() error {
		sessionErr := c.closeSessionBounded(session)
		outcome := "completed"
		if sessionErr != nil {
			outcome = "failed"
		}
		c.observeDiagnostic(corelog.Diagnostic{
			Kind:        corelog.SessionFinished,
			Level:       1,
			Operation:   "sftp subsystem",
			Outcome:     outcome,
			HasExitCode: sessionErr == nil,
		})
		return sessionErr
	})

	return &SFTPStream{
		Reader:      stdout,
		WriteCloser: stdin,
		Stderr:      stderr,
		closer:      closer,
	}, nil
}

func (c *Client) runSFTPStreamAttempt(ctx context.Context, mode SudoMode, force bool, preResolved *PrivilegeMaterial) (_ *SFTPStream, retErr error) {
	mat, err := c.initPrivilegeAttemptMaterial(ctx, mode, force, preResolved)
	if err != nil {
		return nil, err
	}
	defer func() {
		if mat != nil {
			mat.Zero()
			mat = nil
		}
	}()

	sessionCtx, cancelSession := withTimeoutOrDefault(ctx, c.handshakeTimeout, defaultSSHHandshakeTimeout)
	defer cancelSession()
	session, err := c.newSessionContext(sessionCtx)
	if err != nil {
		return nil, err
	}
	var sessionClosed bool
	defer func() {
		if retErr != nil && !sessionClosed {
			retErr = errors.Join(retErr, c.closeSessionBounded(session))
		}
	}()

	if mode == SudoModeSu {
		if err := c.sessionRequest(ctx, session, "privilege pty", func() error {
			return session.RequestPty("xterm", 40, 80, cryptoSSH.TerminalModes{cryptoSSH.ECHO: 0})
		}); err != nil {
			return nil, fmt.Errorf("request su terminal: %w", err)
		}
	}

	stdinPipe, err := session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("create stdin pipe: %w", err)
	}

	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("create stdout pipe: %w", err)
	}

	stderrPipe, err := session.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("create stderr pipe: %w", err)
	}

	readyNonce := rand.Text()
	readyToken := "[xops-ready-" + readyNonce + "]"
	promptNonce := rand.Text()
	promptToken := "[xops-password-" + promptNonce + "]"
	ackToken := "[xops-continue-" + rand.Text() + "]"
	streamNonce := rand.Text()
	streamToken := "[xops-sftp-stream-" + streamNonce + "]"

	fullCmd := c.buildSFTPStreamScript(mode, readyNonce, promptToken, ackToken, streamNonce)
	c.observePrivilegeCommand(mode, c.buildSFTPStreamScriptPreview(mode))

	if err := c.startPrivilegeSession(ctx, session, fullCmd); err != nil {
		return nil, err
	}

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- c.waitSession(session)
	}()

	leftover, stderrReader, stderrDone, err := c.doSFTPStreamHandshake(ctx, mode, session, stdinPipe, stdoutPipe, stderrPipe, &mat, force, readyToken, promptToken, ackToken, streamToken, waitDone)
	if err != nil {
		sessionClosed = true
		return nil, err
	}

	closer := c.sftpStreamCloser(session, waitDone, stderrDone)

	rd := stdoutPipe
	if len(leftover) > 0 {
		rd = io.MultiReader(bytes.NewReader(leftover), stdoutPipe)
	}

	return &SFTPStream{
		Reader:      rd,
		WriteCloser: stdinPipe,
		Stderr:      stderrReader,
		closer:      closer,
	}, nil
}

func (c *Client) sftpStreamCloser(session *cryptoSSH.Session, waitDone <-chan error, stderrDone <-chan struct{}) func() error {
	return sync.OnceValue(func() error {
		sessionErr := c.closeSessionBounded(session)
		waitTimer := time.NewTimer(sessionShutdownTimeout)
		defer waitTimer.Stop()
		var timedOut bool
		var waitErr error
		select {
		case waitErr = <-waitDone:
		case <-waitTimer.C:
			timedOut = true
			interruptErr := c.Interrupt()
			waitErr = <-waitDone
			waitErr = errors.Join(fmt.Errorf("sftp session shutdown timed out after %s", sessionShutdownTimeout), interruptErr, waitErr)
		}
		if stderrDone != nil {
			select {
			case <-stderrDone:
			case <-time.After(sessionShutdownTimeout):
			}
		}
		if !timedOut {
			var exitErr *cryptoSSH.ExitError
			var exitMissingErr *cryptoSSH.ExitMissingError
			if errors.As(waitErr, &exitMissingErr) || errors.Is(waitErr, io.EOF) || errors.Is(waitErr, net.ErrClosed) {
				waitErr = nil
			} else if errors.As(waitErr, &exitErr) && (exitErr.ExitStatus() == 0 || exitErr.ExitStatus() == 255) {
				waitErr = nil
			}
		}
		return errors.Join(sessionErr, waitErr)
	})
}

func (c *Client) buildSFTPStreamScript(mode SudoMode, readyNonce, promptToken, ackToken, streamNonce string) string {
	var ptyFix string
	var execSuffix string
	if mode == SudoModeSu {
		ptyFix = "stty raw -echo -isig -ixon -ixoff -opost -iexten 2>/dev/null || true; "
		execSuffix = " 2>/dev/null"
	}
	inner := fmt.Sprintf(`printf '[xops-ready-%%s]' %s && IFS= read -r xops_credential_ack && test "$xops_credential_ack" = %s && unset xops_credential_ack && { xops_sftp_bin=""; for p in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server /usr/lib/ssh/sftp-server /usr/libexec/sftp-server /usr/local/libexec/sftp-server /usr/local/lib/openssh/sftp-server /usr/lib/misc/sftp-server /usr/lib64/misc/sftp-server /usr/lib64/ssh/sftp-server /usr/lib64/openssh/sftp-server /usr/sbin/sftp-server /usr/bin/sftp-server; do if [ -x "$p" ]; then xops_sftp_bin="$p"; break; fi; done; if [ -z "$xops_sftp_bin" ]; then p=$(command -v sftp-server 2>/dev/null); if [ -n "$p" ] && [ -x "$p" ]; then xops_sftp_bin="$p"; fi; fi; if [ -z "$xops_sftp_bin" ]; then for conf in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do if [ -r "$conf" ]; then p=$(awk 'tolower($1)=="subsystem" && tolower($2)=="sftp" { print $3; exit }' "$conf" 2>/dev/null); case "$p" in /*) if [ -x "$p" ]; then xops_sftp_bin="$p"; break; fi ;; esac; fi; done; fi; if [ -z "$xops_sftp_bin" ]; then echo "sftp-server binary not found" >&2; exit 127; fi; %sprintf '[xops-sftp-stream-%%s]' %s; exec "$xops_sftp_bin"%s; }`, shellQuote(readyNonce), shellQuote(ackToken), ptyFix, shellQuote(streamNonce), execSuffix)

	quote := shellQuote
	if exec := c.privilegeExecution(); exec != nil {
		switch exec.LaunchDialect {
		case LaunchFish:
			quote = fishQuote
		case LaunchCsh:
			quote = cshQuote
		}
	}

	switch mode {
	case SudoModeSu:
		suBody := "exec /bin/sh -c " + shellQuote(inner)
		return "env LC_ALL=C su - root -c " + quote(suBody)
	case SudoModeSudoer:
		return "sudo -n -S -p " + quote(promptToken) + " -- /bin/sh -c " + quote(inner)
	case SudoModeSudo:
		return "sudo -S -p " + quote(promptToken) + " -- /bin/sh -c " + quote(inner)
	default:
		return inner
	}
}

func (c *Client) buildSFTPStreamScriptPreview(mode SudoMode) string {
	quote := shellQuote
	if exec := c.privilegeExecution(); exec != nil {
		switch exec.LaunchDialect {
		case LaunchFish:
			quote = fishQuote
		case LaunchCsh:
			quote = cshQuote
		}
	}
	switch mode {
	case SudoModeSu:
		suBody := "exec /bin/sh -c " + shellQuote("<sftp-server payload>")
		return "env LC_ALL=C su - root -c " + quote(suBody)
	case SudoModeSudoer:
		return "sudo -n -S -p " + quote("<password-prompt>") + " -- /bin/sh -c " + quote("<sftp-server payload>")
	case SudoModeSudo:
		return "sudo -S -p " + quote("<password-prompt>") + " -- /bin/sh -c " + quote("<sftp-server payload>")
	default:
		return "<sftp-server payload>"
	}
}

func findPromptMatch(data []byte, pattern *regexp.Regexp, expand bool, initialLine privilegeLinePrefix) ([]int, bool) {
	if pattern == nil {
		return nil, false
	}
	line := initialLine
	scanned := 0
	search := 0
	for search <= len(data) {
		sub := pattern.FindIndex(data[search:])
		if sub == nil {
			break
		}
		loc := []int{search + sub[0], search + sub[1]}
		if loc[0] == loc[1] {
			if loc[1] == len(data) {
				break
			}
			_, size := utf8.DecodeRune(data[loc[1]:])
			search = loc[1] + size
			continue
		}
		line = advancePrivilegeLine(line, data[scanned:loc[0]])
		scanned = loc[0]
		search = loc[1]
		if privilegeXtraceAt(line, data[loc[0]:]) {
			continue
		}
		if expand {
			full := expandSudoPrompt(data, loc)
			return full, full == nil
		}
		return loc, false
	}
	return nil, false
}

func findSudoPrompt(data []byte, promptPattern, fallbackPattern *regexp.Regexp, marker string, linePrefix privilegeLinePrefix) (match []int, isFallback bool, incomplete bool) {
	if promptPattern != nil {
		match, inc := findPromptMatch(data, promptPattern, true, linePrefix)
		if inc {
			return nil, false, true
		}
		if match != nil {
			return match, false, false
		}
	}
	if fallbackPattern != nil {
		if incompleteSudoPrompt(data, marker) {
			return nil, false, true
		}
		match, inc := findPromptMatch(data, fallbackPattern, false, linePrefix)
		if inc {
			return nil, false, true
		}
		if match != nil {
			return match, true, false
		}
	}
	if incompleteSudoPrompt(data, marker) {
		return nil, false, true
	}
	return nil, false, false
}

var xopsTokenPattern = regexp.MustCompile(`\[xops-[a-zA-Z0-9_-]+\]`)

func sanitizeTrailingOutput(data []byte) string {
	text := string(data)
	text = strings.ReplaceAll(text, "\r", "")
	text = xopsTokenPattern.ReplaceAllString(text, "")
	text = strings.TrimSpace(text)
	if len(text) > 512 {
		text = text[len(text)-512:]
	}
	text = strings.ToValidUTF8(text, "")
	return strings.TrimSpace(text)
}

func checkSudoAuthFailures(text string, ch chan<- struct{}) {
	if strings.Contains(text, "incorrect password") ||
		strings.Contains(text, "Sorry, try again") ||
		strings.Contains(text, "3 incorrect password attempts") ||
		strings.Contains(text, "a password is required") {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func checkSuAuthFailures(text string, ch chan<- struct{}) {
	if strings.Contains(text, "su: Authentication failure") ||
		strings.Contains(text, "su: incorrect password") ||
		strings.Contains(text, "su: Sorry") {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func streamDone(ctx context.Context) <-chan struct{} {
	if ctx == nil {
		return nil
	}
	return ctx.Done()
}

//nolint:gocyclo // Multi-channel privilege handshake coordinates password prompts, ack handoff, stream detection, and exit errors.
func (c *Client) doSFTPStreamHandshake(
	ctx context.Context,
	mode SudoMode,
	session *cryptoSSH.Session,
	stdinPipe io.WriteCloser,
	stdoutPipe io.Reader,
	stderrPipe io.Reader,
	matPtr **PrivilegeMaterial,
	force bool,
	readyToken, promptToken, ackToken, streamToken string,
	waitDone <-chan error,
) ([]byte, io.Reader, <-chan struct{}, error) {
	// 1. Password prompt pattern setup
	var suPromptPattern *regexp.Regexp
	var sudoPromptPattern *regexp.Regexp

	switch mode {
	case SudoModeSu:
		suPromptPattern = c.passwordPromptRegex()
		if suPromptPattern == nil {
			suPromptPattern = regexp.MustCompile(`(?i)(?:password|密码)[^:\n]*:[\t ]*$`)
		}
		c.observePrivilegePromptPattern(mode, suPromptPattern.String(), "", false)
	case SudoModeSudo:
		sudoPromptPattern = regexp.MustCompile(regexp.QuoteMeta(promptToken))
		c.observePrivilegePromptPattern(mode, sudoPromptPattern.String(), promptToken, false)
		if c.sudoPromptFallback != nil {
			c.observePrivilegePromptPattern(mode, c.sudoPromptFallback.String(), promptToken, true)
		}
	}

	// 2. Stderr reader goroutine: feeds stderrBuf, which is exposed via SFTPStream.Stderr
	stderrBuf := newSFTPStderrBuffer()
	stderrPromptCh := make(chan struct{}, 1)
	stderrAuthFailCh := make(chan struct{}, 1)
	stderrDone := make(chan struct{})

	var handoffDone atomic.Bool

	go func() {
		defer close(stderrDone)
		buf := make([]byte, 2048)
		var pending []byte
		var feedback sudoPromptFeedback
		linePrefix := privilegeLineStart

		for {
			n, err := stderrPipe.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				if mode != SudoModeSudo || handoffDone.Load() {
					if len(pending) > 0 {
						text := string(pending)
						checkSudoAuthFailures(text, stderrAuthFailCh)
						_, _ = stderrBuf.Write(pending)
						pending = nil
					}
					_, _ = stderrBuf.Write(chunk)
				} else {
					pending = append(pending, chunk...)
					for len(pending) > 0 {
						beforeFeedback := pending
						pending = feedback.consume(pending)
						if consumed := len(beforeFeedback) - len(pending); consumed > 0 {
							linePrefix = advancePrivilegeLine(linePrefix, beforeFeedback[:consumed])
						}
						match, isFallback, incomplete := findSudoPrompt(pending, sudoPromptPattern, c.sudoPromptFallback, promptToken, linePrefix)
						if match != nil {
							// Write bytes before the prompt to stderrBuf without leaking prompt
							if match[0] > 0 {
								text := string(pending[:match[0]])
								checkSudoAuthFailures(text, stderrAuthFailCh)
								_, _ = stderrBuf.Write(pending[:match[0]])
							}
							if isFallback {
								c.observePrivilege(mode, "password_prompt_fallback", 2, 0)
							}
							c.observePrivilegePrompt(mode, string(pending[match[0]:match[1]]), promptToken)
							select {
							case stderrPromptCh <- struct{}{}:
							default:
							}
							if !isFallback && bytes.HasPrefix(pending[match[0]:match[1]], []byte(sudoRSPromptPrefix)) {
								feedback = true
							}
							linePrefix = privilegeLineStart
							pending = append(pending[:0], pending[match[1]:]...)
							continue
						}
						if incomplete {
							break
						}
						const retainSize = 64
						if len(pending) > retainSize {
							writeLen := len(pending) - retainSize
							text := string(pending[:writeLen])
							checkSudoAuthFailures(text, stderrAuthFailCh)
							_, _ = stderrBuf.Write(pending[:writeLen])
							linePrefix = advancePrivilegeLine(linePrefix, pending[:writeLen])
							pending = append(pending[:0], pending[writeLen:]...)
						}
						break
					}
				}
			}
			if err != nil {
				if len(pending) > 0 {
					text := string(pending)
					checkSudoAuthFailures(text, stderrAuthFailCh)
					_, _ = stderrBuf.Write(pending)
					pending = nil
				}
				stderrBuf.CloseWithError(err)
				return
			}
		}
	}()

	stderrReader := stderrBuf

	// 3. Stdout reader goroutine: detects tokens, prompts (for Su), and stops upon streamToken
	type stdoutResult struct {
		leftover []byte
		err      error
	}
	stdoutResultCh := make(chan stdoutResult, 1)
	stdoutPromptCh := make(chan struct{}, 1)
	stdoutReadyCh := make(chan struct{}, 1)
	stdoutAckProceedCh := make(chan struct{}, 1)
	stdoutAuthFailCh := make(chan struct{}, 1)
	stdoutDone := make(chan struct{})

	doneCh := make(chan struct{})
	var closeDoneOnce sync.Once
	closeDone := func() {
		closeDoneOnce.Do(func() {
			close(doneCh)
		})
	}
	defer closeDone()

	var stdoutTrailingMu sync.Mutex
	var stdoutTrailing []byte

	updateStdoutTrailing := func(chunk []byte) {
		stdoutTrailingMu.Lock()
		defer stdoutTrailingMu.Unlock()
		stdoutTrailing = append(stdoutTrailing, chunk...)
		if len(stdoutTrailing) > 4096 {
			stdoutTrailing = append(stdoutTrailing[:0], stdoutTrailing[len(stdoutTrailing)-4096:]...)
		}
	}

	getStdoutTrailing := func() string {
		stdoutTrailingMu.Lock()
		defer stdoutTrailingMu.Unlock()
		return sanitizeTrailingOutput(stdoutTrailing)
	}

	go func() {
		defer close(stdoutDone)
		buf := make([]byte, 4096)
		var pending []byte
		readySent := false
		const maxStdoutPending = 32 * 1024
		const retainStdoutPending = 4096

		for {
			n, err := stdoutPipe.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				updateStdoutTrailing(chunk)
				pending = append(pending, chunk...)

				// 1. Check for ready token FIRST before checking for su password prompt
				if !readySent {
					if idx := bytes.Index(pending, []byte(readyToken)); idx >= 0 {
						readySent = true
						pending = append(pending[:0], pending[idx+len(readyToken):]...)
						// Reset trailing buffer to capture output starting after readyToken
						stdoutTrailingMu.Lock()
						stdoutTrailing = append(stdoutTrailing[:0], pending...)
						stdoutTrailingMu.Unlock()

						select {
						case stdoutReadyCh <- struct{}{}:
						case <-doneCh:
							return
						}
						// Wait for coordinator to write ackToken to stdin
						select {
						case <-stdoutAckProceedCh:
						case <-doneCh:
							return
						}
						if idx := bytes.Index(pending, []byte(streamToken)); idx >= 0 {
							leftover := make([]byte, len(pending)-idx-len(streamToken))
							copy(leftover, pending[idx+len(streamToken):])
							stdoutResultCh <- stdoutResult{leftover: leftover}
							return
						}
					}
				}

				// 2. Only if not readySent, check for su password prompt and auth failures
				if !readySent && mode == SudoModeSu {
					checkSuAuthFailures(string(pending), stdoutAuthFailCh)

					if suPromptPattern != nil {
						loc, _ := findPromptMatch(pending, suPromptPattern, false, privilegeLineStart)
						if loc != nil {
							c.observePrivilegePrompt(mode, string(pending[loc[0]:loc[1]]), "")
							select {
							case stdoutPromptCh <- struct{}{}:
							default:
							}
							pending = append(pending[:0], pending[loc[1]:]...)
						}
					}
				}

				// 3. Check for stream token
				if readySent {
					if idx := bytes.Index(pending, []byte(streamToken)); idx >= 0 {
						leftover := make([]byte, len(pending)-idx-len(streamToken))
						copy(leftover, pending[idx+len(streamToken):])
						stdoutResultCh <- stdoutResult{leftover: leftover}
						return // Stop reading! Next reads will be done by caller via io.MultiReader.
					}
				}

				// 4. Bound pending buffer size to prevent unbounded memory growth
				if len(pending) > maxStdoutPending {
					discardLen := len(pending) - retainStdoutPending
					if !readySent && mode == SudoModeSu {
						checkSuAuthFailures(string(pending[:discardLen]), stdoutAuthFailCh)
					}
					pending = append(pending[:0], pending[discardLen:]...)
				}
			}
			if err != nil {
				stdoutResultCh <- stdoutResult{err: err}
				return
			}
		}
	}()

	var notConfirmedOnce sync.Once
	observeElevationNotConfirmed := func() {
		notConfirmedOnce.Do(func() {
			if !handoffDone.Load() {
				c.observePrivilege(mode, "elevation_not_confirmed", 1, 0)
			}
		})
	}

	// Cleanup on failure joins reader goroutines and session
	cleanupOnFailure := func(waitErrConsumed bool) error {
		closeDone()
		observeElevationNotConfirmed()
		var closeErr error
		if !waitErrConsumed {
			closeErr = c.closeCanceledSession(ctx, session, waitDone)
		} else {
			closeErr = c.closeSessionBounded(session)
		}

		select {
		case <-stderrDone:
		case <-time.After(sessionShutdownTimeout):
		}

		select {
		case <-stdoutDone:
		case <-time.After(sessionShutdownTimeout):
		}

		return closeErr
	}

	// 4. Coordinator loop
	attempts := 0
	passwordSent := false
	authFailed := false

	authTimeout := c.interactionTimeout
	if authTimeout <= 0 {
		authTimeout = DefaultInteractionTimeout
	}
	authTimer := time.NewTimer(authTimeout)
	defer authTimer.Stop()

	resetAuthTimer := func() {
		if !authTimer.Stop() {
			select {
			case <-authTimer.C:
			default:
			}
		}
		authTimer.Reset(authTimeout)
	}

	var streamCtx context.Context
	var cancelStream context.CancelFunc
	defer func() {
		if cancelStream != nil {
			cancelStream()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			cleanupErr := cleanupOnFailure(false)
			return nil, nil, nil, cleanupErr

		case <-authTimer.C:
			if ctx.Err() != nil {
				cleanupErr := cleanupOnFailure(false)
				return nil, nil, nil, cleanupErr
			}
			err := fmt.Errorf("wait for privilege authentication: %w", context.DeadlineExceeded)
			cleanupErr := cleanupOnFailure(false)
			return nil, nil, nil, errors.Join(err, cleanupErr)

		case <-streamDone(streamCtx):
			err := streamCtx.Err()
			if ctx.Err() != nil {
				cleanupErr := cleanupOnFailure(false)
				return nil, nil, nil, cleanupErr
			}
			fullErr := fmt.Errorf("wait for sftp stream token: %w", err)
			cleanupErr := cleanupOnFailure(false)
			return nil, nil, nil, errors.Join(fullErr, cleanupErr)

		case waitErr := <-waitDone:
			// Drain stderrPipe and stdoutPipe before inspecting buffers on failure
			select {
			case <-stderrDone:
			case <-time.After(sessionShutdownTimeout):
			}
			select {
			case <-stdoutDone:
			case <-time.After(sessionShutdownTimeout):
			}
			errMsg := strings.TrimSpace(stderrBuf.String())
			if errMsg == "" {
				errMsg = strings.TrimSpace(getStdoutTrailing())
			}
			var exitErr *cryptoSSH.ExitError
			if errors.As(waitErr, &exitErr) && exitErr.ExitStatus() == 127 {
				cleanupErr := cleanupOnFailure(true)
				return nil, nil, nil, errors.Join(fmt.Errorf("remote sftp-server binary not found"), cleanupErr)
			}
			if !handoffDone.Load() && (attempts > 0 || passwordSent) && (authFailed || (errors.As(waitErr, &exitErr) && exitErr.ExitStatus() != 0)) {
				c.observePrivilege(mode, "authentication_rejected", 1, 0)
				cleanupErr := cleanupOnFailure(true)
				return nil, nil, nil, errors.Join(errPrivilegeAuthenticationRejected, cleanupErr)
			}
			if waitErr != nil {
				cleanupErr := cleanupOnFailure(true)
				if errMsg != "" {
					return nil, nil, nil, errors.Join(fmt.Errorf("privilege sftp setup failed (%w): %s", waitErr, errMsg), cleanupErr)
				}
				return nil, nil, nil, errors.Join(fmt.Errorf("privilege sftp setup failed: %w", waitErr), cleanupErr)
			}
			cleanupErr := cleanupOnFailure(true)
			return nil, nil, nil, errors.Join(fmt.Errorf("privilege sftp session ended before stream start"), cleanupErr)

		case <-stderrAuthFailCh:
			authFailed = true

		case <-stdoutAuthFailCh:
			authFailed = true

		case <-stderrPromptCh:
			c.observePrivilege(mode, "password_prompt", 2, attempts+1)
			if attempts >= 3 || (attempts > 0 && credentialRecoveryPrompter(c.prompter) == nil) {
				c.observePrivilege(mode, "retry_limit", 1, attempts+1)
				c.observePrivilege(mode, "authentication_rejected", 1, 0)
				cleanupErr := cleanupOnFailure(false)
				return nil, nil, nil, errors.Join(errPrivilegeAuthenticationRejected, cleanupErr)
			}
			if attempts > 0 {
				c.observePrivilege(mode, "password_retry", 1, attempts+1)
			}
			if *matPtr == nil || attempts > 0 {
				newMat, err := c.resolvePrivilegeMaterial(ctx, SecretKindSudoPassword, force || attempts > 0)
				if err != nil {
					cleanupErr := cleanupOnFailure(false)
					return nil, nil, nil, errors.Join(err, cleanupErr)
				}
				if *matPtr != nil {
					(*matPtr).Zero()
				}
				*matPtr = newMat
			}
			if _, err := fmt.Fprintf(stdinPipe, "%s\n", (*matPtr).Password); err != nil {
				cleanupErr := cleanupOnFailure(false)
				return nil, nil, nil, errors.Join(fmt.Errorf("send privilege response: %w", err), cleanupErr)
			}
			passwordSent = true
			attempts++
			c.observePrivilege(mode, "password_response_sent", 2, attempts)
			resetAuthTimer()

		case <-stdoutPromptCh:
			c.observePrivilege(mode, "password_prompt", 2, attempts+1)
			if attempts >= 1 {
				// In SudoModeSu, su only accepts one password per session; limit to one password submission per su session.
				c.observePrivilege(mode, "retry_limit", 1, attempts+1)
				c.observePrivilege(mode, "authentication_rejected", 1, 0)
				cleanupErr := cleanupOnFailure(false)
				return nil, nil, nil, errors.Join(errPrivilegeAuthenticationRejected, cleanupErr)
			}
			if attempts > 0 {
				c.observePrivilege(mode, "password_retry", 1, attempts+1)
			}
			if *matPtr == nil || attempts > 0 {
				newMat, err := c.resolvePrivilegeMaterial(ctx, SecretKindSuPassword, force || attempts > 0)
				if err != nil {
					cleanupErr := cleanupOnFailure(false)
					return nil, nil, nil, errors.Join(err, cleanupErr)
				}
				if *matPtr != nil {
					(*matPtr).Zero()
				}
				*matPtr = newMat
			}
			if _, err := fmt.Fprintf(stdinPipe, "%s\n", (*matPtr).Password); err != nil {
				cleanupErr := cleanupOnFailure(false)
				return nil, nil, nil, errors.Join(fmt.Errorf("send privilege response: %w", err), cleanupErr)
			}
			passwordSent = true
			attempts++
			c.observePrivilege(mode, "password_response_sent", 2, attempts)
			resetAuthTimer()

		case <-stdoutReadyCh:
			authTimer.Stop()
			handoffDone.Store(true)
			authFailed = false
			c.observePrivilege(mode, "elevated_shell_ready", 1, 0)
			if _, err := fmt.Fprintf(stdinPipe, "%s\n", ackToken); err != nil {
				cleanupErr := cleanupOnFailure(false)
				return nil, nil, nil, errors.Join(fmt.Errorf("confirm privilege readiness: %w", err), cleanupErr)
			}
			c.observePrivilege(mode, "handoff_ack_sent", 3, 0)
			if passwordSent && *matPtr != nil {
				(*matPtr).verified = true
				if err := c.confirmPrivilege(ctx, *matPtr); err != nil {
					cleanupErr := cleanupOnFailure(false)
					return nil, nil, nil, errors.Join(err, cleanupErr)
				}
			}
			// Apply handshake timeout while waiting for streamToken
			streamCtx, cancelStream = withTimeoutOrDefault(ctx, c.handshakeTimeout, defaultSSHHandshakeTimeout)
			stdoutAckProceedCh <- struct{}{}

		case res := <-stdoutResultCh:
			if res.err != nil {
				select {
				case <-stderrDone:
				case <-time.After(sessionShutdownTimeout):
				}
				select {
				case <-stdoutDone:
				case <-time.After(sessionShutdownTimeout):
				}
				errMsg := strings.TrimSpace(stderrBuf.String())
				if errMsg == "" {
					errMsg = strings.TrimSpace(getStdoutTrailing())
				}
				var waitErr error
				var waitConsumed bool
				select {
				case waitErr = <-waitDone:
					waitConsumed = true
				case <-time.After(sessionShutdownTimeout):
				}
				var exitErr *cryptoSSH.ExitError
				if errors.As(waitErr, &exitErr) && exitErr.ExitStatus() == 127 {
					cleanupErr := cleanupOnFailure(waitConsumed)
					return nil, nil, nil, errors.Join(fmt.Errorf("remote sftp-server binary not found"), cleanupErr)
				}
				if !handoffDone.Load() && (attempts > 0 || passwordSent) && (authFailed || (errors.As(waitErr, &exitErr) && exitErr.ExitStatus() != 0)) {
					c.observePrivilege(mode, "authentication_rejected", 1, 0)
					cleanupErr := cleanupOnFailure(waitConsumed)
					return nil, nil, nil, errors.Join(errPrivilegeAuthenticationRejected, cleanupErr)
				}
				if waitErr != nil {
					cleanupErr := cleanupOnFailure(waitConsumed)
					if errMsg != "" {
						return nil, nil, nil, errors.Join(fmt.Errorf("privilege sftp setup failed (%w): %s", waitErr, errMsg), cleanupErr)
					}
					return nil, nil, nil, errors.Join(fmt.Errorf("privilege sftp setup failed: %w", waitErr), cleanupErr)
				}
				cleanupErr := cleanupOnFailure(waitConsumed)
				if errMsg != "" {
					return nil, nil, nil, errors.Join(fmt.Errorf("read privilege sftp stream (%w): %s", res.err, errMsg), cleanupErr)
				}
				return nil, nil, nil, errors.Join(fmt.Errorf("read privilege sftp stream: %w", res.err), cleanupErr)
			}
			c.observePrivilege(mode, "sftp_stream_ready", 1, 0)
			return res.leftover, stderrReader, stderrDone, nil
		}
	}
}
