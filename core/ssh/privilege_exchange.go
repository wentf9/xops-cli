package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	cryptoSSH "golang.org/x/crypto/ssh"
)

var errPrivilegeAuthenticationRejected = errors.New("privilege authentication rejected before command start")

// privilegeExchange separates authentication input from command input. A random
// ready frame is emitted inside the elevated shell, before any user command.
// Passwords are sent only on a prompt; ordinary stdin is untouched until ready.
type privilegeExchange struct {
	client                            *Client
	mode                              SudoMode
	readyToken, promptToken, ackToken string
	ready                             chan struct{}
	prompts                           chan struct{}
	readyOnce                         sync.Once
	mu                                sync.Mutex
	outputMu                          sync.Mutex
	writeErr                          error
	rejected                          bool
	material                          *PrivilegeMaterial // owned by input worker, then by its joining caller
	passwordSent                      bool
	forcePrompt                       bool
	outputErrors                      chan struct{}
	terminal                          *privilegeTerminal
	session                           *cryptoSSH.Session
	terminalToken                     string
	terminalReady                     chan struct{}
	terminalOnce                      sync.Once
	interpreter                       Interpreter
	launchDialect                     LaunchDialect
	commandPreview                    string // Setup-owned; populated by the same wrapper as the actual invocation.
}

func newPrivilegeExchange(c *Client, mode SudoMode, force bool, interp ...Interpreter) *privilegeExchange {
	selectedInterp := InterpreterBash
	if len(interp) > 0 && interp[0] != "" {
		selectedInterp = interp[0]
	}
	exchange := &privilegeExchange{
		client:       c,
		mode:         mode,
		interpreter:  selectedInterp,
		readyToken:   "[xops-ready-" + rand.Text() + "]",
		promptToken:  "[xops-password-" + rand.Text() + "]",
		ackToken:     "[xops-continue-" + rand.Text() + "]",
		ready:        make(chan struct{}),
		prompts:      make(chan struct{}, 3),
		forcePrompt:  force,
		outputErrors: make(chan struct{}, 1),
	}
	if execution := c.privilegeExecution(); execution != nil {
		exchange.launchDialect = execution.LaunchDialect
	}
	return exchange
}
func (e *privilegeExchange) started() bool {
	select {
	case <-e.ready:
		return true
	default:
		return false
	}
}
func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
func (e *privilegeExchange) command(command string) string {
	if (e.terminal != nil && e.terminal.portableControl) || e.launchDialect == LaunchFish || e.interpreter == InterpreterFish || e.interpreter == InterpreterZsh {
		return e.portableCommand(command)
	}
	shellName := "bash"
	if e.interpreter == InterpreterSh {
		shellName = "sh"
	}
	if command == "" {
		if e.interpreter == InterpreterSh {
			command = "exec sh"
		} else {
			command = "exec " + shellName + " -l"
		}
	}
	e.commandPreview = e.wrapCommandBody("<privileged payload>", "<password-prompt>")
	return e.wrapCommandBody(e.body(command), e.promptToken)
}

func (e *privilegeExchange) wrapCommandBody(body, prompt string) string {
	shellName := "bash"
	if e.interpreter == InterpreterSh {
		shellName = "sh"
	}
	if e.mode == SudoModeSu {
		return "export LC_ALL=C; su - root -c " + shellQuote("exec "+shellName+" -c "+shellQuote(body))
	}
	prefix := "sudo -S -p "
	if e.terminal != nil {
		prefix = "sudo -i -S -p "
		body = sudoLoginScript(body)
	}
	return prefix + shellQuote(prompt) + " -- " + shellName + " -c " + shellQuote(body)
}

func (e *privilegeExchange) input(ctx context.Context, stdin io.Reader, pipe io.WriteCloser) error {
	timeout := e.client.interactionTimeout
	if timeout <= 0 {
		timeout = DefaultInteractionTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	attempts := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			return fmt.Errorf("wait for privilege authentication: %w", context.DeadlineExceeded)
		case <-e.ready:
			return e.forwardInput(ctx, stdin, pipe)
		case <-e.prompts:
			e.client.observePrivilege(e.mode, "password_prompt", 2, attempts+1)
			sent, err := e.respond(ctx, pipe, attempts)
			if err != nil {
				return err
			}
			if sent {
				attempts++
			}

		}
	}
}

// Each SSH output stream owns its own frame buffer. Shared state only contains
// metadata and channels. Matching stops after ready so command output is opaque.
type privilegeFrameWriter struct {
	exchange        *privilegeExchange
	target          io.Writer
	pending         []byte
	prompt          *regexp.Regexp
	writeErr        error
	failed          bool
	feedback        sudoPromptFeedback
	fallbackMatched bool // Owned by this output stream, reset on every prompt search.
	linePrefix      privilegeLinePrefix
	regexpPrefix    byte                              // Zero means a fresh matching region, otherwise a preceding boundary class.
	contextPatterns map[*regexp.Regexp]*regexp.Regexp // Stream-owned lazy cache: primary and optional fallback only.
}

func (w *privilegeFrameWriter) Write(data []byte) (int, error) {
	n := len(data)
	if w.exchange.outputReady() {
		if err := w.flush(); err != nil {
			return 0, err
		}
		return w.writeBytes(data)
	}
	w.pending = append(w.pending, data...)
	for !w.exchange.outputReady() {
		w.pending = w.feedback.consume(w.pending)
		token := w.exchange.readyToken
		var prompt []int
		if w.exchange.started() {
			token = w.exchange.terminalToken
		} else {
			prompt = w.promptIndex()
		}
		ready := bytes.Index(w.pending, []byte(token))
		if ready >= 0 && (prompt == nil || w.fallbackMatched || ready < prompt[0]) {
			if err := w.emit(w.pending[:ready]); err != nil {
				return 0, err
			}
			w.consumeFrame(ready + len(token))
			if !w.exchange.started() {
				w.exchange.readyOnce.Do(func() {
					w.exchange.client.observePrivilege(w.exchange.mode, "elevated_shell_ready", 1, 0)
					close(w.exchange.ready)
				})
			} else {
				w.exchange.terminalOnce.Do(func() {
					w.exchange.client.observePrivilege(w.exchange.mode, "terminal_handoff_confirmed", 3, 0)
					close(w.exchange.terminalReady)
				})
			}
			if w.exchange.outputReady() {
				return n, w.flush()
			}
			continue
		}
		if prompt == nil {
			break
		}
		if err := w.emit(w.pending[:prompt[0]]); err != nil {
			return 0, err
		}
		w.observePrompt(prompt)
		w.feedback = sudoPromptFeedback(w.exchange.mode == SudoModeSudo && bytes.HasPrefix(w.pending[prompt[0]:prompt[1]], []byte(sudoRSPromptPrefix)))
		w.consumeFrame(prompt[1])
		select {
		case w.exchange.prompts <- struct{}{}:
		default:
			err := fmt.Errorf("too many privilege prompts")
			w.recordError(err)
			return 0, err
		}
	}
	// Bounded look-behind supports fragmented prompts without retaining banners.
	const lookBehind = 4096
	if len(w.pending) > lookBehind {
		count := len(w.pending) - lookBehind
		if err := w.emit(w.pending[:count]); err != nil {
			return 0, err
		}
		w.rememberDiscarded(w.pending[:count])
		w.pending = append(w.pending[:0], w.pending[count:]...)
	}
	return n, nil
}
func (w *privilegeFrameWriter) emit(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if !w.exchange.started() {
		text := string(data)
		if strings.Contains(text, "su: Authentication failure") || strings.Contains(text, "su: incorrect password") || strings.Contains(text, "su: Sorry") {
			w.exchange.mu.Lock()
			w.exchange.rejected = true
			w.exchange.mu.Unlock()
		}
	}
	_, err := w.writeBytes(data)
	return err
}
func (w *privilegeFrameWriter) flush() error {
	var err error
	if !w.failed {
		err = w.emit(w.pending)
	}
	clear(w.pending)
	w.consumeFrame(len(w.pending))
	w.pending = nil
	return err
}

func (c *Client) parsePrivilegeOperationOptions(options ...any) (terminal *privilegeTerminal, cancelOutput context.CancelFunc, config *RunConfig, preResolved *PrivilegeMaterial) {
	config = c.defaultPrivilegeRunConfig()
	for _, opt := range options {
		switch v := opt.(type) {
		case *privilegeTerminal:
			terminal = v
		case Interpreter:
			config.Interpreter = v
		case context.CancelFunc:
			cancelOutput = v
		case *RunConfig:
			if v != nil {
				copied := *v
				config = &copied
			}
		case *PrivilegeMaterial:
			preResolved = v
		}
	}
	return terminal, cancelOutput, config, preResolved
}

func (c *Client) runPrivilegeOperation(ctx context.Context, mode SudoMode, command string, stdin io.Reader, stdout, stderr io.Writer, options ...any) (retErr error) {
	if ctx == nil || c == nil {
		return fmt.Errorf("privilege execution requires a client and context")
	}
	if mode != SudoModeSudo && mode != SudoModeSu && mode != SudoModeSudoer {
		return fmt.Errorf("unsupported privilege exchange mode %q", mode)
	}
	if err := validateCommandStdin(stdin, c.environment.InputBridge); err != nil {
		return err
	}
	terminal, cancelOutput, config, preResolved := c.parsePrivilegeOperationOptions(options...)
	if terminal != nil && terminal.activate == nil {
		return fmt.Errorf("privilege terminal activation is missing")
	}
	defer func() { c.observePrivilegeResult(ctx, mode, retErr) }()
	for attempt := 0; attempt < 3; attempt++ {
		c.observePrivilege(mode, "attempt_started", 1, attempt+1)
		err := c.runPrivilegeAttempt(ctx, mode, command, stdin, stdout, stderr, attempt > 0, terminal, config, cancelOutput, preResolved)
		preResolved = nil
		if mode != SudoModeSu || !errors.Is(err, errPrivilegeAuthenticationRejected) || credentialRecoveryPrompter(c.prompter) == nil || attempt == 2 {
			return err
		}
		c.observePrivilege(mode, "exchange_retry", 1, attempt+2)
	}
	return errPrivilegeAuthenticationRejected
}

func (c *Client) initPrivilegeAttemptMaterial(ctx context.Context, mode SudoMode, force bool, preResolved ...*PrivilegeMaterial) (*PrivilegeMaterial, error) {
	if len(preResolved) > 0 && preResolved[0] != nil && !force {
		return preResolved[0], nil
	}
	if mode == SudoModeSudoer || credentialRecoveryPrompter(c.prompter) != nil {
		return nil, nil
	}
	kind := SecretKindSudoPassword
	if mode == SudoModeSu {
		kind = SecretKindSuPassword
	}
	value, err := c.resolvePrivilegeMaterial(ctx, kind, force)
	if err != nil {
		return nil, fmt.Errorf("%s password is required but not provided: %w", mode, err)
	}
	return value, nil
}

func (c *Client) runPrivilegeAttempt(ctx context.Context, mode SudoMode, command string, stdin io.Reader, stdout, stderr io.Writer, force bool, terminal *privilegeTerminal, config *RunConfig, cancelOuterOutput context.CancelFunc, preResolved ...*PrivilegeMaterial) (retErr error) {
	exchange := newPrivilegeExchange(c, mode, force, config.Interpreter)
	exchange.launchDialect = config.LaunchDialect
	exchange.terminal = terminal
	if terminal != nil {
		exchange.terminalToken = "[xops-terminal-" + rand.Text() + "]"
		exchange.terminalReady = make(chan struct{})
	}
	defer func() { exchange.material.Zero() }()
	mat, err := c.initPrivilegeAttemptMaterial(ctx, mode, force, preResolved...)
	if err != nil {
		return err
	}
	exchange.material = mat
	session, err := c.newSessionContext(ctx)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, c.closeSessionBounded(session)) }()
	exchange.session = session
	if mode == SudoModeSu || terminal != nil {
		width, height := 40, 80
		ptyType := "xterm"
		if terminal != nil {
			width, height = terminal.width, terminal.height
			ptyType = "xterm-256color"
		}
		if err := c.sessionRequest(ctx, session, "privilege pty", func() error {
			return session.RequestPty(ptyType, height, width, cryptoSSH.TerminalModes{cryptoSSH.ECHO: 0})
		}); err != nil {
			return fmt.Errorf("request su terminal: %w", err)
		}
	}
	pipe, err := session.StdinPipe()
	if err != nil {
		return err
	}
	defer func() {
		retErr = errors.Join(retErr, c.closeSessionBounded(session), closeResource(pipe, "privilege stdin"))
	}()
	work, cancel := context.WithCancel(ctx)
	defer cancel()

	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	// Output has its own lifetime: normal Wait completion stops input, but
	// pending frame bytes must still be flushed before output is canceled.
	outputCtx, cancelOutput := context.WithCancel(ctx)
	defer cancelOutput()
	stdout, stderr, closeOutput, err := c.bindCommandOutputs(outputCtx, stdout, stderr, cancelOuterOutput != nil)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, closeOutput()) }()
	abort := func() {
		cancel()
		cancelOutput()
		if cancelOuterOutput != nil {
			cancelOuterOutput()
		}
	}
	pattern := regexp.MustCompile(regexp.QuoteMeta(exchange.promptToken))
	if mode == SudoModeSu {
		pattern = c.passwordPromptRegex()
	}
	if pattern == nil {
		return fmt.Errorf("privilege password prompt pattern is missing")
	}
	out := &privilegeFrameWriter{exchange: exchange, target: stdout, prompt: pattern}
	diagnostic := &privilegeFrameWriter{exchange: exchange, target: stderr, prompt: pattern}
	session.Stdout, session.Stderr = out, diagnostic
	fullCommand := exchange.command(command)
	c.observePrivilegeExchange(exchange, pattern)
	if err := c.startPrivilegeSession(work, session, fullCommand); err != nil {
		return err
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- exchange.waitSession(session, out, diagnostic) }()
	inputDone := make(chan error, 1)
	go func() { inputDone <- exchange.input(work, stdin, pipe) }()
	waitErr, inputErr, closeErr := c.waitPrivilegeExchange(work, cancel, abort, session, waitDone, inputDone, exchange.outputErrors)
	_ = out.flush()
	_ = diagnostic.flush()
	flushErr := exchange.writeErr
	return exchange.finish(ctx, privilegeOutcome{waitErr: waitErr, inputErr: inputErr, closeErr: closeErr, flushErr: flushErr, outputFailed: out.failed || diagnostic.failed})
}

func (e *privilegeExchange) waitSession(session *cryptoSSH.Session, out, diagnostic *privilegeFrameWriter) error {
	err := e.client.waitSession(session)
	e.outputMu.Lock()
	defer e.outputMu.Unlock()
	if err != nil && ((out.writeErr != nil && errors.Is(err, out.writeErr)) || (diagnostic.writeErr != nil && errors.Is(err, diagnostic.writeErr))) {
		return nil
	}
	return err
}

func (c *Client) waitPrivilegeExchange(ctx context.Context, cancel, abort context.CancelFunc, session *cryptoSSH.Session, waitDone, inputDone <-chan error, outputErrors <-chan struct{}) (waitErr, inputErr, closeErr error) {
	select {
	case waitErr = <-waitDone:
		cancel()
		// Close before joining input so a blocked SSH window write is released.
		closeErr = closeResource(session, "completed privilege session")
		inputErr = <-inputDone
	case inputErr = <-inputDone:
		abort()
		closeErr = c.closeCanceledSession(ctx, session, waitDone)
	case <-outputErrors:
		abort()
		closeErr = c.closeCanceledSession(ctx, session, waitDone)
		inputErr = <-inputDone
	case <-ctx.Done():
		abort()
		closeErr = c.closeCanceledSession(ctx, session, waitDone)
		inputErr = <-inputDone
	}
	return
}

func (c *Client) runPrivilegeWithConfig(ctx context.Context, mode SudoMode, command string, stdin io.Reader, config *RunConfig, mat ...*PrivilegeMaterial) (result string, retErr error) {
	if ctx == nil || c == nil {
		return "", fmt.Errorf("privilege execution requires a client and context")
	}
	if config == nil {
		config = c.defaultPrivilegeRunConfig()
	}
	var preResolved *PrivilegeMaterial
	if len(mat) > 0 {
		preResolved = mat[0]
	}
	// This operation owns bindings across pre-command authentication retries.
	// Abort cancels them before joining SSH workers; normal completion flushes first.
	work, cancelOutput := context.WithCancel(ctx)
	defer cancelOutput()
	bound, closeOutput, err := c.bindRunOutput(work, config)
	if err != nil {
		return "", err
	}
	defer func() { retErr = errors.Join(retErr, closeOutput()) }()
	output := newOutputWriter(bound)
	err = c.runPrivilegeOperation(ctx, mode, command, stdin, output, output, config, cancelOutput, preResolved)
	return output.String(), err
}

func (w *privilegeFrameWriter) writeBytes(data []byte) (int, error) {
	w.exchange.outputMu.Lock()
	defer w.exchange.outputMu.Unlock()
	n, err := w.target.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.recordErrorLocked(err)
	}
	return n, err
}

func (w *privilegeFrameWriter) recordError(err error) {
	w.exchange.outputMu.Lock()
	defer w.exchange.outputMu.Unlock()
	w.recordErrorLocked(err)
}

func (w *privilegeFrameWriter) recordErrorLocked(err error) {
	w.failed = true
	w.writeErr = err
	w.exchange.writeErr = errors.Join(w.exchange.writeErr, err)
	select {
	case w.exchange.outputErrors <- struct{}{}:
	default:
	}
}

// Shell xtrace renders command arguments before running sudo/su. Such a line
// is not a password challenge, even if it contains our prompt argument.
func (w *privilegeFrameWriter) promptIndex() []int {
	w.fallbackMatched = false
	match, incomplete := w.findPrompt(w.prompt, w.exchange.mode == SudoModeSudo)
	if match != nil || incomplete {
		return match
	}
	if w.exchange.mode != SudoModeSudo || w.exchange.client == nil || w.exchange.client.sudoPromptFallback == nil {
		return nil
	}
	if incompleteSudoPrompt(w.pending, w.exchange.promptToken) {
		return nil
	}
	match, _ = w.findPrompt(w.exchange.client.sudoPromptFallback, false)
	w.fallbackMatched = match != nil
	return match
}

// An incomplete sudo-rs envelope must wait for its suffix, never fall back to
// a partial challenge. Zero-width matches cannot consume a prompt or send input.
func (w *privilegeFrameWriter) findPrompt(pattern *regexp.Regexp, expand bool) ([]int, bool) {
	if pattern == nil {
		return nil, false
	}
	line, scanned, search := w.linePrefix, 0, 0
	for search <= len(w.pending) {
		match := w.nextPromptMatch(pattern, search)
		if match == nil {
			break
		}
		if match[0] == match[1] {
			if match[1] == len(w.pending) {
				break
			}
			_, size := utf8.DecodeRune(w.pending[match[1]:])
			search = match[1] + size
			continue
		}
		search = match[1]
		line = advancePrivilegeLine(line, w.pending[scanned:match[0]])
		scanned = match[0]
		if privilegeXtraceAt(line, w.pending[match[0]:]) {
			continue
		}
		if expand {
			full := expandSudoPrompt(w.pending, match)
			return full, full == nil
		}
		return match, false
	}
	return nil, false
}

type privilegeOutcome struct {
	waitErr, inputErr, closeErr, flushErr error
	outputFailed                          bool
}

func (e *privilegeExchange) finish(ctx context.Context, o privilegeOutcome) error {
	if !e.started() {
		e.client.observePrivilege(e.mode, "elevation_not_confirmed", 1, 0)
	}
	waitErr := e.interactiveWaitError(o.waitErr)
	result := errors.Join(o.flushErr, waitErr, o.inputErr, o.closeErr)
	if e.terminal != nil && !e.outputReady() && result == nil {
		result = fmt.Errorf("privilege session ended before terminal handoff")
	}
	if e.started() && e.passwordSent {
		if e.material != nil {
			e.material.verified = true
		}
		return errors.Join(result, e.client.confirmPrivilege(ctx, e.material))
	}
	e.mu.Lock()
	rejected := e.rejected
	e.mu.Unlock()
	var exitErr *cryptoSSH.ExitError
	if !e.started() && rejected && errors.As(o.waitErr, &exitErr) && exitErr.ExitStatus() != 0 && o.inputErr == nil && o.closeErr == nil && o.flushErr == nil && !o.outputFailed && ctx.Err() == nil {
		e.client.observePrivilege(e.mode, "authentication_rejected", 1, 0)
		return errors.Join(errPrivilegeAuthenticationRejected, result)
	}
	if !e.started() && result == nil {
		return fmt.Errorf("privilege session ended before command start")
	}
	return result
}

func (e *privilegeExchange) respond(ctx context.Context, pipe io.Writer, attempts int) (bool, error) {
	if e.started() || (e.mode == SudoModeSu && attempts > 0) {
		return false, nil
	}
	if attempts >= 3 || (attempts > 0 && credentialRecoveryPrompter(e.client.prompter) == nil) {
		e.client.observePrivilege(e.mode, "retry_limit", 1, attempts+1)
		return false, errPrivilegeAuthenticationRejected
	}
	if attempts > 0 {
		e.client.observePrivilege(e.mode, "password_retry", 1, attempts+1)
	}
	kind := SecretKindSudoPassword
	if e.mode == SudoModeSu {
		kind = SecretKindSuPassword
	}
	value := e.material
	if value == nil || attempts > 0 {
		var err error
		value, err = e.client.resolvePrivilegeMaterial(ctx, kind, e.forcePrompt || attempts > 0)
		if err != nil {
			return false, err
		}
		e.material.Zero()
		e.material = value
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if e.started() {
		return false, nil
	}
	if _, err := fmt.Fprintf(pipe, "%s\n", value.Password); err != nil {
		return false, fmt.Errorf("send privilege response: %w", err)
	}
	e.passwordSent = true
	e.client.observePrivilege(e.mode, "password_response_sent", 2, attempts+1)
	return true, nil
}

func (e *privilegeExchange) body(command string) string {
	nonce := strings.TrimSuffix(strings.TrimPrefix(e.readyToken, "[xops-ready-"), "]")
	body := "printf '[xops-ready-%s]' " + shellQuote(nonce) + " && IFS= read -r xops_credential_ack && test \"$xops_credential_ack\" = " + shellQuote(e.ackToken) + " && unset xops_credential_ack"
	if e.terminal != nil {
		terminalNonce := strings.TrimSuffix(strings.TrimPrefix(e.terminalToken, "[xops-terminal-"), "]")
		body += " && stty echo && printf '[xops-terminal-%s]' " + shellQuote(terminalNonce)
	}
	return body + " && eval " + shellQuote(command)
}

// Bound the exec request itself; a server may never reply to session.Start.
func (c *Client) startPrivilegeSession(ctx context.Context, session *cryptoSSH.Session, command string) error {
	return c.sessionRequest(ctx, session, "privilege exec", func() error { return session.Start(command) })
}

func (e *privilegeExchange) interactiveWaitError(err error) error {
	// Output, stdin, restoration, and close errors are retained separately in
	// privilegeOutcome; suppress only a full login session's process-exit result.
	if e.terminal != nil && e.terminal.ignoreExit && e.outputReady() {
		var exitErr *cryptoSSH.ExitError
		if errors.As(err, &exitErr) {
			return nil
		}
	}
	return err
}
