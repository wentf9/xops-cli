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
	rejected                          bool
	material                          *PrivilegeMaterial // owned by input worker, then by its joining caller
	passwordSent                      bool
	forcePrompt                       bool
	outputErrors                      chan error
	terminal                          *privilegeTerminal
	session                           *cryptoSSH.Session
	terminalToken                     string
	terminalReady                     chan struct{}
	terminalOnce                      sync.Once
}

func newPrivilegeExchange(c *Client, mode SudoMode, force bool) *privilegeExchange {
	return &privilegeExchange{client: c, mode: mode, readyToken: "[xops-ready-" + rand.Text() + "]", promptToken: "[xops-password-" + rand.Text() + "]", ackToken: "[xops-continue-" + rand.Text() + "]", ready: make(chan struct{}), prompts: make(chan struct{}, 3), forcePrompt: force, outputErrors: make(chan error, 1)}
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
	if command == "" {
		command = "exec bash -l"
	}
	body := e.body(command)
	if e.mode == SudoModeSu {
		return "export LC_ALL=C; su - root -c " + shellQuote("exec bash -c "+shellQuote(body))
	}
	prefix := "sudo -S -p "
	if e.terminal != nil {
		prefix = "sudo -i -S -p "
		body = sudoLoginScript(body)
	}
	return prefix + shellQuote(e.promptToken) + " -- bash -c " + shellQuote(body)
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
	exchange *privilegeExchange
	target   io.Writer
	pending  []byte
	prompt   *regexp.Regexp
	failed   bool
	writeErr error
}

func (w *privilegeFrameWriter) Write(data []byte) (n int, retErr error) {
	defer func() {
		if retErr != nil {
			w.failed = true
			w.writeErr = retErr
			select {
			case w.exchange.outputErrors <- retErr:
			default:
			}
		}
	}()
	n = len(data)
	if w.exchange.outputReady() {
		if err := w.flush(); err != nil {
			return 0, err
		}
		return w.writeBytes(data)
	}
	w.pending = append(w.pending, data...)
	for !w.exchange.outputReady() {
		token := w.exchange.readyToken
		var prompt []int
		if w.exchange.started() {
			token = w.exchange.terminalToken
		} else {
			prompt = w.promptIndex()
		}
		ready := bytes.Index(w.pending, []byte(token))
		if ready >= 0 && (prompt == nil || ready < prompt[0]) {
			if err := w.emit(w.pending[:ready]); err != nil {
				return 0, err
			}
			w.pending = w.pending[ready+len(token):]
			if !w.exchange.started() {
				w.exchange.readyOnce.Do(func() { close(w.exchange.ready) })
			} else {
				w.exchange.terminalOnce.Do(func() { close(w.exchange.terminalReady) })
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
		w.pending = w.pending[prompt[1]:]
		select {
		case w.exchange.prompts <- struct{}{}:
		default:
			return 0, fmt.Errorf("too many privilege prompts")
		}
	}
	// Bounded look-behind supports fragmented prompts without retaining banners.
	const lookBehind = 4096
	if len(w.pending) > lookBehind {
		count := len(w.pending) - lookBehind
		if err := w.emit(w.pending[:count]); err != nil {
			return 0, err
		}
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
	err := w.emit(w.pending)
	clear(w.pending)
	w.pending = nil
	return err
}

func (c *Client) runPrivilegeOperation(ctx context.Context, mode SudoMode, command string, stdin io.Reader, stdout, stderr io.Writer, terminals ...*privilegeTerminal) error {
	if ctx == nil || c == nil {
		return fmt.Errorf("privilege execution requires a client and context")
	}
	if mode != SudoModeSudo && mode != SudoModeSu {
		return fmt.Errorf("unsupported privilege exchange mode %q", mode)
	}
	if err := validateCommandStdin(stdin); err != nil {
		return err
	}
	var terminal *privilegeTerminal
	if len(terminals) > 0 {
		terminal = terminals[0]
		if terminal != nil && terminal.activate == nil {
			return fmt.Errorf("privilege terminal activation is missing")
		}
	}
	for attempt := 0; attempt < 3; attempt++ {
		err := c.runPrivilegeAttempt(ctx, mode, command, stdin, stdout, stderr, attempt > 0, terminal)
		if mode != SudoModeSu || !errors.Is(err, errPrivilegeAuthenticationRejected) || credentialRecoveryPrompter(c.prompter) == nil || attempt == 2 {
			return err
		}
	}
	return errPrivilegeAuthenticationRejected
}

func (c *Client) runPrivilegeAttempt(ctx context.Context, mode SudoMode, command string, stdin io.Reader, stdout, stderr io.Writer, force bool, terminal *privilegeTerminal) (retErr error) {
	exchange := newPrivilegeExchange(c, mode, force)
	exchange.terminal = terminal
	if terminal != nil {
		exchange.terminalToken = "[xops-terminal-" + rand.Text() + "]"
		exchange.terminalReady = make(chan struct{})
	}
	defer func() { exchange.material.Zero() }()
	if credentialRecoveryPrompter(c.prompter) == nil {
		kind := SecretKindSudoPassword
		if mode == SudoModeSu {
			kind = SecretKindSuPassword
		}
		value, err := c.resolvePrivilegeMaterial(ctx, kind, force)
		if err != nil {
			return fmt.Errorf("%s password is required but not provided: %w", mode, err)
		}
		exchange.material = value
	}
	session, err := c.newSessionContext(ctx)
	if err != nil {
		return err
	}
	defer joinResourceCloseError(&retErr, session, "privilege session")
	exchange.session = session
	if mode == SudoModeSu || terminal != nil {
		width, height := 40, 80
		ptyType := "xterm"
		if terminal != nil {
			width, height = terminal.width, terminal.height
			ptyType = "xterm-256color"
		}
		if err := session.RequestPty(ptyType, height, width, cryptoSSH.TerminalModes{cryptoSSH.ECHO: 0}); err != nil {
			return fmt.Errorf("request su terminal: %w", err)
		}
	}
	pipe, err := session.StdinPipe()
	if err != nil {
		return err
	}
	defer joinResourceCloseError(&retErr, pipe, "privilege stdin")
	work, cancel := context.WithCancel(ctx)
	defer cancel()

	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
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
	if err := c.startPrivilegeSession(work, session, exchange.command(command)); err != nil {
		return err
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- session.Wait() }()
	inputDone := make(chan error, 1)
	go func() { inputDone <- exchange.input(work, stdin, pipe) }()
	waitErr, inputErr, closeErr := c.waitPrivilegeExchange(work, cancel, session, waitDone, inputDone, exchange.outputErrors)
	flushErr := errors.Join(out.flush(), diagnostic.flush(), out.writeErr, diagnostic.writeErr)
	return exchange.finish(ctx, privilegeOutcome{waitErr: waitErr, inputErr: inputErr, closeErr: closeErr, flushErr: flushErr, outputFailed: out.failed || diagnostic.failed})
}

func (c *Client) waitPrivilegeExchange(ctx context.Context, cancel context.CancelFunc, session *cryptoSSH.Session, waitDone, inputDone, outputErrors <-chan error) (waitErr, inputErr, closeErr error) {
	select {
	case waitErr = <-waitDone:
		cancel()
		// Close before joining input so a blocked SSH window write is released.
		closeErr = closeResource(session, "completed privilege session")
		inputErr = <-inputDone
	case inputErr = <-inputDone:
		cancel()
		closeErr = c.closeCanceledSession(ctx, session, waitDone)
	case inputErr = <-outputErrors:
		cancel()
		closeErr = c.closeCanceledSession(ctx, session, waitDone)
		inputErr = errors.Join(inputErr, <-inputDone)
	case <-ctx.Done():
		cancel()
		closeErr = c.closeCanceledSession(ctx, session, waitDone)
		inputErr = <-inputDone
	}
	return
}

func (c *Client) runPrivilegeWithConfig(ctx context.Context, mode SudoMode, command string, stdin io.Reader, config *RunConfig) (string, error) {
	if config == nil {
		config = DefaultRunConfig()
	}
	output := newOutputWriter(config)
	err := c.runPrivilegeOperation(ctx, mode, command, stdin, output, output)
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
		w.failed = true
		w.writeErr = err
	}
	return n, err
}

// Shell xtrace renders command arguments before running sudo/su. Such a line
// is not a password challenge, even if it contains our prompt argument.
func (w *privilegeFrameWriter) promptIndex() []int {
	for _, match := range w.prompt.FindAllIndex(w.pending, -1) {
		line := w.pending[:match[0]]
		if at := bytes.LastIndexByte(line, '\n'); at >= 0 {
			line = line[at+1:]
		}
		prefix := strings.TrimLeft(string(line), "+")
		if len(prefix) < len(line) && strings.HasPrefix(prefix, " ") {
			continue
		}
		return match
	}
	return nil
}

type privilegeOutcome struct {
	waitErr, inputErr, closeErr, flushErr error
	outputFailed                          bool
}

func (e *privilegeExchange) finish(ctx context.Context, o privilegeOutcome) error {
	waitErr := e.interactiveWaitError(o.waitErr)
	result := errors.Join(waitErr, o.inputErr, o.closeErr, o.flushErr)
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
		return false, errPrivilegeAuthenticationRejected
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
	startCtx, cancel := withTimeoutOrDefault(ctx, c.handshakeTimeout, defaultSSHHandshakeTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- session.Start(command) }()
	select {
	case err := <-done:
		return err
	case <-startCtx.Done():
		return c.closeCanceledSession(startCtx, session, done)
	}
}

func (e *privilegeExchange) interactiveWaitError(err error) error {
	// Output, stdin, restoration, and close errors are retained separately in
	// privilegeOutcome; suppress only the legacy interactive process-exit result.
	if e.terminal != nil && e.terminal.ignoreExit && e.outputReady() {
		var exitErr *cryptoSSH.ExitError
		if errors.As(err, &exitErr) {
			return nil
		}
	}
	return err
}
