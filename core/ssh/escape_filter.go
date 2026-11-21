package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type escapeState uint8

type escapeDisconnectError struct{}

func (escapeDisconnectError) Error() string {
	return "ssh session disconnected via escape sequence"
}

func (escapeDisconnectError) ExitCode() int {
	return 255
}

func (escapeDisconnectError) AlreadyReported() bool {
	return true
}

// ErrEscapeDisconnect is returned when an interactive PTY session terminates
// locally via the OpenSSH `<newline><EscapeChar>.` disconnect sequence.
var ErrEscapeDisconnect error = escapeDisconnectError{}

const (
	escapeStateLineStart escapeState = iota
	escapeStateNormal
	escapeStateSawEscape
)

type escapeFilterConfig struct {
	escapeByte   byte
	host         string
	localOut     io.Writer
	onDisconnect func()
	onSuspend    func() error
	summaryFn    func() string
}

// escapeFilterWriter wraps the destination writer supplied to startInputCopy for interactive
// PTY terminal sessions. It implements the OpenSSH line-start escape state machine without
// taking ownership of or closing borrowed local terminal streams (such as os.Stdin).
type escapeFilterWriter struct {
	dst          io.Writer
	escapeByte   byte
	host         string
	localOut     io.Writer
	onDisconnect func()
	onSuspend    func() error
	summaryFn    func() string

	mu           sync.Mutex
	state        escapeState
	disconnected atomic.Bool
}

func newEscapeFilterWriter(dst io.Writer, cfg escapeFilterConfig) *escapeFilterWriter {
	localOut := cfg.localOut
	if localOut == nil {
		localOut = io.Discard
	}
	return &escapeFilterWriter{
		dst:          dst,
		escapeByte:   cfg.escapeByte,
		host:         cfg.host,
		localOut:     localOut,
		onDisconnect: cfg.onDisconnect,
		onSuspend:    cfg.onSuspend,
		summaryFn:    cfg.summaryFn,
		state:        escapeStateLineStart,
	}
}

func (w *escapeFilterWriter) Disconnected() bool {
	if w == nil {
		return false
	}
	return w.disconnected.Load()
}

func (w *escapeFilterWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if w.disconnected.Load() {
		return len(p), nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.disconnected.Load() {
		return len(p), nil
	}

	var out []byte
	flush := func() error {
		if len(out) == 0 {
			return nil
		}
		_, err := writeAllEscapePassthrough(w.dst, out)
		out = out[:0]
		return err
	}

	for _, b := range p {
		switch w.state {
		case escapeStateLineStart:
			if b == w.escapeByte {
				w.state = escapeStateSawEscape
				continue
			}
			out = append(out, b)
			if b != '\r' && b != '\n' {
				w.state = escapeStateNormal
			}
		case escapeStateNormal:
			out = append(out, b)
			if b == '\r' || b == '\n' {
				w.state = escapeStateLineStart
			}
		case escapeStateSawEscape:
			done, err := w.handleEscapedByte(b, &out, flush)
			if err != nil {
				return 0, err
			}
			if done {
				return len(p), nil
			}
		}
	}

	if err := flush(); err != nil {
		return 0, err
	}
	return len(p), nil
}

type fatalSuspendTerminalError struct {
	err error
}

func (e fatalSuspendTerminalError) Error() string { return e.err.Error() }
func (e fatalSuspendTerminalError) Unwrap() error { return e.err }

func (w *escapeFilterWriter) handleEscapedByte(b byte, out *[]byte, flush func() error) (bool, error) {
	switch b {
	case w.escapeByte:
		*out = append(*out, w.escapeByte)
		w.state = nextEscapeStateAfterByte(b)
		return false, nil

	case '.':
		_ = flush()
		w.disconnected.Store(true)
		host := strings.TrimSpace(w.host)
		if host == "" {
			host = "remote host"
		}
		_, _ = fmt.Fprintf(w.localOut, "\r\nConnection to %s closed.\r\n", host)
		if w.onDisconnect != nil {
			w.onDisconnect()
		}
		return true, nil

	case 0x1a: // ^Z
		if err := flush(); err != nil {
			return false, err
		}
		w.state = escapeStateLineStart
		if w.onSuspend != nil {
			if err := w.onSuspend(); err != nil {
				var fatalErr fatalSuspendTerminalError
				if errors.As(err, &fatalErr) {
					return false, fatalErr.err
				}
				_, _ = fmt.Fprintf(w.localOut, "\r\n[suspend failed: %v]\r\n", err)
			}
		}
		return false, nil

	case '#':
		if err := flush(); err != nil {
			return false, err
		}
		w.state = escapeStateLineStart
		w.writeOpenChannelsSummary()
		return false, nil

	case '?':
		if err := flush(); err != nil {
			return false, err
		}
		w.state = escapeStateLineStart
		w.writeEscapeHelp()
		return false, nil

	default:
		*out = append(*out, w.escapeByte, b)
		w.state = nextEscapeStateAfterByte(b)
		return false, nil
	}
}

func nextEscapeStateAfterByte(b byte) escapeState {
	if b == '\r' || b == '\n' {
		return escapeStateLineStart
	}
	return escapeStateNormal
}

func writeAllEscapePassthrough(dst io.Writer, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := dst.Write(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func formatEscapeDisplay(ch byte) string {
	if ch == 0x7f {
		return "^?"
	}
	if ch >= 0x01 && ch <= 0x1a {
		return "^" + string('A'+ch-1)
	}
	return string(ch)
}

func (w *escapeFilterWriter) writeEscapeHelp() {
	esc := formatEscapeDisplay(w.escapeByte)
	var b strings.Builder
	b.WriteString("\r\nSupported escape sequences:\r\n")
	fmt.Fprintf(&b, " %s.  - terminate connection (and any multiplexed sessions)\r\n", esc)
	fmt.Fprintf(&b, " %s^Z - suspend ssh\r\n", esc)
	fmt.Fprintf(&b, " %s#  - list forwarded connections\r\n", esc)
	fmt.Fprintf(&b, " %s?  - this message\r\n", esc)
	fmt.Fprintf(&b, " %s%s  - send the escape character by typing it twice\r\n", esc, esc)
	b.WriteString("(Note that escapes are only recognized immediately after newline.)\r\n")
	_, _ = io.WriteString(w.localOut, b.String())
}

func (w *escapeFilterWriter) writeOpenChannelsSummary() {
	var summary string
	if w.summaryFn != nil {
		summary = w.summaryFn()
	}
	if strings.TrimSpace(summary) == "" {
		summary = "\r\nThe following connections are open:\r\n  (none)\r\n"
	}
	_, _ = io.WriteString(w.localOut, summary)
}

func resolveInteractiveEscapeChar(opts *Options) (byte, bool, error) {
	if opts == nil {
		return '~', true, nil
	}
	spec := opts.EscapeChar()
	if spec == "" {
		return '~', true, nil
	}
	return ParseEscapeChar(spec)
}

func (c *Client) trackActiveSession(desc string) func() {
	if c == nil {
		return func() {}
	}
	c.activeMu.Lock()
	c.activeSeq++
	id := c.activeSeq
	if c.activeSessions == nil {
		c.activeSessions = make(map[uint64]string)
	}
	c.activeSessions[id] = desc
	c.activeMu.Unlock()

	return sync.OnceFunc(func() {
		c.activeMu.Lock()
		delete(c.activeSessions, id)
		c.activeMu.Unlock()
	})
}

func (c *Client) trackForwardListener(operation, outcome, source, destination string) {
	if c == nil || source == "" {
		return
	}
	key := fmt.Sprintf("%s forward listener %s -> %s", operation, source, destination)
	c.activeMu.Lock()
	defer c.activeMu.Unlock()
	switch outcome {
	case "listening":
		if c.activeForwardListeners == nil {
			c.activeForwardListeners = make(map[string]struct{})
		}
		c.activeForwardListeners[key] = struct{}{}
	case "closed", "failed":
		delete(c.activeForwardListeners, key)
	}
}

func (c *Client) trackForwardConnection(operation, source, destination string, delta int) {
	if c == nil || source == "" {
		return
	}
	key := fmt.Sprintf("%s forwarded connection %s -> %s", operation, source, destination)
	c.activeMu.Lock()
	defer c.activeMu.Unlock()
	if c.activeForwardConns == nil {
		c.activeForwardConns = make(map[string]int)
	}
	next := c.activeForwardConns[key] + delta
	if next <= 0 {
		delete(c.activeForwardConns, key)
	} else {
		c.activeForwardConns[key] = next
	}
}

func (c *Client) formatOpenChannelsSummary() string {
	if c == nil {
		return "\r\nThe following connections are open:\r\n  (none)\r\n"
	}

	c.activeMu.Lock()
	sessionIDs := make([]uint64, 0, len(c.activeSessions))
	for id := range c.activeSessions {
		sessionIDs = append(sessionIDs, id)
	}
	slices.Sort(sessionIDs)
	sessions := make([]string, 0, len(sessionIDs))
	for _, id := range sessionIDs {
		sessions = append(sessions, c.activeSessions[id])
	}

	listeners := make([]string, 0, len(c.activeForwardListeners))
	for k := range c.activeForwardListeners {
		listeners = append(listeners, k)
	}
	slices.Sort(listeners)

	connKeys := make([]string, 0, len(c.activeForwardConns))
	for k := range c.activeForwardConns {
		connKeys = append(connKeys, k)
	}
	slices.Sort(connKeys)
	conns := make([]string, 0, len(connKeys))
	for _, k := range connKeys {
		conns = append(conns, fmt.Sprintf("%s (active=%d)", k, c.activeForwardConns[k]))
	}
	muxSock := c.muxSocketPath
	muxUID := c.muxExpectedUID
	c.activeMu.Unlock()

	var b strings.Builder
	b.WriteString("\r\nThe following connections are open:\r\n")
	idx := 0
	for _, s := range sessions {
		fmt.Fprintf(&b, "  #%d %s\r\n", idx, s)
		idx++
	}
	for _, l := range listeners {
		fmt.Fprintf(&b, "  #%d %s\r\n", idx, l)
		idx++
	}
	for _, cn := range conns {
		fmt.Fprintf(&b, "  #%d %s\r\n", idx, cn)
		idx++
	}
	if muxSock != "" {
		if muxInfo := queryMuxOpenForwards(muxSock, muxUID); muxInfo != "" {
			for line := range strings.SplitSeq(muxInfo, "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || trimmed == "Active Forwardings:" || trimmed == "(none)" {
					continue
				}
				fmt.Fprintf(&b, "  #%d mux %s\r\n", idx, strings.TrimPrefix(trimmed, "- "))
				idx++
			}
		}
	}
	if idx == 0 {
		b.WriteString("  (none)\r\n")
	}
	return b.String()
}

func queryMuxOpenForwards(socketPath string, expectedUID uint32) string {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	mc, err := DialMuxClient(ctx, socketPath, WithExpectedPeerUID(expectedUID))
	if err != nil {
		return ""
	}
	defer func() { _ = mc.Close() }()
	info, err := mc.RequestInfo(ctx, "channels")
	if err != nil {
		return ""
	}
	return info
}
