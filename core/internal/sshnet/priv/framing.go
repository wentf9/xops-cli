package priv

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/ports"
)

const (
	sudoRSPromptPrefix       = "[sudo: "
	maxSudoRSSuffixBytes     = 64
	fullWidthColonUTF8       = "\xef\xbc\x9a"
	defaultKeepTailHoldBytes = 96
)

// sudoPromptFeedback 在识别到 sudo-rs 封套提示后抑制紧随其后的回显掩码字节（* / \b / 空格 / \r），
// 遇换行符或首个非掩码诊断字节即停止吞噬，确保后续诊断信息完整透出。
type sudoPromptFeedback bool

func (f *sudoPromptFeedback) consume(data []byte) []byte {
	for *f && len(data) > 0 {
		switch data[0] {
		case '*', '\b', ' ', '\r':
			data = data[1:]
		case '\n':
			data = data[1:]
			*f = false
		default:
			*f = false
		}
	}
	return data
}

type sharedHandshakeState struct {
	method    ports.PrivilegeMethod
	tokens    handshakeTokens
	maxBytes  uint64
	usedBytes atomic.Uint64
	truncated atomic.Bool

	readyFlag atomic.Bool
	readyOnce sync.Once
	readyCh   chan struct{}
	promptCh  chan struct{}

	diagMu  sync.Mutex
	diagBuf bytes.Buffer
}

func newSharedHandshakeState(method ports.PrivilegeMethod, tokens handshakeTokens, maxBytes uint64) *sharedHandshakeState {
	return &sharedHandshakeState{
		method:   method,
		tokens:   tokens,
		maxBytes: maxBytes,
		readyCh:  make(chan struct{}),
		promptCh: make(chan struct{}, maxPromptSignals),
	}
}

func (s *sharedHandshakeState) markReady() {
	s.readyFlag.Store(true)
	s.readyOnce.Do(func() { close(s.readyCh) })
}

func (s *sharedHandshakeState) recordDiag(data []byte) {
	if len(data) == 0 {
		return
	}
	s.diagMu.Lock()
	defer s.diagMu.Unlock()
	rem := maxDiagBufferBytes - s.diagBuf.Len()
	if rem <= 0 {
		return
	}
	if len(data) > rem {
		data = data[:rem]
	}
	_, _ = s.diagBuf.Write(data)
}

func (s *sharedHandshakeState) diagText() string {
	s.diagMu.Lock()
	defer s.diagMu.Unlock()
	return s.diagBuf.String()
}

type streamScanner struct {
	state    *sharedHandshakeState
	dst      io.Writer
	pending  []byte
	feedback sudoPromptFeedback
	writeErr error
}

func newStreamScanner(state *sharedHandshakeState, dst io.Writer) *streamScanner {
	if dst == nil {
		dst = io.Discard
	}
	return &streamScanner{state: state, dst: dst}
}

func (sc *streamScanner) pump(src io.Reader) error {
	buf := make([]byte, copyChunkBytes)
	for {
		n, rErr := src.Read(buf)
		if n > 0 {
			if err := sc.feed(buf[:n]); err != nil {
				return err
			}
		}
		if rErr != nil {
			sc.flushTailOnEOF()
			if sc.writeErr != nil {
				return sc.writeErr
			}
			if rErr == io.EOF {
				return nil
			}
			return rErr
		}
	}
}

func (sc *streamScanner) feed(data []byte) error {
	if sc.state.readyFlag.Load() {
		sc.flushPendingToDst()
		sc.writeToDst(data)
		return nil
	}
	sc.pending = append(sc.pending, data...)
	return sc.scanPending()
}

func (sc *streamScanner) scanPending() error {
	readyBytes := []byte(sc.state.tokens.ready)
	for !sc.state.readyFlag.Load() {
		sc.pending = sc.feedback.consume(sc.pending)
		readyIdx := bytes.Index(sc.pending, readyBytes)
		pStart, pEnd, foundPrompt, needMore := matchPrivilegePrompt(sc.state.method, sc.state.tokens.prompt, sc.pending)
		if readyIdx >= 0 && (!foundPrompt || readyIdx < pStart) {
			sc.state.recordDiag(sc.pending[:readyIdx])
			sc.pending = sc.pending[readyIdx+len(readyBytes):]
			sc.state.markReady()
			sc.flushPendingToDst()
			return nil
		}
		if foundPrompt {
			if err := sc.handleMatchedPrompt(pStart, pEnd); err != nil {
				return err
			}
			continue
		}
		if !needMore {
			sc.trimSafeDiagPrefix()
		}
		return nil
	}
	return nil
}

func (sc *streamScanner) handleMatchedPrompt(pStart, pEnd int) error {
	sc.state.recordDiag(sc.pending[:pStart])
	isSudoRS := sc.state.method == ports.PrivilegeMethodSudo && bytes.HasPrefix(sc.pending[pStart:pEnd], []byte(sudoRSPromptPrefix))
	sc.feedback = sudoPromptFeedback(isSudoRS)
	sc.pending = sc.pending[pEnd:]
	select {
	case sc.state.promptCh <- struct{}{}:
		return nil
	default:
		return fmt.Errorf("%w: 远端发送过多提权口令质询", ports.ErrAuthFailed)
	}
}

func (sc *streamScanner) trimSafeDiagPrefix() {
	keep := max(len(sc.state.tokens.ready), len(sc.state.tokens.prompt)) + defaultKeepTailHoldBytes
	if len(sc.pending) <= keep {
		return
	}
	cut := len(sc.pending) - keep
	sc.state.recordDiag(sc.pending[:cut])
	sc.pending = sc.pending[cut:]
}

func (sc *streamScanner) flushTailOnEOF() {
	if len(sc.pending) == 0 {
		return
	}
	if sc.state.readyFlag.Load() {
		sc.flushPendingToDst()
		return
	}
	sc.state.recordDiag(sc.pending)
	sc.pending = nil
}

func (sc *streamScanner) flushPendingToDst() {
	if len(sc.pending) == 0 {
		return
	}
	sc.writeToDst(sc.pending)
	sc.pending = nil
}

func (sc *streamScanner) writeToDst(data []byte) {
	if sc.writeErr != nil || len(data) == 0 {
		return
	}
	chunk := sliceWithinBudget(data, sc.state.maxBytes, &sc.state.usedBytes, &sc.state.truncated)
	if len(chunk) == 0 {
		return
	}
	if _, err := sc.dst.Write(chunk); err != nil {
		sc.writeErr = err
		sc.dst = io.Discard
	}
}

func sliceWithinBudget(data []byte, maxBytes uint64, used *atomic.Uint64, truncated *atomic.Bool) []byte {
	if maxBytes == 0 {
		return data
	}
	for {
		cur := used.Load()
		if cur >= maxBytes {
			truncated.Store(true)
			return nil
		}
		take := min(uint64(len(data)), maxBytes-cur)
		if used.CompareAndSwap(cur, cur+take) {
			if take < uint64(len(data)) {
				truncated.Store(true)
			}
			return data[:take]
		}
	}
}

func matchPrivilegePrompt(method ports.PrivilegeMethod, promptToken string, data []byte) (start, end int, found, needMore bool) {
	switch method {
	case ports.PrivilegeMethodSudo:
		return matchSudoPrompt(promptToken, data)
	case ports.PrivilegeMethodSu:
		return matchKeywordPrompt(data, "password:")
	case ports.PrivilegeMethodDoas:
		return matchKeywordPrompt(data, "password:")
	default:
		return 0, 0, false, false
	}
}

func matchSudoPrompt(marker string, data []byte) (start, end int, found, needMore bool) {
	idx := bytes.Index(data, []byte(marker))
	if idx < 0 {
		return 0, 0, false, hasPartialTail(data, marker) || hasPartialTail(data, sudoRSPromptPrefix)
	}
	mStart, mEnd := idx, idx+len(marker)
	if !bytes.HasSuffix(data[:mStart], []byte(sudoRSPromptPrefix)) {
		return mStart, mEnd, true, false
	}
	return expandSudoRSEnvelope(data, mStart, mEnd)
}

func expandSudoRSEnvelope(data []byte, start, end int) (int, int, bool, bool) {
	suffix := data[end:]
	if len(suffix) == 0 || (len(suffix) == 1 && suffix[0] == ']') {
		return 0, 0, false, true
	}
	if suffix[0] != ']' || suffix[1] != ' ' {
		return start, end, true, false
	}
	win := suffix[:min(len(suffix), maxSudoRSSuffixBytes)]
	if colonEnd, ok := findPromptColonEnd(win); ok {
		return start - len(sudoRSPromptPrefix), end + colonEnd, true, false
	}
	if len(suffix) < maxSudoRSSuffixBytes && !bytes.ContainsAny(suffix, "\r\n") {
		return 0, 0, false, true
	}
	return start, end, true, false
}

func findPromptColonEnd(win []byte) (int, bool) {
	fwColon := []byte(fullWidthColonUTF8)
	for i := 0; i < len(win); i++ {
		if win[i] == '\r' || win[i] == '\n' {
			return 0, false
		}
		if win[i] == ':' {
			return i + 1, true
		}
		if bytes.HasPrefix(win[i:], fwColon) {
			return i + len(fwColon), true
		}
	}
	return 0, false
}

func matchKeywordPrompt(data []byte, keyword string) (start, end int, found, needMore bool) {
	lower := bytes.ToLower(data)
	kw := []byte(keyword)
	if idx := bytes.Index(lower, kw); idx >= 0 {
		endIdx := idx + len(kw)
		if endIdx < len(data) && data[endIdx] == ' ' {
			endIdx++
		}
		return idx, endIdx, true, false
	}
	return 0, 0, false, hasPartialTail(lower, keyword)
}

func hasPartialTail(data []byte, prefix string) bool {
	limit := min(len(prefix)-1, len(data))
	for size := 1; size <= limit; size++ {
		if bytes.HasSuffix(data, []byte(prefix[:size])) {
			return true
		}
	}
	return false
}

func isAuthRejectionDiagnostic(diag string) bool {
	lower := strings.ToLower(diag)
	for _, needle := range [...]string{
		"sorry, try again",
		"incorrect password",
		"authentication failure",
		"a password is required",
		"password is required",
		"not in the sudoers",
		"authentication failed",
		"operation not permitted",
		"permission denied",
		"incorrect passphrase",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}
