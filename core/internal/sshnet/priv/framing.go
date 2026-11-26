package priv

import (
	"bytes"
	"context"
	"errors"
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
	// maxPreReadyHoldBytes 限制次流（如非 PTY 模式的 stdout）在主控流观测到 readyTok 前的最大暂存字节数：
	// 远小于 SSH 2MiB 通道窗口，防止大输出触发流控死锁或内存膨胀，同时确保跨流并发竞争下零输出丢失。
	maxPreReadyHoldBytes = 64 * 1024
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

	readyFlag       atomic.Bool
	readyOnce       sync.Once
	readyCh         chan struct{}
	controlDoneOnce sync.Once
	controlDone     chan struct{}
	promptCh        chan struct{}

	diagMu  sync.Mutex
	diagBuf bytes.Buffer
}

func newSharedHandshakeState(method ports.PrivilegeMethod, tokens handshakeTokens, maxBytes uint64) *sharedHandshakeState {
	return &sharedHandshakeState{
		method:      method,
		tokens:      tokens,
		maxBytes:    maxBytes,
		readyCh:     make(chan struct{}),
		controlDone: make(chan struct{}),
		promptCh:    make(chan struct{}, maxPromptSignals),
	}
}

func (s *sharedHandshakeState) markReady() {
	s.readyFlag.Store(true)
	s.readyOnce.Do(func() { close(s.readyCh) })
}

func (s *sharedHandshakeState) markControlDone() {
	s.controlDoneOnce.Do(func() { close(s.controlDone) })
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
	state        *sharedHandshakeState
	dst          io.Writer
	isControl    bool
	holdPreReady bool
	pending      []byte
	feedback     sudoPromptFeedback
	writeErr     error
}

// newStreamScanner 构造单向输出流扫描器：
//   - isControl=true 表示主控流（非 PTY 模式下为 stderr，PTY 模式下为合并的 stdout），持续扫描提示帧与就绪帧，
//     在 EOF 时关闭 state.controlDone；
//   - isControl=false 表示次流（非 PTY 模式下为 stdout，PTY 模式下为 stderr），在就绪前有界暂存字节
//     并在达到 maxPreReadyHoldBytes 或 EOF 时等待主控流就绪/结束，形成单向无环因果序（次流 -> 主控流）。
func newStreamScanner(state *sharedHandshakeState, dst io.Writer, isControl bool) *streamScanner {
	if dst == nil {
		dst = io.Discard
	}
	return &streamScanner{
		state:        state,
		dst:          dst,
		isControl:    isControl,
		holdPreReady: !isControl,
	}
}

func (sc *streamScanner) pump(ctx context.Context, src io.Reader) error {
	if sc.isControl {
		defer sc.state.markControlDone()
	}
	buf := make([]byte, copyChunkBytes)
	for {
		n, rErr := src.Read(buf)
		if n > 0 {
			if err := sc.feed(ctx, buf[:n]); err != nil {
				return err
			}
		}
		if rErr != nil {
			return sc.finishPumpOnReadErr(ctx, rErr)
		}
	}
}

func (sc *streamScanner) finishPumpOnReadErr(ctx context.Context, rErr error) error {
	if err := sc.flushTailOnEOF(ctx); err != nil {
		return err
	}
	if sc.writeErr != nil {
		return sc.writeErr
	}
	if errors.Is(rErr, io.EOF) || (ctx.Err() != nil && errors.Is(rErr, io.ErrClosedPipe)) {
		return nil
	}
	return rErr
}

func (sc *streamScanner) feed(ctx context.Context, data []byte) error {
	if sc.state.readyFlag.Load() {
		sc.flushPendingToDst()
		sc.writeToDst(data)
		return nil
	}
	// 严格强制单向因果 DAG：仅主控流允许扫描口令提示与就绪帧；
	// 次流（如非 PTY 模式的 stdout）严禁解析任何提示/就绪令牌，杜绝混淆代理口令泄露与输出篡改。
	if !sc.isControl {
		return sc.bufferSecondaryPreReady(ctx, data)
	}
	sc.pending = append(sc.pending, data...)
	return sc.scanControlPending()
}

func (sc *streamScanner) bufferSecondaryPreReady(ctx context.Context, data []byte) error {
	if !sc.holdPreReady {
		sc.state.recordDiag(data)
		return nil
	}
	sc.pending = append(sc.pending, data...)
	if len(sc.pending) < maxPreReadyHoldBytes {
		return nil
	}
	return sc.resolveHeldPreReady(ctx)
}

func (sc *streamScanner) scanControlPending() error {
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
	sc.flushPendingToDst()
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

func (sc *streamScanner) flushTailOnEOF(ctx context.Context) error {
	if len(sc.pending) == 0 {
		return nil
	}
	if sc.state.readyFlag.Load() {
		sc.flushPendingToDst()
		return nil
	}
	if sc.holdPreReady {
		return sc.resolveHeldPreReady(ctx)
	}
	sc.state.recordDiag(sc.pending)
	sc.pending = nil
	return nil
}

// resolveHeldPreReady 等待主控流观测到 readyTok 或到达 EOF，保证次流先于主控流抵达或先到 EOF 时零字节丢失；
// 若主控流未就绪即结束，则将暂存数据转入诊断缓冲并退出暂存态，避免任何阻塞或泄漏。
func (sc *streamScanner) resolveHeldPreReady(ctx context.Context) error {
	if sc.state.readyFlag.Load() {
		sc.flushPendingToDst()
		return nil
	}
	select {
	case <-sc.state.readyCh:
		sc.flushPendingToDst()
		return nil
	case <-sc.state.controlDone:
		if sc.state.readyFlag.Load() {
			sc.flushPendingToDst()
			return nil
		}
		sc.state.recordDiag(sc.pending)
		sc.pending = nil
		sc.holdPreReady = false
		return nil
	case <-ctx.Done():
		sc.state.recordDiag(sc.pending)
		sc.pending = nil
		return ctx.Err()
	}
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
