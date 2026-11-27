package priv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/ports"
)

const (
	defaultKeepTailHoldBytes = 96
	// maxPreReadyHoldBytes 限制次流（如非 PTY 模式的 stdout）在主控流观测到 readyTok 前的最大暂存字节数：
	// 远小于 SSH 2MiB 通道窗口，防止大输出触发流控死锁或内存膨胀，同时确保跨流并发竞争下零输出丢失。
	maxPreReadyHoldBytes = 64 * 1024
)

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
	state     *sharedHandshakeState
	dst       io.Writer
	isControl bool
	pending   []byte
	feedback  sudoPromptFeedback
	writeErr  error

	// 以下字段仅用于次流（isControl == false）的就绪前暂存与就绪时即时刷出：
	//   - preMu 仅保护纯内存状态（preDone / preBuf），绝不在持锁期间执行 dst.Write 阻塞 I/O；
	//   - preFlushed 在一次性暂存刷出或丢弃完成后关闭，经 happens-before 严格隔离 flusher 与次流协程对 dst/writeErr 的访问，
	//     保证精确 FIFO 顺序、零重复写入与零数据竞争；
	//   - preLocalDone 仅由次流自身协程访问，用于就绪后的零锁快路径。
	preMu          sync.Mutex
	preDone        bool
	preBuf         []byte
	preFlushedOnce sync.Once
	preFlushed     chan struct{}
	preLocalDone   bool
}

// newStreamScanner 构造单向输出流扫描器：
//   - isControl=true 表示主控流（非 PTY 模式下为 stderr，PTY 模式下为合并的 stdout），持续扫描提示帧与就绪帧，
//     在 EOF 时关闭 state.controlDone；
//   - isControl=false 表示次流（非 PTY 模式下为 stdout，PTY 模式下为 stderr），在就绪前有界暂存字节；
//     主控流调用 markReady() 时由独立 flusher 协程立即刷出全部暂存字节并关闭 preFlushed 同步屏障，
//     避免远端命令输出不足 64 KiB 后阻塞等待时首包滞留。
func newStreamScanner(state *sharedHandshakeState, dst io.Writer, isControl bool) *streamScanner {
	if dst == nil {
		dst = io.Discard
	}
	sc := &streamScanner{
		state:     state,
		dst:       dst,
		isControl: isControl,
	}
	if !isControl {
		sc.preFlushed = make(chan struct{})
	}
	return sc
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
	// 严格强制单向因果 DAG：仅主控流允许扫描口令提示与就绪帧；
	// 次流（如非 PTY 模式的 stdout）严禁解析任何提示/就绪令牌，杜绝混淆代理口令泄露与输出篡改。
	if !sc.isControl {
		return sc.feedSecondary(ctx, data)
	}
	if sc.state.readyFlag.Load() {
		sc.flushPendingToDst()
		sc.writeToDst(data)
		return nil
	}
	sc.pending = append(sc.pending, data...)
	return sc.scanControlPending()
}

func (sc *streamScanner) feedSecondary(ctx context.Context, data []byte) error {
	if sc.preLocalDone {
		sc.writeToDst(data)
		return nil
	}
	if sc.state.readyFlag.Load() {
		if err := sc.ensureSecondaryReady(ctx); err != nil {
			return err
		}
		sc.writeToDst(data)
		return nil
	}
	return sc.bufferSecondaryPreReady(ctx, data)
}

func (sc *streamScanner) bufferSecondaryPreReady(ctx context.Context, data []byte) error {
	sc.preMu.Lock()
	if !sc.preDone {
		if !sc.state.readyFlag.Load() {
			sc.preBuf = append(sc.preBuf, data...)
			needWait := len(sc.preBuf) >= maxPreReadyHoldBytes
			sc.preMu.Unlock()
			if !needWait {
				return nil
			}
			if err := sc.waitPreReadyFlushed(ctx); err != nil {
				return err
			}
			if sc.state.readyFlag.Load() {
				sc.preLocalDone = true
			}
			return nil
		}
		batch := sc.preBuf
		sc.preBuf = nil
		sc.preDone = true
		sc.preMu.Unlock()
		sc.completePreReadyWrite(batch)
		sc.preLocalDone = true
		sc.writeToDst(data)
		return nil
	}
	sc.preMu.Unlock()
	if err := sc.waitPreReadyFlushed(ctx); err != nil {
		return err
	}
	if sc.state.readyFlag.Load() {
		sc.preLocalDone = true
		sc.writeToDst(data)
		return nil
	}
	sc.state.recordDiag(data)
	return nil
}

// runSecondaryReadyFlusher 监听主控流就绪/结束事件，在主控流触发 markReady() 后立即将次流暂存字节
// 无锁刷出至 dst（绝不阻塞主控流，亦绝不在持锁态执行 I/O）。
func runSecondaryReadyFlusher(ctx context.Context, state *sharedHandshakeState, sec *streamScanner) {
	select {
	case <-state.readyCh:
		sec.flushPreReadyIfPending()
	case <-state.controlDone:
		if state.readyFlag.Load() {
			sec.flushPreReadyIfPending()
		} else {
			sec.discardPreReadyIfPending()
		}
	case <-ctx.Done():
		sec.discardPreReadyIfPending()
	}
}

func (sc *streamScanner) claimPreReady() (batch []byte, won bool) {
	sc.preMu.Lock()
	defer sc.preMu.Unlock()
	if sc.preDone {
		return nil, false
	}
	sc.preDone = true
	batch = sc.preBuf
	sc.preBuf = nil
	return batch, true
}

func (sc *streamScanner) markPreFlushed() {
	sc.preFlushedOnce.Do(func() { close(sc.preFlushed) })
}

func (sc *streamScanner) completePreReadyWrite(batch []byte) {
	defer sc.markPreFlushed()
	if len(batch) > 0 {
		sc.writeToDst(batch)
	}
}

func (sc *streamScanner) flushPreReadyIfPending() {
	if batch, won := sc.claimPreReady(); won {
		sc.completePreReadyWrite(batch)
	}
}

func (sc *streamScanner) discardPreReadyIfPending() {
	if batch, won := sc.claimPreReady(); won {
		defer sc.markPreFlushed()
		sc.state.recordDiag(batch)
	}
}

func (sc *streamScanner) ensureSecondaryReady(ctx context.Context) error {
	if batch, won := sc.claimPreReady(); won {
		sc.completePreReadyWrite(batch)
		sc.preLocalDone = true
		return nil
	}
	if err := sc.waitPreReadyFlushed(ctx); err != nil {
		return err
	}
	sc.preLocalDone = true
	return nil
}

func (sc *streamScanner) waitPreReadyFlushed(ctx context.Context) error {
	select {
	case <-sc.preFlushed:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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
	if !sc.isControl {
		if sc.preLocalDone {
			return nil
		}
		if err := sc.waitPreReadyFlushed(ctx); err != nil {
			return err
		}
		if sc.state.readyFlag.Load() {
			sc.preLocalDone = true
		}
		return nil
	}
	if len(sc.pending) == 0 {
		return nil
	}
	if sc.state.readyFlag.Load() {
		sc.flushPendingToDst()
		return nil
	}
	sc.state.recordDiag(sc.pending)
	sc.pending = nil
	return nil
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
