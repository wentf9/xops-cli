package muxstream

import (
	"bytes"
	"io"
	"sync"

	"github.com/wentf9/xops-cli/core/ports"
)

// maxSessionPipeBufBytes 为单条借出 StdoutPipe/StderrPipe 设置 16 MiB 缓冲上限，
// 既保证单循环解复用器绝不因对端交替写 stdout/stderr 而阻塞死锁，又防止无人消费时无界 OOM。
const maxSessionPipeBufBytes = 16 << 20

// bufferedPipe 为 RemoteSession.StdoutPipe / StderrPipe 提供并发安全的有界缓冲读取流：
// 写入端永不阻塞读循环（彻底消除单解复用循环下的 stdout/stderr 互锁），读取端按需阻塞等待。
type bufferedPipe struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    bytes.Buffer
	eof    bool
	closed bool
	err    error
}

func newBufferedPipe() *bufferedPipe {
	p := &bufferedPipe{}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *bufferedPipe) writeChunk(data []byte) {
	if len(data) == 0 {
		return
	}
	p.mu.Lock()
	if !p.eof && !p.closed {
		if p.buf.Len()+len(data) > maxSessionPipeBufBytes {
			p.closed = true
			if p.err == nil {
				p.err = ports.ErrLimitExceeded
			}
		} else {
			_, _ = p.buf.Write(data)
		}
		p.cond.Broadcast()
	}
	p.mu.Unlock()
}

func (p *bufferedPipe) closeEOF() {
	p.mu.Lock()
	p.eof = true
	p.cond.Broadcast()
	p.mu.Unlock()
}

func (p *bufferedPipe) closeAbort() {
	p.mu.Lock()
	p.closed = true
	p.cond.Broadcast()
	p.mu.Unlock()
}

func (p *bufferedPipe) Read(dst []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.buf.Len() == 0 && !p.eof && !p.closed {
		p.cond.Wait()
	}
	if p.buf.Len() > 0 {
		return p.buf.Read(dst)
	}
	if p.err != nil {
		return 0, p.err
	}
	return 0, io.EOF
}
