package ssh

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// proxyChanCloseGrace bounds how long proxyChanConn.Close waits for a
// direct-tcpip channel close (raw.Close + in-flight raw.Read/Write goroutines)
// to finish cleanly before concluding that the upstream hop is write-wedged or
// blackholed and escalating to abortUpstream. Per RFC 4254 §5.3, a healthy
// upstream bastion echoes SSH_MSG_CHANNEL_CLOSE promptly even when the
// downstream target is dead/blackholed.
// Kept strictly above keepAliveCloseGrace (50ms) so keepalive's own bounded
// escalation timer fires first when probeWithContexts supervises a child hop.
var proxyChanCloseGrace = 90 * time.Millisecond

type proxyChanAlreadyClosedError struct{}

func (proxyChanAlreadyClosedError) Error() string { return io.EOF.Error() }

func (proxyChanAlreadyClosedError) Is(target error) bool {
	return target == io.EOF || target == net.ErrClosed
}

var errProxyChanAlreadyClosed error = proxyChanAlreadyClosedError{}

type proxyWriteResult struct {
	n   int
	err error
}

// proxyChanConn wraps an x/crypto/ssh direct-tcpip *ssh.chanConn to provide:
//  1. Real Read/Write deadlines (waking callers promptly with os.ErrDeadlineExceeded).
//  2. Immediate local wakeup on Close() so callers (including x/crypto/ssh
//     handshakeTransport.readLoop) exit without waiting for a peer reply.
//  3. Bounded asynchronous raw.Close() + in-flight I/O drain that preserves a
//     healthy upstream bastion when SSH_MSG_CHANNEL_CLOSE completes within
//     proxyChanCloseGrace, and escalates to abortUpstream when the upstream hop
//     is write-wedged or silently blackholed, guaranteeing zero goroutine leaks.
type proxyChanConn struct {
	raw           net.Conn
	abortUpstream func(self net.Conn) error

	// lifecycleMu serializes lazy worker startup (ioWG.Add) against Close()
	// (ioWG.Wait) so WaitGroup Add/Wait can never race.
	lifecycleMu  sync.Mutex
	closing      bool
	readStarted  bool
	writeStarted bool

	closedCh  chan struct{}
	closed    atomic.Bool
	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
	escalated atomic.Bool

	ioWG sync.WaitGroup

	readCallMu sync.Mutex
	readMu     sync.Mutex
	readBuf    []byte
	readErr    error
	readReady  chan struct{}
	readNeed   chan struct{}
	readDL     time.Time
	readDLCh   chan struct{}

	writeCallMu sync.Mutex
	writeMu     sync.Mutex
	writeBuf    []byte
	writeBusy   bool
	writeReq    chan []byte
	writeResp   chan proxyWriteResult
	writeDL     time.Time
	writeDLCh   chan struct{}
}

var _ net.Conn = (*proxyChanConn)(nil)

func newProxyChanConn(raw net.Conn, abortUpstream func(self net.Conn) error) *proxyChanConn {
	if raw == nil {
		return nil
	}
	return &proxyChanConn{
		raw:           raw,
		abortUpstream: abortUpstream,
		closedCh:      make(chan struct{}),
		closeDone:     make(chan struct{}),
		readReady:     make(chan struct{}, 1),
		readNeed:      make(chan struct{}, 1),
		readDLCh:      make(chan struct{}, 1),
		writeReq:      make(chan []byte, 1),
		writeResp:     make(chan proxyWriteResult, 1),
		writeDLCh:     make(chan struct{}, 1),
	}
}

func notifyNonBlocking(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func resetConnDeadlineTimer(timer *time.Timer, dl time.Time) (*time.Timer, <-chan time.Time, bool) {
	if dl.IsZero() {
		if timer != nil {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		return timer, nil, false
	}
	remaining := time.Until(dl)
	if remaining <= 0 {
		return timer, nil, true
	}
	if timer == nil {
		timer = time.NewTimer(remaining)
	} else {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(remaining)
	}
	return timer, timer.C, false
}

func (c *proxyChanConn) ensureReaderStarted() bool {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closing {
		return false
	}
	if !c.readStarted {
		c.readStarted = true
		c.ioWG.Add(1)
		go c.readLoop()
	}
	return true
}

func (c *proxyChanConn) ensureWriterStarted() bool {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closing {
		return false
	}
	if !c.writeStarted {
		c.writeStarted = true
		c.ioWG.Add(1)
		go c.writeLoop()
	}
	return true
}

func (c *proxyChanConn) readLoop() {
	defer c.ioWG.Done()
	buf := make([]byte, 32*1024)
	for {
		n, err := c.raw.Read(buf)
		c.readMu.Lock()
		if n > 0 {
			c.readBuf = buf[:n]
		}
		if err != nil {
			c.readErr = err
		}
		c.readMu.Unlock()
		notifyNonBlocking(c.readReady)

		if err != nil {
			return
		}
		if n > 0 {
			select {
			case <-c.readNeed:
			case <-c.closedCh:
				return
			}
		} else {
			select {
			case <-c.closedCh:
				return
			default:
			}
		}
	}
}

func (c *proxyChanConn) writeLoop() {
	defer c.ioWG.Done()
	for {
		select {
		case <-c.closedCh:
			return
		case payload := <-c.writeReq:
			if c.closed.Load() {
				return
			}
			n, err := c.raw.Write(payload)
			if c.closed.Load() {
				return
			}
			select {
			case c.writeResp <- proxyWriteResult{n: n, err: err}:
			case <-c.closedCh:
				return
			}
		}
	}
}

func (c *proxyChanConn) Read(p []byte) (int, error) {
	if c == nil {
		return 0, net.ErrClosed
	}
	c.readCallMu.Lock()
	defer c.readCallMu.Unlock()

	if c.closed.Load() {
		return 0, net.ErrClosed
	}

	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	started := false
	for {
		c.readMu.Lock()
		if c.closed.Load() {
			c.readMu.Unlock()
			return 0, net.ErrClosed
		}
		dl := c.readDL
		if !dl.IsZero() && !time.Now().Before(dl) {
			c.readMu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if len(p) == 0 {
			c.readMu.Unlock()
			return 0, nil
		}
		if len(c.readBuf) > 0 {
			n := copy(p, c.readBuf)
			c.readBuf = c.readBuf[n:]
			if len(c.readBuf) == 0 {
				notifyNonBlocking(c.readNeed)
			}
			c.readMu.Unlock()
			return n, nil
		}
		if c.readErr != nil {
			err := c.readErr
			c.readMu.Unlock()
			return 0, err
		}
		c.readMu.Unlock()

		if !started {
			if !c.ensureReaderStarted() {
				return 0, net.ErrClosed
			}
			started = true
		}

		var (
			timerCh <-chan time.Time
			expired bool
		)
		timer, timerCh, expired = resetConnDeadlineTimer(timer, dl)
		if expired {
			return 0, os.ErrDeadlineExceeded
		}

		select {
		case <-c.closedCh:
			return 0, net.ErrClosed
		case <-c.readReady:
		case <-c.readDLCh:
		case <-timerCh:
		}
	}
}

func (c *proxyChanConn) readWriteDeadline() time.Time {
	c.writeMu.Lock()
	dl := c.writeDL
	c.writeMu.Unlock()
	return dl
}

func (c *proxyChanConn) waitWriteResult(timer **time.Timer) (proxyWriteResult, error) {
	for {
		if c.closed.Load() {
			return proxyWriteResult{}, net.ErrClosed
		}
		dl := c.readWriteDeadline()
		if !dl.IsZero() && !time.Now().Before(dl) {
			return proxyWriteResult{}, os.ErrDeadlineExceeded
		}
		var (
			timerCh <-chan time.Time
			expired bool
		)
		*timer, timerCh, expired = resetConnDeadlineTimer(*timer, dl)
		if expired {
			return proxyWriteResult{}, os.ErrDeadlineExceeded
		}
		select {
		case res := <-c.writeResp:
			c.writeBusy = false
			return res, nil
		case <-c.closedCh:
			return proxyWriteResult{}, net.ErrClosed
		case <-c.writeDLCh:
		case <-timerCh:
		}
	}
}

func (c *proxyChanConn) Write(p []byte) (int, error) {
	if c == nil {
		return 0, net.ErrClosed
	}
	c.writeCallMu.Lock()
	defer c.writeCallMu.Unlock()

	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if dl := c.readWriteDeadline(); !dl.IsZero() && !time.Now().Before(dl) {
		return 0, os.ErrDeadlineExceeded
	}
	if len(p) == 0 && !c.writeBusy {
		return 0, nil
	}
	if !c.ensureWriterStarted() {
		return 0, net.ErrClosed
	}

	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	// If a previous Write timed out while writeLoop was still blocked in
	// raw.Write, wait for it to finish before touching writeBuf or issuing a
	// second raw.Write (x/crypto/ssh channel.WriteExtended forbids concurrent
	// writes on the same channel).
	if c.writeBusy {
		if _, err := c.waitWriteResult(&timer); err != nil {
			return 0, err
		}
		if len(p) == 0 {
			return 0, nil
		}
	}

	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if dl := c.readWriteDeadline(); !dl.IsZero() && !time.Now().Before(dl) {
		return 0, os.ErrDeadlineExceeded
	}

	c.writeBuf = append(c.writeBuf[:0], p...)
	c.writeBusy = true
	c.writeReq <- c.writeBuf

	res, err := c.waitWriteResult(&timer)
	if err != nil {
		return 0, err
	}
	return res.n, res.err
}

func (c *proxyChanConn) isClosing() bool {
	return c != nil && c.closed.Load()
}

func (c *proxyChanConn) Close() error {
	if c == nil {
		return nil
	}
	first := false
	c.closeOnce.Do(func() {
		first = true
		c.closeErr = c.closeOnceBody()
		close(c.closeDone)
	})
	<-c.closeDone
	if !first {
		return errProxyChanAlreadyClosed
	}
	return c.closeErr
}

func (c *proxyChanConn) closeOnceBody() error {
	c.lifecycleMu.Lock()
	c.closing = true
	c.closed.Store(true)
	close(c.closedCh)
	c.lifecycleMu.Unlock()

	if c.raw == nil {
		c.ioWG.Wait()
		return nil
	}

	rawCloseDone := make(chan error, 1)
	go func() {
		rawCloseDone <- c.raw.Close()
	}()

	ioDone := make(chan struct{})
	go func() {
		c.ioWG.Wait()
		close(ioDone)
	}()

	grace := proxyChanCloseGrace
	if grace <= 0 {
		grace = 90 * time.Millisecond
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()

	rawDone := false
	workersDone := false
	var rawErr error
	for !rawDone || !workersDone {
		var rCh <-chan error
		if !rawDone {
			rCh = rawCloseDone
		}
		var wCh <-chan struct{}
		if !workersDone {
			wCh = ioDone
		}
		select {
		case err := <-rCh:
			rawErr = err
			rawDone = true
		case <-wCh:
			workersDone = true
		case <-timer.C:
			c.escalated.Store(true)
			var abortErr error
			if c.abortUpstream != nil {
				abortErr = c.abortUpstream(c)
			}
			if !rawDone {
				rawErr = <-rawCloseDone
			}
			if !workersDone {
				<-ioDone
			}
			if rawErr != nil && (errors.Is(rawErr, net.ErrClosed) || errors.Is(rawErr, io.EOF)) {
				rawErr = nil
			}
			return errors.Join(rawErr, abortErr)
		}
	}
	if rawErr != nil && (errors.Is(rawErr, net.ErrClosed) || errors.Is(rawErr, io.EOF)) {
		return nil
	}
	return rawErr
}

func (c *proxyChanConn) LocalAddr() net.Addr {
	if c == nil || c.raw == nil {
		return nil
	}
	return c.raw.LocalAddr()
}

func (c *proxyChanConn) RemoteAddr() net.Addr {
	if c == nil || c.raw == nil {
		return nil
	}
	return c.raw.RemoteAddr()
}

func (c *proxyChanConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *proxyChanConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.closed.Load() {
		return net.ErrClosed
	}
	c.readMu.Lock()
	c.readDL = t
	c.readMu.Unlock()
	notifyNonBlocking(c.readDLCh)
	return nil
}

func (c *proxyChanConn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.closed.Load() {
		return net.ErrClosed
	}
	c.writeMu.Lock()
	c.writeDL = t
	c.writeMu.Unlock()
	notifyNonBlocking(c.writeDLCh)
	return nil
}
