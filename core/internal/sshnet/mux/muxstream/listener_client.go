package muxstream

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/ports"
)

type muxAddr struct {
	network string
	address string
}

func (a muxAddr) Network() string { return a.network }
func (a muxAddr) String() string  { return a.address }

// RemoteListener 通过单条帧复用连接实现远端 ListenTCP / ListenStreamLocal 的 net.Listener 视图；零值恒失败关闭。
//
//xops:opaque
//xops:failclosed
type RemoteListener struct {
	lifeNursery *conc.Nursery
	conn        io.ReadWriteCloser
	fw          *SyncFrameWriter
	localAddr   net.Addr

	acceptCh   chan net.Conn
	closedCh   chan struct{}
	readerDone chan struct{}

	mu        sync.Mutex
	streams   map[uint32]*muxAcceptedConn
	closed    atomic.Bool
	closeOnce sync.Once
	valid     bool
}

// NewRemoteListener 构造受 lifeNursery 监督的多路复用远端监听器客户端。
func NewRemoteListener(lifeNursery *conc.Nursery, conn io.ReadWriteCloser, network, boundAddr string) (*RemoteListener, error) {
	if lifeNursery == nil || conn == nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, ports.ErrClosed
	}
	l := &RemoteListener{
		lifeNursery: lifeNursery,
		conn:        conn,
		fw:          NewSyncFrameWriter(conn),
		localAddr:   muxAddr{network: network, address: boundAddr},
		acceptCh:    make(chan net.Conn, 16),
		closedCh:    make(chan struct{}),
		readerDone:  make(chan struct{}),
		streams:     make(map[uint32]*muxAcceptedConn),
		valid:       true,
	}
	if err := lifeNursery.Go(func(context.Context) error {
		defer close(l.readerDone)
		l.readLoop()
		return nil
	}); err != nil {
		close(l.readerDone)
		_ = conn.Close()
		return nil, ports.ErrClosed
	}
	return l, nil
}

// Accept 接收下一条由远端监听器经控制通道复用投递的入站连接。
func (l *RemoteListener) Accept() (net.Conn, error) {
	if l == nil || !l.valid {
		return nil, ports.ErrClosed
	}
	select {
	case c := <-l.acceptCh:
		return c, nil
	case <-l.closedCh:
		return nil, net.ErrClosed
	}
}

// Addr 返回远端实际绑定地址。
func (l *RemoteListener) Addr() net.Addr {
	if l == nil || !l.valid {
		return muxAddr{network: "mux", address: ""}
	}
	return l.localAddr
}

// Close 幂等关闭复用监听器与所有在途子连接，并等待后台读泵同步退出。
func (l *RemoteListener) Close() error {
	if l == nil || !l.valid {
		return nil
	}
	l.closeConnOnly()
	<-l.readerDone
	return nil
}

func (l *RemoteListener) closeConnOnly() {
	l.closeOnce.Do(func() {
		l.closed.Store(true)
		close(l.closedCh)
		l.closeAllStreams()
		_ = l.conn.Close()
	})
}

func (l *RemoteListener) closeAllStreams() {
	l.mu.Lock()
	list := make([]*muxAcceptedConn, 0, len(l.streams))
	for id, c := range l.streams {
		list = append(list, c)
		delete(l.streams, id)
	}
	l.mu.Unlock()
	for _, c := range list {
		c.closeLocalOnly()
	}
}

func (l *RemoteListener) readLoop() {
	defer l.closeConnOnly()
	for {
		msgType, body, err := ReadPacket(l.conn)
		if err != nil {
			return
		}
		if done, _ := l.handleFrame(msgType, body); done {
			return
		}
	}
}

func (l *RemoteListener) handleFrame(msgType uint32, body []byte) (bool, error) {
	rd := NewReader(body)
	switch msgType {
	case LstMsgAccept:
		return l.handleAcceptFrame(&rd)
	case LstMsgData:
		id, e1 := rd.ReadUint32()
		data, e2 := rd.ReadBytes()
		if err := FirstErr(e1, e2); err != nil {
			return true, err
		}
		if ac := l.lookupStream(id); ac != nil {
			if pErr := ac.pushData(data); pErr != nil {
				l.removeStreamByID(id)
				_ = l.fw.Write(LstMsgClose, AppendU32(nil, id))
			}
		}
	case LstMsgCloseWrite:
		id, err := rd.ReadUint32()
		if err != nil {
			return true, err
		}
		if ac := l.lookupStream(id); ac != nil {
			ac.markReadEOF()
		}
	case LstMsgClose:
		id, err := rd.ReadUint32()
		if err != nil {
			return true, err
		}
		l.closeStreamByID(id)
	case LstMsgListenerClosed:
		return true, nil
	}
	return false, nil
}

func (l *RemoteListener) handleAcceptFrame(rd *Reader) (bool, error) {
	id, e1 := rd.ReadUint32()
	rNet, e2 := rd.ReadString()
	rAddr, e3 := rd.ReadString()
	if err := FirstErr(e1, e2, e3); err != nil {
		return true, err
	}
	ac := newMuxAcceptedConn(id, l, l.localAddr, muxAddr{network: rNet, address: rAddr})
	l.mu.Lock()
	l.streams[id] = ac
	l.mu.Unlock()
	select {
	case l.acceptCh <- ac:
		return false, nil
	case <-l.closedCh:
		ac.closeLocalOnly()
		return true, nil
	}
}

func (l *RemoteListener) removeStreamByID(id uint32) {
	l.mu.Lock()
	delete(l.streams, id)
	l.mu.Unlock()
}

func (l *RemoteListener) closeStreamByID(id uint32) {
	l.mu.Lock()
	ac := l.streams[id]
	delete(l.streams, id)
	l.mu.Unlock()
	if ac != nil {
		ac.closeLocalOnly()
	}
}

func (l *RemoteListener) lookupStream(id uint32) *muxAcceptedConn {
	l.mu.Lock()
	ac := l.streams[id]
	l.mu.Unlock()
	return ac
}

// maxAcceptedConnBufBytes 限制单条复用远端入站连接的读缓冲高水位（4 MiB），防止慢速消费方导致无界内存增长。
const maxAcceptedConnBufBytes = 4 << 20

// muxAcceptedConn 表示 RemoteListener.Accept 返回的单条复用远端到站连接（支持半关闭 CloseWrite）。
type muxAcceptedConn struct {
	id         uint32
	parent     *RemoteListener
	localAddr  net.Addr
	remoteAddr net.Addr

	mu          sync.Mutex
	cond        *sync.Cond
	buf         bytes.Buffer
	eof         bool
	wClosed     bool
	closed      bool
	localClosed bool
	overflowErr error
	once        sync.Once
}

func newMuxAcceptedConn(id uint32, parent *RemoteListener, localAddr, remoteAddr net.Addr) *muxAcceptedConn {
	c := &muxAcceptedConn{id: id, parent: parent, localAddr: localAddr, remoteAddr: remoteAddr}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *muxAcceptedConn) pushData(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.localClosed {
		return nil
	}
	if c.buf.Len()+len(data) > maxAcceptedConnBufBytes {
		c.closed = true
		c.overflowErr = ports.ErrLimitExceeded
		c.cond.Broadcast()
		return ports.ErrLimitExceeded
	}
	_, err := c.buf.Write(data)
	c.cond.Broadcast()
	return err
}

func (c *muxAcceptedConn) markReadEOF() {
	c.mu.Lock()
	c.eof = true
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *muxAcceptedConn) closeLocalOnly() {
	c.mu.Lock()
	c.eof = true
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *muxAcceptedConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.buf.Len() == 0 && !c.eof && !c.closed && !c.localClosed {
		c.cond.Wait()
	}
	if c.localClosed {
		return 0, net.ErrClosed
	}
	if c.buf.Len() > 0 {
		return c.buf.Read(p)
	}
	if c.overflowErr != nil {
		return 0, c.overflowErr
	}
	return 0, io.EOF
}

func (c *muxAcceptedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	closed := c.closed || c.localClosed || c.wClosed
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	total := 0
	for total < len(p) {
		end := min(total+CopyChunkBytes, len(p))
		if err := c.parent.fw.Write(LstMsgData, AppendBytes(AppendU32(nil, c.id), p[total:end])); err != nil {
			return total, err
		}
		total = end
	}
	return total, nil
}

func (c *muxAcceptedConn) CloseWrite() error {
	c.mu.Lock()
	if c.wClosed || c.closed || c.localClosed {
		c.mu.Unlock()
		return nil
	}
	c.wClosed = true
	c.mu.Unlock()
	return c.parent.fw.Write(LstMsgCloseWrite, AppendU32(nil, c.id))
}

func (c *muxAcceptedConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.localClosed = true
		c.eof = true
		c.closed = true
		c.cond.Broadcast()
		c.mu.Unlock()
		c.parent.removeStreamByID(c.id)
		_ = c.parent.fw.Write(LstMsgClose, AppendU32(nil, c.id))
	})
	return nil
}

func (c *muxAcceptedConn) LocalAddr() net.Addr              { return c.localAddr }
func (c *muxAcceptedConn) RemoteAddr() net.Addr             { return c.remoteAddr }
func (c *muxAcceptedConn) SetDeadline(time.Time) error      { return nil }
func (c *muxAcceptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *muxAcceptedConn) SetWriteDeadline(time.Time) error { return nil }
