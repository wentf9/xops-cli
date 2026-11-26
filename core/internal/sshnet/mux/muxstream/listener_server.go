package muxstream

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/conc"
)

type bridgedStream struct {
	conn              net.Conn
	peerReadEOF       bool
	clientWriteClosed bool
}

// ServeListenerBridge 在服务端将上游远端 net.Listener 的全部到站连接多路复用进单条 AF_UNIX 帧流，
// 完整保留双向 TCP/Unix 半关闭语义直至双侧均结束或客户端显式发送 LstMsgClose。
func ServeListenerBridge(ctx context.Context, conn net.Conn, ln net.Listener) {
	fw := NewSyncFrameWriter(conn)
	var mu sync.Mutex
	streams := make(map[uint32]*bridgedStream)
	var nextID atomic.Uint32

	closeAll := func() {
		_ = ln.Close()
		mu.Lock()
		for id, bs := range streams {
			_ = bs.conn.Close()
			delete(streams, id)
		}
		mu.Unlock()
	}
	defer closeAll()

	_ = conc.RunScoped(ctx, func(wCtx context.Context, n *conc.Nursery) error {
		_ = n.Go(func(c context.Context) error {
			<-c.Done()
			closeAll()
			_ = conn.Close()
			return nil
		})
		_ = n.Go(func(context.Context) error {
			readListenerClientFrames(conn, &mu, streams, closeAll)
			return nil
		})
		return acceptRemoteListenerIntoMux(wCtx, n, ln, fw, &mu, streams, &nextID)
	})
}

func acceptRemoteListenerIntoMux(ctx context.Context, n *conc.Nursery, ln net.Listener, fw *SyncFrameWriter, mu *sync.Mutex, streams map[uint32]*bridgedStream, nextID *atomic.Uint32) error {
	for {
		rc, err := ln.Accept()
		if err != nil {
			_ = fw.Write(LstMsgListenerClosed, AppendStr(nil, err.Error()))
			return nil
		}
		id := nextID.Add(1)
		mu.Lock()
		streams[id] = &bridgedStream{conn: rc}
		mu.Unlock()
		rNet, rAddr := "tcp", ""
		if rc.RemoteAddr() != nil {
			rNet, rAddr = rc.RemoteAddr().Network(), rc.RemoteAddr().String()
		}
		if err := fw.Write(LstMsgAccept, AppendStr(AppendStr(AppendU32(nil, id), rNet), rAddr)); err != nil {
			removeAndCloseStream(id, mu, streams)
			return nil
		}
		if err := n.Go(func(context.Context) error {
			pumpAcceptedToMuxFrames(id, rc, fw, mu, streams)
			return nil
		}); err != nil {
			removeAndCloseStream(id, mu, streams)
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}

func pumpAcceptedToMuxFrames(id uint32, rc net.Conn, fw *SyncFrameWriter, mu *sync.Mutex, streams map[uint32]*bridgedStream) {
	buf := make([]byte, CopyChunkBytes)
	for {
		n, err := rc.Read(buf)
		if n > 0 {
			if wErr := fw.Write(LstMsgData, AppendBytes(AppendU32(nil, id), buf[:n])); wErr != nil {
				removeAndCloseStream(id, mu, streams)
				return
			}
		}
		if err != nil {
			handlePeerReadDone(id, err, fw, mu, streams)
			return
		}
	}
}

func handlePeerReadDone(id uint32, readErr error, fw *SyncFrameWriter, mu *sync.Mutex, streams map[uint32]*bridgedStream) {
	if errors.Is(readErr, io.EOF) {
		_ = fw.Write(LstMsgCloseWrite, AppendU32(nil, id))
		if !markPeerReadEOFAndCheckDone(id, mu, streams) {
			return
		}
	}
	removeAndCloseStream(id, mu, streams)
	_ = fw.Write(LstMsgClose, AppendU32(nil, id))
}

func markPeerReadEOFAndCheckDone(id uint32, mu *sync.Mutex, streams map[uint32]*bridgedStream) bool {
	mu.Lock()
	defer mu.Unlock()
	bs := streams[id]
	if bs == nil {
		return false
	}
	bs.peerReadEOF = true
	return bs.clientWriteClosed
}

func removeAndCloseStream(id uint32, mu *sync.Mutex, streams map[uint32]*bridgedStream) {
	mu.Lock()
	bs := streams[id]
	delete(streams, id)
	mu.Unlock()
	if bs != nil {
		_ = bs.conn.Close()
	}
}

func readListenerClientFrames(conn net.Conn, mu *sync.Mutex, streams map[uint32]*bridgedStream, closeAll func()) {
	defer closeAll()
	for {
		msgType, body, err := ReadPacket(conn)
		if err != nil {
			return
		}
		dispatchListenerClientFrame(msgType, body, mu, streams)
	}
}

func dispatchListenerClientFrame(msgType uint32, body []byte, mu *sync.Mutex, streams map[uint32]*bridgedStream) {
	rd := NewReader(body)
	id, err := rd.ReadUint32()
	if err != nil {
		return
	}
	mu.Lock()
	bs := streams[id]
	mu.Unlock()
	if bs == nil {
		return
	}
	switch msgType {
	case LstMsgData:
		if data, err := rd.ReadBytes(); err == nil && len(data) > 0 {
			_, _ = bs.conn.Write(data)
		}
	case LstMsgCloseWrite:
		handleClientHalfClose(id, bs, mu, streams)
	case LstMsgClose:
		removeAndCloseStream(id, mu, streams)
	}
}

func handleClientHalfClose(id uint32, bs *bridgedStream, mu *sync.Mutex, streams map[uint32]*bridgedStream) {
	hasHalfClose := false
	if hc, ok := bs.conn.(HalfWriteCloser); ok {
		hasHalfClose = true
		_ = hc.CloseWrite()
	}
	mu.Lock()
	bs.clientWriteClosed = true
	done := bs.peerReadEOF || !hasHalfClose
	if done {
		delete(streams, id)
	}
	mu.Unlock()
	if done {
		_ = bs.conn.Close()
	}
}
