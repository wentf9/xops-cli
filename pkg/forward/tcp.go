package forward

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/pkg/logger"
)

// TCPForwarder listens on a local TCP address and forwards connections to a target address.
type TCPForwarder struct {
	listenAddr string
	targetAddr string
}

// NewTCPForwarder creates a new TCPForwarder.
func NewTCPForwarder(listenAddr, targetAddr string) *TCPForwarder {
	return &TCPForwarder{
		listenAddr: listenAddr,
		targetAddr: targetAddr,
	}
}

// Run starts the TCP forwarder and blocks until ctx is canceled.
func (f *TCPForwarder) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", f.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", f.listenAddr, err)
	}

	derivedCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-derivedCtx.Done()
		_ = listener.Close()
	}()

	logger.Infof("TCP %s -> %s", f.listenAddr, f.targetAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("accept error: %w", err)
			}
		}
		go f.handle(conn)
	}
}

func (f *TCPForwarder) handle(src net.Conn) {
	defer func() { _ = src.Close() }()

	if tcpConn, ok := src.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			logger.Warnf("failed to set keepalive on src: %v", err)
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			logger.Warnf("failed to set keepalive period on src: %v", err)
		}
	}

	dst, err := net.DialTimeout("tcp", f.targetAddr, 10*time.Second)
	if err != nil {
		logger.Warnf("TCP dial %s failed: %v", f.targetAddr, err)
		return
	}
	defer func() { _ = dst.Close() }()

	if tcpConn, ok := dst.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			logger.Warnf("failed to set keepalive on dst: %v", err)
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			logger.Warnf("failed to set keepalive period on dst: %v", err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	pipe := func(w net.Conn, r net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(w, r)
		if cw, ok := w.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = w.Close()
		}
	}

	go pipe(dst, src)
	go pipe(src, dst)
	wg.Wait()
}
