package forward

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
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

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	fmt.Fprintf(os.Stderr, "[forward] TCP %s -> %s\n", f.listenAddr, f.targetAddr)

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

	dst, err := net.Dial("tcp", f.targetAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[forward] TCP dial %s failed: %v\n", f.targetAddr, err)
		return
	}
	defer func() { _ = dst.Close() }()

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
