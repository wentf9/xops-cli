package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/pkg/logger"
)

const tcpDialTimeout = 10 * time.Second

// TCPForwarder listens on a local TCP address and forwards connections to a target address.
type TCPForwarder struct {
	listenAddr   string
	targetAddr   string
	logger       logger.DebugLogger
	errorHandler ErrorHandler
}

// NewTCPForwarder creates a new TCPForwarder.
func NewTCPForwarder(listenAddr, targetAddr string, opts ...Option) *TCPForwarder {
	cfg := defaultConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	return &TCPForwarder{
		listenAddr:   listenAddr,
		targetAddr:   targetAddr,
		logger:       cfg.logger,
		errorHandler: cfg.errorHandler,
	}
}

// Run starts the TCP forwarder and blocks until ctx is canceled. It does not
// return until every accepted connection handler has exited.
func (f *TCPForwarder) Run(ctx context.Context) (err error) {
	listener, err := net.Listen("tcp", f.listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s failed: %w", f.listenAddr, err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	closeErrCh := make(chan error, 1)
	go func() {
		<-runCtx.Done()
		closeErrCh <- listener.Close()
	}()

	var handlers sync.WaitGroup
	defer func() {
		cancel()
		if closeErr := <-closeErrCh; closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			err = errors.Join(err, fmt.Errorf("close tcp listener failed: %w", closeErr))
		}
		handlers.Wait()
	}()

	f.logger.Debugf("TCP forwarder listening on %s -> target %s", f.listenAddr, f.targetAddr)

	for {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			if runCtx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept tcp connection failed: %w", acceptErr)
		}
		handlers.Go(func() {
			f.handle(runCtx, conn)
		})
	}
}

//nolint:gocyclo
func (f *TCPForwarder) handle(ctx context.Context, src net.Conn) {
	defer f.closeConn(src, "source connection")
	connectionCtx, cancelConnection := context.WithCancel(ctx)
	defer cancelConnection()

	if tcpConn, ok := src.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			f.report(fmt.Errorf("enable source tcp keepalive failed: %w", err))
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			f.report(fmt.Errorf("set source tcp keepalive period failed: %w", err))
		}
	}

	dialer := net.Dialer{Timeout: tcpDialTimeout}
	dst, err := dialer.DialContext(connectionCtx, "tcp", f.targetAddr)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			f.report(fmt.Errorf("dial target %s failed: %w", f.targetAddr, err))
		}
		return
	}
	defer f.closeConn(dst, "target connection")

	if tcpConn, ok := dst.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			f.report(fmt.Errorf("enable target tcp keepalive failed: %w", err))
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			f.report(fmt.Errorf("set target tcp keepalive period failed: %w", err))
		}
	}

	copyDone := make(chan struct{})
	cancelDone := make(chan struct{})
	go func() {
		defer close(cancelDone)
		select {
		case <-connectionCtx.Done():
			f.closeConn(src, "source connection after cancellation")
			f.closeConn(dst, "target connection after cancellation")
		case <-copyDone:
		}
	}()

	var copies sync.WaitGroup
	pipe := func(w net.Conn, r net.Conn, direction string) {
		defer copies.Done()
		buf := make([]byte, 32*1024)
		for {
			if connectionCtx.Err() != nil {
				return
			}
			if err := r.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
				f.report(fmt.Errorf("set tcp %s read deadline failed: %w", direction, err))
				cancelConnection()
				return
			}
			n, rErr := r.Read(buf)
			if n > 0 {
				if wErr := writeTCPBytes(w, buf[:n]); wErr != nil {
					if !errors.Is(wErr, net.ErrClosed) && !errors.Is(wErr, context.Canceled) && connectionCtx.Err() == nil {
						f.report(fmt.Errorf("forward tcp %s write failed: %w", direction, wErr))
						cancelConnection()
					}
					break
				}
			}
			if rErr != nil {
				if !errors.Is(rErr, io.EOF) && !errors.Is(rErr, net.ErrClosed) && !errors.Is(rErr, context.Canceled) && connectionCtx.Err() == nil {
					var netErr net.Error
					if !errors.As(rErr, &netErr) || !netErr.Timeout() {
						f.report(fmt.Errorf("forward tcp %s read failed: %w", direction, rErr))
						cancelConnection()
					}
				}
				break
			}
		}
		if closeWriter, ok := w.(interface{ CloseWrite() error }); ok {
			if closeErr := closeWriter.CloseWrite(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
				f.report(fmt.Errorf("close tcp %s writer failed: %w", direction, closeErr))
				cancelConnection()
			}
		} else {
			f.closeConn(w, "tcp "+direction+" writer")
		}
	}

	copies.Add(2)
	go pipe(dst, src, "source to target")
	go pipe(src, dst, "target to source")
	copies.Wait()
	close(copyDone)
	<-cancelDone
}

func writeTCPBytes(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		if err := conn.SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
			return fmt.Errorf("set write deadline failed: %w", err)
		}
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (f *TCPForwarder) closeConn(conn net.Conn, resource string) {
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		f.report(fmt.Errorf("close %s failed: %w", resource, err))
	}
}

func (f *TCPForwarder) report(err error) {
	if f.errorHandler != nil {
		f.errorHandler(err)
		return
	}
	f.logger.Debugf("%v", err)
}
