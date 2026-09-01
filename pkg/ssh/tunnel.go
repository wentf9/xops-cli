package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Forward represents one running SSH port forward. Callers must either wait
// for it or cancel the context passed to its constructor.
type Forward struct {
	done chan struct{}
	err  error
}

// ForwardOption configures how a forwarding listener reports connection-level
// failures. These failures never stop the listener.
type ForwardOption func(*forwardOptions)

type forwardOptions struct {
	onConnectionError func(error)
}

// WithForwardErrorHandler receives errors isolated to one accepted
// connection. The callback must be safe for concurrent calls and return
// promptly.
func WithForwardErrorHandler(handler func(error)) ForwardOption {
	return func(options *forwardOptions) {
		if handler != nil {
			options.onConnectionError = handler
		}
	}
}

// Wait blocks until the forwarding listener and all connection handlers exit.
// It is safe to call Wait more than once; every call returns the same result.
func (f *Forward) Wait() error {
	if f == nil || f.done == nil {
		return nil
	}
	<-f.done
	return f.err
}

// LocalForward starts local port forwarding.
// Listens on localAddr, forwards connections to remoteAddr via SSH.
func (c *Client) LocalForward(ctx context.Context, localAddr, remoteAddr string, opts ...ForwardOption) (*Forward, error) {
	if ctx == nil {
		return nil, fmt.Errorf("local forward context is nil")
	}
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("listen on local address %s failed: %w", localAddr, err)
	}
	return runForwardListener(ctx, listener, c.forwardOptions(opts...), func(runCtx context.Context, conn net.Conn) error {
		return c.handleLocalForward(runCtx, conn, remoteAddr)
	}), nil
}

func (c *Client) handleLocalForward(ctx context.Context, localConn net.Conn, remoteAddr string) (retErr error) {
	defer joinResourceCloseError(&retErr, localConn, "local forwarding client connection")
	remoteConn, err := c.dialSSH(ctx, "tcp", remoteAddr)
	if err != nil {
		return fmt.Errorf("dial local forwarding destination %s failed: %w", remoteAddr, err)
	}
	defer joinResourceCloseError(&retErr, remoteConn, "local forwarding remote connection")
	return c.copyStream(ctx, localConn, remoteConn)
}

// RemoteForward starts remote port forwarding.
// Asks SSH server to listen on remoteAddr, forwards connections to localAddr.
func (c *Client) RemoteForward(ctx context.Context, remoteAddr, localAddr string, opts ...ForwardOption) (*Forward, error) {
	if ctx == nil {
		return nil, fmt.Errorf("remote forward context is nil")
	}
	listener, err := c.sshClient.Listen("tcp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("listen on remote address %s failed: %w", remoteAddr, err)
	}
	return runForwardListener(ctx, listener, c.forwardOptions(opts...), func(runCtx context.Context, conn net.Conn) error {
		return c.handleRemoteForward(runCtx, conn, localAddr)
	}), nil
}

func (c *Client) handleRemoteForward(ctx context.Context, remoteConn net.Conn, localAddr string) (retErr error) {
	defer joinResourceCloseError(&retErr, remoteConn, "remote forwarding client connection")
	dialer := net.Dialer{Timeout: 5 * time.Second}
	localConn, err := dialer.DialContext(ctx, "tcp", localAddr)
	if err != nil {
		return fmt.Errorf("dial remote forwarding destination %s failed: %w", localAddr, err)
	}
	defer joinResourceCloseError(&retErr, localConn, "remote forwarding local connection")
	return c.copyStream(ctx, remoteConn, localConn)
}

func (c *Client) forwardOptions(opts ...ForwardOption) forwardOptions {
	options := forwardOptions{onConnectionError: func(err error) {
		c.getLogger().Debugf("ssh forwarding connection failed: %v", err)
	}}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	return options
}

func runForwardListener(ctx context.Context, listener net.Listener, options forwardOptions, handle func(context.Context, net.Conn) error) *Forward {
	forward := &Forward{done: make(chan struct{})}
	go func() {
		defer close(forward.done)
		runCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		cancellationClose := make(chan error, 1)
		stopCancellation := context.AfterFunc(runCtx, func() {
			cancellationClose <- closeResource(listener, "canceled forwarding listener")
		})

		var handlers sync.WaitGroup
		var acceptErr error
		for {
			conn, err := listener.Accept()
			if err != nil {
				if runCtx.Err() == nil {
					acceptErr = fmt.Errorf("accept forwarded connection failed: %w", err)
				}
				break
			}
			handlers.Go(func() {
				if err := handle(runCtx, conn); err != nil && runCtx.Err() == nil {
					options.onConnectionError(err)
				}
			})
		}
		var cancellationCloseErr error
		if !stopCancellation() {
			cancellationCloseErr = <-cancellationClose
		}
		closeErr := errors.Join(cancellationCloseErr, closeResource(listener, "forwarding listener"))
		handlers.Wait()
		forward.err = errors.Join(acceptErr, closeErr)
	}()
	return forward
}

func (c *Client) dialSSH(ctx context.Context, network, addr string) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := c.sshClient.DialContext(dialCtx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s via SSH failed: %w", addr, err)
	}
	return conn, nil
}

//nolint:gocyclo
func (c *Client) copyStream(ctx context.Context, conn1, conn2 net.Conn) error {
	if tcpConn, ok := conn1.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			return fmt.Errorf("enable first tunnel connection keepalive failed: %w", err)
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			return fmt.Errorf("set first tunnel connection keepalive period failed: %w", err)
		}
	}
	if tcpConn, ok := conn2.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			return fmt.Errorf("enable second tunnel connection keepalive failed: %w", err)
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			return fmt.Errorf("set second tunnel connection keepalive period failed: %w", err)
		}
	}

	copyCtx, cancelCopy := context.WithCancel(ctx)
	defer cancelCopy()
	cancellationDone := make(chan struct{})
	stopCancellation := context.AfterFunc(copyCtx, func() {
		defer close(cancellationDone)
		debugCloseResource(c.getLogger(), conn1, "canceled first tunnel connection")
		debugCloseResource(c.getLogger(), conn2, "canceled second tunnel connection")
	})
	defer func() {
		if !stopCancellation() {
			<-cancellationDone
		}
	}()

	errCh := make(chan error, 2)
	var copies sync.WaitGroup

	pipe := func(dst, src net.Conn, name string) {
		defer copies.Done()
		buf := make([]byte, 32*1024)
		for copyCtx.Err() == nil {
			n, rErr := readTunnelBytes(src, buf)
			if n > 0 {
				if err := writeTunnelBytes(dst, buf[:n]); err != nil {
					if copyCtx.Err() == nil && !errors.Is(err, net.ErrClosed) {
						errCh <- fmt.Errorf("write %s failed: %w", name, err)
						cancelCopy()
					} else {
						errCh <- nil
					}
					return
				}
			}
			if rErr != nil {
				if !errors.Is(rErr, io.EOF) && !errors.Is(rErr, net.ErrClosed) && copyCtx.Err() == nil {
					errCh <- fmt.Errorf("read %s failed: %w", name, rErr)
					cancelCopy()
					return
				}
				break
			}
		}

		var closeErr error
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			closeErr = cw.CloseWrite()
		} else {
			closeErr = dst.Close()
		}
		if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) && !errors.Is(closeErr, io.EOF) && copyCtx.Err() == nil {
			errCh <- fmt.Errorf("close %s writer failed: %w", name, closeErr)
			cancelCopy()
			return
		}
		errCh <- nil
	}

	copies.Add(2)
	go pipe(conn1, conn2, "conn2 -> conn1")
	go pipe(conn2, conn1, "conn1 -> conn2")
	copies.Wait()
	return errors.Join(<-errCh, <-errCh)
}

func writeTunnelBytes(dst net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := runTimedTunnelIO(dst, time.Minute, "write", func() (int, error) {
			return dst.Write(data)
		})
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

func readTunnelBytes(src net.Conn, data []byte) (int, error) {
	return runTimedTunnelIO(src, 5*time.Minute, "read", func() (int, error) {
		return src.Read(data)
	})
}

// runTimedTunnelIO bounds operations even for x/crypto/ssh channel
// connections, whose SetDeadline methods explicitly return an unsupported
// error. Closing only that channel connection interrupts the pending I/O.
func runTimedTunnelIO(conn net.Conn, timeout time.Duration, operation string, fn func() (int, error)) (int, error) {
	timeoutResult := make(chan error, 1)
	timer := time.AfterFunc(timeout, func() {
		timeoutResult <- closeResource(conn, "timed out tunnel connection")
	})
	n, err := fn()
	if timer.Stop() {
		return n, err
	}
	closeErr := <-timeoutResult
	return n, errors.Join(fmt.Errorf("tunnel %s timed out after %s", operation, timeout), err, closeErr)
}
