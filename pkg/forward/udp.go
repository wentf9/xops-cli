package forward

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/pkg/logger"
)

const (
	udpSessionTimeout = 60 * time.Second
	udpWriteTimeout   = 10 * time.Second
)

// udpSession tracks an upstream UDP connection for a specific client.
type udpSession struct {
	upstream *net.UDPConn
	lastSeen time.Time
}

// UDPForwarder listens on a local UDP address and forwards datagrams to a target address.
type UDPForwarder struct {
	listenAddr   string
	targetAddr   string
	logger       logger.DebugLogger
	errorHandler ErrorHandler

	mu       sync.Mutex
	sessions map[string]*udpSession // key: client addr string
}

// NewUDPForwarder creates a new UDPForwarder.
func NewUDPForwarder(listenAddr, targetAddr string, opts ...Option) *UDPForwarder {
	cfg := defaultConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	return &UDPForwarder{
		listenAddr:   listenAddr,
		targetAddr:   targetAddr,
		logger:       cfg.logger,
		errorHandler: cfg.errorHandler,
		sessions:     make(map[string]*udpSession),
	}
}

// Run starts the UDP forwarder and blocks until ctx is canceled. It closes all
// sessions and waits for every forwarding goroutine before returning.
func (f *UDPForwarder) Run(ctx context.Context) (err error) {
	laddr, err := net.ResolveUDPAddr("udp", f.listenAddr)
	if err != nil {
		return fmt.Errorf("resolve listen address %s failed: %w", f.listenAddr, err)
	}

	raddr, err := net.ResolveUDPAddr("udp", f.targetAddr)
	if err != nil {
		return fmt.Errorf("resolve target address %s failed: %w", f.targetAddr, err)
	}

	listener, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return fmt.Errorf("listen on %s failed: %w", f.listenAddr, err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	closeErrCh := make(chan error, 1)
	go func() {
		<-runCtx.Done()
		closeErrCh <- listener.Close()
	}()

	var workers sync.WaitGroup
	workers.Go(func() { f.reapSessions(runCtx) })
	defer func() {
		cancel()
		if closeErr := <-closeErrCh; closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			err = errors.Join(err, fmt.Errorf("close udp listener failed: %w", closeErr))
		}
		f.closeSessions()
		workers.Wait()
	}()

	f.logger.Debugf("UDP forwarder listening on %s -> target %s", f.listenAddr, f.targetAddr)

	buf := make([]byte, 64*1024)
	for {
		n, clientAddr, readErr := listener.ReadFromUDP(buf)
		if readErr != nil {
			if runCtx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read udp packet failed: %w", readErr)
		}

		data := append([]byte(nil), buf[:n]...)
		workers.Go(func() {
			f.forward(runCtx, &workers, listener, clientAddr, raddr, data)
		})
	}
}

func (f *UDPForwarder) forward(ctx context.Context, workers *sync.WaitGroup, listener *net.UDPConn, clientAddr, targetAddr *net.UDPAddr, data []byte) {
	if ctx.Err() != nil {
		return
	}

	key := clientAddr.String()
	f.mu.Lock()
	sess := f.sessions[key]
	f.mu.Unlock()

	if sess == nil {
		dialer := net.Dialer{Timeout: udpWriteTimeout}
		conn, err := dialer.DialContext(ctx, "udp", targetAddr.String())
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				f.report(fmt.Errorf("dial udp target %s failed: %w", targetAddr, err))
			}
			return
		}
		upstream, ok := conn.(*net.UDPConn)
		if !ok {
			if closeErr := conn.Close(); closeErr != nil {
				f.report(fmt.Errorf("close unexpected udp connection failed: %w", closeErr))
			}
			f.report(fmt.Errorf("dial udp target %s returned %T", targetAddr, conn))
			return
		}

		f.mu.Lock()
		if ctx.Err() != nil {
			f.mu.Unlock()
			f.closeUDPConn(upstream, "canceled udp upstream")
			return
		}
		if existing := f.sessions[key]; existing != nil {
			sess = existing
			f.mu.Unlock()
			f.closeUDPConn(upstream, "duplicate udp upstream")
		} else {
			sess = &udpSession{upstream: upstream, lastSeen: time.Now()}
			f.sessions[key] = sess
			f.mu.Unlock()
			workers.Go(func() {
				f.relay(ctx, listener, clientAddr, upstream, key)
			})
		}
	}

	if err := sess.upstream.SetWriteDeadline(time.Now().Add(udpWriteTimeout)); err != nil {
		f.report(fmt.Errorf("set udp target write deadline failed: %w", err))
		return
	}
	if _, err := sess.upstream.Write(data); err != nil && !errors.Is(err, net.ErrClosed) {
		f.report(fmt.Errorf("write to udp target %s failed: %w", targetAddr, err))
		return
	}

	f.mu.Lock()
	if current := f.sessions[key]; current == sess {
		current.lastSeen = time.Now()
	}
	f.mu.Unlock()
}

func (f *UDPForwarder) relay(ctx context.Context, listener *net.UDPConn, clientAddr *net.UDPAddr, upstream *net.UDPConn, key string) {
	defer func() {
		f.closeUDPConn(upstream, "udp upstream")
		f.mu.Lock()
		if sess := f.sessions[key]; sess != nil && sess.upstream == upstream {
			delete(f.sessions, key)
		}
		f.mu.Unlock()
	}()

	buf := make([]byte, 64*1024)
	for {
		if ctx.Err() != nil {
			return
		}
		if err := upstream.SetReadDeadline(time.Now().Add(udpSessionTimeout)); err != nil {
			f.report(fmt.Errorf("set udp read deadline failed: %w", err))
			return
		}
		n, err := upstream.Read(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				var netErr net.Error
				if !errors.As(err, &netErr) || !netErr.Timeout() {
					f.report(fmt.Errorf("read udp upstream failed: %w", err))
				}
			}
			return
		}

		if err := listener.SetWriteDeadline(time.Now().Add(udpWriteTimeout)); err != nil {
			f.report(fmt.Errorf("set udp client write deadline failed: %w", err))
			return
		}
		if _, err := listener.WriteToUDP(buf[:n], clientAddr); err != nil {
			if !errors.Is(err, net.ErrClosed) {
				f.report(fmt.Errorf("write to udp client failed: %w", err))
			}
			return
		}

		f.mu.Lock()
		if sess := f.sessions[key]; sess != nil && sess.upstream == upstream {
			sess.lastSeen = time.Now()
		}
		f.mu.Unlock()
	}
}

// reapSessions periodically closes timed-out UDP sessions.
func (f *UDPForwarder) reapSessions(ctx context.Context) {
	ticker := time.NewTicker(udpSessionTimeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			var expired []*net.UDPConn
			f.mu.Lock()
			for _, sess := range f.sessions {
				if now.Sub(sess.lastSeen) > udpSessionTimeout {
					expired = append(expired, sess.upstream)
				}
			}
			f.mu.Unlock()
			for _, upstream := range expired {
				f.closeUDPConn(upstream, "expired udp upstream")
			}
		}
	}
}

func (f *UDPForwarder) closeSessions() {
	var upstreams []*net.UDPConn
	f.mu.Lock()
	for _, sess := range f.sessions {
		upstreams = append(upstreams, sess.upstream)
	}
	f.mu.Unlock()
	for _, upstream := range upstreams {
		f.closeUDPConn(upstream, "udp upstream during shutdown")
	}
}

func (f *UDPForwarder) closeUDPConn(conn *net.UDPConn, resource string) {
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		f.report(fmt.Errorf("close %s failed: %w", resource, err))
	}
}

func (f *UDPForwarder) report(err error) {
	if f.errorHandler != nil {
		f.errorHandler(err)
		return
	}
	f.logger.Debugf("%v", err)
}
