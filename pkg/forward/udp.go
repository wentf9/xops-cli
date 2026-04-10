package forward

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

const udpSessionTimeout = 60 * time.Second

// udpSession tracks an upstream UDP connection for a specific client.
type udpSession struct {
	upstream *net.UDPConn
	lastSeen time.Time
}

// UDPForwarder listens on a local UDP address and forwards datagrams to a target address.
type UDPForwarder struct {
	listenAddr string
	targetAddr string

	mu       sync.Mutex
	sessions map[string]*udpSession // key: client addr string
}

// NewUDPForwarder creates a new UDPForwarder.
func NewUDPForwarder(listenAddr, targetAddr string) *UDPForwarder {
	return &UDPForwarder{
		listenAddr: listenAddr,
		targetAddr: targetAddr,
		sessions:   make(map[string]*udpSession),
	}
}

// Run starts the UDP forwarder and blocks until ctx is canceled.
func (f *UDPForwarder) Run(ctx context.Context) error {
	laddr, err := net.ResolveUDPAddr("udp", f.listenAddr)
	if err != nil {
		return fmt.Errorf("invalid listen address %s: %w", f.listenAddr, err)
	}

	raddr, err := net.ResolveUDPAddr("udp", f.targetAddr)
	if err != nil {
		return fmt.Errorf("invalid target address %s: %w", f.targetAddr, err)
	}

	listener, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", f.listenAddr, err)
	}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	go f.reapSessions(ctx)

	fmt.Fprintf(os.Stderr, "[forward] UDP %s -> %s\n", f.listenAddr, f.targetAddr)

	buf := make([]byte, 64*1024)
	for {
		n, clientAddr, err := listener.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("read error: %w", err)
			}
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		go f.forward(listener, clientAddr, raddr, data)
	}
}

func (f *UDPForwarder) forward(listener *net.UDPConn, clientAddr, targetAddr *net.UDPAddr, data []byte) {
	key := clientAddr.String()

	f.mu.Lock()
	sess, ok := f.sessions[key]
	if !ok {
		upstream, err := net.DialUDP("udp", nil, targetAddr)
		if err != nil {
			f.mu.Unlock()
			fmt.Fprintf(os.Stderr, "[forward] UDP dial %s failed: %v\n", targetAddr, err)
			return
		}
		sess = &udpSession{upstream: upstream, lastSeen: time.Now()}
		f.sessions[key] = sess

		// relay responses back to client
		go f.relay(listener, clientAddr, upstream, key)
	}
	sess.lastSeen = time.Now()
	f.mu.Unlock()

	_, err := sess.upstream.Write(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[forward] UDP write to target failed: %v\n", err)
	}
}

func (f *UDPForwarder) relay(listener *net.UDPConn, clientAddr *net.UDPAddr, upstream *net.UDPConn, key string) {
	defer func() {
		_ = upstream.Close()
		f.mu.Lock()
		delete(f.sessions, key)
		f.mu.Unlock()
	}()

	buf := make([]byte, 64*1024)
	for {
		_ = upstream.SetReadDeadline(time.Now().Add(udpSessionTimeout))
		n, err := upstream.Read(buf)
		if err != nil {
			return
		}

		_, err = listener.WriteToUDP(buf[:n], clientAddr)
		if err != nil {
			return
		}

		f.mu.Lock()
		if sess, ok := f.sessions[key]; ok {
			sess.lastSeen = time.Now()
		}
		f.mu.Unlock()
	}
}

// reapSessions periodically removes timed-out UDP sessions.
func (f *UDPForwarder) reapSessions(ctx context.Context) {
	ticker := time.NewTicker(udpSessionTimeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			f.mu.Lock()
			for _, sess := range f.sessions {
				if now.Sub(sess.lastSeen) > udpSessionTimeout {
					// Only close upstream; relay goroutine's defer handles delete.
					_ = sess.upstream.Close()
				}
			}
			f.mu.Unlock()
		}
	}
}
