// Package sshfixture provides an isolated SSH/SFTP protocol peer for core
// consumer tests. It never executes a local shell or reads personal keys.
package sshfixture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const Password = "synthetic-ssh-fixture-password"

type Server struct {
	Address     string
	HostKey     ssh.PublicKey
	Executed    atomic.Int32
	Forwards    atomic.Int32
	ctx         context.Context
	cancel      context.CancelFunc
	listener    net.Listener
	config      *ssh.ServerConfig
	handlers    sftp.Handlers
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	forwards    map[string]net.Listener
	errors      []error
	workers     sync.WaitGroup
	closeOnce   sync.Once
	closeErr    error
}

type Options struct{ PublicKeys []ssh.PublicKey }

func New(ctx context.Context) (*Server, error) { return NewWithOptions(ctx, Options{}) }

func NewWithOptions(ctx context.Context, options Options) (*Server, error) {
	if ctx == nil {
		return nil, errors.New("fixture context is required")
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("fixture requires a deadline")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	work, cancel := context.WithCancel(ctx)
	s := &Server{Address: listener.Addr().String(), HostKey: signer.PublicKey(), ctx: work, cancel: cancel, listener: listener,
		connections: make(map[net.Conn]struct{}), handlers: sftp.InMemHandler(), config: &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) != Password {
				return nil, errors.New("fixture password rejected")
			}
			return nil, nil
		}},
	}
	s.config.AddHostKey(signer)
	s.forwards = make(map[string]net.Listener)
	s.config.PublicKeyCallback = func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		for _, allowed := range options.PublicKeys {
			if bytes.Equal(allowed.Marshal(), key.Marshal()) {
				return nil, nil
			}
		}
		return nil, errors.New("fixture key rejected")
	}
	s.workers.Add(1)
	// Listener closure ends accept; every accepted transport belongs to Close.
	go s.accept()
	return s, nil
}

func (s *Server) record(err error) {
	if err == nil || peerClosure(err) || s.ctx.Err() != nil {
		return
	}
	s.mu.Lock()
	s.errors = append(s.errors, err)
	s.mu.Unlock()
}

// A client can disconnect while the fixture remains alive for other clients.
// Only known peer-close errors are benign; a joined unrelated failure is kept.
func peerClosure(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		for _, cause := range causes {
			if !peerClosure(cause) {
				return false
			}
		}
		return len(causes) > 0
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		if cause := wrapped.Unwrap(); cause != nil {
			return peerClosure(cause)
		}
	}
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || platformPeerClosure(err)
}

func (s *Server) accept() {
	defer s.workers.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.ctx.Err() != nil {
			s.mu.Unlock()
			s.record(conn.Close())
			return
		}
		s.connections[conn] = struct{}{}
		s.workers.Add(1)
		s.mu.Unlock()
		go s.serve(conn)
	}
}

func (s *Server) serve(conn net.Conn) {
	defer s.workers.Done()
	defer func() { s.record(conn.Close()); s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
	deadline, _ := s.ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		s.record(err)
		return
	}
	stop := context.AfterFunc(s.ctx, func() { s.record(conn.Close()) })
	defer stop()
	server, channels, requests, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		s.record(err)
		return
	}
	defer func() { s.record(server.Close()) }()
	s.workers.Add(1)
	// The owning transport's close ends this request stream.
	go s.globalRequests(server, requests)
	for incoming := range channels {
		if incoming.ChannelType() == "direct-tcpip" {
			s.workers.Add(1)
			go s.direct(incoming)
			continue
		}
		if incoming.ChannelType() != "session" {
			s.record(incoming.Reject(ssh.UnknownChannelType, "session required"))
			continue
		}
		channel, requests, err := incoming.Accept()
		if err != nil {
			s.record(err)
			return
		}
		s.workers.Add(1)
		// Channel I/O is bounded by the owning transport deadline and close.
		go s.session(channel, requests)
	}
}

func (s *Server) session(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer s.workers.Done()
	defer func() { s.record(channel.Close()) }()
	for request := range requests {
		switch request.Type {
		case "exec":
			s.Executed.Add(1)
			s.record(request.Reply(true, nil))
			_, err := io.WriteString(channel, "fixture-output")
			s.record(err)
			_, err = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			s.record(err)
			return
		case "subsystem":
			var payload struct{ Name string }
			if err := ssh.Unmarshal(request.Payload, &payload); err != nil || payload.Name != "sftp" {
				s.record(request.Reply(false, nil))
				continue
			}
			s.record(request.Reply(true, nil))
			server := sftp.NewRequestServer(channel, s.handlers)
			s.record(server.Serve())
			s.record(server.Close())
			return
		default:
			if request.WantReply {
				s.record(request.Reply(false, nil))
			}
		}
	}
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		s.record(s.listener.Close())
		s.mu.Lock()
		for _, listener := range s.forwards {
			if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				s.errors = append(s.errors, err)
			}
		}
		connections := make([]net.Conn, 0, len(s.connections))
		for conn := range s.connections {
			connections = append(connections, conn)
		}
		s.mu.Unlock()
		for _, conn := range connections {
			s.record(conn.Close())
		}
		s.workers.Wait()
		s.mu.Lock()
		s.closeErr = errors.Join(s.errors...)
		s.mu.Unlock()
		if s.closeErr != nil {
			s.closeErr = fmt.Errorf("SSH fixture failed: %w", s.closeErr)
		}
	})
	return s.closeErr
}

func (s *Server) direct(incoming ssh.NewChannel) {
	defer s.workers.Done()
	var target struct {
		Host       string
		Port       uint32
		Origin     string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(incoming.ExtraData(), &target); err != nil {
		s.record(incoming.Reject(ssh.Prohibited, "invalid target"))
		return
	}
	ctx := s.ctx
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))))
	if err != nil {
		s.record(incoming.Reject(ssh.ConnectionFailed, "fixture target unavailable"))
		return
	}
	defer func() { s.record(connection.Close()) }()
	channel, requests, err := incoming.Accept()
	if err != nil {
		s.record(err)
		return
	}
	s.Forwards.Add(1)
	s.pipe(channel, requests, connection)
}

func (s *Server) pipe(channel ssh.Channel, requests <-chan *ssh.Request, connection net.Conn) {
	defer func() { s.record(channel.Close()) }()
	deadline, _ := s.ctx.Deadline()
	s.record(connection.SetDeadline(deadline))
	stop := context.AfterFunc(s.ctx, func() { s.record(connection.Close()); s.record(channel.Close()) })
	defer stop()
	done := make(chan struct{})
	// EOF/cancellation closes both directions before joining their workers.
	go func() { ssh.DiscardRequests(requests); close(done) }()
	copied := make(chan struct{})
	go func() { _, err := io.Copy(channel, connection); s.record(err); close(copied) }()
	_, copyErr := io.Copy(connection, channel)
	s.record(copyErr)
	s.record(connection.Close())
	s.record(channel.Close())
	<-copied
	<-done
}

func (s *Server) globalRequests(connection *ssh.ServerConn, requests <-chan *ssh.Request) {
	defer s.workers.Done()
	for request := range requests {
		if request.Type == "keepalive@openssh.com" {
			if request.WantReply {
				s.record(request.Reply(true, nil))
			}
			continue
		}
		var address struct {
			Host string
			Port uint32
		}
		if err := ssh.Unmarshal(request.Payload, &address); err != nil {
			s.record(request.Reply(false, nil))
			continue
		}
		key := net.JoinHostPort(address.Host, strconv.Itoa(int(address.Port)))
		if request.Type == "cancel-tcpip-forward" {
			s.mu.Lock()
			listener := s.forwards[key]
			delete(s.forwards, key)
			s.mu.Unlock()
			if listener != nil {
				s.record(listener.Close())
			}
			s.record(request.Reply(true, nil))
			continue
		}
		if request.Type != "tcpip-forward" {
			s.record(request.Reply(false, nil))
			continue
		}
		config := net.ListenConfig{}
		listener, err := config.Listen(s.ctx, "tcp", key)
		if err != nil {
			s.record(request.Reply(false, nil))
			continue
		}
		actual := uint32(listener.Addr().(*net.TCPAddr).Port)
		key = net.JoinHostPort(address.Host, strconv.Itoa(int(actual)))
		s.mu.Lock()
		if s.ctx.Err() != nil {
			s.mu.Unlock()
			s.record(listener.Close())
			return
		}
		s.forwards[key] = listener
		s.mu.Unlock()
		s.record(request.Reply(true, ssh.Marshal(struct{ Port uint32 }{actual})))
		s.Forwards.Add(1)
		s.workers.Add(1)
		go s.acceptForward(connection, listener, address.Host, actual)
	}
}

func (s *Server) acceptForward(connection *ssh.ServerConn, listener net.Listener, host string, port uint32) {
	defer s.workers.Done()
	for {
		client, err := listener.Accept()
		if err != nil {
			return
		}
		channel, requests, err := connection.OpenChannel("forwarded-tcpip", ssh.Marshal(struct {
			Host       string
			Port       uint32
			Origin     string
			OriginPort uint32
		}{host, port, "127.0.0.1", 1}))
		if err != nil {
			s.record(client.Close())
			continue
		}
		s.workers.Add(1)
		go func() {
			defer s.workers.Done()
			defer func() { s.record(client.Close()) }()
			s.pipe(channel, requests, client)
		}()
	}
}
