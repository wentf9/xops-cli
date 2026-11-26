package dial_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/ports"
)

// 编译期契约断言：确保真实传输实现严格满足 core/ports 导出接口。
var (
	_ ports.DialerPort    = (*dial.Dialer)(nil)
	_ ports.TransportConn = (*dial.TransportConn)(nil)
)

// loopbackSSHSpec 描述按需 127.0.0.1 回环 SSH 测试桩的认证、通道与转发行为。
// 每次拨号按需绑定 127.0.0.1:0 并在接收单条连接后立即关闭监听器，连接 Close() 时同步等待
// 服务端协程收敛退出，确保在 TCK 子测试的 goleak.VerifyNone 门禁前 100% 零后台协程残留。
type loopbackSSHSpec struct {
	hostSigner     ssh.Signer
	password       string
	authorizedPubs []ssh.PublicKey
	trustedUserCA  ssh.PublicKey
	kiInstruction  string
	kiQuestions    []string
	kiEchos        []bool
	kiExpected     []string
	kiRounds       []kiRoundSpec
	forwardTargets map[string]*loopbackSSHSpec
	stallTargets   map[string]bool
	echoTargets    map[string]bool
	subsystems     map[string]bool
	hangStarted    chan struct{}
	stallEntered   chan struct{}
	hangEnv        bool
	envEntered     chan struct{}

	mu              sync.Mutex
	seenEnv         map[string]string
	seenPTYTerm     string
	seenResizeCols  uint32
	seenResizeRows  uint32
	seenSignals     []string
	activeServerCon []net.Conn
}

type kiRoundSpec struct {
	instruction string
	questions   []string
	echos       []bool
	expected    []string
}

func newLoopbackSSHSpec(t *testing.T) (*loopbackSSHSpec, ports.PublicKeyInfo) {
	t.Helper()
	signer, _, _, pubInfo := generateTestEd25519Key(t, "")
	return &loopbackSSHSpec{
		hostSigner:     signer,
		forwardTargets: make(map[string]*loopbackSSHSpec),
		stallTargets:   make(map[string]bool),
		echoTargets:    make(map[string]bool),
		subsystems:     make(map[string]bool),
		seenEnv:        make(map[string]string),
	}, pubInfo
}

func (s *loopbackSSHSpec) killActiveServerConns() {
	s.mu.Lock()
	conns := append([]net.Conn(nil), s.activeServerCon...)
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (s *loopbackSSHSpec) recordServerConn(c net.Conn) {
	s.mu.Lock()
	s.activeServerCon = append(s.activeServerCon, c)
	s.mu.Unlock()
}

// dialFunc 返回可注入 dial.Config.DialContext 的按需 127.0.0.1 回环拨号器。
func (s *loopbackSSHSpec) dialFunc() dial.DialContextFunc {
	return func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		return s.dialOnDemandLoopback(ctx)
	}
}

func (s *loopbackSSHSpec) dialOnDemandLoopback(ctx context.Context) (net.Conn, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	srvNursery, nErr := conc.NewNursery(context.Background())
	if nErr != nil {
		_ = ln.Close()
		return nil, nErr
	}
	serverDone := make(chan struct{})
	if gErr := srvNursery.Go(func(context.Context) error {
		defer close(serverDone)
		defer func() { _ = ln.Close() }()
		srvConn, aErr := ln.Accept()
		_ = ln.Close()
		if aErr != nil {
			return nil
		}
		s.recordServerConn(srvConn)
		s.serveConn(srvConn)
		return nil
	}); gErr != nil {
		_ = ln.Close()
		_ = srvNursery.Close()
		return nil, gErr
	}
	var nd net.Dialer
	cliConn, dErr := nd.DialContext(ctx, "tcp", ln.Addr().String())
	if dErr != nil {
		_ = ln.Close()
		<-serverDone
		_ = srvNursery.Close()
		return nil, dErr
	}
	return &syncCloseConn{Conn: cliConn, done: serverDone, nursery: srvNursery}, nil
}

func (s *loopbackSSHSpec) buildServerConfig() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{}
	if s.password != "" {
		cfg.PasswordCallback = func(_ ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == s.password {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("invalid password")
		}
	}
	if len(s.authorizedPubs) > 0 || s.trustedUserCA != nil {
		cfg.PublicKeyCallback = s.verifyClientPublicKey
	}
	if len(s.kiQuestions) > 0 || len(s.kiRounds) > 0 {
		cfg.KeyboardInteractiveCallback = s.handleKeyboardInteractive
	}
	cfg.AddHostKey(s.hostSigner)
	return cfg
}

func (s *loopbackSSHSpec) verifyClientPublicKey(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if s.trustedUserCA != nil {
		if _, isCert := key.(*ssh.Certificate); isCert {
			checker := &ssh.CertChecker{
				IsUserAuthority: func(auth ssh.PublicKey) bool {
					return bytes.Equal(auth.Marshal(), s.trustedUserCA.Marshal())
				},
			}
			return checker.Authenticate(meta, key)
		}
	}
	presented := key.Marshal()
	for _, allowed := range s.authorizedPubs {
		if bytes.Equal(presented, allowed.Marshal()) {
			return &ssh.Permissions{}, nil
		}
	}
	return nil, errors.New("unauthorized public key")
}

func (s *loopbackSSHSpec) handleKeyboardInteractive(_ ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	rounds := s.kiRounds
	if len(rounds) == 0 {
		rounds = []kiRoundSpec{{
			instruction: s.kiInstruction,
			questions:   s.kiQuestions,
			echos:       s.kiEchos,
			expected:    s.kiExpected,
		}}
	}
	for ri, r := range rounds {
		answers, err := client("xops-test", r.instruction, r.questions, r.echos)
		if err != nil {
			return nil, err
		}
		if len(answers) != len(r.expected) {
			return nil, fmt.Errorf("round %d wrong answer count", ri)
		}
		for i := range r.expected {
			if answers[i] != r.expected[i] {
				return nil, fmt.Errorf("round %d answer %d mismatch", ri, i)
			}
		}
	}
	return &ssh.Permissions{}, nil
}

func (s *loopbackSSHSpec) serveConn(raw net.Conn) {
	defer func() { _ = raw.Close() }()
	sConn, chans, reqs, err := ssh.NewServerConn(raw, s.buildServerConfig())
	if err != nil {
		return
	}
	defer func() { _ = sConn.Close() }()

	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			handleGlobalRequests(reqs)
			return nil
		}); gErr != nil {
			return gErr
		}
		for newCh := range chans {
			ch := newCh
			if gErr := n.Go(func(context.Context) error {
				s.handleNewChannel(ch)
				return nil
			}); gErr != nil {
				_ = ch.Reject(ssh.ResourceShortage, "nursery stopped")
			}
		}
		return nil
	})
}

func handleGlobalRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "keepalive@openssh.com", "cancel-tcpip-forward", "streamlocal-forward@openssh.com", "cancel-streamlocal-forward@openssh.com":
			replyOK(req, true)
		case "tcpip-forward":
			var p struct {
				Addr string
				Port uint32
			}
			_ = ssh.Unmarshal(req.Payload, &p)
			port := p.Port
			if port == 0 {
				port = 43210
			}
			if req.WantReply {
				var resp [4]byte
				binary.BigEndian.PutUint32(resp[:], port)
				_ = req.Reply(true, resp[:])
			}
		default:
			replyOK(req, false)
		}
	}
}

func (s *loopbackSSHSpec) handleNewChannel(newCh ssh.NewChannel) {
	switch newCh.ChannelType() {
	case "session":
		ch, reqs, err := newCh.Accept()
		if err != nil {
			return
		}
		s.handleSessionChannel(ch, reqs)
	case "direct-tcpip":
		s.handleDirectTCPIP(newCh)
	case "direct-streamlocal@openssh.com", "tun@openssh.com":
		ch, reqs, err := newCh.Accept()
		if err != nil {
			return
		}
		serveEchoChannel(ch, reqs)
	default:
		_ = newCh.Reject(ssh.UnknownChannelType, "unsupported")
	}
}

func (s *loopbackSSHSpec) handleDirectTCPIP(newCh ssh.NewChannel) {
	var msg struct {
		Host       string
		Port       uint32
		OriginAddr string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(newCh.ExtraData(), &msg); err != nil {
		_ = newCh.Reject(ssh.Prohibited, "bad payload")
		return
	}
	target := net.JoinHostPort(msg.Host, fmt.Sprintf("%d", msg.Port))
	if s.stallTargets[target] {
		if ch, reqs, err := newCh.Accept(); err == nil {
			s.serveStallChannel(ch, reqs)
		}
		return
	}
	if s.echoTargets[target] {
		if ch, reqs, err := newCh.Accept(); err == nil {
			serveEchoChannel(ch, reqs)
		}
		return
	}
	if nextHop, ok := s.forwardTargets[target]; ok {
		if ch, reqs, err := newCh.Accept(); err == nil {
			bridgeChannelToSpec(ch, reqs, nextHop)
		}
		return
	}
	_ = newCh.Reject(ssh.ConnectionFailed, "unknown direct-tcpip target")
}

func (s *loopbackSSHSpec) serveStallChannel(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	if s.stallEntered != nil {
		select {
		case s.stallEntered <- struct{}{}:
		default:
		}
	}
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		_ = n.Go(func(context.Context) error { ssh.DiscardRequests(reqs); return nil })
		_, _ = io.Copy(io.Discard, ch)
		return nil
	})
}

func serveEchoChannel(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		_ = n.Go(func(context.Context) error { ssh.DiscardRequests(reqs); return nil })
		_, _ = io.Copy(ch, ch)
		return nil
	})
}

func bridgeChannelToSpec(ch ssh.Channel, reqs <-chan *ssh.Request, next *loopbackSSHSpec) {
	defer func() { _ = ch.Close() }()
	downstream, err := next.dialOnDemandLoopback(context.Background())
	if err != nil {
		return
	}
	defer func() { _ = downstream.Close() }()
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		_ = n.Go(func(context.Context) error { ssh.DiscardRequests(reqs); return nil })
		_ = n.Go(func(context.Context) error {
			_, _ = io.Copy(downstream, ch)
			_ = downstream.Close()
			return nil
		})
		_, _ = io.Copy(ch, downstream)
		_ = ch.Close()
		return nil
	})
}

func (s *loopbackSSHSpec) handleSessionChannel(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	sigCh := make(chan string, 4)
	reqsClosed := make(chan struct{})
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for req := range reqs {
			s.dispatchSessionRequest(n, ch, req, sigCh, reqsClosed)
		}
		close(reqsClosed)
		return nil
	})
}

func (s *loopbackSSHSpec) dispatchSessionRequest(n *conc.Nursery, ch ssh.Channel, req *ssh.Request, sigCh chan string, reqsClosed <-chan struct{}) {
	switch req.Type {
	case "env":
		if s.hangEnv {
			if s.envEntered != nil {
				select {
				case s.envEntered <- struct{}{}:
				default:
				}
			}
			// 模拟对端收到 env 请求后永不发送 Reply（由 req.WantReply==true 使客户端阻塞），
			// 同时保持 reqs 消费循环非阻塞以便会话/连接关闭时能正常收敛 reqsClosed。
			return
		}
		s.recordSessionControlRequest(req, sigCh)
		replyOK(req, true)
	case "pty-req", "window-change", "signal":
		s.recordSessionControlRequest(req, sigCh)
		replyOK(req, true)
	case "exec":
		var p struct{ Command string }
		_ = ssh.Unmarshal(req.Payload, &p)
		replyOK(req, true)
		_ = n.Go(func(context.Context) error { s.runStubCommand(ch, p.Command, sigCh, reqsClosed); return nil })
	case "shell":
		replyOK(req, true)
		_ = n.Go(func(context.Context) error { runStubShell(ch); return nil })
	case "subsystem":
		var p struct{ Name string }
		_ = ssh.Unmarshal(req.Payload, &p)
		if s.subsystems[p.Name] {
			replyOK(req, true)
			_ = n.Go(func(context.Context) error { runStubShell(ch); return nil })
			return
		}
		replyOK(req, false)
	default:
		replyOK(req, false)
	}
}

func (s *loopbackSSHSpec) recordSessionControlRequest(req *ssh.Request, sigCh chan string) {
	switch req.Type {
	case "env":
		var p struct{ Name, Value string }
		if ssh.Unmarshal(req.Payload, &p) == nil {
			s.mu.Lock()
			s.seenEnv[p.Name] = p.Value
			s.mu.Unlock()
		}
	case "pty-req":
		var p struct {
			Term       string
			Cols, Rows uint32
		}
		if ssh.Unmarshal(req.Payload, &p) == nil {
			s.mu.Lock()
			s.seenPTYTerm, s.seenResizeCols, s.seenResizeRows = p.Term, p.Cols, p.Rows
			s.mu.Unlock()
		}
	case "window-change":
		var p struct{ Cols, Rows uint32 }
		if ssh.Unmarshal(req.Payload, &p) == nil {
			s.mu.Lock()
			s.seenResizeCols, s.seenResizeRows = p.Cols, p.Rows
			s.mu.Unlock()
		}
	case "signal":
		var p struct{ Name string }
		if ssh.Unmarshal(req.Payload, &p) == nil {
			s.mu.Lock()
			s.seenSignals = append(s.seenSignals, p.Name)
			s.mu.Unlock()
			select {
			case sigCh <- p.Name:
			default:
			}
		}
	}
}

func replyOK(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

func runStubShell(ch ssh.Channel) {
	_, _ = io.Copy(ch, ch)
	sendExitStatus(ch, 0)
	_ = ch.Close()
}

func (s *loopbackSSHSpec) runStubCommand(ch ssh.Channel, cmd string, sigCh <-chan string, reqsClosed <-chan struct{}) {
	defer func() { _ = ch.Close() }()
	switch {
	case strings.Contains(cmd, "bash"):
		_, _ = io.Copy(ch, ch)
		_, _ = ch.Stderr().Write([]byte("err-msg"))
		sendExitStatus(ch, 0)
	case strings.Contains(cmd, "exit-42"):
		_, _ = ch.Write([]byte("fail-out"))
		_, _ = ch.Stderr().Write([]byte("fail-err"))
		sendExitStatus(ch, 42)
	case strings.Contains(cmd, "exit-sig"):
		sendExitSignal(ch, "TERM", "terminated")
	case strings.Contains(cmd, "exit-missing"):
		_, _ = ch.Write([]byte("no-exit-status"))
	case strings.Contains(cmd, "big-output"):
		_, _ = ch.Write(bytes.Repeat([]byte("A"), 4096))
		sendExitStatus(ch, 0)
	case strings.Contains(cmd, "hang-until-signal"):
		s.runHangUntilSignal(ch, sigCh, reqsClosed)
	default:
		_, _ = ch.Write([]byte("tck-ok\n"))
		sendExitStatus(ch, 0)
	}
}

func (s *loopbackSSHSpec) runHangUntilSignal(ch ssh.Channel, sigCh <-chan string, reqsClosed <-chan struct{}) {
	if s.hangStarted != nil {
		select {
		case s.hangStarted <- struct{}{}:
		default:
		}
	}
	select {
	case sigName := <-sigCh:
		sendExitSignal(ch, sigName, "signaled")
	case <-reqsClosed:
	}
}

func sendExitStatus(ch ssh.Channel, code uint32) {
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], code)
	_, _ = ch.SendRequest("exit-status", false, payload[:])
}

func sendExitSignal(ch ssh.Channel, name, msg string) {
	payload := ssh.Marshal(&struct {
		Signal string
		Core   bool
		Msg    string
		Lang   string
	}{Signal: name, Msg: msg})
	_, _ = ch.SendRequest("exit-signal", false, payload)
}
