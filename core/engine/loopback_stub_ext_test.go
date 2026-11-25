package engine_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/ports"
)

// loopbackSSHServer 是基于 127.0.0.1:0 按需监听的进程内真实 SSH 服务端测试桩：
// 每次拨号绑定 127.0.0.1:0 并在接收单条连接后立即关闭监听器，客户端关闭底层连接时同步等待
// 服务端 Nursery 退出，确保所有测试在 goleak.VerifyNone 门禁下保持零后台协程残留。
type loopbackSSHServer struct {
	hostSigner     ssh.Signer
	authorizedPubs []ssh.PublicKey
	forwardTargets map[string]*loopbackSSHServer
	shellGreeting  string

	mu             sync.Mutex
	dialCount      atomic.Int32
	execCount      atomic.Int32
	seenUsers      []string
	seenEnv        map[string]string
	seenPTYTerm    string
	seenPTYCols    uint32
	seenPTYRows    uint32
	seenResizeCols uint32
	seenResizeRows uint32
	resizeCount    int
}

func newLoopbackSSHServer(t *testing.T, authorizedPubs ...ssh.PublicKey) *loopbackSSHServer {
	t.Helper()
	hostSigner, _ := generateEd25519TestSigner(t)
	return &loopbackSSHServer{
		hostSigner:     hostSigner,
		authorizedPubs: authorizedPubs,
		forwardTargets: make(map[string]*loopbackSSHServer),
		shellGreeting:  "loopback-shell> ",
		seenEnv:        make(map[string]string),
	}
}

func generateEd25519TestSigner(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("ssh.MarshalPrivateKey: %v", err)
	}
	return signer, pem.EncodeToMemory(block)
}

func writeTestKeyInRoot(t *testing.T, rootFS ports.ScopedRootFS, dir pathalg.LocalDir, name string) (ssh.PublicKey, string) {
	t.Helper()
	signer, pemBytes := generateEd25519TestSigner(t)
	if err := rootFS.EnsureRoot(dir, 0o700); err != nil {
		t.Fatalf("EnsureRoot(%s): %v", dir, err)
	}
	dest, err := pathalg.ParseLocalRootedDest(name)
	if err != nil {
		t.Fatalf("ParseLocalRootedDest(%s): %v", name, err)
	}
	err = rootFS.WithRoot(dir, func(r ports.RootHandle) error {
		return r.AtomicReplace(dest, 0o600, func(w io.Writer) error {
			_, wErr := w.Write(pemBytes)
			return wErr
		})
	})
	if err != nil {
		t.Fatalf("写入测试私钥 %s 失败: %v", name, err)
	}
	fullDir, err := dir.JoinComponent(name)
	if err != nil {
		t.Fatalf("JoinComponent(%s): %v", name, err)
	}
	return signer.PublicKey(), fullDir.String()
}

func (s *loopbackSSHServer) dialFunc() engine.DialContextFunc {
	return func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		return s.dialOnDemand(ctx)
	}
}

func (s *loopbackSSHServer) dialOnDemand(ctx context.Context) (net.Conn, error) {
	s.dialCount.Add(1)
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	srvNursery, err := conc.NewNursery(context.Background())
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	done := make(chan struct{})
	if gErr := srvNursery.Go(func(context.Context) error {
		defer close(done)
		defer func() { _ = ln.Close() }()
		srvConn, aErr := ln.Accept()
		_ = ln.Close()
		if aErr != nil {
			return nil
		}
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
		<-done
		_ = srvNursery.Close()
		return nil, dErr
	}
	return &syncCloseNetConn{Conn: cliConn, done: done, nursery: srvNursery}, nil
}

type syncCloseNetConn struct {
	net.Conn
	done      <-chan struct{}
	nursery   *conc.Nursery
	closeOnce sync.Once
	closeErr  error
}

func (c *syncCloseNetConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
		<-c.done
		_ = c.nursery.Close()
	})
	return c.closeErr
}

func (s *loopbackSSHServer) buildServerConfig() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			presented := key.Marshal()
			for _, allowed := range s.authorizedPubs {
				if bytes.Equal(presented, allowed.Marshal()) {
					s.mu.Lock()
					s.seenUsers = append(s.seenUsers, meta.User())
					s.mu.Unlock()
					return &ssh.Permissions{}, nil
				}
			}
			return nil, errors.New("unauthorized public key")
		},
	}
	cfg.AddHostKey(s.hostSigner)
	return cfg
}

func (s *loopbackSSHServer) serveConn(raw net.Conn) {
	defer func() { _ = raw.Close() }()
	sConn, chans, reqs, err := ssh.NewServerConn(raw, s.buildServerConfig())
	if err != nil {
		return
	}
	defer func() { _ = sConn.Close() }()

	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			for req := range reqs {
				if req.WantReply {
					_ = req.Reply(req.Type == "keepalive@openssh.com", nil)
				}
			}
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

func (s *loopbackSSHServer) handleNewChannel(newCh ssh.NewChannel) {
	switch newCh.ChannelType() {
	case "session":
		ch, reqs, err := newCh.Accept()
		if err != nil {
			return
		}
		s.handleSession(ch, reqs)
	case "direct-tcpip":
		s.handleDirectTCPIP(newCh)
	default:
		_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel")
	}
}

func (s *loopbackSSHServer) handleDirectTCPIP(newCh ssh.NewChannel) {
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
	targetAddr := net.JoinHostPort(msg.Host, fmt.Sprintf("%d", msg.Port))
	next, ok := s.forwardTargets[targetAddr]
	if !ok {
		_ = newCh.Reject(ssh.ConnectionFailed, "unknown forward target")
		return
	}
	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	defer func() { _ = ch.Close() }()
	downstream, err := next.dialOnDemand(context.Background())
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

func (s *loopbackSSHServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for req := range reqs {
			s.dispatchSessionReq(n, ch, req)
		}
		return nil
	})
}

func (s *loopbackSSHServer) dispatchSessionReq(n *conc.Nursery, ch ssh.Channel, req *ssh.Request) {
	switch req.Type {
	case "env":
		var p struct{ Name, Value string }
		if ssh.Unmarshal(req.Payload, &p) == nil {
			s.mu.Lock()
			s.seenEnv[p.Name] = p.Value
			s.mu.Unlock()
		}
		replyReq(req, true)
	case "pty-req":
		var p struct {
			Term                string
			Cols, Rows          uint32
			WidthPx, HeightPx   uint32
			TerminalModesString string
		}
		if ssh.Unmarshal(req.Payload, &p) == nil {
			s.mu.Lock()
			s.seenPTYTerm, s.seenPTYCols, s.seenPTYRows = p.Term, p.Cols, p.Rows
			s.mu.Unlock()
		}
		replyReq(req, true)
	case "window-change":
		var p struct {
			Cols, Rows        uint32
			WidthPx, HeightPx uint32
		}
		if ssh.Unmarshal(req.Payload, &p) == nil {
			s.mu.Lock()
			s.seenResizeCols, s.seenResizeRows = p.Cols, p.Rows
			s.resizeCount++
			s.mu.Unlock()
		}
		replyReq(req, true)
	case "exec":
		var p struct{ Command string }
		_ = ssh.Unmarshal(req.Payload, &p)
		replyReq(req, true)
		_ = n.Go(func(context.Context) error {
			s.runExec(ch, p.Command)
			return nil
		})
	case "shell":
		replyReq(req, true)
		_ = n.Go(func(context.Context) error {
			s.runShell(ch)
			return nil
		})
	default:
		replyReq(req, false)
	}
}

func (s *loopbackSSHServer) runExec(ch ssh.Channel, cmd string) {
	defer func() { _ = ch.Close() }()
	s.execCount.Add(1)
	switch {
	case strings.Contains(cmd, "exit-42"):
		_, _ = io.WriteString(ch, "cmd-out:"+cmd+"\n")
		_, _ = io.WriteString(ch.Stderr(), "cmd-err:nonzero\n")
		sendChannelExitStatus(ch, 42)
	default:
		_, _ = io.WriteString(ch, "ok:"+cmd+"\n")
		sendChannelExitStatus(ch, 0)
	}
}

func (s *loopbackSSHServer) runShell(ch ssh.Channel) {
	defer func() { _ = ch.Close() }()
	if s.shellGreeting != "" {
		_, _ = io.WriteString(ch, s.shellGreeting)
	}
	_, _ = io.Copy(ch, ch)
	sendChannelExitStatus(ch, 0)
}

func (s *loopbackSSHServer) envSnapshot() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.seenEnv)
}

func (s *loopbackSSHServer) ptySnapshot() (term string, cols, rows, rCols, rRows uint32, resizes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seenPTYTerm, s.seenPTYCols, s.seenPTYRows, s.seenResizeCols, s.seenResizeRows, s.resizeCount
}

func replyReq(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

func sendChannelExitStatus(ch ssh.Channel, code uint32) {
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], code)
	_, _ = ch.SendRequest("exit-status", false, payload[:])
}

// mapOpenSSHSource 是供集成测试使用的内存 ports.OpenSSHConfigSource 桩。
type mapOpenSSHSource struct {
	hosts []ports.OpenSSHVirtualHost
	tiers map[string]option.OptionLayer
}

func (m *mapOpenSSHSource) ListVirtualHosts(context.Context) ([]ports.OpenSSHVirtualHost, error) {
	return append([]ports.OpenSSHVirtualHost(nil), m.hosts...), nil
}

func (m *mapOpenSSHSource) ResolveTier4(_ context.Context, orig option.OriginalHostSpec, _ algebraic.Option[netaddr.Endpoint]) (option.OptionLayer, error) {
	if layer, ok := m.tiers[orig.String()]; ok {
		return layer, nil
	}
	return option.UnsetOptionLayer(), nil
}

// faultInjectAuditSink 包装真实 AuditSink，按需在 AuditPhaseFinalized 注入 AuditPostWriteError，
// 以验证 StrictAgentProfile 下 Gate -> OnHaltFunc -> Pool.GateHalted 的全链路不可逆熔断传播。
type faultInjectAuditSink struct {
	inner         ports.AuditSink
	failFinalized atomic.Bool
}

func (f *faultInjectAuditSink) ProcessInstanceID() ports.ProcessInstanceID {
	return f.inner.ProcessInstanceID()
}

func (f *faultInjectAuditSink) StageOperation(ctx context.Context, opID security.OperationID) error {
	return f.inner.StageOperation(ctx, opID)
}

func (f *faultInjectAuditSink) UnstageOperation(ctx context.Context, opID security.OperationID) error {
	return f.inner.UnstageOperation(ctx, opID)
}

func (f *faultInjectAuditSink) Record(ctx context.Context, entry ports.AuditEntry) error {
	if entry.Phase() == ports.AuditPhaseFinalized && f.failFinalized.Load() {
		postErr, err := ports.NewAuditPostWriteError(entry.OperationID(), errors.New("injected disk full on finalize"))
		if err != nil {
			return err
		}
		return postErr
	}
	return f.inner.Record(ctx, entry)
}

func (f *faultInjectAuditSink) Close() error { return f.inner.Close() }
