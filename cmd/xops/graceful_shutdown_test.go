package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	jsonv2 "encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

// signalLineWriter 是线程安全、永不阻塞的测试输出捕获器；当累计写入包含目标子串时立即关闭 readyCh（零 time.Sleep）。
type signalLineWriter struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	substr  string
	readyCh chan struct{}
	once    sync.Once
}

func newSignalLineWriter(substr string) *signalLineWriter {
	return &signalLineWriter{substr: substr, readyCh: make(chan struct{})}
}

func (w *signalLineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buf.Write(p)
	if w.substr != "" && strings.Contains(w.buf.String(), w.substr) {
		w.once.Do(func() { close(w.readyCh) })
	}
	w.mu.Unlock()
	return n, err
}

func (w *signalLineWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func assertZeroRemainingLocks(t *testing.T, xopsHome pathalg.LocalDir) {
	t.Helper()
	rootFS := osfs.NewScopedRootFS()
	runDest, _ := pathalg.ParseLocalRootedDest("run")
	var remaining []string
	err := rootFS.WithRoot(xopsHome, func(root ports.RootHandle) error {
		entries, rErr := root.ReadDir(algebraic.Some(runDest))
		if rErr != nil {
			return rErr
		}
		for _, e := range entries {
			remaining = append(remaining, e.Name())
		}
		return nil
	})
	if err != nil && !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("读取 run 锁目录失败: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("优雅取消停机后检测到残留锁文件: %v", remaining)
	}
}

// TestGracefulCancel_MCPHTTPAndTunnelZeroRemainingLocks 在全部四平台（含 Windows）进程内实测：
// 对真实 `xops mcp --transport http` 与 `xops tunnel -L` 触发优雅 ctx 取消（等价信号/Console CTRL_C_EVENT），
// 严格断言返回退出码 0、全链路逆序停机完成且 ~/.xops/run 零残留锁文件、零 goroutine 泄漏。
func TestGracefulCancel_MCPHTTPAndTunnelZeroRemainingLocks(t *testing.T) {
	defer goleak.VerifyNone(t)
	homeDir, xopsHome := setupIsolatedRootEnv(t)

	assertGracefulCancelMCPHTTP(t, xopsHome)
	assertGracefulCancelTunnel(t, homeDir, xopsHome)
}

func assertGracefulCancelMCPHTTP(t *testing.T, xopsHome pathalg.LocalDir) {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen 127.0.0.1:0: %v", err)
	}
	listenAddr := ln.Addr().String()
	_ = ln.Close()

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdout := newSignalLineWriter("")
	stderr := newSignalLineWriter("xops-mcp: ready transport=http")
	exitCode := -1

	err = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			exitCode = runProcessWithContext(runCtx, []string{"mcp", "--transport", "http", "--listen", listenAddr}, strings.NewReader(""), stdout, stderr)
			return nil
		}); gErr != nil {
			return gErr
		}
		if wErr := waitSignalWithTimeout(stderr.readyCh, 10*time.Second); wErr != nil {
			cancel()
			return wErr
		}
		postErr := postGracefulMCPInit("http://" + listenAddr + "/mcp")
		cancel()
		return postErr
	})
	if err != nil || exitCode != 0 {
		t.Fatalf("MCP HTTP 优雅取消失败: err=%v exitCode=%d stdout=%q stderr=%q", err, exitCode, stdout.String(), stderr.String())
	}
	assertZeroRemainingLocks(t, xopsHome)
}

func postGracefulMCPInit(url string) error {
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"graceful","version":"1.0"}}}`
	client := &http.Client{Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	for range 50 {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(initReq))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := client.Do(req)
		if err != nil {
			tm := time.NewTimer(20 * time.Millisecond)
			<-tm.C
			continue
		}
		body, rErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if rErr != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"protocolVersion"`) {
			return errors.New("unexpected mcp response: " + string(body))
		}
		return nil
	}
	return io.ErrUnexpectedEOF
}

func assertGracefulCancelTunnel(t *testing.T, homeDir, xopsHome pathalg.LocalDir) {
	t.Helper()
	clientSigner, keyPEM := generateGracefulEd25519Key(t)
	srv := startGracefulTunnelSSHServer(t, clientSigner.PublicKey())
	defer srv.Close()

	sshDir, err := homeDir.JoinComponent(".ssh")
	if err != nil {
		t.Fatalf("JoinComponent(.ssh): %v", err)
	}
	rootFS := osfs.NewScopedRootFS()
	if err := rootFS.EnsureRoot(sshDir, 0o700); err != nil {
		t.Fatalf("EnsureRoot(.ssh): %v", err)
	}
	keyRel, _ := pathalg.ParseLocalRootedDest("id_graceful")
	if err := rootFS.WithRoot(sshDir, func(root ports.RootHandle) error {
		return root.AtomicReplace(keyRel, 0o600, func(w io.Writer) error {
			_, wErr := w.Write(keyPEM)
			return wErr
		})
	}); err != nil {
		t.Fatalf("写入密钥失败: %v", err)
	}
	keyDir, _ := sshDir.JoinComponent("id_graceful")
	keyPath := keyDir.String()

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdout := newSignalLineWriter("\n")
	stderr := newSignalLineWriter("")
	exitCode := -1

	err = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			args := []string{
				"tunnel", "--json", "-F", "none", "-p", srv.port, "-l", "deploy", "-i", keyPath,
				"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
				"-L", "127.0.0.1:0:10.99.0.1:8080", "127.0.0.1",
			}
			exitCode = runProcessWithContext(runCtx, args, strings.NewReader(""), stdout, stderr)
			return nil
		}); gErr != nil {
			return gErr
		}
		if wErr := waitSignalWithTimeout(stdout.readyCh, 10*time.Second); wErr != nil {
			cancel()
			return wErr
		}
		rtErr := verifyTunnelEchoFromBanner(stdout.String())
		cancel()
		return rtErr
	})
	if err != nil || exitCode != 0 {
		t.Fatalf("Tunnel 优雅取消失败: err=%v exitCode=%d stdout=%q stderr=%q", err, exitCode, stdout.String(), stderr.String())
	}
	assertZeroRemainingLocks(t, xopsHome)
}

func verifyTunnelEchoFromBanner(raw string) error {
	line, _, _ := strings.Cut(raw, "\n")
	var ready struct {
		OK       bool `json:"ok"`
		Forwards []struct {
			BindAddr string `json:"bind_addr"`
		} `json:"forwards"`
	}
	if err := jsonv2.Unmarshal([]byte(line), &ready); err != nil || !ready.OK || len(ready.Forwards) != 1 {
		return errors.New("invalid tunnel ready json: " + raw)
	}
	var nd net.Dialer
	conn, err := nd.DialContext(context.Background(), "tcp", ready.Forwards[0].BindAddr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "ping-graceful\n")
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || reply != "fwd[10.99.0.1:8080]:ping-graceful\n" {
		return errors.New("unexpected tunnel reply: " + reply)
	}
	return nil
}

func waitSignalWithTimeout(ch <-chan struct{}, d time.Duration) error {
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ch:
		return nil
	case <-tm.C:
		return context.DeadlineExceeded
	}
}

func generateGracefulEd25519Key(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	return signer, pem.EncodeToMemory(block)
}

type gracefulTunnelSSHServer struct {
	ln       net.Listener
	port     string
	nursery  *conc.Nursery
	hostKey  ssh.Signer
	allowPub ssh.PublicKey
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	once     sync.Once
}

func startGracefulTunnelSSHServer(t *testing.T, allowPub ssh.PublicKey) *gracefulTunnelSSHServer {
	t.Helper()
	hostKey, _ := generateGracefulEd25519Key(t)
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	n, err := conc.NewNursery(context.Background())
	if err != nil {
		_ = ln.Close()
		t.Fatalf("NewNursery: %v", err)
	}
	srv := &gracefulTunnelSSHServer{
		ln: ln, port: port, nursery: n, hostKey: hostKey, allowPub: allowPub,
		conns: make(map[net.Conn]struct{}),
	}
	if err := n.Go(func(context.Context) error { srv.acceptLoop(); return nil }); err != nil {
		_ = ln.Close()
		_ = n.Close()
		t.Fatalf("acceptLoop: %v", err)
	}
	return srv
}

func (s *gracefulTunnelSSHServer) Close() {
	s.once.Do(func() {
		_ = s.ln.Close()
		s.mu.Lock()
		for c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
		_ = s.nursery.Close()
	})
}

func (s *gracefulTunnelSSHServer) acceptLoop() {
	for {
		raw, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[raw] = struct{}{}
		s.mu.Unlock()
		if err := s.nursery.Go(func(context.Context) error {
			defer func() {
				s.mu.Lock()
				delete(s.conns, raw)
				s.mu.Unlock()
				_ = raw.Close()
			}()
			s.serveConn(raw)
			return nil
		}); err != nil {
			_ = raw.Close()
			return
		}
	}
}

func (s *gracefulTunnelSSHServer) serveConn(raw net.Conn) {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(s.allowPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("unauthorized")
		},
	}
	cfg.AddHostKey(s.hostKey)
	sConn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sConn.Close() }()
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		_ = n.Go(func(context.Context) error { ssh.DiscardRequests(reqs); return nil })
		for newCh := range chans {
			if newCh.ChannelType() != "direct-tcpip" {
				_ = newCh.Reject(ssh.UnknownChannelType, "unsupported")
				continue
			}
			_ = n.Go(func(context.Context) error { handleGracefulDirectTCPIP(newCh); return nil })
		}
		return nil
	})
}

func handleGracefulDirectTCPIP(newCh ssh.NewChannel) {
	var msg struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(newCh.ExtraData(), &msg); err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, "bad payload")
		return
	}
	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	defer func() { _ = ch.Close() }()
	target := net.JoinHostPort(msg.Host, strconv.FormatUint(uint64(msg.Port), 10))
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		_ = n.Go(func(context.Context) error { ssh.DiscardRequests(reqs); return nil })
		line, rErr := bufio.NewReader(ch).ReadString('\n')
		if rErr != nil && line == "" {
			return nil
		}
		_, _ = io.WriteString(ch, "fwd["+target+"]:"+line)
		return nil
	})
}
