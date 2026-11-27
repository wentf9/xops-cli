package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/entry/cli"
	"github.com/wentf9/xops-cli/internal/entry/tui"
)

// TestTUITakeover_RealEngineInteractiveSSH 验证 cmd/xops 的 TUI OnTakeover 钩子
// 针对真实 *engine.Engine 走 Engine.InteractiveSSH（而非空命令 Exec），可正常完成交互式 Shell 会话，
// 并对非完成态 ExecutionOutcome 严格失败关闭。
func TestTUITakeover_RealEngineInteractiveSSH(t *testing.T) {
	defer goleak.VerifyNone(t)
	homeDir, xopsHome := setupIsolatedRootEnv(t)

	clientSigner, keyPEM := generateGracefulEd25519Key(t)
	srv := startInteractiveShellSSHServer(t, clientSigner.PublicKey())
	defer srv.Close()

	cfgPath := writeTakeoverSSHConfig(t, homeDir, srv.port, keyPEM)
	ctx := context.Background()
	rt, err := wireRuntime(ctx, cli.EngineInitOptions{OpenSSHConfigFile: cfgPath}, runtimeModeCLI, strings.NewReader(""), io.Discard)
	if err != nil {
		t.Fatalf("wireRuntime(CLI): %v", err)
	}
	defer func() {
		if cErr := rt.Close(ctx); cErr != nil {
			t.Errorf("rt.Close: %v", cErr)
		}
		assertZeroRemainingLocks(t, xopsHome)
	}()

	var stdout, stderr bytes.Buffer
	takeover := buildTUITakeover(rt.engine, strings.NewReader("hi-tui\nexit\n"), &stdout, &stderr)
	if err := takeover(ctx, tui.TakeoverRequest{TargetSpec: "tui-box"}); err != nil {
		t.Fatalf("TUI OnTakeover 针对真实 Engine 失败（isInvalidReq=%v）: %v stderr=%q", errors.Is(err, engine.ErrInvalidRequest), err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "shell-ready\n") || !strings.Contains(stdout.String(), "echo:hi-tui\n") {
		t.Fatalf("交互式 Shell 输出失配: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	// 验证仅填 NodeID 时的回退路由同样经 InteractiveSSH 正常完成。
	var stdout2, stderr2 bytes.Buffer
	takeover2 := buildTUITakeover(rt.engine, strings.NewReader("by-node\nexit\n"), &stdout2, &stderr2)
	if err := takeover2(ctx, tui.TakeoverRequest{NodeID: "tui-box"}); err != nil {
		t.Fatalf("TUI OnTakeover(NodeID fallback) 失败: %v", err)
	}
	if !strings.Contains(stdout2.String(), "echo:by-node\n") {
		t.Fatalf("NodeID 回退输出失配: stdout=%q", stdout2.String())
	}

	assertCheckTakeoverOutcomeFailClosed(t)
}

func assertCheckTakeoverOutcomeFailClosed(t *testing.T) {
	t.Helper()
	notStarted, err := execution.NewOutcomeNotStarted(execution.StartPhaseValidate, "denied", "blocked by policy")
	if err != nil {
		t.Fatalf("NewOutcomeNotStarted: %v", err)
	}
	if err := checkTakeoverOutcome(notStarted); err == nil || !strings.Contains(err.Error(), "not started") {
		t.Fatalf("OutcomeNotStarted 必须失败关闭，实际=%v", err)
	}
	unknown, err := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, "eof", "connection dropped")
	if err != nil {
		t.Fatalf("NewOutcomeUnknown: %v", err)
	}
	if err := checkTakeoverOutcome(unknown); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("OutcomeUnknown 必须失败关闭，实际=%v", err)
	}
	if err := checkTakeoverOutcome(nil); err == nil {
		t.Fatal("nil ExecutionOutcome 必须失败关闭")
	}
	if err := checkTakeoverOutcome((*execution.OutcomeCompleted)(nil)); err == nil {
		t.Fatal("无效零值 OutcomeCompleted 必须失败关闭")
	}
}

// TestSSHBackgroundForward_PureForwardWithoutControlPath 验证 `xops ssh -f -N -L ... <host>`
// 在未配置 -S/ControlPath 时自动走 muxdaemon 纯转发监督模式，不因 ErrControlMasterDisabled 失败，
// 且在优雅取消后完整回滚端口转发并清理全部运行锁。
func TestSSHBackgroundForward_PureForwardWithoutControlPath(t *testing.T) {
	defer goleak.VerifyNone(t)
	homeDir, xopsHome := setupIsolatedRootEnv(t)

	clientSigner, keyPEM := generateGracefulEd25519Key(t)
	srv := startGracefulTunnelSSHServer(t, clientSigner.PublicKey())
	defer srv.Close()

	keyPath := writeTakeoverKeyFile(t, homeDir, "id_bg_fwd", keyPEM)
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdout := newSignalLineWriter("forward local -> ")
	stderr := newSignalLineWriter("")
	exitCode := -1

	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			args := []string{
				"ssh", "-f", "-N", "-F", "none", "-p", srv.port, "-l", "deploy", "-i", keyPath,
				"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
				"-L", "127.0.0.1:0:10.99.0.2:9090", "127.0.0.1",
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
		rtErr := verifyPureForwardBannerEcho(stdout.String())
		cancel()
		return rtErr
	})
	if err != nil || exitCode != 0 {
		t.Fatalf("ssh -f -N -L 纯转发后台守护失败: err=%v exitCode=%d stdout=%q stderr=%q", err, exitCode, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "mux daemon ready (forwards)") {
		t.Fatalf("纯转发模式横幅失配: stdout=%q", stdout.String())
	}
	assertZeroRemainingLocks(t, xopsHome)
}

func verifyPureForwardBannerEcho(banner string) error {
	idx := strings.Index(banner, "forward local -> ")
	if idx < 0 {
		return fmt.Errorf("missing forward bind address in banner: %q", banner)
	}
	rest := banner[idx+len("forward local -> "):]
	bindAddr, _, _ := strings.Cut(rest, "\n")
	bindAddr = strings.TrimSpace(bindAddr)
	var nd net.Dialer
	conn, err := nd.DialContext(context.Background(), "tcp", bindAddr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "ping-bg-fwd\n")
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read pure-forward reply failed: %w", err)
	}
	if reply != "fwd[10.99.0.2:9090]:ping-bg-fwd\n" {
		return fmt.Errorf("unexpected pure-forward reply: %q", reply)
	}
	return nil
}

func writeTakeoverKeyFile(t *testing.T, homeDir pathalg.LocalDir, name string, keyPEM []byte) string {
	t.Helper()
	sshDir, err := homeDir.JoinComponent(".ssh")
	if err != nil {
		t.Fatalf("JoinComponent(.ssh): %v", err)
	}
	rootFS := osfs.NewScopedRootFS()
	if err := rootFS.EnsureRoot(sshDir, 0o700); err != nil {
		t.Fatalf("EnsureRoot(.ssh): %v", err)
	}
	keyRel, _ := pathalg.ParseLocalRootedDest(name)
	if err := rootFS.WithRoot(sshDir, func(root ports.RootHandle) error {
		return root.AtomicReplace(keyRel, 0o600, func(w io.Writer) error {
			_, wErr := w.Write(keyPEM)
			return wErr
		})
	}); err != nil {
		t.Fatalf("写入密钥失败: %v", err)
	}
	return filepath.Join(filepath.FromSlash(sshDir.String()), name)
}

func writeTakeoverSSHConfig(t *testing.T, homeDir pathalg.LocalDir, port string, keyPEM []byte) string {
	t.Helper()
	keyPath := writeTakeoverKeyFile(t, homeDir, "id_takeover", keyPEM)
	sshDir, _ := homeDir.JoinComponent(".ssh")
	cfgContent := fmt.Sprintf("Host tui-box\n  HostName 127.0.0.1\n  Port %s\n  User deploy\n  IdentityFile %s\n  IdentitiesOnly yes\n  StrictHostKeyChecking accept-new\n",
		port, filepath.ToSlash(keyPath))
	cfgRel, _ := pathalg.ParseLocalRootedDest("takeover_config")
	rootFS := osfs.NewScopedRootFS()
	if err := rootFS.WithRoot(sshDir, func(root ports.RootHandle) error {
		return root.AtomicReplace(cfgRel, 0o600, func(w io.Writer) error {
			_, wErr := io.WriteString(w, cfgContent)
			return wErr
		})
	}); err != nil {
		t.Fatalf("写入 takeover_config 失败: %v", err)
	}
	return filepath.Join(filepath.FromSlash(sshDir.String()), "takeover_config")
}

type interactiveShellSSHServer struct {
	ln       net.Listener
	port     string
	nursery  *conc.Nursery
	hostKey  ssh.Signer
	allowPub ssh.PublicKey
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	once     sync.Once
}

func startInteractiveShellSSHServer(t *testing.T, allowPub ssh.PublicKey) *interactiveShellSSHServer {
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
	srv := &interactiveShellSSHServer{
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

func (s *interactiveShellSSHServer) Close() {
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

func (s *interactiveShellSSHServer) acceptLoop() {
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

func (s *interactiveShellSSHServer) serveConn(raw net.Conn) {
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
			if newCh.ChannelType() != "session" {
				_ = newCh.Reject(ssh.UnknownChannelType, "unsupported")
				continue
			}
			_ = n.Go(func(context.Context) error { handleInteractiveShellSession(newCh); return nil })
		}
		return nil
	})
}

func handleInteractiveShellSession(newCh ssh.NewChannel) {
	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	defer func() { _ = ch.Close() }()
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for req := range reqs {
			dispatchInteractiveShellReq(n, ch, req)
		}
		return nil
	})
}

func dispatchInteractiveShellReq(n *conc.Nursery, ch ssh.Channel, req *ssh.Request) {
	switch req.Type {
	case "pty-req", "window-change", "env":
		replySSHReq(req, true)
	case "shell":
		replySSHReq(req, true)
		_ = n.Go(func(context.Context) error { runEchoShellLoop(ch); return nil })
	default:
		replySSHReq(req, false)
	}
}

func replySSHReq(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

func runEchoShellLoop(ch ssh.Channel) {
	defer func() { _ = ch.Close() }()
	_, _ = io.WriteString(ch, "shell-ready\n")
	sc := bufio.NewScanner(ch)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "exit" {
			break
		}
		_, _ = io.WriteString(ch, "echo:"+line+"\n")
	}
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], 0)
	_, _ = ch.SendRequest("exit-status", false, payload[:])
}
