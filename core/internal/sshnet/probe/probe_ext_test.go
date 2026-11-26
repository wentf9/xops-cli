package probe_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/keysigner"
	"github.com/wentf9/xops-cli/core/internal/sshnet/hostkey"
	"github.com/wentf9/xops-cli/core/internal/sshnet/probe"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// 编译期接口断言：确保 *probe.Prober 严格满足 ports.ShellProbePort 契约。
var _ ports.ShellProbePort = (*probe.Prober)(nil)

type probeReply struct {
	stdout   string
	exitCode uint32
}

type probeSSHStub struct {
	hostSigner   ssh.Signer
	clientSigner ssh.Signer
	handler      func(cmd string) probeReply

	mu       sync.Mutex
	seenCmds []string
}

func newProbeSSHConn(t *testing.T, handler func(cmd string) probeReply) (*probeSSHStub, ports.TransportConn) {
	t.Helper()
	hostSigner, hostPub := mustGenProbeKey(t)
	cliSigner, cliPub := mustGenProbeKey(t)
	stub := &probeSSHStub{hostSigner: hostSigner, clientSigner: cliSigner, handler: handler}

	ctx := context.Background()
	base, _ := pathalg.ParseLocalDir(t.TempDir())
	dir, _ := base.JoinComponent("ssh")
	_ = osfs.NewScopedRootFS().EnsureRoot(dir, 0o700)
	db, err := hostkey.NewKnownHostsDB(hostkey.Config{RootFS: osfs.NewScopedRootFS(), DefaultDir: dir})
	if err != nil {
		t.Fatalf("NewKnownHostsDB: %v", err)
	}
	ep := tck.MustEndpoint(t, "probe.example.test", 22)
	if err := db.RecordHostKey(ctx, ep, hostPub, option.UnsetKnownHostsList()); err != nil {
		t.Fatalf("RecordHostKey: %v", err)
	}
	d, err := dial.NewDialer(dial.Config{
		HostTrust:   db,
		Agent:       &probeStubAgent{signer: cliSigner, pub: cliPub},
		DialContext: stub.dialLoopback,
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	user, _ := option.ParseUsername("ops")
	auth, _ := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	unset := option.UnsetOptionLayer()
	eff, _ := option.ResolveEffectivePolicy(option.OriginManaged, ep, unset, unset, unset, unset)
	hop, _ := plan.NewHopSpecFromAuth(0, "probe-node", user, auth, eff)
	cp, _ := plan.SealConnectionPlan(hop)
	dig, _ := cp.HopDigestAt(0)
	conn, err := d.DialHop(ctx, hop, dig, nil)
	if err != nil {
		t.Fatalf("DialHop: %v", err)
	}
	return stub, conn
}

// ephemeralProbeOpener 为 TCK 子测试提供按会话隔离的真实回环 SSH SessionOpener，
// 在每次 RemoteSession.Close 时同步关闭底层 TransportConn，确保 TCK 内的 defer VerifyNoLeaks 零残留。
type ephemeralProbeOpener struct {
	dialer *dial.Dialer
	hop    plan.HopSpec
	digest plan.HopDigest
}

type ownedProbeSession struct {
	ports.RemoteSession
	conn      ports.TransportConn
	closeOnce sync.Once
}

func (s *ownedProbeSession) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.RemoteSession.Close()
		_ = s.conn.Close()
	})
	return err
}

func (o *ephemeralProbeOpener) OpenSession(ctx context.Context) (ports.RemoteSession, error) {
	conn, err := o.dialer.DialHop(ctx, o.hop, o.digest, nil)
	if err != nil {
		return nil, err
	}
	sess, err := conn.OpenSession(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &ownedProbeSession{RemoteSession: sess, conn: conn}, nil
}

func newEphemeralProbeOpener(t *testing.T, handler func(cmd string) probeReply) (*probeSSHStub, ports.SessionOpener) {
	t.Helper()
	hostSigner, hostPub := mustGenProbeKey(t)
	cliSigner, cliPub := mustGenProbeKey(t)
	stub := &probeSSHStub{hostSigner: hostSigner, clientSigner: cliSigner, handler: handler}

	ctx := context.Background()
	base, _ := pathalg.ParseLocalDir(t.TempDir())
	dir, _ := base.JoinComponent("ssh")
	_ = osfs.NewScopedRootFS().EnsureRoot(dir, 0o700)
	db, err := hostkey.NewKnownHostsDB(hostkey.Config{RootFS: osfs.NewScopedRootFS(), DefaultDir: dir})
	if err != nil {
		t.Fatalf("NewKnownHostsDB: %v", err)
	}
	ep := tck.MustEndpoint(t, "probe.example.test", 22)
	if err := db.RecordHostKey(ctx, ep, hostPub, option.UnsetKnownHostsList()); err != nil {
		t.Fatalf("RecordHostKey: %v", err)
	}
	d, err := dial.NewDialer(dial.Config{
		HostTrust:   db,
		Agent:       &probeStubAgent{signer: cliSigner, pub: cliPub},
		DialContext: stub.dialLoopback,
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	user, _ := option.ParseUsername("ops")
	auth, _ := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	unset := option.UnsetOptionLayer()
	eff, _ := option.ResolveEffectivePolicy(option.OriginManaged, ep, unset, unset, unset, unset)
	hop, _ := plan.NewHopSpecFromAuth(0, "probe-node", user, auth, eff)
	cp, _ := plan.SealConnectionPlan(hop)
	dig, _ := cp.HopDigestAt(0)
	return stub, &ephemeralProbeOpener{dialer: d, hop: hop, digest: dig}
}

func mustGenProbeKey(t *testing.T) (ssh.Signer, ports.PublicKeyInfo) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	pub, err := keysigner.PublicKeyInfoFromSSH(signer.PublicKey())
	if err != nil {
		t.Fatalf("PublicKeyInfoFromSSH: %v", err)
	}
	return signer, pub
}

type probeStubAgent struct {
	signer ssh.Signer
	pub    ports.PublicKeyInfo
}

func (*probeStubAgent) DialAgent(context.Context, algebraic.Option[inventory.AgentSpec]) (net.Conn, error) {
	return nil, ports.ErrUnsupported
}
func (a *probeStubAgent) ListAgentKeys(context.Context, algebraic.Option[inventory.AgentSpec]) ([]ports.PublicKeyInfo, error) {
	return []ports.PublicKeyInfo{a.pub}, nil
}
func (a *probeStubAgent) SignWithAgent(_ context.Context, _ algebraic.Option[inventory.AgentSpec], _ inventory.KeyFingerprint, _ string, data []byte) (ports.Signature, error) {
	sig, err := a.signer.Sign(rand.Reader, data)
	if err != nil {
		var zero ports.Signature
		return zero, err
	}
	return ports.NewSignature(sig.Format, sig.Blob)
}

type syncProbeConn struct {
	net.Conn
	done      <-chan struct{}
	nursery   *conc.Nursery
	closeOnce sync.Once
	closeErr  error
}

func (c *syncProbeConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
		<-c.done
		_ = c.nursery.Close()
	})
	return c.closeErr
}

func (s *probeSSHStub) dialLoopback(ctx context.Context, _, _ string) (net.Conn, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	n, err := conc.NewNursery(context.Background())
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	done := make(chan struct{})
	_ = n.Go(func(context.Context) error {
		defer close(done)
		defer func() { _ = ln.Close() }()
		srvConn, aErr := ln.Accept()
		_ = ln.Close()
		if aErr != nil {
			return nil
		}
		s.serve(srvConn)
		return nil
	})
	var nd net.Dialer
	cli, err := nd.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		<-done
		_ = n.Close()
		return nil, err
	}
	return &syncProbeConn{Conn: cli, done: done, nursery: n}, nil
}

func (s *probeSSHStub) serve(raw net.Conn) {
	defer func() { _ = raw.Close() }()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), s.clientSigner.PublicKey().Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("unauthorized")
		},
	}
	cfg.AddHostKey(s.hostSigner)
	sConn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sConn.Close() }()
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		_ = n.Go(func(context.Context) error { ssh.DiscardRequests(reqs); return nil })
		for newCh := range chans {
			ch := newCh
			_ = n.Go(func(context.Context) error {
				s.handleChan(ch)
				return nil
			})
		}
		return nil
	})
}

func (s *probeSSHStub) handleChan(newCh ssh.NewChannel) {
	if newCh.ChannelType() != "session" {
		_ = newCh.Reject(ssh.UnknownChannelType, "unsupported")
		return
	}
	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	defer func() { _ = ch.Close() }()
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for req := range reqs {
			if req.Type == "exec" {
				var p struct{ Command string }
				_ = ssh.Unmarshal(req.Payload, &p)
				_ = req.Reply(true, nil)
				_ = n.Go(func(context.Context) error { s.handleExec(ch, p.Command); return nil })
				continue
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		}
		return nil
	})
}

func (s *probeSSHStub) handleExec(ch ssh.Channel, cmd string) {
	defer func() { _ = ch.Close() }()
	s.mu.Lock()
	s.seenCmds = append(s.seenCmds, cmd)
	s.mu.Unlock()
	rep := s.handler(cmd)
	if rep.stdout != "" {
		_, _ = ch.Write([]byte(rep.stdout))
	}
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], rep.exitCode)
	_, _ = ch.SendRequest("exit-status", false, p[:])
}

func posixHandler(osName, shellPath string, interps ...string) func(string) probeReply {
	return func(cmd string) probeReply {
		if strings.Contains(cmd, "__XOPS_DIALECT_POSIX__") {
			return probeReply{stdout: "__XOPS_DIALECT_POSIX__:" + osName + ":" + shellPath + "\n"}
		}
		if strings.Contains(cmd, "__XOPS_INTERP_END__") {
			var b strings.Builder
			for _, it := range interps {
				b.WriteString("__XOPS_INTERP__:" + it + "\n")
			}
			b.WriteString("__XOPS_INTERP_END__\n")
			return probeReply{stdout: b.String()}
		}
		return probeReply{exitCode: 2}
	}
}

func TestProber_TCKSuite(t *testing.T) {
	defer goleak.VerifyNone(t)
	tck.RunShellProbeSuite(t, tck.ShellProbeFixture{
		NewProbe: func(st *testing.T) (ports.ShellProbePort, ports.SessionOpener) {
			_, opener := newEphemeralProbeOpener(st, posixHandler("Linux", "/bin/bash", "bash", "sh"))
			pr, err := probe.NewProber(probe.Config{})
			if err != nil {
				st.Fatalf("NewProber: %v", err)
			}
			return pr, opener
		},
	})
}

func TestProber_LegalDialectsAndStage1Mode(t *testing.T) {
	defer goleak.VerifyNone(t)
	t.Run("POSIXZshOnDarwin", testProbePOSIXZshDarwin)
	t.Run("WindowsCmdWithHint", testProbeWindowsCmd)
	t.Run("PowerShellWinAndUnix", testProbePowerShell)
	t.Run("Stage1OnlyMode", testProbeStage1Only)
}

func testProbePOSIXZshDarwin(t *testing.T) {
	defer goleak.VerifyNone(t)
	_, conn := newProbeSSHConn(t, posixHandler("Darwin", "/bin/zsh", "bash", "sh", "zsh"))
	defer func() { _ = conn.Close() }()
	pr, _ := probe.NewProber(probe.Config{})
	res, err := pr.ProbeShell(context.Background(), conn)
	if err != nil {
		t.Fatalf("ProbeShell(zsh/darwin): %v", err)
	}
	if res.Dialect() != execution.DialectPOSIX || res.Interpreter() != execution.InterpreterZsh ||
		res.OSFamily() != "darwin" || res.ProbeStage() != 2 {
		t.Fatalf("探测结果不符预期: dialect=%s interp=%s os=%q stage=%d", res.Dialect(), res.Interpreter(), res.OSFamily(), res.ProbeStage())
	}
}

func testProbeWindowsCmd(t *testing.T) {
	defer goleak.VerifyNone(t)
	stub, conn := newProbeSSHConn(t, func(cmd string) probeReply {
		if strings.Contains(cmd, "__XOPS_DIALECT_CMD__") {
			return probeReply{stdout: "__XOPS_DIALECT_CMD__:C:\\Windows\\System32\\cmd.exe\r\n"}
		}
		if strings.Contains(cmd, "__XOPS_INTERP_END__") {
			return probeReply{stdout: "__XOPS_INTERP__:powershell\r\n__XOPS_INTERP__:cmd\r\n__XOPS_INTERP_END__\r\n"}
		}
		return probeReply{exitCode: 1}
	})
	defer func() { _ = conn.Close() }()
	pr, _ := probe.NewProber(probe.Config{ServerVersionHint: "SSH-2.0-OpenSSH_for_Windows_9.5"})
	res, err := pr.ProbeShell(context.Background(), conn)
	if err != nil {
		t.Fatalf("ProbeShell(cmd): %v", err)
	}
	if res.Dialect() != execution.DialectCmd || res.Interpreter() != execution.InterpreterCmd ||
		res.OSFamily() != "windows" || res.ProbeStage() != 2 {
		t.Fatalf("Windows cmd 探测结果异常: dialect=%s interp=%s os=%q stage=%d", res.Dialect(), res.Interpreter(), res.OSFamily(), res.ProbeStage())
	}
	// ServerVersionHint 应优先执行 cmd 探针（只需 2 条命令完成 2 阶段探测）。
	if len(stub.seenCmds) != 2 {
		t.Fatalf("OpenSSH_for_Windows 提示应 2 条命令完成，实际 %d", len(stub.seenCmds))
	}
}

func testProbePowerShell(t *testing.T) {
	defer goleak.VerifyNone(t)
	_, conn := newProbeSSHConn(t, func(cmd string) probeReply {
		if strings.Contains(cmd, "__XOPS_DIALECT_POWERSHELL__") {
			return probeReply{stdout: "__XOPS_DIALECT_POWERSHELL__:7.5.0-preview.3\n__XOPS_PLATFORM__:Unix\n"}
		}
		if strings.Contains(cmd, "__XOPS_INTERP_END__") {
			return probeReply{stdout: "__XOPS_INTERP__:pwsh\n__XOPS_INTERP__:bash\n__XOPS_INTERP_END__\n"}
		}
		return probeReply{exitCode: 1}
	})
	defer func() { _ = conn.Close() }()
	pr, _ := probe.NewProber(probe.Config{})
	res, err := pr.ProbeShell(context.Background(), conn)
	if err != nil {
		t.Fatalf("ProbeShell(pwsh): %v", err)
	}
	if res.Dialect() != execution.DialectPowerShell || res.Interpreter() != execution.InterpreterPwsh ||
		res.OSFamily() != "unix" || res.ProbeStage() != 2 {
		t.Fatalf("PowerShell 探测异常: dialect=%s interp=%s os=%q stage=%d", res.Dialect(), res.Interpreter(), res.OSFamily(), res.ProbeStage())
	}
}

func testProbeStage1Only(t *testing.T) {
	defer goleak.VerifyNone(t)
	stub, conn := newProbeSSHConn(t, posixHandler("FreeBSD", "/bin/sh", "sh"))
	defer func() { _ = conn.Close() }()
	pr, _ := probe.NewProber(probe.Config{Stage1Only: true})
	res, err := pr.ProbeShell(context.Background(), conn)
	if err != nil {
		t.Fatalf("ProbeShell(stage1): %v", err)
	}
	if res.ProbeStage() != 1 || res.Dialect() != execution.DialectPOSIX || res.Interpreter() != execution.InterpreterServer || res.OSFamily() != "freebsd" {
		t.Fatalf("Stage1Only 结果异常: stage=%d dialect=%s interp=%s os=%q", res.ProbeStage(), res.Dialect(), res.Interpreter(), res.OSFamily())
	}
	if len(stub.seenCmds) != 1 {
		t.Fatalf("Stage1Only 不应触发阶段 2 枚举，实际命令数 %d", len(stub.seenCmds))
	}
}

func TestProber_FailClosedCases(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	// 零值与非法配置失败关闭。
	var zeroProber probe.Prober
	if _, err := zeroProber.ProbeShell(ctx, nil); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 Prober 须返回 ErrInvalidArgument，实际 %v", err)
	}
	if _, err := probe.NewProber(probe.Config{CommandTimeout: -time.Second}); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("负 CommandTimeout 须拒绝，实际 %v", err)
	}
	if _, err := probe.NewProber(probe.Config{MaxOutputBytes: 10 << 20}); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("超大 MaxOutputBytes 须拒绝，实际 %v", err)
	}

	// 1. 未知/非受支持外层壳（如受限设备 CLI 或 fish/csh）均须 Fail-Closed。
	_, connUnknown := newProbeSSHConn(t, func(string) probeReply {
		return probeReply{stdout: "unsupported router banner\n", exitCode: 127}
	})
	defer func() { _ = connUnknown.Close() }()
	pr, _ := probe.NewProber(probe.Config{})
	if _, err := pr.ProbeShell(ctx, connUnknown); !errors.Is(err, probe.ErrProbeFailed) {
		t.Fatalf("未知外层壳须返回 ErrProbeFailed，实际 %v", err)
	}

	// 2. 阶段 2 缺失结束帧 -> Fail-Closed。
	_, connNoEnd := newProbeSSHConn(t, func(cmd string) probeReply {
		if strings.Contains(cmd, "__XOPS_DIALECT_POSIX__") {
			return probeReply{stdout: "__XOPS_DIALECT_POSIX__:Linux:/bin/bash\n"}
		}
		return probeReply{stdout: "__XOPS_INTERP__:bash\n"}
	})
	defer func() { _ = connNoEnd.Close() }()
	if _, err := pr.ProbeShell(ctx, connNoEnd); !errors.Is(err, probe.ErrProbeFailed) {
		t.Fatalf("阶段 2 缺失结束帧须返回 ErrProbeFailed，实际 %v", err)
	}

	// 3. 阶段 1 输出重复方言帧或超限截断 -> Fail-Closed。
	_, connDup := newProbeSSHConn(t, func(cmd string) probeReply {
		if strings.Contains(cmd, "__XOPS_DIALECT_POSIX__") {
			return probeReply{stdout: "__XOPS_DIALECT_POSIX__:Linux:/bin/sh\n__XOPS_DIALECT_POSIX__:Linux:/bin/bash\n"}
		}
		return probeReply{exitCode: 1}
	})
	defer func() { _ = connDup.Close() }()
	if _, err := pr.ProbeShell(ctx, connDup); !errors.Is(err, probe.ErrProbeFailed) {
		t.Fatalf("重复方言帧须返回 ErrProbeFailed，实际 %v", err)
	}
	_, connTrunc := newProbeSSHConn(t, func(string) probeReply {
		return probeReply{stdout: strings.Repeat("X", 2048)}
	})
	defer func() { _ = connTrunc.Close() }()
	prSmall, _ := probe.NewProber(probe.Config{MaxOutputBytes: 128})
	if _, err := prSmall.ProbeShell(ctx, connTrunc); !errors.Is(err, probe.ErrProbeFailed) {
		t.Fatalf("超限截断输出须返回 ErrProbeFailed，实际 %v", err)
	}
}
