package mux_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
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
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/internal/sshnet/forward"
	"github.com/wentf9/xops-cli/core/internal/sshnet/mux"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// TestMuxSocket_RealSSHLoopbackEndToEnd 验证真实 x/crypto/ssh + dial.TransportConn + mux.Serve +
// forward.Forwarder + mux.DialMux 全链路（含会话管道/PTY/缩放/信号/退出码、DialTCP/StreamLocal/TUN/ListenTCP 与优雅停机）。
func TestMuxSocket_RealSSHLoopbackEndToEnd(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upConn, hop, dig := dialLoopbackRealSSH(t, ctx)
	defer func() { _ = upConn.Close() }()

	dir := shortMuxTempDir(t)
	sockPath := mustLocalSource(t, filepath.Join(dir, "e2e.sock"))
	m := mux.NewMuxSocket(mux.Config{})
	fwd := forward.NewForwarder(forward.Config{TUNDevice: sim.NewSimTUNDevicePort()})

	ready := make(chan struct{})
	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(c context.Context) error {
			return m.WithListener(c, sockPath, func(ln net.Listener) error {
				close(ready)
				return m.Serve(c, ln, upConn, fwd)
			})
		}); gErr != nil {
			return gErr
		}
		return n.Go(func(c context.Context) error {
			select {
			case <-ready:
			case <-c.Done():
				return c.Err()
			}
			return verifyFullMuxClientOverRealSSH(t, c, m, sockPath, dig, hop.Endpoint())
		})
	})
	if err != nil {
		t.Fatalf("真实 SSH 回环 ControlMaster 端到端测试失败: %v", err)
	}
}

func verifyFullMuxClientOverRealSSH(t *testing.T, ctx context.Context, m *mux.MuxSocket, sockPath pathalg.LocalSourcePath, dig plan.HopDigest, ep netaddr.Endpoint) error {
	mc, err := m.DialMux(ctx, sockPath, dig, ep)
	if err != nil {
		return err
	}
	defer func() { _ = mc.Close() }()
	if !mc.IsAlive() || !mc.HopDigest().Equal(dig) || !mc.Endpoint().Equal(ep) {
		return errors.New("DialMux 身份绑定不匹配")
	}
	if err := verifyMuxSessionPipesAndSignals(t, ctx, mc); err != nil {
		return err
	}
	if err := verifyMuxTunnels(ctx, mc); err != nil {
		return err
	}
	// 验证通过 ControlMaster 复用通道打开 SFTP 子系统并完成 SFTP v3 协议握手与 RealPath。
	if err := verifyMuxOpenRemoteFS(ctx, mc); err != nil {
		return err
	}
	// 请求优雅退出 ControlMaster。
	exitReq, _ := ports.NewMuxControlRequest(ports.MuxActionExit, sockPath, algebraic.None[ports.ForwardSpec]())
	_, err = m.Control(ctx, exitReq)
	return err
}

func verifyMuxOpenRemoteFS(ctx context.Context, mc ports.TransportConn) error {
	rfs, err := mc.OpenRemoteFS(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = rfs.Close() }()
	rp, err := pathalg.ParseRemotePath("/mux-sftp-probe")
	if err != nil {
		return err
	}
	got, err := rfs.RealPath(ctx, rp)
	if err != nil || got.String() != "/mux-sftp-probe" {
		return errors.Join(errors.New("复用 SFTP RealPath 失败"), err)
	}
	return nil
}

func verifyMuxSessionPipesAndSignals(t *testing.T, ctx context.Context, mc ports.TransportConn) error {
	// 1. 借出管道模式执行（含互斥校验与退出码 0）。
	sess, err := mc.OpenSession(ctx)
	if err != nil {
		return err
	}
	inW, e1 := sess.StdinPipe()
	outR, e2 := sess.StdoutPipe()
	errR, e3 := sess.StderrPipe()
	if err := errors.Join(e1, e2, e3); err != nil {
		_ = sess.Close()
		return err
	}
	if _, dupErr := sess.StdinPipe(); dupErr == nil {
		_ = sess.Close()
		return errors.New("重复 StdinPipe 必须被拒绝")
	}
	cmd := tck.MustCommandPlan(t, "echo-stdin")
	if err := sess.Start(ctx, cmd, ports.ExecStreams{}); err != nil {
		_ = sess.Close()
		return err
	}
	_, _ = inW.Write([]byte("mux-pipe-ok"))
	_ = inW.Close()
	gotOut, _ := io.ReadAll(outR)
	_, _ = io.ReadAll(errR)
	out, wErr := sess.Wait(ctx)
	_ = sess.Close()
	if wErr != nil || !bytes.Contains(gotOut, []byte("mux-pipe-ok")) {
		return errors.Join(errors.New("复用管道执行输出异常"), wErr)
	}
	if comp, ok := out.(*execution.OutcomeCompleted); !ok || !comp.Succeeded() {
		return errors.New("复用管道执行期望 ExitCode(0)")
	}
	// 2. Shell + PTY + ResizePTY + Signal 校验。
	return verifyMuxShellPTYResizeSignal(ctx, mc)
}

func verifyMuxShellPTYResizeSignal(ctx context.Context, mc ports.TransportConn) error {
	sh, err := mc.OpenSession(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = sh.Close() }()
	sz, _ := ports.NewTerminalSize(80, 24)
	ptyReq, _ := ports.NewPTYRequest("xterm-256color", sz)
	var outBuf bytes.Buffer
	if err := sh.StartShell(ctx, ports.ExecStreams{
		Stdin:  strings.NewReader("hi"),
		Stdout: &outBuf,
		PTY:    algebraic.Some(ptyReq),
		Env:    map[string]string{"LANG": "C.UTF-8"},
	}); err != nil {
		return err
	}
	sz2, _ := ports.NewTerminalSize(120, 40)
	if err := sh.ResizePTY(ctx, sz2); err != nil {
		return err
	}
	if err := sh.Signal(ctx, "TERM"); err != nil {
		return err
	}
	out, err := sh.Wait(ctx)
	if err != nil || out == nil || !out.IsValid() {
		return errors.Join(errors.New("Shell Wait 失败"), err)
	}
	return nil
}

func verifyMuxTunnels(ctx context.Context, mc ports.TransportConn) error {
	hp, _ := netaddr.ParseHostPort("10.0.0.9:8080")
	tc, err := mc.DialTCP(ctx, hp)
	if err != nil {
		return err
	}
	if err := roundTripEcho(tc, "tcp-mux"); err != nil {
		return err
	}
	rp, _ := pathalg.ParseRemotePath("/run/echo.sock")
	uc, err := mc.DialStreamLocal(ctx, rp)
	if err != nil {
		return err
	}
	if err := roundTripEcho(uc, "unix-mux"); err != nil {
		return err
	}
	ts, _ := ports.NewTUNSpec(ports.TUNModePointToPoint, 0, 0)
	tun, err := mc.OpenTUN(ctx, ts)
	if err != nil {
		return err
	}
	if err := roundTripEcho(tun, "tun-mux"); err != nil {
		return err
	}
	ln, err := mc.ListenTCP(ctx, "127.0.0.1:0")
	if err != nil {
		return err
	}
	return ln.Close()
}

func roundTripEcho(rw io.ReadWriteCloser, payload string) error {
	defer func() { _ = rw.Close() }()
	if _, err := rw.Write([]byte(payload)); err != nil {
		return err
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(rw, buf); err != nil {
		return err
	}
	if string(buf) != payload {
		return errors.New("回显数据不一致")
	}
	return nil
}

func dialLoopbackRealSSH(t *testing.T, ctx context.Context) (ports.TransportConn, plan.HopSpec, plan.HopDigest) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	fp, _ := inventory.ParseKeyFingerprint(ssh.FingerprintSHA256(hostSigner.PublicKey()))
	pubInfo, _ := ports.NewPublicKeyInfo(ports.PublicKeyInfoSpec{
		Algorithm: hostSigner.PublicKey().Type(), Fingerprint: fp, WireBlob: hostSigner.PublicKey().Marshal(),
	})
	ep, _ := netaddr.ParseEndpoint("127.0.0.1:22")
	trust := sim.NewSimHostTrust()
	_ = trust.RecordHostKey(ctx, ep, pubInfo, option.UnsetKnownHostsList())
	vault := sim.NewSimVault(sim.NewSeededRand(2))
	ref, _ := secret.ParseRef("vault/mux-loopback-pass")
	_ = secret.WithBytes([]byte("mux-pass"), func(box *secret.SecretBox) error { return vault.PutAndVerify(ctx, ref, box) })
	d, err := dial.NewDialer(dial.Config{
		HostTrust:   trust,
		Vault:       vault,
		DialContext: makeMuxSSHLoopbackDialer(hostSigner, "mux-pass"),
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	user, _ := option.ParseUsername("ops")
	auth, _ := inventory.NewAuthPassword(ref)
	eff, _ := option.ResolveEffectivePolicy(option.OriginManaged, ep, option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer())
	hop, _ := plan.NewHopSpecFromAuth(0, "mux-e2e", user, auth, eff)
	sealed, _ := plan.SealConnectionPlan(hop)
	dig, _ := sealed.HopDigestAt(0)
	conn, err := d.DialHop(ctx, hop, dig, nil)
	if err != nil {
		t.Fatalf("DialHop: %v", err)
	}
	return conn, hop, dig
}

func makeMuxSSHLoopbackDialer(hostSigner ssh.Signer, pass string) dial.DialContextFunc {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
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
		if err := n.Go(func(context.Context) error {
			defer close(done)
			defer func() { _ = ln.Close() }()
			raw, aErr := ln.Accept()
			_ = ln.Close()
			if aErr != nil {
				return nil
			}
			serveMuxSSHStub(raw, hostSigner, pass)
			return nil
		}); err != nil {
			_ = ln.Close()
			_ = n.Close()
			return nil, err
		}
		cli, dErr := (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
		if dErr != nil {
			_ = ln.Close()
			<-done
			_ = n.Close()
			return nil, dErr
		}
		return &muxSyncConn{Conn: cli, done: done, closeN: n.Close}, nil
	}
}

type muxSyncConn struct {
	net.Conn
	done   <-chan struct{}
	closeN func() error
	once   sync.Once
	err    error
}

func (c *muxSyncConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		<-c.done
		_ = c.closeN()
	})
	return c.err
}

func serveMuxSSHStub(raw net.Conn, hostSigner ssh.Signer, pass string) {
	defer func() { _ = raw.Close() }()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if string(p) == pass {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("bad pass")
		},
	}
	cfg.AddHostKey(hostSigner)
	sc, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sc.Close() }()
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		_ = n.Go(func(context.Context) error { handleMuxGlobalReqs(reqs); return nil })
		for newCh := range chans {
			ch := newCh
			_ = n.Go(func(context.Context) error { handleMuxSSHChannel(ch); return nil })
		}
		return nil
	})
}

func handleMuxGlobalReqs(reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			var resp [4]byte
			binary.BigEndian.PutUint32(resp[:], 44123)
			if req.WantReply {
				_ = req.Reply(true, resp[:])
			}
		case "cancel-tcpip-forward", "keepalive@openssh.com":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func handleMuxSSHChannel(newCh ssh.NewChannel) {
	switch newCh.ChannelType() {
	case "session":
		ch, reqs, err := newCh.Accept()
		if err != nil {
			return
		}
		handleMuxSSHSession(ch, reqs)
	case "direct-tcpip", "direct-streamlocal@openssh.com", "tun@openssh.com":
		ch, reqs, err := newCh.Accept()
		if err != nil {
			return
		}
		_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
			defer func() { _ = ch.Close() }()
			_ = n.Go(func(context.Context) error { ssh.DiscardRequests(reqs); return nil })
			_, _ = io.Copy(ch, ch)
			return nil
		})
	default:
		_ = newCh.Reject(ssh.UnknownChannelType, "unsupported")
	}
}

func handleMuxSSHSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for req := range reqs {
			dispatchMuxSessionReq(n, ch, req)
		}
		return nil
	})
}

func dispatchMuxSessionReq(n *conc.Nursery, ch ssh.Channel, req *ssh.Request) {
	switch req.Type {
	case "env", "pty-req", "window-change", "signal":
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
	case "exec", "shell":
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
		_ = n.Go(func(context.Context) error {
			_, _ = io.Copy(ch, ch)
			var code [4]byte
			_, _ = ch.SendRequest("exit-status", false, code[:])
			_ = ch.Close()
			return nil
		})
	case "subsystem":
		var p struct{ Name string }
		ok := ssh.Unmarshal(req.Payload, &p) == nil && p.Name == "sftp"
		if req.WantReply {
			_ = req.Reply(ok, nil)
		}
		if ok {
			_ = n.Go(func(context.Context) error {
				serveMiniSFTPRealPath(ch)
				return nil
			})
		}
	default:
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

func serveMiniSFTPRealPath(ch ssh.Channel) {
	defer func() { _ = ch.Close() }()
	// 读取 SSH_FXP_INIT 并回传 SSH_FXP_VERSION=3。
	if _, _, err := readMiniSFTPPkt(ch); err != nil {
		return
	}
	ver := []byte{0, 0, 0, 5, 2, 0, 0, 0, 3}
	if _, err := ch.Write(ver); err != nil {
		return
	}
	for {
		pType, body, err := readMiniSFTPPkt(ch)
		if err != nil || len(body) < 8 {
			return
		}
		if pType == 16 { // SSH_FXP_REALPATH
			reqID := binary.BigEndian.Uint32(body[:4])
			n := binary.BigEndian.Uint32(body[4:8])
			if int(8+n) > len(body) {
				return
			}
			pStr := string(body[8 : 8+n])
			var out []byte
			out = binary.BigEndian.AppendUint32(out, reqID)
			out = binary.BigEndian.AppendUint32(out, 1)
			out = binary.BigEndian.AppendUint32(out, uint32(len(pStr)))
			out = append(out, pStr...)
			out = binary.BigEndian.AppendUint32(out, uint32(len(pStr)))
			out = append(out, pStr...)
			out = binary.BigEndian.AppendUint32(out, 0) // attrs flags=0
			frame := make([]byte, 5+len(out))
			binary.BigEndian.PutUint32(frame[:4], uint32(1+len(out)))
			frame[4] = 104 // SSH_FXP_NAME
			copy(frame[5:], out)
			if _, wErr := ch.Write(frame); wErr != nil {
				return
			}
		}
	}
}

func readMiniSFTPPkt(r io.Reader) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return buf[0], buf[1:], nil
}
