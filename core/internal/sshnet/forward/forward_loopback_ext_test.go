package forward_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/chanconn"
	"github.com/wentf9/xops-cli/core/internal/sshnet/forward"
	"github.com/wentf9/xops-cli/core/ports"
)

// fwdLoopbackStub 协调回环 SSH 服务端桩的反向转发推送时机，严格确保仅在客户端
// StartForward 返回（x/crypto/ssh Client.ListenTCP 完成 forwards 注册）后才发起 forwarded-tcpip。
type fwdLoopbackStub struct {
	triggerReverse chan struct{}
	triggerOnce    sync.Once
	reverseDone    chan error
}

func newFwdLoopbackStub() *fwdLoopbackStub {
	return &fwdLoopbackStub{
		triggerReverse: make(chan struct{}),
		reverseDone:    make(chan error, 1),
	}
}

func (s *fwdLoopbackStub) fireReverse() {
	s.triggerOnce.Do(func() { close(s.triggerReverse) })
}

// TestForwarder_RealSSHLoopbackIntegration 验证 forward.Forwarder 与真实 x/crypto/ssh +
// dial.TransportConn 对接 -L (direct-tcpip)、-D (零 DNS 泄露 SOCKS5) 与 -R (tcpip-forward/forwarded-tcpip) 端到端数据面。
func TestForwarder_RealSSHLoopbackIntegration(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stub := newFwdLoopbackStub()
	conn := dialRealSSHForForward(t, ctx, stub)
	defer func() { _ = conn.Close() }()

	// 启动一个本地回显目标供 -R 反向转发连接。
	var lc net.ListenConfig
	localTargetLn, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen local target: %v", err)
	}
	defer func() { _ = localTargetLn.Close() }()

	fwd := forward.NewForwarder(forward.Config{})

	// 1. -L 本地 TCP -> 远端 SSH direct-tcpip 回显。
	lSpec, _ := ports.NewForwardSpec(ports.ForwardLocal, "127.0.0.1:0", "10.9.0.1:8080")
	lh, err := fwd.StartForward(ctx, conn, lSpec)
	if err != nil {
		t.Fatalf("StartForward(-L): %v", err)
	}
	if err := roundTripTCPForward(ctx, lh.BoundAddr(), "ssh-local-fwd"); err != nil {
		_ = lh.Close()
		t.Fatalf("-L 数据面失败: %v", err)
	}
	if err := lh.Close(); err != nil {
		t.Fatalf("-L Close: %v", err)
	}

	// 2. -D 动态 SOCKS5（域名 .invalid 零本机 DNS 泄露）-> 远端 SSH direct-tcpip。
	dSpec, _ := ports.NewForwardSpec(ports.ForwardDynamic, "127.0.0.1:0", "")
	dh, err := fwd.StartForward(ctx, conn, dSpec)
	if err != nil {
		t.Fatalf("StartForward(-D): %v", err)
	}
	if err := verifyRealSSHSOCKS5(ctx, dh.BoundAddr(), "internal-db.invalid", 5432, "ssh-socks5-ok"); err != nil {
		_ = dh.Close()
		t.Fatalf("-D SOCKS5 数据面失败: %v", err)
	}
	if err := dh.Close(); err != nil {
		t.Fatalf("-D Close: %v", err)
	}

	// 3. -R 远端监听 -> 在 StartForward 注册完成后触发反向通道，完成端到端双向回显。
	verifyRealSSHReverseForward(t, ctx, fwd, conn, localTargetLn, stub)
}

func verifyRealSSHSOCKS5(ctx context.Context, proxyAddr, domain string, port uint16, msg string) error {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	var mRep [2]byte
	if _, err := io.ReadFull(c, mRep[:]); err != nil || mRep != [2]byte{0x05, 0x00} {
		return errors.New("SOCKS5 方法协商失败")
	}
	req := make([]byte, 0, 7+len(domain))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(domain)))
	req = append(req, domain...)
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := c.Write(req); err != nil {
		return err
	}
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil || rep[1] != 0x00 {
		return errors.New("SOCKS5 CONNECT 应答异常")
	}
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	got, err := io.ReadAll(c)
	if err != nil {
		return err
	}
	if !bytes.Contains(got, []byte(domain)) || !bytes.Contains(got, []byte(msg)) {
		return errors.New("真实 SSH SOCKS5 回显缺少目标域名或载荷")
	}
	return nil
}

func verifyRealSSHReverseForward(
	t *testing.T,
	ctx context.Context,
	fwd *forward.Forwarder,
	conn ports.TunnelTransport,
	localTargetLn net.Listener,
	stub *fwdLoopbackStub,
) {
	t.Helper()
	revCtx, cancelRev := context.WithTimeout(ctx, 10*time.Second)
	defer cancelRev()

	gotReverse := make(chan []byte, 1)
	err := conc.RunWait(revCtx, func(wCtx context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(c context.Context) error {
			return serveSingleLocalEcho(c, localTargetLn, gotReverse)
		}); gErr != nil {
			return gErr
		}
		rSpec, _ := ports.NewForwardSpec(ports.ForwardRemote, "127.0.0.1:0", localTargetLn.Addr().String())
		rh, sErr := fwd.StartForward(wCtx, conn, rSpec)
		if sErr != nil {
			_ = localTargetLn.Close()
			return sErr
		}
		defer func() { _ = rh.Close() }()

		// 仅在 StartForward 返回（x/crypto/ssh Client.ListenTCP 完成 forwards 注册）后触发远端推流，彻底消除竞态。
		stub.fireReverse()
		return awaitReverseRoundTrip(wCtx, gotReverse, stub.reverseDone)
	})
	if err != nil {
		t.Fatalf("-R 真实 SSH 反向转发验证失败: %v", err)
	}
}

func serveSingleLocalEcho(ctx context.Context, ln net.Listener, gotReverse chan<- []byte) error {
	var accepted net.Conn
	if err := chanconn.RunWithAbortWatchdog(ctx, func() { _ = ln.Close() }, func() error {
		c, aErr := ln.Accept()
		if aErr != nil {
			return aErr
		}
		accepted = c
		return nil
	}); err != nil {
		return err
	}
	defer func() { _ = accepted.Close() }()
	buf := make([]byte, len("from-remote"))
	if _, rErr := io.ReadFull(accepted, buf); rErr != nil {
		return rErr
	}
	gotReverse <- append([]byte(nil), buf...)
	_, wErr := accepted.Write(bytes.ToUpper(buf))
	return wErr
}

func awaitReverseRoundTrip(ctx context.Context, gotReverse <-chan []byte, reverseDone <-chan error) error {
	var payload []byte
	select {
	case payload = <-gotReverse:
	case revErr := <-reverseDone:
		return fmt.Errorf("远端反向通道提前结束: %w", revErr)
	case <-ctx.Done():
		return fmt.Errorf("等待反向转发入站数据超时: %w", ctx.Err())
	}
	if string(payload) != "from-remote" {
		return fmt.Errorf("反向转发入站数据不匹配: got %q", string(payload))
	}
	select {
	case revErr := <-reverseDone:
		return revErr
	case <-ctx.Done():
		return fmt.Errorf("等待远端反向通道读回显超时: %w", ctx.Err())
	}
}

func dialRealSSHForForward(t *testing.T, ctx context.Context, stub *fwdLoopbackStub) ports.TransportConn {
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
	vault := sim.NewSimVault(sim.NewSeededRand(3))
	ref, _ := secret.ParseRef("vault/fwd-loopback-pass")
	_ = secret.WithBytes([]byte("fwd-pass"), func(box *secret.SecretBox) error { return vault.PutAndVerify(ctx, ref, box) })
	d, err := dial.NewDialer(dial.Config{
		HostTrust:   trust,
		Vault:       vault,
		DialContext: makeFwdSSHLoopbackDialer(hostSigner, "fwd-pass", stub),
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	user, _ := option.ParseUsername("ops")
	auth, _ := inventory.NewAuthPassword(ref)
	eff, _ := option.ResolveEffectivePolicy(option.OriginManaged, ep, option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer())
	hop, _ := plan.NewHopSpecFromAuth(0, "fwd-e2e", user, auth, eff)
	sealed, _ := plan.SealConnectionPlan(hop)
	dig, _ := sealed.HopDigestAt(0)
	conn, err := d.DialHop(ctx, hop, dig, nil)
	if err != nil {
		t.Fatalf("DialHop: %v", err)
	}
	return conn
}

func makeFwdSSHLoopbackDialer(hostSigner ssh.Signer, pass string, stub *fwdLoopbackStub) dial.DialContextFunc {
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
			serveFwdSSHStub(raw, hostSigner, pass, stub)
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
		return &fwdLoopbackConn{Conn: cli, done: done, closeN: n.Close}, nil
	}
}

type fwdLoopbackConn struct {
	net.Conn
	done   <-chan struct{}
	closeN func() error
	once   sync.Once
	err    error
}

func (c *fwdLoopbackConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		<-c.done
		_ = c.closeN()
	})
	return c.err
}

func serveFwdSSHStub(raw net.Conn, hostSigner ssh.Signer, pass string, stub *fwdLoopbackStub) {
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
	connCtx, cancelConn := context.WithCancel(context.Background())
	defer cancelConn()
	_ = conc.RunWait(connCtx, func(_ context.Context, n *conc.Nursery) error {
		_ = n.Go(func(c context.Context) error { handleFwdGlobalReqs(c, n, sc, reqs, stub); return nil })
		for newCh := range chans {
			ch := newCh
			_ = n.Go(func(context.Context) error { handleFwdSSHChannel(ch); return nil })
		}
		cancelConn()
		return nil
	})
}

func handleFwdGlobalReqs(ctx context.Context, n *conc.Nursery, sc *ssh.ServerConn, reqs <-chan *ssh.Request, stub *fwdLoopbackStub) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			handleTCPIPForwardReq(ctx, n, sc, req, stub)
		case "cancel-tcpip-forward":
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

func handleTCPIPForwardReq(ctx context.Context, n *conc.Nursery, sc *ssh.ServerConn, req *ssh.Request, stub *fwdLoopbackStub) {
	var p struct {
		Addr string
		Port uint32
	}
	_ = ssh.Unmarshal(req.Payload, &p)
	var resp [4]byte
	binary.BigEndian.PutUint32(resp[:], 45555)
	if req.WantReply {
		_ = req.Reply(true, resp[:])
	}
	// 等待测试侧确认 StartForward 已返回后再打开 forwarded-tcpip，并显式回传结果消除静默吞错。
	_ = n.Go(func(c context.Context) error {
		select {
		case <-stub.triggerReverse:
			stub.reverseDone <- openReverseTestChannel(sc, p.Addr, 45555)
		case <-c.Done():
		case <-ctx.Done():
		}
		return nil
	})
}

func openReverseTestChannel(sc *ssh.ServerConn, addr string, port uint32) error {
	extra := ssh.Marshal(struct {
		Addr       string
		Port       uint32
		OriginAddr string
		OriginPort uint32
	}{Addr: addr, Port: port, OriginAddr: "127.0.0.1", OriginPort: 50001})
	ch, reqs, err := sc.OpenChannel("forwarded-tcpip", extra)
	if err != nil {
		return fmt.Errorf("OpenChannel(forwarded-tcpip): %w", err)
	}
	return conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		defer func() { _ = ch.Close() }()
		_ = n.Go(func(context.Context) error { ssh.DiscardRequests(reqs); return nil })
		if _, wErr := ch.Write([]byte("from-remote")); wErr != nil {
			return fmt.Errorf("reverse channel write: %w", wErr)
		}
		buf := make([]byte, len("FROM-REMOTE"))
		if _, rErr := io.ReadFull(ch, buf); rErr != nil {
			return fmt.Errorf("reverse channel read echo: %w", rErr)
		}
		if string(buf) != "FROM-REMOTE" {
			return fmt.Errorf("reverse echo mismatch: got %q", string(buf))
		}
		return nil
	})
}

func handleFwdSSHChannel(newCh ssh.NewChannel) {
	if newCh.ChannelType() != "direct-tcpip" {
		_ = newCh.Reject(ssh.UnknownChannelType, "unsupported")
		return
	}
	var p struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}
	_ = ssh.Unmarshal(newCh.ExtraData(), &p)
	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		defer func() { _ = ch.Close() }()
		_ = n.Go(func(context.Context) error { ssh.DiscardRequests(reqs); return nil })
		_, _ = ch.Write([]byte("DEST:" + p.DestAddr + "|"))
		_, _ = io.Copy(ch, ch)
		_ = ch.CloseWrite()
		return nil
	})
}
