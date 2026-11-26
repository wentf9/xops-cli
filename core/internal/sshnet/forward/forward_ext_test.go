package forward_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/sshnet/forward"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// 编译期契约断言：确保 Forwarder 与 Handle 严格满足 core/ports 导出接口。
var (
	_ ports.ForwarderPort = (*forward.Forwarder)(nil)
	_ ports.ForwardHandle = (*forward.Handle)(nil)
)

// memTunnelTransport 提供进程内可观测、支持回显与反向推送的 ports.TunnelTransport 测试桩。
type memTunnelTransport struct {
	mu           sync.Mutex
	dialTCPHosts []string
	dialUnixPath []string
	remoteLn     *pushListener
	tunOpened    int
	dialErr      error
}

func newMemTunnelTransport() *memTunnelTransport {
	return &memTunnelTransport{}
}

func (m *memTunnelTransport) DialTCP(_ context.Context, target netaddr.HostPort) (net.Conn, error) {
	m.mu.Lock()
	m.dialTCPHosts = append(m.dialTCPHosts, target.String())
	dErr := m.dialErr
	m.mu.Unlock()
	if dErr != nil {
		return nil, dErr
	}
	return newEchoPipeConn("tcp:"+target.String(), "TCP:"+target.String()+"|"), nil
}

func (m *memTunnelTransport) ListenTCP(_ context.Context, bindAddr string) (net.Listener, error) {
	ln := newPushListener("tcp", bindAddr)
	m.mu.Lock()
	m.remoteLn = ln
	m.mu.Unlock()
	return ln, nil
}

func (m *memTunnelTransport) DialStreamLocal(_ context.Context, remoteSocket pathalg.RemotePath) (net.Conn, error) {
	m.mu.Lock()
	m.dialUnixPath = append(m.dialUnixPath, remoteSocket.String())
	dErr := m.dialErr
	m.mu.Unlock()
	if dErr != nil {
		return nil, dErr
	}
	return newEchoPipeConn("unix:"+remoteSocket.String(), "UNIX:"+remoteSocket.String()+"|"), nil
}

func (m *memTunnelTransport) ListenStreamLocal(_ context.Context, remoteSocket pathalg.RemotePath) (net.Listener, error) {
	ln := newPushListener("unix", remoteSocket.String())
	m.mu.Lock()
	m.remoteLn = ln
	m.mu.Unlock()
	return ln, nil
}

func (m *memTunnelTransport) OpenTUN(_ context.Context, _ ports.TUNSpec) (io.ReadWriteCloser, error) {
	m.mu.Lock()
	m.tunOpened++
	m.mu.Unlock()
	return newEchoPipeConn("tun", ""), nil
}

// pushListener 允许测试主动注入模拟远端到站连接以验证 -R 反向转发数据面。
type pushListener struct {
	netw   string
	addr   string
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPushListener(netw, addr string) *pushListener {
	return &pushListener{netw: netw, addr: addr, ch: make(chan net.Conn, 4), closed: make(chan struct{})}
}

func (l *pushListener) push(c net.Conn) bool {
	select {
	case <-l.closed:
		return false
	case l.ch <- c:
		return true
	}
}

func (l *pushListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case c := <-l.ch:
		return c, nil
	}
}

func (l *pushListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pushListener) Addr() net.Addr { return stubAddr{netw: l.netw, addr: l.addr} }

type stubAddr struct{ netw, addr string }

func (a stubAddr) Network() string { return a.netw }
func (a stubAddr) String() string  { return a.addr }

// echoPipeConn 使用纯内存缓冲回显写入数据，零后台协程（100% goleak 安全）。
type echoPipeConn struct {
	addr   string
	prefix []byte
	mu     sync.Mutex
	buf    bytes.Buffer
	cond   *sync.Cond
	closed bool
	wClose bool
}

func newEchoPipeConn(addr, prefix string) *echoPipeConn {
	c := &echoPipeConn{addr: addr, prefix: []byte(prefix)}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *echoPipeConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.buf.Len() == 0 && !c.closed && !c.wClose {
		c.cond.Wait()
	}
	if c.buf.Len() > 0 {
		return c.buf.Read(p)
	}
	if c.closed {
		return 0, net.ErrClosed
	}
	return 0, io.EOF
}

func (c *echoPipeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.wClose {
		return 0, net.ErrClosed
	}
	if len(c.prefix) > 0 {
		c.buf.Write(c.prefix)
		c.prefix = nil
	}
	c.buf.Write(p)
	c.cond.Broadcast()
	return len(p), nil
}

func (c *echoPipeConn) CloseWrite() error {
	c.mu.Lock()
	c.wClose = true
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

func (c *echoPipeConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

func (c *echoPipeConn) LocalAddr() net.Addr              { return stubAddr{"mem", c.addr} }
func (c *echoPipeConn) RemoteAddr() net.Addr             { return stubAddr{"mem", c.addr} }
func (c *echoPipeConn) SetDeadline(time.Time) error      { return nil }
func (c *echoPipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *echoPipeConn) SetWriteDeadline(time.Time) error { return nil }

func shortTempSocketDir(t *testing.T) string {
	t.Helper()
	parent := os.TempDir()
	if runtime.GOOS != "windows" {
		parent = "/tmp"
	}
	dir, err := os.MkdirTemp(parent, "xf-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sub := filepath.Join(dir, "s")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	return sub
}

func TestForwarder_TCKSuite_AllDirectionsAndCombinations(t *testing.T) {
	sockDir := shortTempSocketDir(t)
	localUnix1 := filepath.Join(sockDir, "l1.sock")
	localUnix2 := filepath.Join(sockDir, "l2.sock")
	localTargetUnix := filepath.Join(sockDir, "tgt.sock")

	lTCP, _ := ports.NewForwardSpec(ports.ForwardLocal, "127.0.0.1:0", "10.0.0.2:80")
	lTCPUnix, _ := ports.NewTypedForwardSpec(ports.ForwardLocal, ports.ForwardEndpointTCP, "127.0.0.1:0", ports.ForwardEndpointUnix, "/run/remote.sock")
	lUnixTCP, _ := ports.NewTypedForwardSpec(ports.ForwardLocal, ports.ForwardEndpointUnix, localUnix1, ports.ForwardEndpointTCP, "10.0.0.2:5432")
	lUnixUnix, _ := ports.NewTypedForwardSpec(ports.ForwardLocal, ports.ForwardEndpointUnix, localUnix2, ports.ForwardEndpointUnix, "/run/r2.sock")
	rTCP, _ := ports.NewForwardSpec(ports.ForwardRemote, "0.0.0.0:19090", "127.0.0.1:3000")
	rUnixTCP, _ := ports.NewTypedForwardSpec(ports.ForwardRemote, ports.ForwardEndpointUnix, "/run/rev.sock", ports.ForwardEndpointTCP, "127.0.0.1:3001")
	rTCPUnix, _ := ports.NewTypedForwardSpec(ports.ForwardRemote, ports.ForwardEndpointTCP, "0.0.0.0:19091", ports.ForwardEndpointUnix, localTargetUnix)
	dyn, _ := ports.NewForwardSpec(ports.ForwardDynamic, "127.0.0.1:0", "")
	tunSpec, _ := ports.NewTUNSpec(ports.TUNModePointToPoint, 0, 0)
	tunFwd, _ := ports.NewForwardTUNSpec(tunSpec)

	var currentTransport *memTunnelTransport
	tck.RunForwarderSuite(t, tck.ForwarderFixture{
		Specs: []ports.ForwardSpec{lTCP, lTCPUnix, lUnixTCP, lUnixUnix, rTCP, rUnixTCP, rTCPUnix, dyn, tunFwd},
		NewForwarder: func(t *testing.T) (ports.ForwarderPort, ports.TunnelTransport) {
			currentTransport = newMemTunnelTransport()
			fwd := forward.NewForwarder(forward.Config{
				TUNDevice: sim.NewSimTUNDevicePort(),
				LocalDialer: func(_ context.Context, network, addr string) (net.Conn, error) {
					return newEchoPipeConn(network+":"+addr, "LOCAL:"+addr+"|"), nil
				},
			})
			return fwd, currentTransport
		},
		ExerciseHandle: func(ctx context.Context, h ports.ForwardHandle) error {
			return exerciseForwardHandle(ctx, h, currentTransport)
		},
	})
}

func exerciseForwardHandle(ctx context.Context, h ports.ForwardHandle, tr *memTunnelTransport) error {
	if !h.IsValid() {
		return ports.ErrClosed
	}
	sp := h.Spec()
	switch sp.Direction() {
	case ports.ForwardLocal:
		if sp.BindKind() == ports.ForwardEndpointUnix {
			return roundTripUnixForward(ctx, h.BoundAddr(), "ping")
		}
		return roundTripTCPForward(ctx, h.BoundAddr(), "ping")
	case ports.ForwardDynamic:
		return roundTripSOCKS5Domain(ctx, h.BoundAddr(), "zero-dns-leak.invalid", 443, "hello")
	case ports.ForwardRemote:
		return exerciseRemoteReverse(tr)
	case ports.ForwardTUN:
		return nil
	default:
		return ports.ErrInvalidArgument
	}
}

func roundTripTCPForward(ctx context.Context, addr, msg string) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ports.ErrClosed
	}
	defer func() { _ = c.Close() }()
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
	if !bytes.Contains(got, []byte(msg)) {
		return errors.New("TCP 转发回显内容不匹配")
	}
	return nil
}

func roundTripUnixForward(ctx context.Context, nativePath, msg string) error {
	cp, err := osfs.ValidateControlSocketPath(nativePath)
	if err != nil {
		return err
	}
	c, _, err := osfs.DialUnixVerified(ctx, cp)
	if err != nil {
		return ports.ErrClosed
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	_ = c.CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil {
		return err
	}
	if !bytes.Contains(got, []byte(msg)) {
		return errors.New("Unix StreamLocal 转发回显内容不匹配")
	}
	return nil
}

func exerciseRemoteReverse(tr *memTunnelTransport) error {
	tr.mu.Lock()
	ln := tr.remoteLn
	tr.mu.Unlock()
	if ln == nil {
		return ports.ErrClosed
	}
	remoteEnd, peerEnd := net.Pipe()
	if !ln.push(peerEnd) {
		_ = remoteEnd.Close()
		_ = peerEnd.Close()
		return ports.ErrClosed
	}
	defer func() { _ = remoteEnd.Close() }()
	var got []byte
	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			_, wErr := remoteEnd.Write([]byte("rev-ping"))
			return wErr
		}); gErr != nil {
			return gErr
		}
		buf := make([]byte, 64)
		nr, rErr := remoteEnd.Read(buf)
		if rErr != nil {
			return rErr
		}
		got = buf[:nr]
		return remoteEnd.Close()
	})
	if err != nil {
		return err
	}
	if !bytes.Contains(got, []byte("rev-ping")) {
		return errors.New("反向转发回显不匹配")
	}
	return nil
}

func roundTripSOCKS5Domain(ctx context.Context, proxyAddr, domain string, port uint16, msg string) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return ports.ErrClosed
	}
	defer func() { _ = c.Close() }()
	// 握手协商：VER=5, NMETHODS=1, NO_AUTH(0)。
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	var mResp [2]byte
	if _, err := io.ReadFull(c, mResp[:]); err != nil {
		return err
	}
	if mResp != [2]byte{0x05, 0x00} {
		return errors.New("SOCKS5 方法协商失败")
	}
	// 发送 ATYP=DOMAINNAME (0x03) 请求，绝不触发本机 DNS。
	req := make([]byte, 0, 7+len(domain))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(domain)))
	req = append(req, domain...)
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := c.Write(req); err != nil {
		return err
	}
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return err
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		return errors.New("SOCKS5 CONNECT 被拒绝")
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
	wantPrefix := "TCP:" + domain + ":"
	if !bytes.Contains(got, []byte(wantPrefix)) || !bytes.Contains(got, []byte(msg)) {
		return errors.New("SOCKS5 域名未原样透传或数据不匹配")
	}
	return nil
}

func TestForwarder_SOCKS5SecurityAndIllegalBindRejection(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	tr := newMemTunnelTransport()
	fwd := forward.NewForwarder(forward.Config{})

	// 1. 默认 GatewayPorts=false 必须拒绝非回环与通配本地绑定（-L 与 -D）。
	for _, badBind := range []string{"0.0.0.0:0", "[::]:0", ":0", "*:0", "192.0.2.10:0"} {
		spL, _ := ports.NewForwardSpec(ports.ForwardLocal, badBind, "10.0.0.1:80")
		if _, err := fwd.StartForward(ctx, tr, spL); !errors.Is(err, ports.ErrPermissionDenied) {
			t.Fatalf("本地 -L 非回环绑定 %q = %v, 期望 ErrPermissionDenied", badBind, err)
		}
		spD, _ := ports.NewForwardSpec(ports.ForwardDynamic, badBind, "")
		if _, err := fwd.StartForward(ctx, tr, spD); !errors.Is(err, ports.ErrPermissionDenied) {
			t.Fatalf("本地 -D 非回环绑定 %q = %v, 期望 ErrPermissionDenied", badBind, err)
		}
	}

	// 2. 启动合法回环 SOCKS5 并验证拒绝 UDP ASSOCIATE / BIND / 非法 ATYP / 非零 RSV / 端口 0 / 不支持认证。
	dynSpec, _ := ports.NewForwardSpec(ports.ForwardDynamic, "127.0.0.1:0", "")
	h, err := fwd.StartForward(ctx, tr, dynSpec)
	if err != nil {
		t.Fatalf("StartForward(dynamic): %v", err)
	}
	defer func() { _ = h.Close() }()

	// 2a. 域名原样透传（.invalid 永不本机解析，验证 0 DNS 泄露）。
	if err := roundTripSOCKS5Domain(ctx, h.BoundAddr(), "corp-secret.invalid", 8443, "ok"); err != nil {
		t.Fatalf("SOCKS5 域名透传失败: %v", err)
	}

	// 2b. IPv4 与 IPv6 目标。
	verifySOCKS5RawAddr(t, h.BoundAddr(), []byte{0x05, 0x01, 0x00, 0x01, 10, 0, 0, 5, 0x00, 0x50}, 0x00)
	ipv6Req := append([]byte{0x05, 0x01, 0x00, 0x04}, net.ParseIP("2001:db8::1").To16()...)
	ipv6Req = binary.BigEndian.AppendUint16(ipv6Req, 443)
	verifySOCKS5RawAddr(t, h.BoundAddr(), ipv6Req, 0x00)

	// 2c. 拒绝 BIND(0x02) 与 UDP ASSOCIATE(0x03) -> 0x07。
	verifySOCKS5RawAddr(t, h.BoundAddr(), []byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50}, 0x07)
	verifySOCKS5RawAddr(t, h.BoundAddr(), []byte{0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x35}, 0x07)
	// 2d. 拒绝非零 RSV -> 0x01；非法 ATYP(0x09) -> 0x08；端口 0 -> 0x08。
	verifySOCKS5RawAddr(t, h.BoundAddr(), []byte{0x05, 0x01, 0x01, 0x01, 127, 0, 0, 1, 0x00, 0x50}, 0x01)
	verifySOCKS5RawAddr(t, h.BoundAddr(), []byte{0x05, 0x01, 0x00, 0x09, 0x00}, 0x08)
	verifySOCKS5RawAddr(t, h.BoundAddr(), []byte{0x05, 0x01, 0x00, 0x01, 10, 0, 0, 5, 0x00, 0x00}, 0x08)

	// 2e. 拒绝不含 NO_AUTH(0x00) 的认证协商 -> 0x05 0xFF。
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", h.BoundAddr())
	if err != nil {
		t.Fatalf("Dial SOCKS5: %v", err)
	}
	_, _ = c.Write([]byte{0x05, 0x01, 0x02})
	var mRep [2]byte
	if _, err := io.ReadFull(c, mRep[:]); err != nil || mRep != [2]byte{0x05, 0xFF} {
		t.Fatalf("不支持认证响应 = (%x, %v), 期望 05ff", mRep, err)
	}
	_ = c.Close()

	// 3. 未配置 TUNDevice 时 ForwardTUN 失败关闭返回 ErrUnsupported；零值 Forwarder 返回 ErrClosed。
	tunSpec, _ := ports.NewTUNSpec(ports.TUNModeEthernet, 1, 1)
	tunFwd, _ := ports.NewForwardTUNSpec(tunSpec)
	if _, err := fwd.StartForward(ctx, tr, tunFwd); !errors.Is(err, ports.ErrUnsupported) {
		t.Fatalf("无 TUNDevicePort 时期望 ErrUnsupported，实际 %v", err)
	}
	var zeroFwd forward.Forwarder
	if _, err := zeroFwd.StartForward(ctx, tr, dynSpec); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("零值 Forwarder 期望 ErrClosed，实际 %v", err)
	}
}

func verifySOCKS5RawAddr(t *testing.T, proxyAddr string, req []byte, wantRep byte) {
	t.Helper()
	c, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial SOCKS5: %v", err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	var mRep [2]byte
	if _, err := io.ReadFull(c, mRep[:]); err != nil || mRep != [2]byte{0x05, 0x00} {
		t.Fatalf("SOCKS5 方法协商异常: (%x, %v)", mRep, err)
	}
	_, _ = c.Write(req)
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		t.Fatalf("读取 SOCKS5 应答失败: %v", err)
	}
	if rep[0] != 0x05 || rep[1] != wantRep {
		t.Fatalf("SOCKS5 应答码 = %#x, 期望 %#x", rep[1], wantRep)
	}
}

func TestForwarder_StalledSOCKS5ClientClosesInO1(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	tr := newMemTunnelTransport()
	fwd := forward.NewForwarder(forward.Config{SOCKSHandshakeTimeout: 30 * time.Second})
	dynSpec, _ := ports.NewForwardSpec(ports.ForwardDynamic, "127.0.0.1:0", "")
	h, err := fwd.StartForward(ctx, tr, dynSpec)
	if err != nil {
		t.Fatalf("StartForward(dynamic): %v", err)
	}
	slowClient, err := (&net.Dialer{}).DialContext(ctx, "tcp", h.BoundAddr())
	if err != nil {
		_ = h.Close()
		t.Fatalf("Dial SOCKS5: %v", err)
	}
	defer func() { _ = slowClient.Close() }()
	// 仅发送 1 字节后故意停滞，模拟 Slowloris 客户端。
	if _, err := slowClient.Write([]byte{0x05}); err != nil {
		_ = h.Close()
		t.Fatalf("Write partial handshake: %v", err)
	}
	start := time.Now()
	if err := h.Close(); err != nil {
		t.Fatalf("Handle.Close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("存在停滞 SOCKS5 客户端时 Handle.Close() 耗时 %v 过长", elapsed)
	}
}
