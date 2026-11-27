package sftp_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/internal/sshnet/sftp"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

func openStubSFTPClient(t *testing.T, opts stubSFTPServerOpts, cfg sftp.Config) (*sftp.Client, *stubSFTPServer) {
	t.Helper()
	srv := newStubSFTPServer(opts)
	cliConn, srvConn := net.Pipe()
	n, err := conc.NewNursery(context.Background())
	if err != nil {
		t.Fatalf("NewNursery: %v", err)
	}
	done := make(chan struct{})
	if err := n.Go(func(context.Context) error {
		defer close(done)
		srv.serve(srvConn)
		return nil
	}); err != nil {
		t.Fatalf("Nursery.Go: %v", err)
	}
	rw := &syncCloseRWC{ReadWriteCloser: cliConn, done: done, nursery: &concNurseryCloser{closeFn: n.Close}}
	client, err := sftp.OpenStream(context.Background(), rw, cfg)
	if err != nil {
		_ = rw.Close()
		t.Fatalf("OpenStream: %v", err)
	}
	return client, srv
}

func TestSFTP_TCKSuite_DevInoAndOpenSSHCompat(t *testing.T) {
	t.Run("WithDevInoAnchor", func(t *testing.T) {
		tck.RunRemoteFSSuite(t, tck.RemoteFSFixture{
			CheckDevInoAnchor: true,
			NewRemoteFS: func(t *testing.T) (ports.RemoteFSPort, pathalg.RemotePath) {
				cli, srv := openStubSFTPClient(t, stubSFTPServerOpts{emitDevIno: true}, sftp.Config{})
				t.Cleanup(func() {
					if srv.sawTruncOpen() {
						t.Errorf("ADR-016 违例：SFTP 客户端不得发送 SSH_FXF_TRUNC 截断打开标志")
					}
					_ = cli.Close()
				})
				return cli, mustParseRemotePath(t, "/work/tck-devino")
			},
		})
	})

	t.Run("StandardOpenSSHNoDevInoAndFallbackRename", func(t *testing.T) {
		tck.RunRemoteFSSuite(t, tck.RemoteFSFixture{
			CheckDevInoAnchor: false,
			NewRemoteFS: func(t *testing.T) (ports.RemoteFSPort, pathalg.RemotePath) {
				cli, srv := openStubSFTPClient(t, stubSFTPServerOpts{
					emitDevIno:     false,
					disablePosix:   true,
					disableHardlnk: true,
					disableLimits:  true,
				}, sftp.Config{MaxPacketSize: 4096})
				t.Cleanup(func() {
					if srv.sawTruncOpen() {
						t.Errorf("ADR-016 违例：回退路径同样不得发送 SSH_FXF_TRUNC")
					}
					_ = cli.Close()
				})
				return cli, mustParseRemotePath(t, "/work/tck-fallback")
			},
		})
	})
}

func buildLoopbackTestDialerAndHop(t *testing.T, ctx context.Context, sftpSrv *stubSFTPServer) (*dial.Dialer, plan.HopSpec, plan.HopDigest) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(host): %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("NewSignerFromKey(host): %v", err)
	}
	hostPubInfo, err := ports.NewPublicKeyInfo(ports.PublicKeyInfoSpec{
		Algorithm:   hostSigner.PublicKey().Type(),
		Fingerprint: mustKeyFP(t, hostSigner.PublicKey()),
		WireBlob:    hostSigner.PublicKey().Marshal(),
	})
	if err != nil {
		t.Fatalf("NewPublicKeyInfo: %v", err)
	}
	ep, _ := netaddr.ParseEndpoint("127.0.0.1:22")
	trust := sim.NewSimHostTrust()
	if err := trust.RecordHostKey(ctx, ep, hostPubInfo, option.UnsetKnownHostsList()); err != nil {
		t.Fatalf("RecordHostKey: %v", err)
	}
	vault := sim.NewSimVault(sim.NewSeededRand(1))
	secretRef, _ := secret.ParseRef("vault/sftp-loopback-pass")
	if err := secret.WithBytes([]byte("secret-pass"), func(box *secret.SecretBox) error {
		return vault.PutAndVerify(ctx, secretRef, box)
	}); err != nil {
		t.Fatalf("vault.PutAndVerify: %v", err)
	}
	d, err := dial.NewDialer(dial.Config{
		HostTrust:    trust,
		Vault:        vault,
		DialContext:  buildSSHLoopbackDialer(t, hostSigner, "secret-pass", sftpSrv),
		OpenRemoteFS: sftp.Open,
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	user, _ := option.ParseUsername("deploy")
	authMethod, _ := inventory.NewAuthPassword(secretRef)
	eff, _ := option.ResolveEffectivePolicy(
		option.OriginManaged, ep,
		option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer(),
	)
	hop, err := plan.NewHopSpecFromAuth(0, "loopback-sftp", user, authMethod, eff)
	if err != nil {
		t.Fatalf("NewHopSpecFromAuth: %v", err)
	}
	sealed, err := plan.SealConnectionPlan(hop)
	if err != nil {
		t.Fatalf("SealConnectionPlan: %v", err)
	}
	dig0, _ := sealed.HopDigestAt(0)
	return d, hop, dig0
}

func TestSFTP_RealSSHLoopbackTCKIntegration(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	sftpSrv := newStubSFTPServer(stubSFTPServerOpts{emitDevIno: true})
	d, hop, dig0 := buildLoopbackTestDialerAndHop(t, ctx, sftpSrv)

	tck.RunRemoteFSSuite(t, tck.RemoteFSFixture{
		CheckDevInoAnchor: true,
		NewRemoteFS: func(t *testing.T) (ports.RemoteFSPort, pathalg.RemotePath) {
			conn, dErr := d.DialHop(ctx, hop, dig0, nil)
			if dErr != nil {
				t.Fatalf("DialHop: %v", dErr)
			}
			rfs, rErr := conn.OpenRemoteFS(ctx)
			if rErr != nil {
				_ = conn.Close()
				t.Fatalf("OpenRemoteFS: %v", rErr)
			}
			// TCK 子测试的 defer VerifyNoLeaks 先于 t.Cleanup 执行，因此将 conn.Close 绑定到 rfs.Close。
			return &closeBothRemoteFS{RemoteFSPort: rfs, closeConn: conn.Close}, mustParseRemotePath(t, "/loopback-ssh-sftp")
		},
	})
}

type closeBothRemoteFS struct {
	ports.RemoteFSPort
	closeConn func() error
	once      sync.Once
	err       error
}

func (c *closeBothRemoteFS) Close() error {
	c.once.Do(func() {
		c.err = errors.Join(c.RemoteFSPort.Close(), c.closeConn())
	})
	return c.err
}

func TestSFTP_GrowingFileReadLinkAndTempCleanup(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	cli, srv := openStubSFTPClient(t, stubSFTPServerOpts{emitDevIno: true, growOnSecondRd: true}, sftp.Config{MaxPacketSize: 4096})
	defer func() { _ = cli.Close() }()

	workDir := mustParseRemotePath(t, "/sec")
	if err := cli.MkdirAll(ctx, workDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	target := mustParseRemotePath(t, "/sec/data.txt")
	ws, _ := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{Perm: 0o600, AtomicRename: true})
	if _, err := cli.WriteFileAtomic(ctx, target, ws, bytes.NewReader(bytes.Repeat([]byte("A"), 5000))); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	lim, _ := ports.NewReadLimits(5010)
	err := cli.WithReadFile(ctx, target, lim, func(r io.Reader, _ int64) error {
		_, rErr := io.ReadAll(r)
		return rErr
	})
	if !errors.Is(err, ports.ErrLimitExceeded) {
		t.Fatalf("增长超限文件读取 = %v, 期望 ErrLimitExceeded", err)
	}
	verifyReadLinkAndCleanup(t, ctx, cli, srv, workDir, target, ws)
}

func verifyReadLinkAndCleanup(t *testing.T, ctx context.Context, cli *sftp.Client, srv *stubSFTPServer, workDir, target pathalg.RemotePath, ws ports.RemoteWriteSpec) {
	t.Helper()
	srv.putSymlink("/sec/link.txt", "/sec/data.txt")
	gotTarget, err := cli.ReadLink(ctx, mustParseRemotePath(t, "/sec/link.txt"))
	if err != nil || gotTarget != "/sec/data.txt" {
		t.Fatalf("ReadLink = (%q, %v)", gotTarget, err)
	}
	if _, err := cli.ReadLink(ctx, target); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("非软链接 ReadLink = %v, 期望 ErrInvalidArgument", err)
	}
	if _, wErr := cli.WriteFileAtomic(ctx, mustParseRemotePath(t, "/sec/aborted.txt"), ws, &errReader{prefix: []byte("partial"), err: errors.New("boom")}); wErr == nil {
		t.Fatal("读错源 WriteFileAtomic 必须失败")
	}
	entries, err := cli.ReadDir(ctx, workDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name().String(), ".xops-tmp-") {
			t.Fatalf("发现未清理临时文件残留: %s", e.Name())
		}
	}
}

func TestSFTP_ZeroGuardsBlackholeAndSymlinkAnchor(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	var zeroCli sftp.Client
	var nilCtx context.Context
	if _, err := zeroCli.Stat(ctx, mustParseRemotePath(t, "/")); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("零值 Client.Stat = %v, 期望 ErrClosed", err)
	}
	if _, err := sftp.OpenStream(nilCtx, nil, sftp.Config{}); !errors.Is(err, ports.ErrNilContext) {
		t.Fatalf("OpenStream(nil ctx) = %v, 期望 ErrNilContext", err)
	}
	if _, err := sftp.OpenStream(ctx, nil, sftp.Config{}); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("OpenStream(nil rw) = %v, 期望 ErrInvalidArgument", err)
	}
	if _, err := sftp.Open(ctx, nil); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("Open(nil conn) = %v, 期望 ErrClosed", err)
	}
	verifyBlackholeCancel(t, ctx)
	verifyBlackholeAfterOpenNoHang(t, ctx)
	verifySymlinkAnchorMismatch(t, ctx)
	verifyMidWriteInodeSwapAnchorMismatch(t, ctx)
}

func verifyBlackholeCancel(t *testing.T, ctx context.Context) {
	t.Helper()
	cli, _ := openStubSFTPClient(t, stubSFTPServerOpts{blackholeAfter: 2, disableLimits: true}, sftp.Config{})
	defer func() { _ = cli.Close() }()
	rootP := mustParseRemotePath(t, "/")
	if _, err := cli.Stat(ctx, rootP); err != nil {
		t.Fatalf("首个 Stat 应成功: %v", err)
	}
	cancelCtx, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer cancel()
	if _, err := cli.Stat(cancelCtx, rootP); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("黑洞对端 RPC 取消 = %v, 期望 context.DeadlineExceeded", err)
	}
}

func verifyBlackholeAfterOpenNoHang(t *testing.T, ctx context.Context) {
	t.Helper()
	// 放行前 4 个请求（MkdirAll 探查/创建 + OPEN），第 5 个请求（FSTAT/READ）进入黑洞，
	// 验证 WithReadFile 及延迟 closeHandle 均在有界时间内解阻返回，零挂死。
	cli, srv := openStubSFTPClient(t, stubSFTPServerOpts{emitDevIno: true, disableLimits: true, blackholeAfter: 2}, sftp.Config{})
	defer func() { _ = cli.Close() }()
	srv.putRegularFile("/bh.txt", []byte("payload"))

	start := time.Now()
	cancelCtx, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer cancel()
	lim, _ := ports.NewReadLimits(1024)
	err := cli.WithReadFile(cancelCtx, mustParseRemotePath(t, "/bh.txt"), lim, func(r io.Reader, _ int64) error {
		_, rErr := io.ReadAll(r)
		return rErr
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("OPEN 后黑洞 WithReadFile = %v, 期望 context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("OPEN 后黑洞释放耗时 %v 过长（defer closeHandle 必须有界解阻）", elapsed)
	}
}

func verifyMidWriteInodeSwapAnchorMismatch(t *testing.T, ctx context.Context) {
	t.Helper()
	cli, srv := openStubSFTPClient(t, stubSFTPServerOpts{emitDevIno: true, swapTargetOnTmp: "/swap/target.txt"}, sftp.Config{})
	defer func() { _ = cli.Close() }()
	if err := cli.MkdirAll(ctx, mustParseRemotePath(t, "/swap"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	srv.putRegularFile("/swap/target.txt", []byte("original"))
	target := mustParseRemotePath(t, "/swap/target.txt")
	st, err := cli.Lstat(ctx, target)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	ws, _ := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{
		Perm: 0o600, ExpectedAnchor: algebraic.Some(st.Anchor()), AtomicRename: true,
	})
	if _, err := cli.WriteFileAtomic(ctx, target, ws, strings.NewReader("new-data")); !errors.Is(err, ports.ErrRemoteAnchorMismatch) {
		t.Fatalf("写入中途目标 inode 被替换时期望 ErrRemoteAnchorMismatch，实际 %v", err)
	}
	// 确认未覆写且无临时文件残留。
	entries, err := cli.ReadDir(ctx, mustParseRemotePath(t, "/swap"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name().String(), ".xops-tmp-") {
			t.Fatalf("锚点冲突回滚后仍残留临时文件: %s", e.Name())
		}
	}
}

func verifySymlinkAnchorMismatch(t *testing.T, ctx context.Context) {
	t.Helper()
	cli, srv := openStubSFTPClient(t, stubSFTPServerOpts{emitDevIno: true}, sftp.Config{})
	defer func() { _ = cli.Close() }()
	if err := cli.MkdirAll(ctx, mustParseRemotePath(t, "/a"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	ws, _ := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{Perm: 0o644, AtomicRename: true})
	st, err := cli.WriteFileAtomic(ctx, mustParseRemotePath(t, "/a/real.txt"), ws, strings.NewReader("real"))
	if err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	srv.putSymlink("/a/evil-link", "/a/real.txt")
	anchoredSpec, _ := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{
		Perm: 0o644, ExpectedAnchor: algebraic.Some(st.Anchor()), AtomicRename: true,
	})
	if _, err := cli.WriteFileAtomic(ctx, mustParseRemotePath(t, "/a/evil-link"), anchoredSpec, strings.NewReader("overwrite")); !errors.Is(err, ports.ErrRemoteAnchorMismatch) {
		t.Fatalf("目标被掉包为软链接时期望 ErrRemoteAnchorMismatch，实际 %v", err)
	}
}

func mustKeyFP(t *testing.T, pub ssh.PublicKey) inventory.KeyFingerprint {
	t.Helper()
	fp, err := inventory.ParseKeyFingerprint(ssh.FingerprintSHA256(pub))
	if err != nil {
		t.Fatalf("ParseKeyFingerprint: %v", err)
	}
	return fp
}

func buildSSHLoopbackDialer(t *testing.T, hostSigner ssh.Signer, pass string, sftpSrv *stubSFTPServer) dial.DialContextFunc {
	t.Helper()
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
			serveLoopbackSFTPSSH(raw, hostSigner, pass, sftpSrv)
			return nil
		}); err != nil {
			_ = ln.Close()
			_ = n.Close()
			return nil, err
		}
		var nd net.Dialer
		cli, dErr := nd.DialContext(ctx, "tcp", ln.Addr().String())
		if dErr != nil {
			_ = ln.Close()
			<-done
			_ = n.Close()
			return nil, dErr
		}
		return &loopbackSyncConn{Conn: cli, done: done, closeNursery: n.Close}, nil
	}
}

type loopbackSyncConn struct {
	net.Conn
	done         <-chan struct{}
	closeNursery func() error
	once         sync.Once
	err          error
}

func (c *loopbackSyncConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		<-c.done
		_ = c.closeNursery()
	})
	return c.err
}

func serveLoopbackSFTPSSH(raw net.Conn, hostSigner ssh.Signer, pass string, sftpSrv *stubSFTPServer) {
	defer func() { _ = raw.Close() }()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if string(p) == pass {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("bad password")
		},
	}
	cfg.AddHostKey(hostSigner)
	sConn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		defer func() { _ = sConn.Close() }()
		_ = n.Go(func(context.Context) error { ssh.DiscardRequests(reqs); return nil })
		for newCh := range chans {
			if newCh.ChannelType() != "session" {
				_ = newCh.Reject(ssh.UnknownChannelType, "only session")
				continue
			}
			ch, chReqs, aErr := newCh.Accept()
			if aErr != nil {
				continue
			}
			_ = n.Go(func(context.Context) error {
				handleSFTPSessionChannel(ch, chReqs, sftpSrv)
				return nil
			})
		}
		return nil
	})
}

func handleSFTPSessionChannel(ch ssh.Channel, reqs <-chan *ssh.Request, sftpSrv *stubSFTPServer) {
	defer func() { _ = ch.Close() }()
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for req := range reqs {
			dispatchSFTPSubsysReq(n, ch, req, sftpSrv)
		}
		return nil
	})
}

func dispatchSFTPSubsysReq(n *conc.Nursery, ch ssh.Channel, req *ssh.Request, sftpSrv *stubSFTPServer) {
	var p struct{ Name string }
	ok := req.Type == "subsystem" && ssh.Unmarshal(req.Payload, &p) == nil && p.Name == "sftp"
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
	if ok {
		_ = n.Go(func(context.Context) error {
			sftpSrv.serve(ch)
			return nil
		})
	}
}

func TestSFTPStatusErrorLocalizableNodeContract(t *testing.T) {
	defer goleak.VerifyNone(t)
	cli, _ := openStubSFTPClient(t, stubSFTPServerOpts{}, sftp.Config{})
	defer func() { _ = cli.Close() }()

	missing, err := pathalg.ParseRemotePath("/definitely-missing-i18n-file")
	if err != nil {
		t.Fatalf("ParseRemotePath 失败: %v", err)
	}
	_, statErr := cli.Stat(context.Background(), missing)
	if !errors.Is(statErr, ports.ErrNotFound) {
		t.Fatalf("Stat 缺失路径期望匹配 ErrNotFound，实际=%v", statErr)
	}
	view, ok := domi18n.InspectNode(statErr)
	if !ok {
		t.Fatalf("sftpStatusError 必须实现 domi18n.LocalizableNode: %v", statErr)
	}
	if view.Message.ID() != domi18n.KeySFTPStatusCode && view.Message.ID() != domi18n.KeySFTPStatusCodeDetail {
		t.Fatalf("sftpStatusError MessageID 异常: %v", view.Message.ID())
	}
	if !errors.Is(view.Sentinel, ports.ErrNotFound) {
		t.Fatalf("sftpStatusError Sentinel 期望 ErrNotFound，实际=%v", view.Sentinel)
	}
	if statErr.Error() != domi18n.CanonicalError(statErr) {
		t.Fatalf("sftpStatusError.Error()=%q 与 CanonicalError=%q 不一致", statErr.Error(), domi18n.CanonicalError(statErr))
	}
}
