package sshfp_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/sys/sshfp"
	"go.uber.org/goleak"
)

// 编译期接口契约断言（ADR-002 / P4-T4）。
var _ ports.SSHFPLookupPort = (*sshfp.SystemLookup)(nil)

type dnsMockResponder func(query []byte, isTCP bool) []byte

type loopbackDNSServer struct {
	addr    string
	pc      net.PacketConn
	tcpLn   net.Listener
	nursery *conc.Nursery
}

func startLoopbackDNSServer(t *testing.T, handler dnsMockResponder) *loopbackDNSServer {
	t.Helper()
	// 先监听 TCP 127.0.0.1:0 获取空闲端口，再在相同端口绑定 UDP，以便客户端通过单一 host:port 执行 UDP->TCP 回退。
	var tcpLn net.Listener
	var pc net.PacketConn
	var err error
	for range 16 {
		tcpLn, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("监听回环 TCP DNS 端口失败: %v", err)
		}
		pc, err = net.ListenPacket("udp", tcpLn.Addr().String())
		if err == nil {
			break
		}
		_ = tcpLn.Close()
	}
	if pc == nil {
		t.Fatalf("绑定同端口回环 UDP DNS 失败: %v", err)
	}
	n, err := conc.NewNursery(context.Background())
	if err != nil {
		_ = pc.Close()
		_ = tcpLn.Close()
		t.Fatalf("NewNursery 失败: %v", err)
	}
	srv := &loopbackDNSServer{
		addr:    tcpLn.Addr().String(),
		pc:      pc,
		tcpLn:   tcpLn,
		nursery: n,
	}
	if err := n.Go(func(context.Context) error { return srv.serveUDP(handler) }); err != nil {
		srv.Close()
		t.Fatalf("启动 UDP DNS 循环失败: %v", err)
	}
	if err := n.Go(func(context.Context) error { return srv.serveTCP(handler) }); err != nil {
		srv.Close()
		t.Fatalf("启动 TCP DNS 循环失败: %v", err)
	}
	return srv
}

func (s *loopbackDNSServer) Close() {
	_ = s.pc.Close()
	_ = s.tcpLn.Close()
	_ = s.nursery.Close()
}

func (s *loopbackDNSServer) serveUDP(handler dnsMockResponder) error {
	buf := make([]byte, 2048)
	for {
		n, peer, err := s.pc.ReadFrom(buf)
		if err != nil {
			return nil
		}
		resp := handler(buf[:n], false)
		if len(resp) > 0 {
			_, _ = s.pc.WriteTo(resp, peer)
		}
	}
}

func (s *loopbackDNSServer) serveTCP(handler dnsMockResponder) error {
	for {
		conn, err := s.tcpLn.Accept()
		if err != nil {
			return nil
		}
		if gErr := s.nursery.Go(func(context.Context) error {
			defer func() { _ = conn.Close() }()
			var lenBuf [2]byte
			if _, rErr := io.ReadFull(conn, lenBuf[:]); rErr != nil {
				return nil
			}
			qLen := int(binary.BigEndian.Uint16(lenBuf[:]))
			q := make([]byte, qLen)
			if _, rErr := io.ReadFull(conn, q); rErr != nil {
				return nil
			}
			resp := handler(q, true)
			if len(resp) == 0 {
				return nil
			}
			frame := make([]byte, 2+len(resp))
			binary.BigEndian.PutUint16(frame[:2], uint16(len(resp)))
			copy(frame[2:], resp)
			_, _ = conn.Write(frame)
			return nil
		}); gErr != nil {
			_ = conn.Close()
		}
	}
}

func buildTestWireName(name string) []byte {
	var out []byte
	for _, lbl := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		out = append(out, byte(len(lbl)))
		out = append(out, lbl...)
	}
	return append(out, 0x00)
}

func buildTestDNSResponse(txid uint16, flags uint16, qname string, answers [][]byte) []byte {
	qWire := buildTestWireName(qname)
	var out []byte
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], txid)
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	binary.BigEndian.PutUint16(hdr[6:8], uint16(len(answers)))
	out = append(out, hdr[:]...)
	out = append(out, qWire...)
	out = binary.BigEndian.AppendUint16(out, 44) // SSHFP
	out = binary.BigEndian.AppendUint16(out, 1)  // IN
	for _, a := range answers {
		out = append(out, a...)
	}
	return out
}

func buildTestRR(owner string, rtype uint16, rdata []byte) []byte {
	out := buildTestWireName(owner)
	out = binary.BigEndian.AppendUint16(out, rtype)
	out = binary.BigEndian.AppendUint16(out, 1) // IN
	out = binary.BigEndian.AppendUint32(out, 300)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
	return append(out, rdata...)
}

func buildSSHFPRData(algo, fpType byte, digest []byte) []byte {
	out := make([]byte, 2+len(digest))
	out[0], out[1] = algo, fpType
	copy(out[2:], digest)
	return out
}

// TestTCKSSHFPLookup 验证 SystemLookup 对回环 DNS 桩完整通过 core/ports/tck.RunSSHFPLookupSuite，
// 并验证 TrustAD 失败关闭（AD=1 但 TrustAD=false 恒返回 Authenticated()==false）。
func TestTCKSSHFPLookup(t *testing.T) {
	defer goleak.VerifyNone(t)
	digest := sha256.Sum256([]byte("xops-tck-hostkey-ed25519"))
	srv := startLoopbackDNSServer(t, func(query []byte, _ bool) []byte {
		txid := binary.BigEndian.Uint16(query[0:2])
		ans := buildTestRR("node1.example.test", 44, buildSSHFPRData(4, 2, digest[:]))
		// QR(0x8000) | RD(0x0100) | RA(0x0080) | AD(0x0020)
		return buildTestDNSResponse(txid, 0x81a0, "node1.example.test", [][]byte{ans})
	})
	defer srv.Close()

	host, err := netaddr.ParseCanonicalHost("node1.example.test")
	if err != nil {
		t.Fatalf("ParseCanonicalHost 失败: %v", err)
	}
	tck.RunSSHFPLookupSuite(t, tck.SSHFPLookupFixture{
		NewLookup: func(t *testing.T) ports.SSHFPLookupPort {
			t.Helper()
			lp, lErr := sshfp.NewSystemLookup(sshfp.Spec{
				Servers: []string{srv.addr},
				TrustAD: true,
				Entropy: tck.NewDeterministicEntropy(11),
			})
			if lErr != nil {
				t.Fatalf("NewSystemLookup 失败: %v", lErr)
			}
			return lp
		},
		KnownHost: host,
		MinCount:  1,
	})

	// 验证 AD=1 在 TrustAD=true vs TrustAD=false 下的失败关闭区分。
	trustedLP, _ := sshfp.NewSystemLookup(sshfp.Spec{Servers: []string{srv.addr}, TrustAD: true})
	untrustedLP, _ := sshfp.NewSystemLookup(sshfp.Spec{Servers: []string{srv.addr}, TrustAD: false})
	recsT, err := trustedLP.LookupSSHFP(context.Background(), host)
	if err != nil || len(recsT) != 1 || !recsT[0].Authenticated() || !bytes.Equal(recsT[0].Digest(), digest[:]) {
		t.Fatalf("TrustAD=true 结果异常: recs=%v err=%v", recsT, err)
	}
	recsU, err := untrustedLP.LookupSSHFP(context.Background(), host)
	if err != nil || len(recsU) != 1 || recsU[0].Authenticated() {
		t.Fatalf("TrustAD=false 必须失败关闭 Authenticated()=false: recs=%v err=%v", recsU, err)
	}
}

// TestSSHFPLookupTCPFallbackAndCNAME 验证 UDP TC=1 自动 TCP 回退与 CNAME 链跟随。
func TestSSHFPLookupTCPFallbackAndCNAME(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	digest := sha256.Sum256([]byte("xops-cname-target-key"))
	var tcpHit bool
	srv := startLoopbackDNSServer(t, func(query []byte, isTCP bool) []byte {
		txid := binary.BigEndian.Uint16(query[0:2])
		if !isTCP {
			// QR(0x8000) | TC(0x0200) | RD(0x0100)
			return buildTestDNSResponse(txid, 0x8300, "alias.example.test", nil)
		}
		tcpHit = true
		cname := buildTestRR("alias.example.test", 5, buildTestWireName("target.example.test"))
		sshfpRR := buildTestRR("target.example.test", 44, buildSSHFPRData(4, 2, digest[:]))
		return buildTestDNSResponse(txid, 0x8180, "alias.example.test", [][]byte{cname, sshfpRR})
	})
	defer srv.Close()

	lp, err := sshfp.NewSystemLookup(sshfp.Spec{Servers: []string{srv.addr}, TrustAD: true})
	if err != nil {
		t.Fatalf("NewSystemLookup 失败: %v", err)
	}
	h, _ := netaddr.ParseCanonicalHost("alias.example.test")
	recs, err := lp.LookupSSHFP(ctx, h)
	if err != nil || !tcpHit || len(recs) != 1 || !bytes.Equal(recs[0].Digest(), digest[:]) {
		t.Fatalf("TCP 回退 + CNAME 查询异常: tcpHit=%v recs=%v err=%v", tcpHit, recs, err)
	}
}

// TestSSHFPLookupNXDOMAINIPLiteralAndResolvConf 验证 NXDOMAIN、IP 字面量空操作、零值失败关闭与 resolv.conf 解析。
func TestSSHFPLookupNXDOMAINIPLiteralAndResolvConf(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	srv := startLoopbackDNSServer(t, func(query []byte, _ bool) []byte {
		txid := binary.BigEndian.Uint16(query[0:2])
		// NXDOMAIN (RCODE=3)
		return buildTestDNSResponse(txid, 0x8183, "missing.example.test", nil)
	})
	defer srv.Close()

	lp, err := sshfp.NewSystemLookup(sshfp.Spec{Servers: []string{srv.addr}})
	if err != nil {
		t.Fatalf("NewSystemLookup 失败: %v", err)
	}
	missingHost, _ := netaddr.ParseCanonicalHost("missing.example.test")
	if _, err := lp.LookupSSHFP(ctx, missingHost); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("NXDOMAIN 期望 ports.ErrNotFound，实际得到: %v", err)
	}
	ipHost, _ := netaddr.ParseCanonicalHost("127.0.0.1")
	if recs, err := lp.LookupSSHFP(ctx, ipHost); err != nil || len(recs) != 0 {
		t.Fatalf("IP 字面量应返回 (nil, nil)，实际得到 (%v, %v)", recs, err)
	}
	var zero sshfp.SystemLookup
	if _, err := zero.LookupSSHFP(ctx, missingHost); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 LookupSSHFP 期望 ErrInvalidArgument，实际得到: %v", err)
	}

	raw := []byte("# comment\nnameserver 127.0.0.53\nnameserver ::1\nnameserver 127.0.0.53\nnameserver 192.0.2.1\nnameserver 192.0.2.2\noptions edns0 trust-ad\n")
	srvs, trustAD := sshfp.ParseResolvConf(raw)
	if !trustAD || len(srvs) != 3 || srvs[0] != "127.0.0.53:53" || srvs[1] != "[::1]:53" || srvs[2] != "192.0.2.1:53" {
		t.Fatalf("ParseResolvConf 结果异常: srvs=%v trustAD=%v", srvs, trustAD)
	}
}

// TestSSHFPLookup_QuestionMismatchCNAMEOverflowAndCancel 回归验证：
// 1. RFC 5452 Question 不匹配的 NXDOMAIN 拒绝为 ErrCorruptData；
// 2. 超过 8 跳的 CNAME 链拒绝为 ErrCorruptData；
// 3. 无响应服务器在 ctx 取消时立即返回 context.Canceled（无需等待整段 perTryTimeout）。
func TestSSHFPLookup_QuestionMismatchCNAMEOverflowAndCancel(t *testing.T) {
	defer goleak.VerifyNone(t)

	t.Run("QuestionMismatchRejected", func(t *testing.T) {
		srv := startLoopbackDNSServer(t, func(query []byte, _ bool) []byte {
			txid := binary.BigEndian.Uint16(query[0:2])
			return buildTestDNSResponse(txid, 0x8183, "other.example.test", nil)
		})
		defer srv.Close()
		lp, _ := sshfp.NewSystemLookup(sshfp.Spec{Servers: []string{srv.addr}})
		h, _ := netaddr.ParseCanonicalHost("wanted.example.test")
		if _, err := lp.LookupSSHFP(context.Background(), h); !errors.Is(err, ports.ErrCorruptData) {
			t.Fatalf("Question 不匹配应返回 ErrCorruptData，实际得到: %v", err)
		}
	})

	t.Run("CNAMEChainOverflowRejected", func(t *testing.T) {
		srv := startLoopbackDNSServer(t, func(query []byte, _ bool) []byte {
			txid := binary.BigEndian.Uint16(query[0:2])
			var ans [][]byte
			for i := range 9 {
				src := "h" + strconv.Itoa(i) + ".example.test"
				dst := "h" + strconv.Itoa(i+1) + ".example.test"
				ans = append(ans, buildTestRR(src, 5, buildTestWireName(dst)))
			}
			return buildTestDNSResponse(txid, 0x8180, "h0.example.test", ans)
		})
		defer srv.Close()
		lp, _ := sshfp.NewSystemLookup(sshfp.Spec{Servers: []string{srv.addr}})
		h, _ := netaddr.ParseCanonicalHost("h0.example.test")
		if _, err := lp.LookupSSHFP(context.Background(), h); !errors.Is(err, ports.ErrCorruptData) {
			t.Fatalf("超长 CNAME 链应返回 ErrCorruptData，实际得到: %v", err)
		}
	})

	t.Run("ContextCancelInterruptsBlackhole", func(t *testing.T) {
		srv := startLoopbackDNSServer(t, func([]byte, bool) []byte { return nil })
		defer srv.Close()
		lp, _ := sshfp.NewSystemLookup(sshfp.Spec{
			Servers:       []string{srv.addr},
			PerTryTimeout: algebraic.Some(algebraic.FromStdDuration(5 * time.Second)),
		})
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
		defer cancel()
		h, _ := netaddr.ParseCanonicalHost("hang.example.test")
		start := time.Now()
		_, err := lp.LookupSSHFP(ctx, h)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("黑洞服务器超时取消期望 context.DeadlineExceeded，实际得到: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("ctx 取消未立即中断阻塞连接: elapsed=%v", elapsed)
		}
	})
}
