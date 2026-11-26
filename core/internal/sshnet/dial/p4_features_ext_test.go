package dial_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/internal/sshnet/hostkey"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// TestDialer_OTPAuthURIsMultiRoundKIAndLoopCap 验证：
//   - otpauth://totp URI（SHA1/SHA256/SHA512、8 位口令、自定义 period、带连字符 Base32）；
//   - 多轮 RFC 4256 质询（含 0 问横幅轮 + 密码轮 + OTP 轮）与超过最大轮次上限的失败关闭拦截。
func TestDialer_OTPAuthURIsMultiRoundKIAndLoopCap(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	clk := sim.NewSimClock(time.Unix(1700000120, 0).UTC())
	vault := sim.NewSimVault(sim.NewSeededRand(105))

	refSHA256 := tck.MustRef(t, "sim", "totp-sha256")
	refSHA512 := tck.MustRef(t, "sim", "totp-sha512")
	refBadURI := tck.MustRef(t, "sim", "totp-bad")
	putSimSecret(t, ctx, vault, refSHA256, "otpauth://totp/XOps:ops?secret=JBSW-Y3DP-EHPK-3PXP%3D&algorithm=SHA256&digits=8&period=60")
	putSimSecret(t, ctx, vault, refSHA512, "otpauth://totp/XOps:ops?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512&digits=6&period=30")
	putSimSecret(t, ctx, vault, refBadURI, "otpauth://hotp/XOps:ops?secret=JBSWY3DPEHPK3PXP")

	want256 := computeExpectedTOTPWith(t, "JBSWY3DPEHPK3PXP", sha256.New, 8, 60, clk.Now())
	want512 := computeExpectedTOTPWith(t, "JBSWY3DPEHPK3PXP", sha512.New, 6, 30, clk.Now())

	srv, srvPub := newLoopbackSSHSpec(t)
	srv.kiRounds = []kiRoundSpec{
		{instruction: "Banner only"},
		{instruction: "Step 1", questions: []string{"SHA256 OTP:"}, echos: []bool{false}, expected: []string{want256}},
		{instruction: "Step 2", questions: []string{"SHA512 OTP:"}, echos: []bool{false}, expected: []string{want512}},
	}
	db, _ := newRealKnownHostsDB(t)
	ep := tck.MustEndpoint(t, "otp-uri.example.test", 22)
	if err := db.RecordHostKey(ctx, ep, srvPub, option.UnsetKnownHostsList()); err != nil {
		t.Fatalf("RecordHostKey: %v", err)
	}

	r256, _ := inventory.NewRuleTOTP(inventory.ChallengeRuleMeta{PromptPattern: "SHA256 OTP"}, refSHA256)
	r512, _ := inventory.NewRuleTOTP(inventory.ChallengeRuleMeta{PromptPattern: "SHA512 OTP"}, refSHA512)
	kiAuth, _ := inventory.NewAuthKeyboardInteractive(algebraic.NewNonEmpty[inventory.ChallengeRule](r256, r512))
	d, err := dial.NewDialer(dial.Config{HostTrust: db, Vault: vault, Clock: clk, DialContext: srv.dialFunc()})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	assertDialSucceeds(t, ctx, d, ep, kiAuth, option.UnsetOptionLayer())

	// 非法 otpauth://hotp URI 必须严格失败关闭。
	rBad, _ := inventory.NewRuleTOTP(inventory.ChallengeRuleMeta{PromptPattern: "SHA256 OTP"}, refBadURI)
	badAuth, _ := inventory.NewAuthKeyboardInteractive(algebraic.NewNonEmpty[inventory.ChallengeRule](rBad))
	hopBad, digBad := mustSingleHopPlan(t, ep, badAuth, option.UnsetOptionLayer())
	if _, err := d.DialHop(ctx, hopBad, digBad, nil); !errors.Is(err, ports.ErrAuthFailed) {
		t.Fatalf("非法 otpauth URI 须返回 ErrAuthFailed，实际 %v", err)
	}

	// 恶意服务端发送超额轮次（20 轮 > 16 轮上限）须失败关闭退出。
	srvLoop, loopPub := newLoopbackSSHSpec(t)
	for range 20 {
		srvLoop.kiRounds = append(srvLoop.kiRounds, kiRoundSpec{instruction: "Loop"})
	}
	epLoop := tck.MustEndpoint(t, "otp-loop.example.test", 22)
	_ = db.RecordHostKey(ctx, epLoop, loopPub, option.UnsetKnownHostsList())
	dLoop, _ := dial.NewDialer(dial.Config{HostTrust: db, Vault: vault, Clock: clk, DialContext: srvLoop.dialFunc()})
	hopLoop, digLoop := mustSingleHopPlan(t, epLoop, kiAuth, option.UnsetOptionLayer())
	if _, err := dLoop.DialHop(ctx, hopLoop, digLoop, nil); !errors.Is(err, ports.ErrAuthFailed) {
		t.Fatalf("超额 KI 轮次须返回 ErrAuthFailed，实际 %v", err)
	}
}

// TestDialer_Wave2HooksRemoteFSAndSSHFPWiring 验证：
//   - TransportConn 面向 P4-T2 暴露的 OpenChannel / OpenWatchedChannel / OpenSubsystem / SendGlobalRequest / WaitDone；
//   - tck.RunDialerSuite 启用 CheckRemoteFS 端到端通过；
//   - Dialer + KnownHostsDB + SSHFPLookupPort 端到端 DNSSEC 放行与冲突拦截。
func TestDialer_Wave2HooksRemoteFSAndSSHFPWiring(t *testing.T) {
	defer goleak.VerifyNone(t)
	t.Run("TCKWithRemoteFSAndHooks", runTCKWithRemoteFS)
	t.Run("TransportConnP4T2Primitives", runTransportConnP4T2Primitives)
	t.Run("EndToEndSSHFPWiring", runEndToEndSSHFPWiring)
}

func runTCKWithRemoteFS(t *testing.T) {
	ctx := context.Background()
	tck.RunDialerSuite(t, tck.DialerFixture{
		NewDialer: func(st *testing.T) ports.DialerPort {
			signer, _, _, pub := generateTestEd25519Key(st, "")
			srv, srvPub := newLoopbackSSHSpec(st)
			srv.authorizedPubs = []ssh.PublicKey{signer.PublicKey()}
			srv.subsystems["sftp"] = true
			db, _ := newRealKnownHostsDB(st)
			ep0 := tck.MustEndpoint(st, "198.51.100.1", 22)
			if err := db.RecordHostKey(ctx, ep0, srvPub, option.UnsetKnownHostsList()); err != nil {
				st.Fatalf("RecordHostKey: %v", err)
			}
			d, err := dial.NewDialer(dial.Config{
				HostTrust:   db,
				Agent:       &testSignerPort{signer: signer, pub: pub},
				DialContext: srv.dialFunc(),
				OpenRemoteFS: func(context.Context, *ssh.Client) (ports.RemoteFSPort, error) {
					return sim.NewSimRemoteFS(sim.NewSimClock(sim.DefaultBaseTime())), nil
				},
			})
			if err != nil {
				st.Fatalf("NewDialer: %v", err)
			}
			return d
		},
		CheckRemoteFS: true,
	})
}

func runTransportConnP4T2Primitives(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	signer, _, _, pub := generateTestEd25519Key(t, "")
	srv, srvPub := newLoopbackSSHSpec(t)
	srv.authorizedPubs = []ssh.PublicKey{signer.PublicKey()}
	srv.subsystems["sftp"] = true
	srv.echoTargets["127.0.0.1:7777"] = true
	db, _ := newRealKnownHostsDB(t)
	ep := tck.MustEndpoint(t, "hooks.example.test", 22)
	_ = db.RecordHostKey(ctx, ep, srvPub, option.UnsetKnownHostsList())
	d, err := dial.NewDialer(dial.Config{
		HostTrust:   db,
		Agent:       &testSignerPort{signer: signer, pub: pub},
		DialContext: srv.dialFunc(),
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	hop, dig := mustSingleHopPlan(t, ep, mustAgentAuth(t), option.UnsetOptionLayer())
	conn, err := d.DialHop(ctx, hop, dig, nil)
	if err != nil {
		t.Fatalf("DialHop: %v", err)
	}
	tc, ok := conn.(*dial.TransportConn)
	if !ok {
		t.Fatalf("期望 *dial.TransportConn，实际 %T", conn)
	}
	subConn, err := tc.OpenSubsystem(ctx, "sftp")
	if err != nil {
		t.Fatalf("OpenSubsystem(sftp): %v", err)
	}
	if _, err := subConn.Write([]byte("sftp-ping")); err != nil {
		t.Fatalf("subConn.Write: %v", err)
	}
	buf := make([]byte, 9)
	if _, err := io.ReadFull(subConn, buf); err != nil || string(buf) != "sftp-ping" {
		t.Fatalf("subConn echo 失配: buf=%q err=%v", string(buf), err)
	}
	_ = subConn.Close()
	if _, err := tc.OpenSubsystem(ctx, "unsupported-sub"); !errors.Is(err, ports.ErrUnsupported) {
		t.Fatalf("未支持子系统须返回 ErrUnsupported，实际 %v", err)
	}
	okReply, _, err := tc.SendGlobalRequest(ctx, "keepalive@openssh.com", true, nil)
	if err != nil || !okReply {
		t.Fatalf("SendGlobalRequest 失败: ok=%v err=%v", okReply, err)
	}
	_ = tc.Close()
	select {
	case <-tc.WaitDone():
	default:
		t.Fatal("Close 后 WaitDone() 必须已关闭")
	}
}

func runEndToEndSSHFPWiring(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	signer, _, _, pub := generateTestEd25519Key(t, "")
	srv, srvPub := newLoopbackSSHSpec(t)
	srv.authorizedPubs = []ssh.PublicKey{signer.PublicKey()}
	base, _ := pathalg.ParseLocalDir(t.TempDir())
	dir, _ := base.JoinComponent("ssh")
	_ = osfs.NewScopedRootFS().EnsureRoot(dir, 0o700)
	sshfp := sim.NewSimSSHFPLookup()
	db, err := hostkey.NewKnownHostsDB(hostkey.Config{
		RootFS:      osfs.NewScopedRootFS(),
		DefaultDir:  dir,
		SSHFPLookup: sshfp,
	})
	if err != nil {
		t.Fatalf("NewKnownHostsDB: %v", err)
	}
	ep := tck.MustEndpoint(t, "dnssec.example.test", 22)
	sum256 := sha256.Sum256(srvPub.WireBlob())
	goodRec, _ := ports.NewSSHFPRecord(ports.SSHFPRecordSpec{Algorithm: 4, FingerprintType: 2, Digest: sum256[:], Authenticated: true})
	sshfp.SetRecords(ep.Host(), goodRec)

	d, err := dial.NewDialer(dial.Config{
		HostTrust:   db,
		Agent:       &testSignerPort{signer: signer, pub: pub},
		DialContext: srv.dialFunc(),
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	layerYesBatch := option.UnsetOptionLayer().WithStrictHostKeyChecking(option.StrictHostKeyCheckingYes).WithBatchMode(true)
	assertDialSucceeds(t, ctx, d, ep, mustAgentAuth(t), layerYesBatch)

	// DNSSEC SSHFP 不匹配时即使 accept-new 也必须阻断建连。
	badSum := sha256.Sum256([]byte("other-host-key"))
	badRec, _ := ports.NewSSHFPRecord(ports.SSHFPRecordSpec{Algorithm: 4, FingerprintType: 2, Digest: badSum[:], Authenticated: true})
	sshfp.SetRecords(ep.Host(), badRec)
	hopAcc, digAcc := mustSingleHopPlan(t, ep, mustAgentAuth(t), option.UnsetOptionLayer().WithStrictHostKeyChecking(option.StrictHostKeyCheckingAcceptNew))
	if _, err := d.DialHop(ctx, hopAcc, digAcc, nil); !errors.Is(err, ports.ErrHostKeyMismatch) {
		t.Fatalf("DNSSEC SSHFP 冲突在 accept-new 下须返回 ErrHostKeyMismatch，实际 %v", err)
	}
}

func computeExpectedTOTPWith(t *testing.T, base32Secret string, hFn func() hash.Hash, digits int, period int64, now time.Time) string {
	t.Helper()
	if hFn == nil {
		hFn = sha1.New
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(base32Secret)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	mac := hmac.New(hFn, key)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(now.Unix()/period))
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	var mod uint64 = 1
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, uint64(bin)%mod)
}
