package priv_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"regexp"
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
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/keysigner"
	"github.com/wentf9/xops-cli/core/internal/sshnet/hostkey"
	"github.com/wentf9/xops-cli/core/internal/sshnet/priv"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// 编译期接口断言：确保 *priv.Escalator 严格满足 ports.PrivilegeEscalationPort 契约。
var _ ports.PrivilegeEscalationPort = (*priv.Escalator)(nil)

type privSSHStub struct {
	hostSigner     ssh.Signer
	clientSigner   ssh.Signer
	expectedPass   string
	requirePass    bool
	sudoRSStyle    bool
	fullWidthColon bool
	repromptOnFail bool
	echoStdin      bool
	stdoutOutput   string
	hangPrompt     bool

	mu          sync.Mutex
	seenCommand string
}

func newPrivSSHStub(t *testing.T) (*privSSHStub, ports.TransportConn) {
	t.Helper()
	hostSigner, hostPub := mustGenSSHKey(t)
	cliSigner, cliPub := mustGenSSHKey(t)
	stub := &privSSHStub{
		hostSigner:   hostSigner,
		clientSigner: cliSigner,
		stdoutOutput: "uid=0(root)\n",
	}
	conn := dialStubSSH(t, stub, hostPub, cliSigner, cliPub)
	return stub, conn
}

func mustGenSSHKey(t *testing.T) (ssh.Signer, ports.PublicKeyInfo) {
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

func dialStubSSH(t *testing.T, stub *privSSHStub, hostPub ports.PublicKeyInfo, cliSigner ssh.Signer, cliPub ports.PublicKeyInfo) ports.TransportConn {
	t.Helper()
	ctx := context.Background()
	base, _ := pathalg.ParseLocalDir(t.TempDir())
	dir, _ := base.JoinComponent("ssh")
	_ = osfs.NewScopedRootFS().EnsureRoot(dir, 0o700)
	db, err := hostkey.NewKnownHostsDB(hostkey.Config{RootFS: osfs.NewScopedRootFS(), DefaultDir: dir})
	if err != nil {
		t.Fatalf("NewKnownHostsDB: %v", err)
	}
	ep := tck.MustEndpoint(t, "priv.example.test", 22)
	if err := db.RecordHostKey(ctx, ep, hostPub, option.UnsetKnownHostsList()); err != nil {
		t.Fatalf("RecordHostKey: %v", err)
	}
	d, err := dial.NewDialer(dial.Config{
		HostTrust:   db,
		Agent:       &stubAgent{signer: cliSigner, pub: cliPub},
		DialContext: stub.dialLoopback,
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	user, _ := option.ParseUsername("ops")
	auth, _ := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	unset := option.UnsetOptionLayer()
	eff, _ := option.ResolveEffectivePolicy(option.OriginManaged, ep, unset, unset, unset, unset)
	hop, _ := plan.NewHopSpecFromAuth(0, "priv-node", user, auth, eff)
	cp, _ := plan.SealConnectionPlan(hop)
	dig, _ := cp.HopDigestAt(0)
	conn, err := d.DialHop(ctx, hop, dig, nil)
	if err != nil {
		t.Fatalf("DialHop: %v", err)
	}
	return conn
}

// ephemeralPrivOpener 为 TCK 子测试提供按会话隔离的真实回环 SSH SessionOpener，
// 在每次 RemoteSession.Close 时同步关闭底层 TransportConn 与回环服务协程，确保 TCK 内的 defer VerifyNoLeaks 零残留。
type ephemeralPrivOpener struct {
	dialer *dial.Dialer
	hop    plan.HopSpec
	digest plan.HopDigest
}

type ownedPrivSession struct {
	ports.RemoteSession
	conn      ports.TransportConn
	closeOnce sync.Once
}

func (s *ownedPrivSession) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.RemoteSession.Close()
		_ = s.conn.Close()
	})
	return err
}

func (o *ephemeralPrivOpener) OpenSession(ctx context.Context) (ports.RemoteSession, error) {
	conn, err := o.dialer.DialHop(ctx, o.hop, o.digest, nil)
	if err != nil {
		return nil, err
	}
	sess, err := conn.OpenSession(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &ownedPrivSession{RemoteSession: sess, conn: conn}, nil
}

func newEphemeralPrivOpener(t *testing.T) (*privSSHStub, ports.SessionOpener) {
	t.Helper()
	ctx := context.Background()
	hostSigner, hostPub := mustGenSSHKey(t)
	cliSigner, cliPub := mustGenSSHKey(t)
	stub := &privSSHStub{
		hostSigner:   hostSigner,
		clientSigner: cliSigner,
		stdoutOutput: "uid=0(root)\n",
	}
	base, _ := pathalg.ParseLocalDir(t.TempDir())
	dir, _ := base.JoinComponent("ssh")
	_ = osfs.NewScopedRootFS().EnsureRoot(dir, 0o700)
	db, err := hostkey.NewKnownHostsDB(hostkey.Config{RootFS: osfs.NewScopedRootFS(), DefaultDir: dir})
	if err != nil {
		t.Fatalf("NewKnownHostsDB: %v", err)
	}
	ep := tck.MustEndpoint(t, "priv.example.test", 22)
	if err := db.RecordHostKey(ctx, ep, hostPub, option.UnsetKnownHostsList()); err != nil {
		t.Fatalf("RecordHostKey: %v", err)
	}
	d, err := dial.NewDialer(dial.Config{
		HostTrust:   db,
		Agent:       &stubAgent{signer: cliSigner, pub: cliPub},
		DialContext: stub.dialLoopback,
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	user, _ := option.ParseUsername("ops")
	auth, _ := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	unset := option.UnsetOptionLayer()
	eff, _ := option.ResolveEffectivePolicy(option.OriginManaged, ep, unset, unset, unset, unset)
	hop, _ := plan.NewHopSpecFromAuth(0, "priv-node", user, auth, eff)
	cp, _ := plan.SealConnectionPlan(hop)
	dig, _ := cp.HopDigestAt(0)
	return stub, &ephemeralPrivOpener{dialer: d, hop: hop, digest: dig}
}

type stubAgent struct {
	signer ssh.Signer
	pub    ports.PublicKeyInfo
}

func (*stubAgent) DialAgent(context.Context, algebraic.Option[inventory.AgentSpec]) (net.Conn, error) {
	return nil, ports.ErrUnsupported
}
func (a *stubAgent) ListAgentKeys(context.Context, algebraic.Option[inventory.AgentSpec]) ([]ports.PublicKeyInfo, error) {
	return []ports.PublicKeyInfo{a.pub}, nil
}
func (a *stubAgent) SignWithAgent(_ context.Context, _ algebraic.Option[inventory.AgentSpec], _ inventory.KeyFingerprint, algo string, data []byte) (ports.Signature, error) {
	sig, err := a.signer.Sign(rand.Reader, data)
	if err != nil {
		var zero ports.Signature
		return zero, err
	}
	_ = algo
	return ports.NewSignature(sig.Format, sig.Blob)
}

type syncConn struct {
	net.Conn
	done      <-chan struct{}
	nursery   *conc.Nursery
	closeOnce sync.Once
	closeErr  error
}

func (c *syncConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
		<-c.done
		_ = c.nursery.Close()
	})
	return c.closeErr
}

func (s *privSSHStub) dialLoopback(ctx context.Context, _, _ string) (net.Conn, error) {
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
	return &syncConn{Conn: cli, done: done, nursery: n}, nil
}

func (s *privSSHStub) serve(raw net.Conn) {
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

func (s *privSSHStub) handleChan(newCh ssh.NewChannel) {
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

func (s *privSSHStub) handleExec(ch ssh.Channel, cmd string) {
	defer func() { _ = ch.Close() }()
	s.mu.Lock()
	s.seenCommand = cmd
	s.mu.Unlock()

	promptTok := extractBracketToken(cmd, `[xops-priv-prompt-`)
	readyTok := extractBracketToken(cmd, `[xops-priv-ready-`)
	isNonInteractive := strings.Contains(cmd, "sudo -n ") || strings.Contains(cmd, "doas -n")

	if s.hangPrompt {
		_, _ = io.Copy(io.Discard, ch)
		return
	}
	if s.requirePass {
		if isNonInteractive {
			_, _ = ch.Stderr().Write([]byte("sudo: a password is required\n"))
			writeExitStatus(ch, 1)
			return
		}
		if err := s.performAuthPrompt(ch, cmd, promptTok); err != nil {
			writeExitStatus(ch, 1)
			return
		}
	}
	_, _ = ch.Stderr().Write([]byte(readyTok))
	if s.echoStdin {
		data, _ := io.ReadAll(ch)
		_, _ = ch.Write(data)
	} else {
		_, _ = ch.Write([]byte(s.stdoutOutput))
	}
	writeExitStatus(ch, 0)
}

func (s *privSSHStub) performAuthPrompt(ch ssh.Channel, cmd, promptTok string) error {
	s.emitPrompt(ch, cmd, promptTok)
	br := bufio.NewReader(ch)
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	got := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if s.sudoRSStyle {
		_, _ = ch.Stderr().Write([]byte("****\n"))
	}
	if got != s.expectedPass {
		_, _ = ch.Stderr().Write([]byte("Sorry, try again.\n"))
		if s.repromptOnFail {
			s.emitPrompt(ch, cmd, promptTok)
			_, _ = br.ReadString('\n')
		}
		return errors.New("password mismatch")
	}
	return nil
}

func (s *privSSHStub) emitPrompt(ch ssh.Channel, cmd, promptTok string) {
	switch {
	case strings.Contains(cmd, " doas"):
		_, _ = ch.Stderr().Write([]byte("doas (ops@host) password: "))
	case strings.Contains(cmd, " su "):
		_, _ = ch.Stderr().Write([]byte("Password: "))
	case s.sudoRSStyle:
		colon := ": "
		if s.fullWidthColon {
			colon = "\xef\xbc\x9a"
		}
		full := "[sudo: " + promptTok + "] authenticate" + colon
		// 故意按半包切分写入，验证跨 TCP 分片封套解析不丢失字节。
		mid := len(full) / 2
		_, _ = ch.Stderr().Write([]byte(full[:mid]))
		_, _ = ch.Stderr().Write([]byte(full[mid:]))
	default:
		_, _ = ch.Stderr().Write([]byte(promptTok))
	}
}

func extractBracketToken(cmd, prefix string) string {
	re := regexp.MustCompile(regexp.QuoteMeta(prefix) + `[0-9a-f]+\]`)
	return re.FindString(cmd)
}

func writeExitStatus(ch ssh.Channel, code uint32) {
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], code)
	_, _ = ch.SendRequest("exit-status", false, p[:])
}

func TestEscalator_TCKSuite_PasswordAndPasswordless(t *testing.T) {
	defer goleak.VerifyNone(t)
	t.Run("RequirePassword", func(t *testing.T) {
		tck.RunPrivilegeEscalationSuite(t, tck.PrivilegeEscalationFixture{
			NewEscalator: func(st *testing.T) (ports.PrivilegeEscalationPort, ports.SessionOpener) {
				stub, opener := newEphemeralPrivOpener(st)
				stub.requirePass = true
				stub.expectedPass = "s3cr3t-sudo"
				esc, err := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(31)})
				if err != nil {
					st.Fatalf("NewEscalator: %v", err)
				}
				return esc, opener
			},
			CorrectPassword: "s3cr3t-sudo",
			WrongPassword:   "wrong-sudo",
			RequirePassword: true,
		})
	})
	t.Run("Passwordless", func(t *testing.T) {
		tck.RunPrivilegeEscalationSuite(t, tck.PrivilegeEscalationFixture{
			NewEscalator: func(st *testing.T) (ports.PrivilegeEscalationPort, ports.SessionOpener) {
				stub, opener := newEphemeralPrivOpener(st)
				stub.requirePass = false
				esc, err := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(32)})
				if err != nil {
					st.Fatalf("NewEscalator: %v", err)
				}
				return esc, opener
			},
			RequirePassword: false,
		})
	})
}

func TestEscalator_SudoRS_Su_Doas_ScriptAndCombinedSecret(t *testing.T) {
	defer goleak.VerifyNone(t)
	t.Run("SudoRSFragmentedAndFeedback", testSudoRSFragmented)
	t.Run("SuAndDoasAndNonInteractive", testSuDoasNonInteractive)
	t.Run("ScriptStdinIsolatedAfterReady", testScriptIsolation)
	t.Run("CombinedNestedSecretBoxes", testCombinedNestedSecret)
	t.Run("HandshakeTimeoutAndZeroFailClosed", testTimeoutAndZeroEscalator)
}

func testSudoRSFragmented(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	stub, conn := newPrivSSHStub(t)
	defer func() { _ = conn.Close() }()
	stub.requirePass = true
	stub.expectedPass = "rs-pass"
	stub.sudoRSStyle = true
	stub.fullWidthColon = true
	stub.repromptOnFail = true

	esc, _ := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(41)})
	targetU, _ := option.ParseUsername("admin")
	req, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:     ports.PrivilegeMethodSudo,
		Command:    tck.MustCommandPlan(t, "whoami"),
		TargetUser: algebraic.Some(targetU),
	})
	var stdout, stderr bytes.Buffer
	err := secret.WithBytes([]byte("rs-pass"), func(box *secret.SecretBox) error {
		out, rErr := esc.RunPrivileged(ctx, conn, req, box, ports.ExecStreams{Stdout: &stdout, Stderr: &stderr})
		if rErr != nil {
			return rErr
		}
		if comp, ok := out.(*execution.OutcomeCompleted); !ok || !comp.Succeeded() {
			t.Fatalf("期望成功 OutcomeCompleted，实际 %#v", out)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("sudo-rs 提权失败: %v", err)
	}
	if stdout.String() != "uid=0(root)\n" || stderr.Len() != 0 {
		t.Fatalf("sudo-rs 提示帧或掩码回显不应泄露至输出: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	// 错误密码触发重复质询时立即中止并返回 ErrAuthFailed。
	_ = secret.WithBytes([]byte("bad-rs"), func(box *secret.SecretBox) error {
		if _, rErr := esc.RunPrivileged(ctx, conn, req, box, ports.ExecStreams{}); !errors.Is(rErr, ports.ErrAuthFailed) {
			t.Fatalf("重复质询须返回 ErrAuthFailed，实际 %v", rErr)
		}
		return nil
	})
}

func testSuDoasNonInteractive(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	stub, conn := newPrivSSHStub(t)
	defer func() { _ = conn.Close() }()
	stub.requirePass = true
	stub.expectedPass = "alt-pass"
	esc, _ := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(42)})

	for _, method := range []ports.PrivilegeMethod{ports.PrivilegeMethodSu, ports.PrivilegeMethodDoas} {
		req, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
			Method:  method,
			Command: tck.MustCommandPlan(t, "id"),
		})
		var stdout bytes.Buffer
		err := secret.WithBytes([]byte("alt-pass"), func(box *secret.SecretBox) error {
			out, rErr := esc.RunPrivileged(ctx, conn, req, box, ports.ExecStreams{Stdout: &stdout})
			if rErr != nil {
				return rErr
			}
			if comp, ok := out.(*execution.OutcomeCompleted); !ok || !comp.Succeeded() {
				t.Fatalf("method=%s 期望成功，实际 %#v", method, out)
			}
			return nil
		})
		if err != nil || stdout.String() != "uid=0(root)\n" {
			t.Fatalf("method=%s 提权失败: stdout=%q err=%v", method, stdout.String(), err)
		}
	}

	reqNI, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:         ports.PrivilegeMethodDoas,
		Command:        tck.MustCommandPlan(t, "id"),
		NonInteractive: true,
	})
	if _, err := esc.RunPrivileged(ctx, conn, reqNI, nil, ports.ExecStreams{}); !errors.Is(err, ports.ErrAuthFailed) {
		t.Fatalf("NonInteractive doas -n 需要口令时须返回 ErrAuthFailed，实际 %v", err)
	}
}

func testScriptIsolation(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	stub, conn := newPrivSSHStub(t)
	defer func() { _ = conn.Close() }()
	stub.requirePass = true
	stub.expectedPass = "pw-only"
	stub.echoStdin = true
	esc, _ := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(43)})

	prof, _ := execution.POSIXLaunchProfile(execution.InterpreterSH, execution.LoginModeDisabled)
	scriptPlan, _ := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:    execution.PlanKindScript,
		Profile: prof,
		Command: "SCRIPT_PAYLOAD_BODY",
	})
	req, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:  ports.PrivilegeMethodSudo,
		Command: scriptPlan,
	})
	var stdout bytes.Buffer
	err := secret.WithBytes([]byte("pw-only"), func(box *secret.SecretBox) error {
		_, rErr := esc.RunPrivileged(ctx, conn, req, box, ports.ExecStreams{
			Stdin:  strings.NewReader("+USER_STDIN"),
			Stdout: &stdout,
		})
		return rErr
	})
	if err != nil {
		t.Fatalf("脚本提权失败: %v", err)
	}
	if stdout.String() != "SCRIPT_PAYLOAD_BODY+USER_STDIN" {
		t.Fatalf("脚本正文须在就绪帧后无污染投递，实际 %q", stdout.String())
	}
}

func testCombinedNestedSecret(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	stub, conn := newPrivSSHStub(t)
	defer func() { _ = conn.Close() }()
	stub.requirePass = true
	stub.expectedPass = "basePass+654321"
	esc, _ := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(44)})

	req, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:  ports.PrivilegeMethodSudo,
		Command: tck.MustCommandPlan(t, "id"),
	})
	var stdout bytes.Buffer
	err := secret.WithBytes([]byte("basePass"), func(p1 *secret.SecretBox) error {
		return secret.WithBytes([]byte("+654321"), func(p2 *secret.SecretBox) error {
			out, rErr := esc.RunPrivilegedWithCombinedSecret(ctx, conn, req, p1, p2, ports.ExecStreams{Stdout: &stdout})
			if rErr != nil {
				return rErr
			}
			if comp, ok := out.(*execution.OutcomeCompleted); !ok || !comp.Succeeded() {
				t.Fatalf("双因素组合提权期望成功，实际 %#v", out)
			}
			return nil
		})
	})
	if err != nil || stdout.String() != "uid=0(root)\n" {
		t.Fatalf("RunPrivilegedWithCombinedSecret 失败: stdout=%q err=%v", stdout.String(), err)
	}
}

func testTimeoutAndZeroEscalator(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	var zeroEsc priv.Escalator
	req, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:  ports.PrivilegeMethodSudo,
		Command: tck.MustCommandPlan(t, "id"),
	})
	if _, err := zeroEsc.RunPrivileged(ctx, nil, req, nil, ports.ExecStreams{}); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 Escalator 须返回 ErrInvalidArgument，实际 %v", err)
	}
	if _, err := priv.NewEscalator(priv.Config{HandshakeTimeout: -time.Second}); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("负 HandshakeTimeout 须返回 ErrInvalidArgument，实际 %v", err)
	}

	stub, conn := newPrivSSHStub(t)
	defer func() { _ = conn.Close() }()
	stub.hangPrompt = true
	esc, _ := priv.NewEscalator(priv.Config{HandshakeTimeout: 30 * time.Millisecond})
	if _, err := esc.RunPrivileged(ctx, conn, req, nil, ports.ExecStreams{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("握手挂起超时须返回 DeadlineExceeded，实际 %v", err)
	}
}
