package session_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/internal/sim"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	"github.com/wentf9/xops-cli/core/ports"
)

// 编译期端口契约断言：确认 P3-T2 依赖的冻结出站端口与测试桩均严格实现接口契约。
var (
	_ ports.PrivilegeEscalationPort = (*sim.SimPrivilegeEscalator)(nil)
	_ ports.ShellProbePort          = (*sim.SimShellProbe)(nil)
	_ ports.ForwarderPort           = (*sim.SimForwarder)(nil)
	_ ports.TUNDevicePort           = (*sim.SimTUNDevicePort)(nil)
	_ ports.MuxSocketPort           = (*sim.SimMuxSocket)(nil)
	_ ports.ShellProbePort          = (*corruptShellProbeStub)(nil)
)

// fullSessionRig 聚合基于纯内存 sim 端口的完整 P3-T2 会话服务夹具（0 真实 OS / 网络 / 睡眠）。
type fullSessionRig struct {
	clk         *sim.SimClock
	rng         *sim.SeededRand
	cluster     *sim.SimAuditCluster
	bus         *events.SystemBus
	dialer      *sim.SimDialer
	pool        *pool.Pool
	gate        *gate.Gate
	env         *sim.SimEnvPort
	term        *sim.SimTerminalPort
	escalator   *sim.SimPrivilegeEscalator
	vault       *sim.SimVault
	interaction *sim.SimInteractionPort
	shellProbe  *sim.SimShellProbe
	forwarder   *sim.SimForwarder
	tunDevice   *sim.SimTUNDevicePort
	muxSocket   *sim.SimMuxSocket
	svc         *ucsess.Service
}

type fullRigOptions struct {
	profile           gate.PolicyProfileKind
	approvalThreshold security.RiskLevel
	noElicitFallback  gate.NoElicitFallback
	protectedPatterns []string
	interactive       bool
	disableEnv        bool
	customDialer      ports.DialerPort
	customAuditSink   func(ports.AuditSink) ports.AuditSink
	customInteraction ports.InteractionPort
	customProbe       ports.ShellProbePort
	customMux         ports.MuxSocketPort
	customTUN         ports.TUNDevicePort
	disableTUN        bool
}

func newFullSessionRig(t *testing.T, opt fullRigOptions) *fullSessionRig {
	t.Helper()
	if !opt.profile.IsValid() {
		opt.profile = gate.PolicyProfileDirectOperator
	}
	if !opt.approvalThreshold.IsValid() {
		opt.approvalThreshold = security.RiskDangerous
	}
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	rng := sim.NewSeededRand(3022)
	cluster := sim.NewSimAuditCluster()
	var sink ports.AuditSink
	baseSink, err := cluster.NewSinkFromEntropy(rng)
	if err != nil {
		t.Fatalf("NewSinkFromEntropy: %v", err)
	}
	sink = baseSink
	if opt.customAuditSink != nil {
		sink = opt.customAuditSink(baseSink)
	}
	bus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: 32})
	if err != nil {
		t.Fatalf("NewSystemBus: %v", err)
	}
	simDial := sim.NewSimDialer(clk, rng.Fork())
	var dialerPort ports.DialerPort = simDial
	if opt.customDialer != nil {
		dialerPort = opt.customDialer
	}
	p, err := pool.NewPool(context.Background(), pool.PoolConfig{Dialer: dialerPort, Clock: clk, Entropy: rng.Fork(), Bus: bus})
	if err != nil {
		bus.Close()
		t.Fatalf("NewPool: %v", err)
	}
	pol, err := gate.NewGuardrailPolicyFromPatterns(opt.approvalThreshold, opt.noElicitFallback, opt.protectedPatterns)
	if err != nil {
		_ = p.Close()
		bus.Close()
		t.Fatalf("NewGuardrailPolicyFromPatterns: %v", err)
	}
	g, err := gate.NewGate(gate.GateConfig{
		Profile: opt.profile, Policy: pol, AuditSink: sink, Reconciler: cluster,
		Clock: clk, Entropy: rng.Fork(), SystemBus: bus,
		OnHalt: func(info gate.HaltInfo) { p.GateHalted(info.Cause()) },
	})
	if err != nil {
		_ = p.Close()
		bus.Close()
		t.Fatalf("NewGate: %v", err)
	}
	id, err := ports.NewLocalIdentityInfo(ports.LocalIdentityInfoSpec{LocalHost: "workstation", LocalUser: "alice", LocalUID: "1001", HomeDir: "/home/alice"})
	if err != nil {
		t.Fatalf("NewLocalIdentityInfo: %v", err)
	}
	var zeroProbeRes ports.ShellProbeResult
	rig := &fullSessionRig{
		clk: clk, rng: rng, cluster: cluster, bus: bus, dialer: simDial, pool: p, gate: g,
		env:         sim.NewSimEnvPort(map[string]string{"LANG": "en_US.UTF-8", "TERM": "xterm-256color"}, id),
		term:        sim.NewSimTerminalPort(opt.interactive, 100, 30),
		escalator:   sim.NewSimPrivilegeEscalator(),
		vault:       sim.NewSimVault(rng.Fork()),
		interaction: sim.NewSimInteractionPort(opt.interactive),
		shellProbe:  sim.NewSimShellProbe(zeroProbeRes),
		forwarder:   sim.NewSimForwarder(),
		tunDevice:   sim.NewSimTUNDevicePort(),
		muxSocket:   sim.NewSimMuxSocket(simDial),
	}
	svc, err := ucsess.NewService(buildRigServiceConfig(rig, opt))
	if err != nil {
		_ = p.Close()
		bus.Close()
		t.Fatalf("NewService: %v", err)
	}
	rig.svc = svc
	return rig
}

func buildRigServiceConfig(r *fullSessionRig, opt fullRigOptions) ucsess.ServiceConfig {
	cfg := ucsess.ServiceConfig{
		Gate: r.gate, Pool: r.pool, Clock: r.clk, Env: r.env, Terminal: r.term,
		Escalator: r.escalator, Vault: r.vault, Interaction: r.interaction,
		ShellProbe: r.shellProbe, Forwarder: r.forwarder, TUNDevice: r.tunDevice, MuxSocket: r.muxSocket,
	}
	if opt.disableEnv {
		cfg.Env = nil
	}
	if opt.customInteraction != nil {
		cfg.Interaction = opt.customInteraction
	}
	if opt.customProbe != nil {
		cfg.ShellProbe = opt.customProbe
	}
	if opt.disableTUN {
		cfg.TUNDevice = nil
	} else if opt.customTUN != nil {
		cfg.TUNDevice = opt.customTUN
	}
	if opt.customMux != nil {
		cfg.MuxSocket = opt.customMux
	}
	return cfg
}

func (r *fullSessionRig) close() {
	if r == nil {
		return
	}
	_ = r.pool.Close()
	r.bus.Close()
}

func mustPutVaultSecret(t *testing.T, v *sim.SimVault, rawRef string, plain []byte) secret.Ref {
	t.Helper()
	ref, err := secret.ParseRef(rawRef)
	if err != nil {
		t.Fatalf("ParseRef(%q): %v", rawRef, err)
	}
	if err := secret.WithBytes(plain, func(box *secret.SecretBox) error {
		return v.PutAndVerify(context.Background(), ref, box)
	}); err != nil {
		t.Fatalf("PutAndVerify: %v", err)
	}
	return ref
}

func mustPrivilegeReq(t *testing.T, method ports.PrivilegeMethod, cmdStr string, targetUser string, nonInteractive bool) ports.PrivilegeRequest {
	t.Helper()
	var tu algebraic.Option[option.Username]
	if targetUser != "" {
		u, err := option.ParseUsername(targetUser)
		if err != nil {
			t.Fatalf("ParseUsername: %v", err)
		}
		tu = algebraic.Some(u)
	}
	req, err := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method: method, Command: mustCommandPlan(t, cmdStr), TargetUser: tu, NonInteractive: nonInteractive,
	})
	if err != nil {
		t.Fatalf("NewPrivilegeRequest: %v", err)
	}
	return req
}

func mustApproveChallenge(t *testing.T, err error) gate.ApprovalSubmission {
	t.Helper()
	var chErr *gate.ApprovalChallengeError
	if !errors.As(err, &chErr) {
		t.Fatalf("期望 ApprovalChallengeError，实际=%v", err)
	}
	env := chErr.Envelope()
	dig, dErr := env.Digest()
	if dErr != nil {
		t.Fatalf("Envelope.Digest: %v", dErr)
	}
	resp, rErr := ports.NewApprovalDecisionResponse(security.VerdictAllow, dig, "approved in test")
	if rErr != nil {
		t.Fatalf("NewApprovalDecisionResponse: %v", rErr)
	}
	sub, sErr := gate.NewApprovalSubmission(gate.ApprovalSubmissionSpec{Envelope: algebraic.Some(env), Response: resp})
	if sErr != nil {
		t.Fatalf("NewApprovalSubmission: %v", sErr)
	}
	return sub
}

func TestSessionExecPrivileged_MethodsVaultAndInteractivePassword(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newFullSessionRig(t, fullRigOptions{profile: gate.PolicyProfileDirectOperator, interactive: true})
	defer rig.close()
	pl := mustTestPlan(t, "LANG")
	rig.dialer.SetDefaultProfile(sim.HopFaultProfile{SessionOutput: "root-ok\n"})
	rig.escalator.SetRequiredPassword([]byte("s3cr3t-pass"))
	goodRef := mustPutVaultSecret(t, rig.vault, "vault/sudo-web01", []byte("s3cr3t-pass"))
	badRef := mustPutVaultSecret(t, rig.vault, "vault/sudo-wrong", []byte("wrong-pass"))

	// 1. sudo + Vault 借用口令成功并输出 OperationStream EOF。
	var outBuf bytes.Buffer
	stream := mustTestOperationStream(t, rig.rng)
	out, err := rig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: mustPrivilegeReq(t, ports.PrivilegeMethodSudo, "id", "root", false),
		PasswordRef: algebraic.Some(goodRef), Stdout: &outBuf, OperationStream: stream,
	})
	if err != nil {
		t.Fatalf("ExecPrivileged(sudo+vault): %v", err)
	}
	assertSucceededOutcome(t, out)
	if outBuf.String() != "root-ok\n" {
		t.Fatalf("提权输出失配: got=%q", outBuf.String())
	}
	assertStreamHasCompletedEvent(t, stream, true)

	// 2. 错误口令 / 缺失凭据 / 锁定 Vault 均须归类为启动前失败且不降级。
	out, err = rig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: mustPrivilegeReq(t, ports.PrivilegeMethodSudo, "id", "", false),
		PasswordRef: algebraic.Some(badRef),
	})
	if !errors.Is(err, ports.ErrAuthFailed) || out.Kind() != execution.OutcomeKindNotStarted {
		t.Fatalf("错误口令期望 ErrAuthFailed + NotStarted，实际 out=%#v err=%v", out, err)
	}
	missingRef, err := secret.ParseRef("vault/sudo-missing")
	if err != nil {
		t.Fatalf("ParseRef(missing): %v", err)
	}
	if _, err := rig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: mustPrivilegeReq(t, ports.PrivilegeMethodSudo, "id", "", false),
		PasswordRef: algebraic.Some(missingRef),
	}); !errors.Is(err, ports.ErrSecretNotFound) {
		t.Fatalf("缺失凭据期望 ErrSecretNotFound，实际=%v", err)
	}
	if err := rig.vault.Lock(context.Background()); err != nil {
		t.Fatalf("vault.Lock: %v", err)
	}
	if _, err := rig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: mustPrivilegeReq(t, ports.PrivilegeMethodSudo, "id", "", false),
		PasswordRef: algebraic.Some(goodRef),
	}); !errors.Is(err, ports.ErrVaultLocked) {
		t.Fatalf("锁定凭据库期望 ErrVaultLocked，实际=%v", err)
	}

	// 3. su + 交互式 PromptPassword 成功；doas + NonInteractive 跳过口令借用。
	rig.interaction.SetReplies("", []byte("s3cr3t-pass"))
	out, err = rig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: mustPrivilegeReq(t, ports.PrivilegeMethodSu, "whoami", "postgres", false),
		PromptPassword: true,
	})
	if err != nil {
		t.Fatalf("ExecPrivileged(su+prompt): %v", err)
	}
	assertSucceededOutcome(t, out)

	rig.escalator.SetRequiredPassword(nil)
	out, err = rig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: mustPrivilegeReq(t, ports.PrivilegeMethodDoas, "uname", "", true),
		PasswordRef: algebraic.Some(goodRef), // NonInteractive 必须不读取已锁定 Vault
	})
	if err != nil {
		t.Fatalf("ExecPrivileged(doas+noninteractive): %v", err)
	}
	assertSucceededOutcome(t, out)

	assertPrivilegeConflictRejections(t, rig, pl, goodRef)
}

func assertPrivilegeConflictRejections(t *testing.T, rig *fullSessionRig, pl plan.SealedConnectionPlan, goodRef secret.Ref) {
	t.Helper()
	if _, err := rig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: mustPrivilegeReq(t, ports.PrivilegeMethodSudo, "id", "", false),
		PasswordRef: algebraic.Some(goodRef), PromptPassword: true,
	}); !errors.Is(err, ucsess.ErrInvalidRequest) {
		t.Fatalf("PasswordRef+PromptPassword 期望 ErrInvalidRequest，实际=%v", err)
	}
	if _, err := rig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: mustPrivilegeReq(t, ports.PrivilegeMethodSudo, "id", "", true), PromptPassword: true,
	}); !errors.Is(err, ucsess.ErrInvalidRequest) {
		t.Fatalf("NonInteractive+PromptPassword 期望 ErrInvalidRequest，实际=%v", err)
	}
	shProf, err := execution.NewLaunchProfile(execution.LaunchProfileSpec{
		Dialect: algebraic.Some(execution.DialectPOSIX), Interpreter: execution.InterpreterSH, Login: execution.LoginModeInherit,
	})
	if err != nil {
		t.Fatalf("NewLaunchProfile: %v", err)
	}
	scriptPlan, err := execution.NewCommandPlan(execution.CommandPlanSpec{Kind: execution.PlanKindScript, Profile: shProf, Command: "echo hi\n"})
	if err != nil {
		t.Fatalf("NewCommandPlan(script): %v", err)
	}
	scriptPriv, err := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{Method: ports.PrivilegeMethodSudo, Command: scriptPlan})
	if err != nil {
		t.Fatalf("NewPrivilegeRequest(script): %v", err)
	}
	if _, err := rig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: scriptPriv, RequestTTY: ucsess.RequestTTYForce,
	}); !errors.Is(err, ucsess.ErrInvalidRequest) {
		t.Fatalf("提权脚本+TTYForce 期望 ErrInvalidRequest，实际=%v", err)
	}
}

func TestSessionExecPrivileged_GuardrailApprovalAndCanonicalScopeEscalated(t *testing.T) {
	defer goleak.VerifyNone(t)
	// 1. StrictAgent 下提权恒满足 RiskDangerous 下限：未审批绝不拨号，提交审批回执后放行。
	strictRig := newFullSessionRig(t, fullRigOptions{
		profile: gate.PolicyProfileStrictAgent, approvalThreshold: security.RiskDangerous, noElicitFallback: gate.NoElicitFallbackChallenge,
	})
	defer strictRig.close()
	pl := mustTestPlan(t, "")
	privReq := mustPrivilegeReq(t, ports.PrivilegeMethodSudo, "systemctl restart nginx", "root", true)

	out, err := strictRig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: privReq, Risk: algebraic.Some(security.RiskSafe), // 企图降风险，必须被 RiskDangerous 下限覆盖
	})
	if out.Kind() != execution.OutcomeKindNotStarted || strictRig.dialer.DialCount() != 0 {
		t.Fatalf("StrictAgent 未审批禁止拨号: out=%#v dials=%d err=%v", out, strictRig.dialer.DialCount(), err)
	}
	sub := mustApproveChallenge(t, err)
	out, err = strictRig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: privReq, Risk: algebraic.Some(security.RiskSafe), Approval: algebraic.Some(sub),
	})
	if err != nil {
		t.Fatalf("两步审批后 ExecPrivileged 失败: %v", err)
	}
	assertSucceededOutcome(t, out)

	// 2. DirectOperator 下显式 LexicalScope：身份漂移直接拒绝（0 拨号），词法升级触发强制审批挑战。
	directRig := newFullSessionRig(t, fullRigOptions{profile: gate.PolicyProfileDirectOperator, noElicitFallback: gate.NoElicitFallbackChallenge})
	defer directRig.close()
	targetHop, _ := pl.Target()
	driftLex, err := security.NewScopeSnapshot(security.ScopeSnapshotSpec{
		Capability: security.CapabilityExecute, TargetNode: "other-node", Endpoint: algebraic.Some(targetHop.Endpoint()),
		Verdict: security.VerdictAllow, Risk: security.RiskModerate, Decision: security.NewDecisionAllow("lexical"),
	})
	if err != nil {
		t.Fatalf("NewScopeSnapshot(drift): %v", err)
	}
	if _, err := directRig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: privReq, LexicalScope: algebraic.Some(driftLex),
	}); !errors.Is(err, ucsess.ErrEscalationScopeChanged) || directRig.dialer.DialCount() != 0 {
		t.Fatalf("身份漂移期望 ErrEscalationScopeChanged 且 0 拨号，实际 err=%v dials=%d", err, directRig.dialer.DialCount())
	}

	unprivLex, err := security.NewScopeSnapshot(security.ScopeSnapshotSpec{
		Capability: security.CapabilityExecute, TargetNode: targetHop.NodeID(), Endpoint: algebraic.Some(targetHop.Endpoint()),
		Verdict: security.VerdictAllow, Risk: security.RiskModerate, Decision: security.NewDecisionAllow("lexical"),
	})
	if err != nil {
		t.Fatalf("NewScopeSnapshot(unpriv): %v", err)
	}
	_, err = directRig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: privReq, LexicalScope: algebraic.Some(unprivLex),
	})
	directSub := mustApproveChallenge(t, err)
	if directRig.dialer.DialCount() != 0 {
		t.Fatalf("作用域升级触发审批挑战前禁止拨号: dials=%d", directRig.dialer.DialCount())
	}
	out, err = directRig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: privReq, LexicalScope: algebraic.Some(unprivLex), Approval: algebraic.Some(directSub),
	})
	if err != nil {
		t.Fatalf("提交作用域升级审批后应成功: %v", err)
	}
	assertSucceededOutcome(t, out)

	// 3. OutcomeUnknown 绝不被降级。
	unk, _ := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, "sudo_lost", "transport dropped")
	directRig.escalator.SetOutcome(unk)
	out, err = directRig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{Plan: pl, Privilege: privReq})
	if err != nil || out.Kind() != execution.OutcomeKindUnknown {
		t.Fatalf("OutcomeUnknown 必须原样保留: out=%#v err=%v", out, err)
	}
}

// TestSessionExecPrivileged_LatticeMonotonicityProtectedPathsAndPreStartIsolation 验证：
// 1. LexicalScope 含 VerdictDeny / DecisionDeny 绝不被降级放行（0 拨号）；
// 2. LexicalScope 含 RiskCritical + NeedApproval 在 DirectOperator 下保留 RiskCritical 审批下限；
// 3. /tmp/benign -> /etc/sudoers 受保护区跃迁与 /etc/a -> /root/b 跨受保护分区替换必被捕获；
// 4. 取密（Vault 锁定 / 取消）位于 WithLease 外：0 拨号且返回 OutcomeNotStarted（非 OutcomeUnknown）。
func TestSessionExecPrivileged_LatticeMonotonicityProtectedPathsAndPreStartIsolation(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newFullSessionRig(t, fullRigOptions{
		profile: gate.PolicyProfileDirectOperator, noElicitFallback: gate.NoElicitFallbackChallenge,
		protectedPatterns: []string{"/etc/**", "/root/**"},
	})
	defer rig.close()
	pl := mustTestPlan(t, "")
	targetHop, _ := pl.Target()
	privReq := mustPrivilegeReq(t, ports.PrivilegeMethodSudo, "cat /etc/sudoers", "root", true)

	assertLexicalDenyNeverRelaxed(t, rig, pl, targetHop, privReq)
	assertLexicalCriticalAndProtectedPathCaught(t, rig, pl, targetHop, privReq)
	assertPreStartSecretFailureZeroDialNotStarted(t, pl)
}

func assertLexicalDenyNeverRelaxed(t *testing.T, rig *fullSessionRig, pl plan.SealedConnectionPlan, targetHop plan.HopSpec, privReq ports.PrivilegeRequest) {
	t.Helper()
	denyVerdictLex, err := security.NewScopeSnapshot(security.ScopeSnapshotSpec{
		Capability: security.CapabilityExecute, TargetNode: targetHop.NodeID(), Endpoint: algebraic.Some(targetHop.Endpoint()),
		Verdict: security.VerdictDeny, Risk: security.RiskDangerous, Decision: security.NewDecisionDeny("lexical deny"),
	})
	if err != nil {
		t.Fatalf("NewScopeSnapshot(verdictDeny): %v", err)
	}
	if _, err := rig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: privReq, LexicalScope: algebraic.Some(denyVerdictLex),
	}); !errors.Is(err, ucsess.ErrEscalationScopeChanged) || rig.dialer.DialCount() != 0 {
		t.Fatalf("VerdictDeny 必须被阻断且 0 拨号: err=%v dials=%d", err, rig.dialer.DialCount())
	}
	denyDecLex, err := security.NewScopeSnapshot(security.ScopeSnapshotSpec{
		Capability: security.CapabilityExecute, TargetNode: targetHop.NodeID(), Endpoint: algebraic.Some(targetHop.Endpoint()),
		Verdict: security.VerdictAllow, Risk: security.RiskDangerous, Decision: security.NewDecisionDeny("policy deny"),
	})
	if err != nil {
		t.Fatalf("NewScopeSnapshot(decDeny): %v", err)
	}
	if _, err := rig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: privReq, LexicalScope: algebraic.Some(denyDecLex),
	}); !errors.Is(err, ucsess.ErrEscalationScopeChanged) || rig.dialer.DialCount() != 0 {
		t.Fatalf("DecisionDeny 必须被阻断且 0 拨号: err=%v dials=%d", err, rig.dialer.DialCount())
	}
}

func assertLexicalCriticalAndProtectedPathCaught(t *testing.T, rig *fullSessionRig, pl plan.SealedConnectionPlan, targetHop plan.HopSpec, privReq ports.PrivilegeRequest) {
	t.Helper()
	// 1. 词法阶段已给出 NeedApproval(RiskDangerous) 且路径一致（未继续升级）：DirectOperator 亦不可放松为 Allow。
	dangDec, _ := security.NewDecisionNeedApproval(security.RiskDangerous, "lexical approval floor")
	floorLex, err := security.NewScopeSnapshot(security.ScopeSnapshotSpec{
		Capability: security.CapabilityExecute, TargetNode: targetHop.NodeID(), Endpoint: algebraic.Some(targetHop.Endpoint()),
		Verdict: security.VerdictAllow, Risk: security.RiskDangerous, Decision: dangDec,
	})
	if err != nil {
		t.Fatalf("NewScopeSnapshot(floor): %v", err)
	}
	_, err = rig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: privReq, LexicalScope: algebraic.Some(floorLex),
	})
	var chErr *gate.ApprovalChallengeError
	if !errors.As(err, &chErr) || chErr.Envelope().Risk() != security.RiskDangerous || rig.dialer.DialCount() != 0 {
		t.Fatalf("词法 NeedApproval 下限不可放松为 Allow: err=%v dials=%d", err, rig.dialer.DialCount())
	}

	// 2. /tmp/benign -> /etc/sudoers 受保护区跃迁与 /etc/a -> /root/b 跨受保护分区替换均须触发审批挑战（0 拨号）。
	benignPath, _ := security.NewScopedPath("/tmp/benign", false)
	pathLex, err := security.NewScopeSnapshot(security.ScopeSnapshotSpec{
		Capability: security.CapabilityExecute, TargetNode: targetHop.NodeID(), Endpoint: algebraic.Some(targetHop.Endpoint()),
		Verdict: security.VerdictAllow, Risk: security.RiskDangerous, Decision: dangDec, Paths: []security.ScopedPath{benignPath},
	})
	if err != nil {
		t.Fatalf("NewScopeSnapshot(benignPath): %v", err)
	}
	_, err = rig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: privReq, Paths: []string{"/etc/sudoers"}, LexicalScope: algebraic.Some(pathLex),
	})
	_ = mustApproveChallenge(t, err)
	if rig.dialer.DialCount() != 0 {
		t.Fatalf("/tmp/benign -> /etc/sudoers 受保护替换前禁止拨号: dials=%d", rig.dialer.DialCount())
	}
	etcPath, _ := security.NewScopedPath("/etc/a", false, "/etc/**")
	etcLex, err := security.NewScopeSnapshot(security.ScopeSnapshotSpec{
		Capability: security.CapabilityExecute, TargetNode: targetHop.NodeID(), Endpoint: algebraic.Some(targetHop.Endpoint()),
		Verdict: security.VerdictAllow, Risk: security.RiskDangerous, Decision: dangDec, Paths: []security.ScopedPath{etcPath},
	})
	if err != nil {
		t.Fatalf("NewScopeSnapshot(etcPath): %v", err)
	}
	_, err = rig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: privReq, Paths: []string{"/root/b"}, LexicalScope: algebraic.Some(etcLex),
	})
	_ = mustApproveChallenge(t, err)
	if rig.dialer.DialCount() != 0 {
		t.Fatalf("/etc/a -> /root/b 跨受保护分区替换前禁止拨号: dials=%d", rig.dialer.DialCount())
	}
}

func assertPreStartSecretFailureZeroDialNotStarted(t *testing.T, pl plan.SealedConnectionPlan) {
	t.Helper()
	rig := newFullSessionRig(t, fullRigOptions{profile: gate.PolicyProfileDirectOperator})
	defer rig.close()
	ref := mustPutVaultSecret(t, rig.vault, "vault/sudo-locked", []byte("pw"))
	if err := rig.vault.Lock(context.Background()); err != nil {
		t.Fatalf("vault.Lock: %v", err)
	}
	out, err := rig.svc.ExecPrivileged(context.Background(), ucsess.PrivilegeExecRequest{
		Plan: pl, Privilege: mustPrivilegeReq(t, ports.PrivilegeMethodSudo, "id", "", false),
		PasswordRef: algebraic.Some(ref),
	})
	if !errors.Is(err, ports.ErrVaultLocked) || out.Kind() != execution.OutcomeKindNotStarted || rig.dialer.DialCount() != 0 {
		t.Fatalf("取密阶段 Vault 锁定必须 0 拨号且返回 NotStarted: out=%#v err=%v dials=%d", out, err, rig.dialer.DialCount())
	}
}

type panicShellProbeStub struct{}

func (panicShellProbeStub) ProbeShell(context.Context, ports.SessionOpener) (ports.ShellProbeResult, error) {
	panic("injected synchronous probe panic")
}

// TestSessionRunAuthorized_PanicEmitsCompletedEventOnStream 验证同步 run 发生 panic 时 OperationStream 仍收到终态 Completed(Succeeded=false)。
func TestSessionRunAuthorized_PanicEmitsCompletedEventOnStream(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newFullSessionRig(t, fullRigOptions{customProbe: panicShellProbeStub{}})
	defer rig.close()
	stream := mustTestOperationStream(t, rig.rng)
	panicked := false
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		_, _ = rig.svc.ProbeShell(context.Background(), ucsess.ProbeShellRequest{
			Plan: mustTestPlan(t, ""), OperationStream: stream,
		})
	}()
	if !panicked {
		t.Fatal("期望 panic 向上传播")
	}
	assertStreamHasCompletedEvent(t, stream, false)
}

type corruptShellProbeStub struct{}

func (c *corruptShellProbeStub) ProbeShell(context.Context, ports.SessionOpener) (ports.ShellProbeResult, error) {
	var zero ports.ShellProbeResult
	return zero, nil
}

func TestSessionProbeShell_TwoStageAndFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newFullSessionRig(t, fullRigOptions{profile: gate.PolicyProfileDirectOperator})
	defer rig.close()
	pl := mustTestPlan(t, "")

	// 1. 阶段 1 POSIX sh 探测 + OperationStream EOF。
	stream := mustTestOperationStream(t, rig.rng)
	res1, err := rig.svc.ProbeShell(context.Background(), ucsess.ProbeShellRequest{
		Plan: pl, Timeout: algebraic.Some(algebraic.FromStdDuration(5 * time.Second)), OperationStream: stream,
	})
	if err != nil {
		t.Fatalf("ProbeShell(stage1): %v", err)
	}
	if !res1.IsValid() || res1.ProbeStage() != 1 || res1.Dialect() != execution.DialectPOSIX {
		t.Fatalf("阶段 1 探测结果失配: %#v", res1)
	}
	assertStreamHasCompletedEvent(t, stream, true)

	// 2. 阶段 2 PowerShell 探测。
	stage2, err := ports.NewShellProbeResult(ports.ShellProbeResultSpec{
		Dialect: execution.DialectPowerShell, Interpreter: execution.InterpreterPwsh,
		OSFamily: "windows", ProbeStage: 2, RawBanner: "PowerShell 7.4",
	})
	if err != nil {
		t.Fatalf("NewShellProbeResult(stage2): %v", err)
	}
	rig.shellProbe.SetResult(stage2)
	res2, err := rig.svc.ProbeShell(context.Background(), ucsess.ProbeShellRequest{Plan: pl})
	if err != nil || res2.ProbeStage() != 2 || res2.Dialect() != execution.DialectPowerShell || res2.Interpreter() != execution.InterpreterPwsh {
		t.Fatalf("阶段 2 探测失配: res=%#v err=%v", res2, err)
	}

	// 3. 底层返回零值/非法探测快照必须严格失败关闭为 ErrInvalidProbeResult。
	corruptRig := newFullSessionRig(t, fullRigOptions{customProbe: &corruptShellProbeStub{}})
	defer corruptRig.close()
	if _, err := corruptRig.svc.ProbeShell(context.Background(), ucsess.ProbeShellRequest{Plan: pl}); !errors.Is(err, ucsess.ErrInvalidProbeResult) {
		t.Fatalf("非法探测快照期望 ErrInvalidProbeResult，实际=%v", err)
	}

	// 4. 未注入端口、非正超时与门控拒绝（0 拨号）。
	baseRig := newTestRig(t, gate.PolicyProfileDirectOperator, false)
	defer baseRig.close()
	if _, err := baseRig.svc.ProbeShell(context.Background(), ucsess.ProbeShellRequest{Plan: pl}); !errors.Is(err, ucsess.ErrPortUnavailable) {
		t.Fatalf("未注入 ShellProbePort 期望 ErrPortUnavailable，实际=%v", err)
	}
	if _, err := rig.svc.ProbeShell(context.Background(), ucsess.ProbeShellRequest{
		Plan: pl, Timeout: algebraic.Some(algebraic.ZeroDuration()),
	}); !errors.Is(err, ucsess.ErrInvalidRequest) {
		t.Fatalf("非正超时期望 ErrInvalidRequest，实际=%v", err)
	}
	strictRig := newFullSessionRig(t, fullRigOptions{
		profile: gate.PolicyProfileStrictAgent, approvalThreshold: security.RiskDangerous, noElicitFallback: gate.NoElicitFallbackChallenge,
	})
	defer strictRig.close()
	if _, err := strictRig.svc.ProbeShell(context.Background(), ucsess.ProbeShellRequest{
		Plan: pl, Risk: algebraic.Some(security.RiskDangerous),
	}); err == nil || strictRig.dialer.DialCount() != 0 {
		t.Fatalf("门控阻断下严禁拨号: err=%v dials=%d", err, strictRig.dialer.DialCount())
	}
}
