package sim

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/internal/sim/memtree"
	"github.com/wentf9/xops-cli/core/ports"
)

// SimEnvPort / SimSSHFPLookup / SimTUNDevicePort 为 memtree 纯内存仿真端口的公开别名。
type (
	SimEnvPort       = memtree.EnvPort
	SimSSHFPLookup   = memtree.SSHFPLookup
	SimTUNDevicePort = memtree.TUNDevicePort
)

// NewSimEnvPort 创建预置环境变量快照与可选本机身份信息的仿真环境端口。
func NewSimEnvPort(env map[string]string, id ports.LocalIdentityInfo) *SimEnvPort {
	return memtree.NewEnvPort(ErrSimNotInitialized, env, id)
}

// NewSimSSHFPLookup 创建空白的 SSHFP 查询仿真器。
func NewSimSSHFPLookup() *SimSSHFPLookup { return memtree.NewSSHFPLookup(ErrSimNotInitialized) }

// NewSimTUNDevicePort 创建默认可用的纯内存本机 TUN/TAP 设备仿真器。
func NewSimTUNDevicePort() *SimTUNDevicePort { return memtree.NewTUNDevicePort(ErrSimNotInitialized) }

// SimSSHAgent 实现 ports.SSHAgentPort 的纯内存 SSH Agent 通道、公钥列举与签名仿真器。
//
//xops:opaque
//xops:failclosed
type SimSSHAgent struct {
	simBase
	available bool
	keys      []ports.PublicKeyInfo
}

// NewSimSSHAgent 创建预置公钥且默认可用的 SSH Agent 仿真器。
func NewSimSSHAgent(keys ...ports.PublicKeyInfo) *SimSSHAgent {
	a := &SimSSHAgent{simBase: newSimBase(nil), available: true}
	for _, k := range keys {
		a.AddKey(k)
	}
	return a
}

// SetAvailable / AddKey 控制 Agent 可达状态与已加载公钥。
func (a *SimSSHAgent) SetAvailable(en bool) { a.withLock(func() { a.available = en }) }
func (a *SimSSHAgent) AddKey(pub ports.PublicKeyInfo) {
	if pub.IsValid() {
		a.withLock(func() { a.keys = append(a.keys, pub) })
	}
}
func (a *SimSSHAgent) checkAgentSpec(ctx context.Context, op string, spec algebraic.Option[inventory.AgentSpec], extraOK ...bool) error {
	sp, has := spec.Get()
	args := append([]bool{!has || sp.IsValid()}, extraOK...)
	if err := a.check(ctx, op, args...); err != nil {
		return err
	}
	if !withLockRet(&a.simBase, false, func() bool { return a.available }) {
		return ports.ErrSignerUnavailable
	}
	return nil
}
func (a *SimSSHAgent) DialAgent(ctx context.Context, spec algebraic.Option[inventory.AgentSpec]) (net.Conn, error) {
	if err := a.checkAgentSpec(ctx, "agent.dial", spec); err != nil {
		return nil, err
	}
	return memtree.NewEchoConn("sim-ssh-agent"), nil
}
func (a *SimSSHAgent) ListAgentKeys(ctx context.Context, spec algebraic.Option[inventory.AgentSpec]) ([]ports.PublicKeyInfo, error) {
	if err := a.checkAgentSpec(ctx, "agent.list", spec); err != nil {
		return nil, err
	}
	return withLockRet(&a.simBase, nil, func() []ports.PublicKeyInfo { return slices.Clone(a.keys) }), nil
}
func (a *SimSSHAgent) SignWithAgent(ctx context.Context, spec algebraic.Option[inventory.AgentSpec], key inventory.KeyFingerprint, algorithm string, data []byte) (out ports.Signature, err error) {
	if err = a.checkAgentSpec(ctx, "agent.sign", spec, key.IsValid(), algorithm != ""); err != nil {
		return out, err
	}
	if !withLockRet(&a.simBase, false, func() bool {
		return slices.ContainsFunc(a.keys, func(k ports.PublicKeyInfo) bool { return k.Fingerprint().Equal(key) })
	}) {
		return out, ports.ErrSignerUnavailable
	}
	return memtree.SignSimKey("agent:", key, algorithm, data)
}

// SimPrivilegeEscalator 实现 ports.PrivilegeEscalationPort，仅以 SHA-256 摘要校验借用的提权口令（0 明文留存）。
//
//xops:opaque
//xops:failclosed
type SimPrivilegeEscalator struct {
	simBase
	requirePass bool
	passHash    [32]byte
	outcome     execution.ExecutionOutcome
}

// NewSimPrivilegeEscalator 创建默认免密放行的远端提权仿真器。
func NewSimPrivilegeEscalator() *SimPrivilegeEscalator {
	return &SimPrivilegeEscalator{simBase: newSimBase(nil)}
}

// SetRequiredPassword 设置提权所需口令的摘要（传空切片关闭口令校验）；SetOutcome 预设自定义执行结果。
func (p *SimPrivilegeEscalator) SetRequiredPassword(raw []byte) {
	p.withLock(func() {
		if len(raw) == 0 {
			p.requirePass, p.passHash = false, [32]byte{}
			return
		}
		p.requirePass, p.passHash = true, sha256.Sum256(raw)
	})
}
func (p *SimPrivilegeEscalator) SetOutcome(out execution.ExecutionOutcome) {
	p.withLock(func() { p.outcome = out })
}

// RunPrivileged 通过借用的 opener 打开远端会话并校验可选提权口令（参数级 //xops:borrowed 静态审计零逃逸）。
func (p *SimPrivilegeEscalator) RunPrivileged(
	ctx context.Context,
	//xops:borrowed
	opener ports.SessionOpener,
	req ports.PrivilegeRequest,
	//xops:borrowed
	password *secret.SecretBox,
	streams ports.ExecStreams,
) (execution.ExecutionOutcome, error) {
	passValid := password == nil || password.IsValid()
	if err := p.check(ctx, "priv.run", opener != nil, req.IsValid(), passValid); err != nil {
		return nil, err
	}
	var needPass bool
	var wantHash [32]byte
	var customOut execution.ExecutionOutcome
	p.withLock(func() { needPass, wantHash, customOut = p.requirePass, p.passHash, p.outcome })
	if needPass {
		if req.NonInteractive() || password == nil {
			return nil, ports.ErrAuthFailed
		}
		gotHash, err := hashSecretBox(password)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare(wantHash[:], gotHash[:]) != 1 {
			return nil, ports.ErrAuthFailed
		}
	}
	sess, err := opener.OpenSession(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = sess.Close() }()
	if err := sess.Start(ctx, req.Command(), streams); err != nil {
		return nil, err
	}
	out, err := sess.Wait(ctx)
	if err != nil {
		return nil, err
	}
	if customOut != nil && customOut.IsValid() {
		return customOut, nil
	}
	return out, nil
}

// SimShellProbe 实现 ports.ShellProbePort 的两阶段远端 Shell 探测仿真器。
//
//xops:opaque
//xops:failclosed
type SimShellProbe struct {
	simBase
	result ports.ShellProbeResult
}

// NewSimShellProbe 创建返回指定探测快照的仿真器（若传入零值则默认 POSIX sh 阶段 1 结果）。
func NewSimShellProbe(result ports.ShellProbeResult) *SimShellProbe {
	if !result.IsValid() {
		result, _ = ports.NewShellProbeResult(ports.ShellProbeResultSpec{
			Dialect: execution.DialectPOSIX, Interpreter: execution.InterpreterSH, OSFamily: "linux", ProbeStage: 1, RawBanner: "POSIX sh",
		})
	}
	return &SimShellProbe{simBase: newSimBase(nil), result: result}
}

// SetResult 更新仿真探测返回结果。
func (p *SimShellProbe) SetResult(res ports.ShellProbeResult) {
	if res.IsValid() {
		p.withLock(func() { p.result = res })
	}
}
func (p *SimShellProbe) ProbeShell(
	ctx context.Context,
	//xops:borrowed
	opener ports.SessionOpener,
) (out ports.ShellProbeResult, err error) {
	if err = p.check(ctx, "probe.shell", opener != nil); err != nil {
		return out, err
	}
	res := withLockRet(&p.simBase, out, func() ports.ShellProbeResult { return p.result })
	for range res.ProbeStage() {
		sess, sErr := opener.OpenSession(ctx)
		if sErr != nil {
			return out, sErr
		}
		_ = sess.Close()
	}
	return res, nil
}

// SimForwarder 实现 ports.ForwarderPort，返回持留池钉选传输的 *SimForwardHandle（满足 pool.ManagedResource）。
//
//xops:opaque
//xops:failclosed
type SimForwarder struct{ simBase }

// NewSimForwarder 创建纯内存 SSH 隧道转发仿真器。
func NewSimForwarder() *SimForwarder { return &SimForwarder{simBase: newSimBase(nil)} }

// StartForward 启动单条受管隧道转发并持留非借用 transport 直至 ForwardHandle.Close()（支持启动后持续打开新通道）。
func (f *SimForwarder) StartForward(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec) (ports.ForwardHandle, error) {
	if err := f.check(ctx, "forward.start", transport != nil, spec.IsValid()); err != nil {
		return nil, err
	}
	bound, closer, err := memtree.OpenSimForwardChannel(ctx, transport, spec)
	if err != nil {
		return nil, err
	}
	return memtree.NewForwardHandle(spec, bound, transport, closer), nil
}

// SimForwardHandle 是 memtree.ForwardHandle 的别名，实现 ports.ForwardHandle 与 pool.ManagedResource。
type SimForwardHandle = memtree.ForwardHandle
