package sim

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"maps"
	"net"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/internal/sim/memtree"
	"github.com/wentf9/xops-cli/core/ports"
)

// SimEnvPort 实现 ports.EnvPort 的纯内存环境变量与本机身份元信息仿真器（零 os.Getenv）。
//
//xops:opaque
//xops:failclosed
type SimEnvPort struct {
	simBase
	env  map[string]string
	id   ports.LocalIdentityInfo
	hasI bool
}

// NewSimEnvPort 创建预置环境变量快照与可选本机身份信息的仿真环境端口。
func NewSimEnvPort(env map[string]string, id ports.LocalIdentityInfo) *SimEnvPort {
	p := &SimEnvPort{simBase: newSimBase(nil), env: maps.Clone(env)}
	if p.env == nil {
		p.env = make(map[string]string)
	}
	if id.IsValid() {
		p.id, p.hasI = id, true
	}
	return p
}

// SetEnv / SetIdentity 更新测试夹具环境变量与本机身份快照。
func (e *SimEnvPort) SetEnv(key, val string) {
	if key != "" {
		e.withLock(func() { e.env[key] = val })
	}
}
func (e *SimEnvPort) SetIdentity(id ports.LocalIdentityInfo) {
	e.withLock(func() { e.id, e.hasI = id, id.IsValid() })
}
func (e *SimEnvPort) LookupEnv(key string) (val string, ok bool) {
	if !e.ok() || key == "" {
		return "", false
	}
	e.withLock(func() { val, ok = e.env[key] })
	return val, ok
}
func (e *SimEnvPort) Environ() map[string]string {
	return withLockRet(&e.simBase, nil, func() map[string]string { return maps.Clone(e.env) })
}
func (e *SimEnvPort) LookupLocalIdentity() (out ports.LocalIdentityInfo, err error) {
	if !e.ok() {
		return out, ErrSimNotInitialized
	}
	if fErr := e.faults.Check("env.identity"); fErr != nil {
		return out, fErr
	}
	return withLockRet(&e.simBase, out, func() ports.LocalIdentityInfo {
		if !e.hasI {
			err = ports.ErrNotFound
			return out
		}
		return e.id
	}), err
}

// SimSSHFPLookup 实现 ports.SSHFPLookupPort 的确定性内存 DNS SSHFP 查询仿真器。
//
//xops:opaque
//xops:failclosed
type SimSSHFPLookup struct {
	simBase
	records map[string][]ports.SSHFPRecord
}

// NewSimSSHFPLookup 创建空白的 SSHFP 查询仿真器。
func NewSimSSHFPLookup() *SimSSHFPLookup {
	return &SimSSHFPLookup{simBase: newSimBase(nil), records: make(map[string][]ports.SSHFPRecord)}
}

// SetRecords 为指定规范化主机设置有效 SSHFP 记录集（过滤无效零值记录）。
func (s *SimSSHFPLookup) SetRecords(host netaddr.CanonicalHost, recs ...ports.SSHFPRecord) {
	if host.IsValid() {
		valid := slices.DeleteFunc(slices.Clone(recs), func(r ports.SSHFPRecord) bool { return !r.IsValid() })
		s.withLock(func() { s.records[host.String()] = valid })
	}
}
func (s *SimSSHFPLookup) LookupSSHFP(ctx context.Context, host netaddr.CanonicalHost) ([]ports.SSHFPRecord, error) {
	if err := s.check(ctx, "sshfp.lookup", host.IsValid()); err != nil {
		return nil, err
	}
	return withLockRet(&s.simBase, nil, func() []ports.SSHFPRecord { return slices.Clone(s.records[host.String()]) }), nil
}

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

// SimForwarder 实现 ports.ForwarderPort，返回满足 pool.ManagedResource 契约的 *SimForwardHandle。
//
//xops:opaque
//xops:failclosed
type SimForwarder struct{ simBase }

// NewSimForwarder 创建纯内存 SSH 隧道转发仿真器。
func NewSimForwarder() *SimForwarder { return &SimForwarder{simBase: newSimBase(nil)} }

// StartForward 按 ForwardSpec 方向演练借用的底层 TunnelTransport 通道，返回可受管转发句柄（参数级 //xops:borrowed 零逃逸）。
func (f *SimForwarder) StartForward(
	ctx context.Context,
	//xops:borrowed
	transport ports.TunnelTransport,
	spec ports.ForwardSpec,
) (ports.ForwardHandle, error) {
	if err := f.check(ctx, "forward.start", transport != nil, spec.IsValid()); err != nil {
		return nil, err
	}
	bound, closer, err := memtree.OpenSimForwardChannel(ctx, transport, spec)
	if err != nil {
		return nil, err
	}
	return &SimForwardHandle{initialized: true, spec: spec, boundAddr: bound, closer: closer, doneCh: make(chan struct{})}, nil
}

// SimForwardHandle 实现 ports.ForwardHandle 与 core/internal/pool.ManagedResource。
//
//xops:opaque
//xops:failclosed
type SimForwardHandle struct {
	initialized bool
	spec        ports.ForwardSpec
	boundAddr   string
	closer      io.Closer
	doneCh      chan struct{}
	closeOnce   sync.Once
	closed      atomic.Bool
	closeErr    error
}

func (h *SimForwardHandle) IsValid() bool           { return h != nil && h.initialized && !h.closed.Load() }
func (h *SimForwardHandle) Spec() ports.ForwardSpec { return h.spec }
func (h *SimForwardHandle) BoundAddr() string       { return h.boundAddr }
func (h *SimForwardHandle) Done() <-chan struct{}   { return h.doneCh }
func (h *SimForwardHandle) Err() error              { return h.closeErr }
func (h *SimForwardHandle) Close() error {
	if h == nil || !h.initialized {
		return nil
	}
	h.closeOnce.Do(func() {
		h.closed.Store(true)
		if h.closer != nil {
			h.closeErr = h.closer.Close()
		}
		close(h.doneCh)
	})
	return h.closeErr
}
