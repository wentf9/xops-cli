package tck

import (
	"bytes"
	"context"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
)

// EnvFixture 描述 EnvPort 契约测试夹具。
type EnvFixture struct {
	NewEnv         func(t *testing.T) ports.EnvPort
	KnownKey       string
	ExpectedValue  string
	MissingKey     string
	ExpectIdentity bool
}

// SSHFPLookupFixture 描述 SSHFPLookupPort 契约测试夹具。
type SSHFPLookupFixture struct {
	NewLookup func(t *testing.T) ports.SSHFPLookupPort
	KnownHost netaddr.CanonicalHost
	MinCount  int
}

// SSHAgentFixture 描述 SSHAgentPort 契约测试夹具。
type SSHAgentFixture struct {
	NewAgent            func(t *testing.T) ports.SSHAgentPort
	NewUnavailableAgent func(t *testing.T) ports.SSHAgentPort
	Spec                algebraic.Option[inventory.AgentSpec]
}

// VaultControlFixture 描述 VaultControlPort 生命周期契约测试夹具。
type VaultControlFixture struct {
	NewUninitialized func(t *testing.T) ports.VaultControlPort
}

// PrivilegeEscalationFixture 描述 PrivilegeEscalationPort 契约测试夹具。
type PrivilegeEscalationFixture struct {
	NewEscalator    func(t *testing.T) (ports.PrivilegeEscalationPort, ports.SessionOpener)
	CorrectPassword string
	WrongPassword   string
	RequirePassword bool
}

// ShellProbeFixture 描述 ShellProbePort 契约测试夹具。
type ShellProbeFixture struct {
	NewProbe func(t *testing.T) (ports.ShellProbePort, ports.SessionOpener)
}

// ForwarderFixture 描述 ForwarderPort 与 ForwardHandle（pool.ManagedResource 兼容）契约测试夹具。
type ForwarderFixture struct {
	NewForwarder func(t *testing.T) (ports.ForwarderPort, ports.TunnelTransport)
	Specs        []ports.ForwardSpec
}

// RunEnvSuite 验证 EnvPort 的只读键查询、Environ 防御性克隆与可选本机身份快照契约。
func RunEnvSuite(t *testing.T, fx EnvFixture) {
	t.Helper()
	requireTrue(t, fx.NewEnv != nil && fx.KnownKey != "", "EnvFixture 缺少必需字段")

	t.Run("LookupEnvironAndIdentity", func(t *testing.T) {
		env := fx.NewEnv(t)
		val, ok := env.LookupEnv(fx.KnownKey)
		requireTrue(t, ok && val == fx.ExpectedValue, "LookupEnv(KnownKey) 返回不匹配")
		if fx.MissingKey != "" {
			_, missingOK := env.LookupEnv(fx.MissingKey)
			requireTrue(t, !missingOK, "LookupEnv(MissingKey) 必须返回 false")
		}
		snap := env.Environ()
		requireTrue(t, snap[fx.KnownKey] == fx.ExpectedValue, "Environ 快照须包含 KnownKey")
		snap[fx.KnownKey] = "mutated-outside"
		valAfter, _ := env.LookupEnv(fx.KnownKey)
		requireTrue(t, valAfter == fx.ExpectedValue, "修改 Environ 返回 map 不得污染内部状态")

		if fx.ExpectIdentity {
			id, err := env.LookupLocalIdentity()
			requireNoErr(t, err, "LookupLocalIdentity")
			requireTrue(t, id.IsValid(), "LocalIdentityInfo 必须有效")
		}
	})
}

// RunSSHFPLookupSuite 验证 SSHFPLookupPort 的空上下文/零主机拒绝与有效 SSHFP 记录返回契约。
func RunSSHFPLookupSuite(t *testing.T, fx SSHFPLookupFixture) {
	t.Helper()
	requireTrue(t, fx.NewLookup != nil && fx.KnownHost.IsValid(), "SSHFPLookupFixture 缺少必需字段")

	t.Run("ValidationAndLookup", func(t *testing.T) {
		ctx := context.Background()
		lp := fx.NewLookup(t)
		var nilCtx context.Context
		var zeroHost netaddr.CanonicalHost

		_, err := lp.LookupSSHFP(nilCtx, fx.KnownHost)
		requireErrIs(t, err, ports.ErrNilContext, "LookupSSHFP(nil ctx)")
		_, err = lp.LookupSSHFP(ctx, zeroHost)
		requireErr(t, err, "LookupSSHFP(zero host)")

		recs, err := lp.LookupSSHFP(ctx, fx.KnownHost)
		requireNoErr(t, err, "LookupSSHFP(known)")
		requireTrue(t, len(recs) >= fx.MinCount, "LookupSSHFP 返回记录数低于夹具预期")
		for _, r := range recs {
			requireTrue(t, r.IsValid(), "返回的每条 SSHFPRecord 均须有效")
		}
	})
}

// RunSSHAgentSuite 验证 SSHAgentPort 的通道连接、公钥列举、签名与不可达失败关闭契约。
func RunSSHAgentSuite(t *testing.T, fx SSHAgentFixture) {
	t.Helper()
	requireTrue(t, fx.NewAgent != nil, "SSHAgentFixture.NewAgent 不能为 nil")

	t.Run("DialListSignAndUnavailable", func(t *testing.T) {
		defer VerifyNoLeaks(t)
		ctx := context.Background()
		ag := fx.NewAgent(t)
		var nilCtx context.Context
		var zeroAgent inventory.AgentSpec
		var zeroFP inventory.KeyFingerprint

		_, err := ag.DialAgent(nilCtx, fx.Spec)
		requireErrIs(t, err, ports.ErrNilContext, "DialAgent(nil ctx)")
		_, err = ag.DialAgent(ctx, algebraic.Some(zeroAgent))
		requireErr(t, err, "DialAgent(Some(zeroSpec))")

		conn, err := ag.DialAgent(ctx, fx.Spec)
		requireNoErr(t, err, "DialAgent")
		requireNoErr(t, conn.Close(), "DialAgent.Close")

		keys, err := ag.ListAgentKeys(ctx, fx.Spec)
		requireNoErr(t, err, "ListAgentKeys")
		requireTrue(t, len(keys) > 0 && keys[0].IsValid(), "ListAgentKeys 至少应返回 1 把有效公钥")

		_, err = ag.SignWithAgent(ctx, fx.Spec, zeroFP, keys[0].Algorithm(), []byte("data"))
		requireErr(t, err, "SignWithAgent(zero fp)")
		sig, err := ag.SignWithAgent(ctx, fx.Spec, keys[0].Fingerprint(), keys[0].Algorithm(), []byte("agent-challenge"))
		requireNoErr(t, err, "SignWithAgent")
		requireTrue(t, sig.IsValid(), "SignWithAgent 必须产出有效 Signature")

		if fx.NewUnavailableAgent != nil {
			unavail := fx.NewUnavailableAgent(t)
			_, err = unavail.DialAgent(ctx, fx.Spec)
			requireErrIs(t, err, ports.ErrSignerUnavailable, "不可用 Agent DialAgent 须返回 ErrSignerUnavailable")
		}
	})
}

// RunVaultControlSuite 验证 VaultControlPort 的 Uninitialized -> Init -> Locked -> Unlock 全状态机契约（0 box.Use）。
func RunVaultControlSuite(t *testing.T, fx VaultControlFixture) {
	t.Helper()
	requireTrue(t, fx.NewUninitialized != nil, "VaultControlFixture.NewUninitialized 不能为 nil")

	t.Run("InitLockUnlockLifecycle", func(t *testing.T) {
		ctx := context.Background()
		vc := fx.NewUninitialized(t)
		var nilCtx context.Context
		var zeroBox secret.SecretBox

		st, err := vc.Status(ctx)
		requireNoErr(t, err, "Status(initial)")
		requireTrue(t, st.IsValid() && st.State() == ports.VaultStateUninitialized && !st.IsUnlocked(), "初始状态须为 Uninitialized")
		requireErrIs(t, vc.Lock(ctx), ports.ErrNotFound, "未初始化 Lock 须返回 ErrNotFound")
		requireErr(t, vc.Init(ctx, nil), "Init(nil box)")
		requireErr(t, vc.Init(ctx, &zeroBox), "Init(zero box)")

		requireNoErr(t, secret.WithBytes([]byte(TestSecretTokenA), func(pass *secret.SecretBox) error {
			requireErrIs(t, vc.Init(nilCtx, pass), ports.ErrNilContext, "Init(nil ctx)")
			requireErrIs(t, vc.Unlock(ctx, pass), ports.ErrNotFound, "未初始化 Unlock 须返回 ErrNotFound")
			requireNoErr(t, vc.Init(ctx, pass), "Init")
			requireErrIs(t, vc.Init(ctx, pass), ports.ErrAlreadyExists, "重复 Init 须返回 ErrAlreadyExists")
			return nil
		}), "Init cycle")

		st, err = vc.Status(ctx)
		requireNoErr(t, err, "Status(after Init)")
		requireTrue(t, st.State() == ports.VaultStateUnlocked && st.IsUnlocked(), "Init 后须处于 Unlocked")

		requireNoErr(t, vc.Lock(ctx), "Lock")
		st, err = vc.Status(ctx)
		requireNoErr(t, err, "Status(after Lock)")
		requireTrue(t, st.State() == ports.VaultStateLocked && !st.IsUnlocked(), "Lock 后须处于 Locked")

		requireNoErr(t, secret.WithBytes([]byte(TestSecretTokenB), func(wrong *secret.SecretBox) error {
			requireErrIs(t, vc.Unlock(ctx, wrong), ports.ErrAuthFailed, "错误主口令 Unlock 须返回 ErrAuthFailed")
			return nil
		}), "Unlock(wrong)")

		requireNoErr(t, secret.WithBytes([]byte(TestSecretTokenA), func(pass *secret.SecretBox) error {
			requireNoErr(t, vc.Unlock(ctx, pass), "Unlock(correct)")
			return nil
		}), "Unlock(correct)")

		st, err = vc.Status(ctx)
		requireNoErr(t, err, "Status(after Unlock)")
		requireTrue(t, st.State() == ports.VaultStateUnlocked && st.IsUnlocked(), "正确解锁后须处于 Unlocked")
	})
}

// RunPrivilegeEscalationSuite 验证 PrivilegeEscalationPort 参数守卫、借用口令校验与执行结果契约（0 box.Use）。
func RunPrivilegeEscalationSuite(t *testing.T, fx PrivilegeEscalationFixture) {
	t.Helper()
	requireTrue(t, fx.NewEscalator != nil, "PrivilegeEscalationFixture.NewEscalator 不能为 nil")

	t.Run("ValidationAndRunPrivileged", func(t *testing.T) {
		defer VerifyNoLeaks(t)
		ctx := context.Background()
		esc, opener := fx.NewEscalator(t)
		req, err := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
			Method:  ports.PrivilegeMethodSudo,
			Command: MustCommandPlan(t, "id"),
		})
		requireNoErr(t, err, "NewPrivilegeRequest")

		var nilCtx context.Context
		var zeroReq ports.PrivilegeRequest
		var zeroBox secret.SecretBox
		_, err = esc.RunPrivileged(nilCtx, opener, req, nil, ports.ExecStreams{})
		requireErrIs(t, err, ports.ErrNilContext, "RunPrivileged(nil ctx)")
		_, err = esc.RunPrivileged(ctx, nil, req, nil, ports.ExecStreams{})
		requireErr(t, err, "RunPrivileged(nil opener)")
		_, err = esc.RunPrivileged(ctx, opener, zeroReq, nil, ports.ExecStreams{})
		requireErr(t, err, "RunPrivileged(zero req)")
		_, err = esc.RunPrivileged(ctx, opener, req, &zeroBox, ports.ExecStreams{})
		requireErr(t, err, "RunPrivileged(zero box)")

		if fx.RequirePassword {
			_, err = esc.RunPrivileged(ctx, opener, req, nil, ports.ExecStreams{})
			requireErrIs(t, err, ports.ErrAuthFailed, "需要口令时传 nil 须返回 ErrAuthFailed")
			if fx.WrongPassword != "" {
				requireNoErr(t, secret.WithBytes([]byte(fx.WrongPassword), func(bad *secret.SecretBox) error {
					_, wErr := esc.RunPrivileged(ctx, opener, req, bad, ports.ExecStreams{})
					requireErrIs(t, wErr, ports.ErrAuthFailed, "错误提权口令须返回 ErrAuthFailed")
					return nil
				}), "wrong pass")
			}
			passStr := fx.CorrectPassword
			if passStr == "" {
				passStr = TestSecretTokenA
			}
			var outBuf bytes.Buffer
			requireNoErr(t, secret.WithBytes([]byte(passStr), func(good *secret.SecretBox) error {
				out, rErr := esc.RunPrivileged(ctx, opener, req, good, ports.ExecStreams{Stdout: &outBuf})
				requireNoErr(t, rErr, "RunPrivileged(correct pass)")
				requireTrue(t, out != nil && out.IsValid(), "RunPrivileged 须返回有效 ExecutionOutcome")
				return nil
			}), "correct pass")
			return
		}
		out, err := esc.RunPrivileged(ctx, opener, req, nil, ports.ExecStreams{})
		requireNoErr(t, err, "RunPrivileged(passwordless)")
		requireTrue(t, out != nil && out.IsValid(), "RunPrivileged 须返回有效 ExecutionOutcome")
	})
}

// RunShellProbeSuite 验证 ShellProbePort 空参数拦截与已校验 LaunchProfile 产出契约。
func RunShellProbeSuite(t *testing.T, fx ShellProbeFixture) {
	t.Helper()
	requireTrue(t, fx.NewProbe != nil, "ShellProbeFixture.NewProbe 不能为 nil")

	t.Run("ValidationAndProbe", func(t *testing.T) {
		defer VerifyNoLeaks(t)
		ctx := context.Background()
		probe, opener := fx.NewProbe(t)
		var nilCtx context.Context

		_, err := probe.ProbeShell(nilCtx, opener)
		requireErrIs(t, err, ports.ErrNilContext, "ProbeShell(nil ctx)")
		_, err = probe.ProbeShell(ctx, nil)
		requireErr(t, err, "ProbeShell(nil opener)")

		res, err := probe.ProbeShell(ctx, opener)
		requireNoErr(t, err, "ProbeShell")
		requireTrue(t, res.IsValid() && res.LaunchProfile().IsValid() && (res.ProbeStage() == 1 || res.ProbeStage() == 2), "ShellProbeResult 必须有效")
	})
}

// RunForwarderSuite 验证 ForwarderPort 启动与 ForwardHandle（IsValid/Done/幂等 Close）生命周期契约。
func RunForwarderSuite(t *testing.T, fx ForwarderFixture) {
	t.Helper()
	requireTrue(t, fx.NewForwarder != nil && len(fx.Specs) > 0, "ForwarderFixture 缺少必需字段")

	t.Run("ValidationAndForwardLifecycle", func(t *testing.T) {
		defer VerifyNoLeaks(t)
		ctx := context.Background()
		fwd, tr := fx.NewForwarder(t)
		var nilCtx context.Context
		var zeroSpec ports.ForwardSpec

		_, err := fwd.StartForward(nilCtx, tr, fx.Specs[0])
		requireErrIs(t, err, ports.ErrNilContext, "StartForward(nil ctx)")
		_, err = fwd.StartForward(ctx, nil, fx.Specs[0])
		requireErr(t, err, "StartForward(nil transport)")
		_, err = fwd.StartForward(ctx, tr, zeroSpec)
		requireErr(t, err, "StartForward(zero spec)")
		_, err = ports.NewForwardSpec(ports.ForwardTUN, "tun0", "tun1")
		requireErr(t, err, "NewForwardSpec(ForwardTUN) 必须拒绝，强制使用 NewForwardTUNSpec")

		for _, sp := range fx.Specs {
			h, sErr := fwd.StartForward(ctx, tr, sp)
			requireNoErr(t, sErr, "StartForward("+sp.Direction().String()+")")
			requireTrue(t, h != nil && h.IsValid() && h.Spec().Equal(sp) && h.BoundAddr() != "", "ForwardHandle 元信息须有效")
			if sp.Direction() == ports.ForwardTUN {
				wantTUN, okW := sp.TUN().Get()
				gotTUN, okG := h.Spec().TUN().Get()
				requireTrue(t, okW && okG && gotTUN.Equal(wantTUN), "ForwardTUN 句柄须完整保留强类型 TUNSpec")
			}
			requireNoErr(t, h.Close(), "ForwardHandle.Close(1)")
			requireNoErr(t, h.Close(), "ForwardHandle.Close(2, idempotent)")
			requireTrue(t, !h.IsValid(), "Close 后 ForwardHandle.IsValid 须为 false")
			select {
			case <-h.Done():
			default:
				t.Fatalf("Close 后 ForwardHandle.Done() 必须已关闭")
			}
		}
	})
}
