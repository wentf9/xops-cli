package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

// MuxRequest 描述面向 ControlMaster 套接字执行探测（ProbeMux）、stdio 透传（WithMuxProxy/RunMuxProxy）
// 或共享连接复用（WithMuxConn）的通用强类型输入。
type MuxRequest struct {
	Plan            plan.SealedConnectionPlan
	NodeID          string
	SocketPath      algebraic.Option[pathalg.LocalSourcePath]
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

// MuxControlRequest 描述向 ControlMaster 发送 `-O` 控制动作（check/forward/cancel/exit/stop）的强类型输入。
type MuxControlRequest struct {
	Target  MuxRequest
	Action  ports.MuxControlAction
	Forward algebraic.Option[ports.ForwardSpec]
}

// ProbeMux 经 CapInspect 门控探测指定 ControlMaster 套接字存活状态与主进程 PID。
func (s *Service) ProbeMux(ctx context.Context, req MuxRequest) (ports.MuxControlResponse, error) {
	defer closeStream(req.OperationStream)
	return runMuxControl[security.CapInspect](ctx, s, req, "mux_probe", security.RiskSafe, nil, func(authCtx context.Context, sockPath pathalg.LocalSourcePath) (ports.MuxControlResponse, error) {
		return s.cfg.MuxSocket.Probe(authCtx, sockPath)
	})
}

// ControlMux 向活跃 ControlMaster 发送 -O 控制命令（check/forward/cancel/exit/stop）。
func (s *Service) ControlMux(ctx context.Context, req MuxControlRequest) (ports.MuxControlResponse, error) {
	defer closeStream(req.Target.OperationStream)
	if err := s.validateServiceAndCtx(ctx); err != nil {
		return zeroVal[ports.MuxControlResponse](), err
	}
	if req.Action == ports.MuxActionProxy {
		return zeroVal[ports.MuxControlResponse](), fmt.Errorf("%w: MuxActionProxy 请调用 WithMuxProxy 或 RunMuxProxy", ErrInvalidRequest)
	}
	extra := map[string]string{"action": req.Action.String()}
	call := func(authCtx context.Context, sockPath pathalg.LocalSourcePath) (ports.MuxControlResponse, error) {
		muxReq, err := ports.NewMuxControlRequest(req.Action, sockPath, req.Forward)
		if err != nil {
			return zeroVal[ports.MuxControlResponse](), fmt.Errorf("%w: %w", ErrInvalidRequest, err)
		}
		return s.cfg.MuxSocket.Control(authCtx, muxReq)
	}
	if req.Action == ports.MuxActionCheck {
		return runMuxControl[security.CapInspect](ctx, s, req.Target, "mux_check", security.RiskSafe, extra, call)
	}
	defaultRisk := security.RiskModerate
	if fwd, hasFwd := req.Forward.Get(); hasFwd {
		extra["forward_direction"], extra["bind_addr"] = fwd.Direction().String(), fwd.BindAddr()
		if req.Action == ports.MuxActionForward {
			defaultRisk = defaultForwardRisk(fwd)
		}
	}
	return runMuxControl[security.CapTunnel](ctx, s, req.Target, "mux_"+req.Action.String(), defaultRisk, extra, call)
}

//xops:syncclosure
func runMuxAuthorized[C security.Capability](ctx context.Context, s *Service, req MuxRequest, action string, defaultRisk security.RiskLevel, extra map[string]string, run func(authCtx context.Context, targetHop plan.HopSpec, nodeID string, sockPath pathalg.LocalSourcePath, effMaster option.ControlMasterMode) error) error {
	targetHop, nodeID, sockPath, effMaster, err := s.prepareMuxOp(ctx, req)
	if err != nil {
		return err
	}
	gateReq, err := buildMuxGateReq[C](req.Plan, targetHop, nodeID, action, sockPath, effMaster, req.Risk.OrElse(defaultRisk), extra, req.Approval, req.OperationStream)
	if err != nil {
		return err
	}
	_, _, gateErr := runAuthorized[C](ctx, s, req.Plan.PlanDigest(), nodeID, action, gateReq, req.OperationStream, false,
		func(authCtx context.Context, _ security.OperationBinding, _ *operationEmitter) (execution.ExecutionOutcome, error) {
			return nil, run(authCtx, targetHop, nodeID, sockPath, effMaster)
		})
	return gateErr
}
func runMuxControl[C security.Capability](ctx context.Context, s *Service, req MuxRequest, action string, defaultRisk security.RiskLevel, extra map[string]string, call func(authCtx context.Context, sockPath pathalg.LocalSourcePath) (ports.MuxControlResponse, error)) (ports.MuxControlResponse, error) {
	var resp ports.MuxControlResponse
	if err := runMuxAuthorized[C](ctx, s, req, action, defaultRisk, extra, func(authCtx context.Context, _ plan.HopSpec, _ string, sockPath pathalg.LocalSourcePath, _ option.ControlMasterMode) error {
		r, rErr := call(authCtx, sockPath)
		if rErr != nil || !r.IsValid() {
			return firstNonNilErr(rErr, ErrMuxMasterUnavailable)
		}
		resp = r
		return nil
	}); err != nil {
		return zeroVal[ports.MuxControlResponse](), err
	}
	return resp, nil
}

// WithMuxProxy 以同步作用域闭包打开 ControlMaster `-O proxy`（MuxActionProxy）双向透传连接，
// 退出回调时无条件关闭底层 net.Conn，确保零命令式泄漏。
//
//xops:syncclosure
//xops:borrowed
func (s *Service) WithMuxProxy(ctx context.Context, req MuxRequest, fn func(ctx context.Context, conn net.Conn) error) error {
	defer closeStream(req.OperationStream)
	if err := s.validateServiceAndCtx(ctx); err != nil {
		return err
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	return s.openMuxProxyScope(ctx, req, func(authCtx context.Context, conn net.Conn) error { return fn(authCtx, conn) })
}

type muxHalfCloser interface{ CloseWrite() error }

// RunMuxProxy 打开 `-O proxy` 连接并在 conc.RunScoped 监督下完成可关闭 stdin 与 stdout 的双向中继；
// 在 Nursery 作用域内监听 wCtx 同步中止，确保 stdin 真实读错、远端先达 EOF、背压写阻塞或 ctx 取消
// 均即时关闭 conn 与 stdin 并忠实传播非关闭故障与取消错误（0 死锁、0 goleak，适配真实 *os.File 的 fs.ErrClosed）。
func (s *Service) RunMuxProxy(ctx context.Context, req MuxRequest, stdin io.ReadCloser, stdout io.Writer) error {
	defer closeStream(req.OperationStream)
	return s.openMuxProxyScope(ctx, req, func(pCtx context.Context, conn net.Conn) error {
		var aborted atomic.Bool
		var abortOnce sync.Once
		abort := func() { abortOnce.Do(func() { aborted.Store(true); _ = closeClosers(conn, stdin) }) }
		defer abort()
		runErr := conc.RunScoped(pCtx, func(wCtx context.Context, n *conc.Nursery) error {
			defer registerSyncAbort(wCtx, abort)()
			if stdout == nil {
				return copyMuxStdin(conn, stdin, &aborted, nil)
			}
			if stdin != nil {
				if err := n.Go(func(context.Context) error { return copyMuxStdin(conn, stdin, &aborted, abort) }); err != nil {
					abort()
					return err
				}
			}
			err := copyMuxStream(stdout, conn, &aborted)
			abort()
			return err
		})
		return firstNonNilErr(runErr, pCtx.Err())
	})
}
func copyMuxStream(dst io.Writer, src io.Reader, aborted *atomic.Bool) error {
	if src == nil {
		return nil
	}
	_, err := io.Copy(dst, src)
	if err == nil || isRemotePipeClosedErr(err) || (aborted.Load() && errors.Is(err, fs.ErrClosed)) {
		return nil
	}
	return err
}
func copyMuxStdin(conn net.Conn, stdin io.Reader, aborted *atomic.Bool, abort func()) error {
	err := copyMuxStream(conn, stdin, aborted)
	if err != nil && abort != nil {
		abort()
	}
	if hc, ok := conn.(muxHalfCloser); ok && stdin != nil {
		_ = hc.CloseWrite()
	}
	return err
}

//xops:syncclosure
func (s *Service) openMuxProxyScope(ctx context.Context, req MuxRequest, run func(ctx context.Context, conn net.Conn) error) error {
	return runMuxAuthorized[security.CapTunnel](ctx, s, req, "mux_proxy", security.RiskModerate, nil, func(authCtx context.Context, _ plan.HopSpec, _ string, sockPath pathalg.LocalSourcePath, _ option.ControlMasterMode) error {
		conn, err := s.cfg.MuxSocket.OpenProxy(authCtx, sockPath)
		if err != nil || conn == nil {
			return firstNonNilErr(err, ErrMuxMasterUnavailable)
		}
		defer func() { _ = conn.Close() }()
		return run(authCtx, conn)
	})
}

// WithMuxConn 经 MuxSocketPort.DialMux 复用活跃 ControlMaster 并严格核验返回的 (HopDigest, Endpoint)
// 身份与计划末跳精确一致，在同步作用域闭包内借出 ports.TransportConn，退出时无条件关闭。
//
//xops:syncclosure
//xops:borrowed
func (s *Service) WithMuxConn(ctx context.Context, req MuxRequest, fn func(ctx context.Context, conn ports.TransportConn) error) error {
	defer closeStream(req.OperationStream)
	if err := s.validateServiceAndCtx(ctx); err != nil {
		return err
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	leafDigest, ok := req.Plan.HopDigestAt(req.Plan.Len() - 1)
	if !ok || !leafDigest.IsValid() {
		return fmt.Errorf("%w: 计划缺少有效末跳摘要", ErrInvalidRequest)
	}
	return runMuxAuthorized[security.CapTunnel](ctx, s, req, "mux_dial", security.RiskModerate, nil, func(authCtx context.Context, targetHop plan.HopSpec, nodeID string, sockPath pathalg.LocalSourcePath, effMaster option.ControlMasterMode) error {
		conn, err := s.dialVerifiedMuxConn(authCtx, nodeID, sockPath, targetHop, leafDigest, effMaster)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		return fn(authCtx, conn)
	})
}

// TryDialMuxClient 按 ControlPolicy 生效投影执行透明客户端 ControlMaster 附着（INV-C4，供 core/engine 拨号适配复用）：
//   - 仅在 ControlPath 已启用且 EffectiveMaster 为 no/auto/autoask 时尝试附着（yes/ask 强制新建主连接不走客户端附着）；
//   - autoask 模式先探测活跃套接字，存活时经 confirmMuxMasterWith 请求操作员确认（拒签/不可交互时失败关闭）；
//   - 遇 ErrNotFound/ErrMuxUnavailable 透明返回 (nil, false, nil) 供拨号层回退底层新建连接；
//   - 严格核验 DialMux 返回连接的 IsAlive()、(HopDigest, Endpoint) 精确一致，失配即关闭并失败关闭报错。
func TryDialMuxClient(ctx context.Context, muxPort ports.MuxSocketPort, env ports.EnvPort, interaction ports.InteractionPort, hop plan.HopSpec, dig plan.HopDigest) (ports.TransportConn, bool, error) {
	if muxPort == nil || !hop.IsValid() || !dig.IsValid() {
		return nil, false, nil
	}
	cp := hop.Transport().ControlPolicy()
	if eff := cp.EffectiveMaster(); !cp.IsEnabled() || (eff != option.ControlMasterNo && eff != option.ControlMasterAuto && eff != option.ControlMasterAutoAsk) {
		return nil, false, nil
	}
	sockPath, err := expandControlPath(hop, cp.Path(), env)
	if err != nil {
		return nil, false, err
	}
	if cp.EffectiveMaster() == option.ControlMasterAutoAsk {
		if ok, cErr := confirmAutoAskMuxAttach(ctx, muxPort, interaction, sockPath, hop.NodeID()); !ok || cErr != nil {
			return nil, false, cErr
		}
	}
	conn, err := muxPort.DialMux(ctx, sockPath, dig, hop.Endpoint())
	if errors.Is(err, ports.ErrNotFound) || errors.Is(err, ports.ErrMuxUnavailable) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return verifyDialedMuxConn(conn, dig, hop.Endpoint())
}
func confirmAutoAskMuxAttach(ctx context.Context, muxPort ports.MuxSocketPort, interaction ports.InteractionPort, sockPath pathalg.LocalSourcePath, nodeID string) (bool, error) {
	resp, err := muxPort.Probe(ctx, sockPath)
	if errors.Is(err, ports.ErrNotFound) || errors.Is(err, ports.ErrMuxUnavailable) {
		return false, nil
	}
	if err != nil || !resp.IsValid() || !resp.Alive() {
		return false, err
	}
	err = confirmMuxMasterWith(ctx, interaction, nodeID, domi18n.NewMessage(domi18n.KeyInteractMuxAttachBody))
	return err == nil, err
}
func verifyDialedMuxConn(conn ports.TransportConn, leafDigest plan.HopDigest, ep netaddr.Endpoint) (ports.TransportConn, bool, error) {
	if conn == nil || !conn.IsAlive() || !conn.HopDigest().Equal(leafDigest) || !conn.Endpoint().Equal(ep) {
		_ = closeClosers(conn)
		return nil, false, fmt.Errorf("%w: DialMux 返回连接无效或与计划末跳身份不匹配", ErrMuxMasterUnavailable)
	}
	return conn, true, nil
}
func (s *Service) dialVerifiedMuxConn(ctx context.Context, nodeID string, sockPath pathalg.LocalSourcePath, targetHop plan.HopSpec, leafDigest plan.HopDigest, effMaster option.ControlMasterMode) (ports.TransportConn, error) {
	if effMaster == option.ControlMasterAsk || effMaster == option.ControlMasterAutoAsk {
		if err := confirmMuxMasterWith(ctx, s.cfg.Interaction, nodeID, domi18n.NewMessage(domi18n.KeyInteractMuxAttachBody)); err != nil {
			return nil, err
		}
	}
	conn, err := s.cfg.MuxSocket.DialMux(ctx, sockPath, leafDigest, targetHop.Endpoint())
	if err != nil {
		return nil, err
	}
	verified, _, vErr := verifyDialedMuxConn(conn, leafDigest, targetHop.Endpoint())
	return verified, vErr
}
func buildMuxGateReq[C security.Capability](connPlan plan.SealedConnectionPlan, targetHop plan.HopSpec, nodeID, action string, sockPath pathalg.LocalSourcePath, effMaster option.ControlMasterMode, risk security.RiskLevel, extra map[string]string, approval algebraic.Option[gate.ApprovalSubmission], stream *events.OperationStream) (gate.GateRequest[C], error) {
	params := map[string]string{"socket_path": sockPath.String(), "effective_master": effMaster.String(), "effective_persist": targetHop.Transport().ControlPolicy().EffectivePersist().String()}
	maps.Copy(params, extra)
	return buildGateReq[C](gateReqInput{
		plan: connPlan, targetHop: targetHop, nodeID: nodeID, action: action, summary: fmt.Sprintf("%s on %s (%s)", action, nodeID, sockPath.String()),
		risk: risk, params: params, approval: approval, stream: stream,
	})
}
func (s *Service) validateMuxBaseCall(ctx context.Context, connPlan plan.SealedConnectionPlan, risk algebraic.Option[security.RiskLevel]) error {
	if err := s.validateBaseCall(ctx, connPlan, RequestTTYUnset, risk); err != nil {
		return err
	}
	if s.cfg.MuxSocket == nil {
		return fmt.Errorf("%w: MuxSocketPort 未配置", ErrPortUnavailable)
	}
	return nil
}
func (s *Service) prepareMuxOp(ctx context.Context, req MuxRequest) (zh plan.HopSpec, nodeID string, zp pathalg.LocalSourcePath, eff option.ControlMasterMode, err error) {
	if err = s.validateMuxBaseCall(ctx, req.Plan, req.Risk); err != nil {
		return zh, "", zp, option.ControlMasterNo, err
	}
	targetHop, nodeID, err := resolvePlanTargetAndNode(req.Plan, req.NodeID)
	if err != nil {
		return zh, "", zp, option.ControlMasterNo, err
	}
	cp := targetHop.Transport().ControlPolicy()
	if cp.IsDisabled() {
		return zh, "", zp, option.ControlMasterNo, fmt.Errorf("%w: ControlPath 已显式禁用（none）", ErrControlMasterDisabled)
	}
	eff = cp.EffectiveMaster()
	if p, ok := req.SocketPath.Get(); ok {
		if !cp.Path().IsEnabled() {
			eff = cp.Master()
		}
		if !p.IsValid() {
			return zh, "", zp, option.ControlMasterNo, fmt.Errorf("%w: 显式 SocketPath 无效", ErrInvalidRequest)
		}
		return targetHop, nodeID, p, eff, nil
	}
	sockPath, err := expandControlPath(targetHop, cp.Path(), s.cfg.Env)
	return targetHop, nodeID, sockPath, eff, err
}

// expandControlPath 展开 ControlPath 模板占位符（%r/%h/%p/%l/%u/%i/%j/%C）与前导 ~/；
// 对任何无法展开的前导 ~（含 Env 缺失、HomeDir 为空、~user 或字面量 ~）一律严格失败关闭。
func expandControlPath(targetHop plan.HopSpec, spec option.ControlPathSpec, env ports.EnvPort) (pathalg.LocalSourcePath, error) {
	if !spec.IsEnabled() {
		return zeroVal[pathalg.LocalSourcePath](), fmt.Errorf("%w: ControlPath 未启用", ErrControlMasterDisabled)
	}
	raw := spec.String()
	tokCtx := option.TokenContext{
		TargetHost: targetHop.Endpoint().Host().String(), Port: targetHop.Endpoint().Port(), RemoteUser: targetHop.Username().String(),
		OriginalHost: targetHop.OriginalHost().String(), JumpHost: extractJumpHostForPercentJ(targetHop),
	}
	if env != nil {
		if id, err := env.LookupLocalIdentity(); err == nil && id.IsValid() {
			tokCtx = id.ApplyToTokenContext(tokCtx)
		}
	}
	if !spec.IsLiteral() {
		expanded, err := option.ExpandPathTokens(raw, tokCtx)
		if err != nil {
			return zeroVal[pathalg.LocalSourcePath](), fmt.Errorf("%w: 展开 ControlPath 模板失败: %w", ErrInvalidRequest, err)
		}
		raw = expanded
	}
	if strings.HasPrefix(raw, "~") {
		home, hErr := pathalg.ParseLocalSourcePath(tokCtx.HomeDir)
		if (!strings.HasPrefix(raw, "~/") && !strings.HasPrefix(raw, `~\`)) || hErr != nil || !home.IsAbs() {
			return zeroVal[pathalg.LocalSourcePath](), fmt.Errorf("%w: 拒绝未展开的前导 ~ 控制套接字路径 %q", ErrInvalidRequest, raw)
		}
		raw = strings.TrimRight(tokCtx.HomeDir, `/\`) + raw[1:]
	}
	p, err := pathalg.ParseLocalSourcePath(raw)
	if err != nil {
		return zeroVal[pathalg.LocalSourcePath](), fmt.Errorf("%w: 非法控制套接字路径 %q: %w", ErrInvalidRequest, raw, err)
	}
	return p, nil
}

// extractJumpHostForPercentJ 严格遵循 RFC §3.6 与 option/solver.go：
// 仅在 ProxyJumpChain 激活时返回末跳规范主机名，其余路由（ProxyUnset/ProxyDisabled/ProxyCommandSpec）一律返回空串。
func extractJumpHostForPercentJ(targetHop plan.HopSpec) string {
	switch route := targetHop.Transport().ProxyRoute().(type) {
	case *option.ProxyJumpChain:
		if route.IsValid() {
			hops := route.Hops().Slice()
			return hops[len(hops)-1].Host()
		}
	case nil, *option.ProxyUnset, *option.ProxyDisabled, *option.ProxyCommandSpec:
		return ""
	default:
		return ""
	}
	return ""
}
