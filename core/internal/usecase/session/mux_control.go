package session

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
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
func runMuxAuthorized[C security.Capability](ctx context.Context, s *Service, req MuxRequest, action string, defaultRisk security.RiskLevel, extra map[string]string, run func(authCtx context.Context, targetHop plan.HopSpec, nodeID string, sockPath pathalg.LocalSourcePath) error) error {
	targetHop, nodeID, sockPath, err := s.prepareMuxOp(ctx, req)
	if err != nil {
		return err
	}
	gateReq, err := buildMuxGateReq[C](req.Plan, targetHop, nodeID, action, sockPath, req.Risk.OrElse(defaultRisk), extra, req.Approval, req.OperationStream)
	if err != nil {
		return err
	}
	_, _, gateErr := runAuthorized[C](ctx, s, req.Plan.PlanDigest(), nodeID, action, gateReq, req.OperationStream, false,
		func(authCtx context.Context, _ security.OperationBinding, _ *operationEmitter) (execution.ExecutionOutcome, error) {
			return nil, run(authCtx, targetHop, nodeID, sockPath)
		})
	return gateErr
}
func runMuxControl[C security.Capability](ctx context.Context, s *Service, req MuxRequest, action string, defaultRisk security.RiskLevel, extra map[string]string, call func(authCtx context.Context, sockPath pathalg.LocalSourcePath) (ports.MuxControlResponse, error)) (ports.MuxControlResponse, error) {
	var resp ports.MuxControlResponse
	if err := runMuxAuthorized[C](ctx, s, req, action, defaultRisk, extra, func(authCtx context.Context, _ plan.HopSpec, _ string, sockPath pathalg.LocalSourcePath) error {
		r, rErr := call(authCtx, sockPath)
		if rErr != nil {
			return rErr
		}
		if !r.IsValid() {
			return ErrMuxMasterUnavailable
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
	if fn == nil {
		return ports.ErrNilCallback
	}
	return s.openMuxProxyScope(ctx, req, func(authCtx context.Context, conn net.Conn) error { return fn(authCtx, conn) })
}

type muxHalfCloser interface{ CloseWrite() error }

// RunMuxProxy 打开 `-O proxy` 连接并在 conc.RunScoped 监督下完成 stdin/stdout 与 ControlMaster 的双向中继；
// stdin 读尽时若底层连接支持半关闭则调用 CloseWrite，stdout 结束或上下文取消时立即关闭连接避免泄漏。
func (s *Service) RunMuxProxy(ctx context.Context, req MuxRequest, stdin io.Reader, stdout io.Writer) error {
	defer closeStream(req.OperationStream)
	return s.openMuxProxyScope(ctx, req, func(pCtx context.Context, conn net.Conn) error {
		return conc.RunScoped(pCtx, func(wCtx context.Context, n *conc.Nursery) error {
			stopClose := context.AfterFunc(wCtx, func() { _ = conn.Close() })
			defer stopClose()
			if stdout == nil {
				return copyMuxStdin(conn, stdin)
			}
			if stdin != nil {
				if err := n.Go(func(context.Context) error { return copyMuxStdin(conn, stdin) }); err != nil {
					return err
				}
			}
			return copyPipeBestEffort(stdout, conn)
		})
	})
}

func copyMuxStdin(conn net.Conn, stdin io.Reader) error {
	err := copyPipeBestEffort(conn, stdin)
	if hc, ok := conn.(muxHalfCloser); ok && stdin != nil {
		_ = hc.CloseWrite()
	}
	return err
}

//xops:syncclosure
func (s *Service) openMuxProxyScope(ctx context.Context, req MuxRequest, run func(ctx context.Context, conn net.Conn) error) error {
	return runMuxAuthorized[security.CapTunnel](ctx, s, req, "mux_proxy", security.RiskModerate, nil, func(authCtx context.Context, _ plan.HopSpec, _ string, sockPath pathalg.LocalSourcePath) error {
		conn, err := s.cfg.MuxSocket.OpenProxy(authCtx, sockPath)
		if err != nil {
			return err
		}
		if conn == nil {
			return ErrMuxMasterUnavailable
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
	if fn == nil {
		return ports.ErrNilCallback
	}
	leafDigest, ok := req.Plan.HopDigestAt(req.Plan.Len() - 1)
	if !ok || !leafDigest.IsValid() {
		return fmt.Errorf("%w: 计划缺少有效末跳摘要", ErrInvalidRequest)
	}
	return runMuxAuthorized[security.CapTunnel](ctx, s, req, "mux_dial", security.RiskModerate, nil, func(authCtx context.Context, targetHop plan.HopSpec, nodeID string, sockPath pathalg.LocalSourcePath) error {
		conn, err := s.dialVerifiedMuxConn(authCtx, nodeID, sockPath, targetHop, leafDigest)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		return fn(authCtx, conn)
	})
}

func (s *Service) dialVerifiedMuxConn(ctx context.Context, nodeID string, sockPath pathalg.LocalSourcePath, targetHop plan.HopSpec, leafDigest plan.HopDigest) (ports.TransportConn, error) {
	if eff := targetHop.Transport().ControlPolicy().EffectiveMaster(); eff == option.ControlMasterAsk || eff == option.ControlMasterAutoAsk {
		if err := s.confirmMuxMaster(ctx, nodeID, "Attach to active ControlMaster via DialMux"); err != nil {
			return nil, err
		}
	}
	conn, err := s.cfg.MuxSocket.DialMux(ctx, sockPath, leafDigest, targetHop.Endpoint())
	if err != nil {
		return nil, err
	}
	if conn == nil || !conn.IsAlive() || !conn.HopDigest().Equal(leafDigest) || !conn.Endpoint().Equal(targetHop.Endpoint()) {
		_ = closeClosers(conn)
		return nil, fmt.Errorf("%w: DialMux 返回连接无效或与计划末跳身份不匹配", ErrMuxMasterUnavailable)
	}
	return conn, nil
}
func buildMuxGateReq[C security.Capability](connPlan plan.SealedConnectionPlan, targetHop plan.HopSpec, nodeID, action string, sockPath pathalg.LocalSourcePath, risk security.RiskLevel, extra map[string]string, approval algebraic.Option[gate.ApprovalSubmission], stream *events.OperationStream) (gate.GateRequest[C], error) {
	cp := targetHop.Transport().ControlPolicy()
	params := map[string]string{"socket_path": sockPath.String(), "effective_master": cp.EffectiveMaster().String(), "effective_persist": cp.EffectivePersist().String()}
	maps.Copy(params, extra)
	return buildGateReq[C](gateReqInput{
		plan: connPlan, targetHop: targetHop, nodeID: nodeID, action: action,
		summary: fmt.Sprintf("%s on %s (%s)", action, nodeID, sockPath.String()),
		risk:    risk, params: params, approval: approval, stream: stream,
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
func (s *Service) prepareMuxOp(ctx context.Context, req MuxRequest) (plan.HopSpec, string, pathalg.LocalSourcePath, error) {
	zh, zp := zeroVal[plan.HopSpec](), zeroVal[pathalg.LocalSourcePath]()
	if err := s.validateMuxBaseCall(ctx, req.Plan, req.Risk); err != nil {
		return zh, "", zp, err
	}
	targetHop, nodeID, err := resolvePlanTargetAndNode(req.Plan, req.NodeID)
	if err != nil {
		return zh, "", zp, err
	}
	cp := targetHop.Transport().ControlPolicy()
	if cp.IsDisabled() {
		return zh, "", zp, fmt.Errorf("%w: ControlPath 已显式禁用（none）", ErrControlMasterDisabled)
	}
	if p, ok := req.SocketPath.Get(); ok {
		if !p.IsValid() {
			return zh, "", zp, fmt.Errorf("%w: 显式 SocketPath 无效", ErrInvalidRequest)
		}
		return targetHop, nodeID, p, nil
	}
	sockPath, err := expandControlPath(req.Plan, targetHop, cp.Path(), s.cfg.Env)
	return targetHop, nodeID, sockPath, err
}
