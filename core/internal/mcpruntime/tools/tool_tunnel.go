package tools

import (
	"context"
	"encoding/json/jsontext"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	"github.com/wentf9/xops-cli/core/ports"
)

type tunnelArgs struct {
	Action         string                                           `json:"action"`
	Target         string                                           `json:"target,omitzero"`
	Handle         jsontext.Value                                   `json:"handle,omitzero"`
	HandleToken    string                                           `json:"handle_token,omitzero"`
	Direction      string                                           `json:"direction,omitzero"`
	BindKind       string                                           `json:"bind_kind,omitzero"`
	BindAddr       string                                           `json:"bind_addr,omitzero"`
	TargetKind     string                                           `json:"target_kind,omitzero"`
	TargetAddr     string                                           `json:"target_addr,omitzero"`
	TUNMode        string                                           `json:"tun_mode,omitzero"`
	TUNLocalUnit   algebraic.Option[uint32]                         `json:"tun_local_unit,omitzero"`
	TUNRemoteUnit  algebraic.Option[uint32]                         `json:"tun_remote_unit,omitzero"`
	SocketPath     string                                           `json:"socket_path,omitzero"`
	ControlMaster  string                                           `json:"control_master,omitzero"`
	ControlPersist string                                           `json:"control_persist,omitzero"`
	MuxAction      string                                           `json:"mux_action,omitzero"`
	Risk           algebraic.Option[security.RiskLevel]             `json:"risk,omitzero"`
	Approval       algebraic.Option[protocol.ApprovalSubmissionDTO] `json:"approval,omitzero"`
}

func (r *Registry) callTunnel(ctx context.Context, rawArgs jsontext.Value) (protocol.CallToolResult, error) {
	if r.session == nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: SessionService 未配置", ErrServiceUnavailable)
	}
	args, err := decodeToolArgs[tunnelArgs](rawArgs)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	risk, approval, err := validateApprovalAndRisk(args.Risk, args.Approval)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	switch args.Action {
	case "start_forward":
		return r.tunnelStartForward(ctx, args, risk, approval)
	case "inspect_forward", "stop_forward":
		return r.tunnelManageForward(ctx, args)
	case "start_mux":
		return r.tunnelStartMux(ctx, args, risk, approval)
	case "inspect_mux", "stop_mux":
		return r.tunnelManageMux(ctx, args)
	case "probe_mux", "control_mux":
		return r.tunnelProbeOrControlMux(ctx, args, risk, approval)
	default:
		return protocol.CallToolResult{}, fmt.Errorf("%w: 未知 tunnel action %q", protocol.ErrInvalidParams, args.Action)
	}
}

func parseForwardSpecArgs(args tunnelArgs) (ports.ForwardSpec, error) {
	dir, err := ports.ParseForwardDirection(args.Direction)
	if err != nil {
		return zeroVal[ports.ForwardSpec](), fmt.Errorf("%w: direction 非法: %w", protocol.ErrInvalidParams, err)
	}
	if dir == ports.ForwardTUN {
		mode, mErr := ports.ParseTUNMode(args.TUNMode)
		if mErr != nil {
			return zeroVal[ports.ForwardSpec](), fmt.Errorf("%w: tun_mode 非法: %w", protocol.ErrInvalidParams, mErr)
		}
		tunSpec, tErr := ports.NewTUNSpec(mode, args.TUNLocalUnit.OrElse(ports.TUNUnitAny), args.TUNRemoteUnit.OrElse(ports.TUNUnitAny))
		if tErr != nil {
			return zeroVal[ports.ForwardSpec](), fmt.Errorf("%w: %w", protocol.ErrInvalidParams, tErr)
		}
		return ports.NewForwardTUNSpec(tunSpec)
	}
	bindKind := ports.ForwardEndpointTCP
	if args.BindKind != "" {
		if bindKind, err = ports.ParseForwardEndpointKind(args.BindKind); err != nil {
			return zeroVal[ports.ForwardSpec](), fmt.Errorf("%w: bind_kind 非法: %w", protocol.ErrInvalidParams, err)
		}
	}
	targetKind := ports.ForwardEndpointTCP
	if dir == ports.ForwardDynamic {
		targetKind = ports.ForwardEndpointInvalid
	} else if args.TargetKind != "" {
		if targetKind, err = ports.ParseForwardEndpointKind(args.TargetKind); err != nil {
			return zeroVal[ports.ForwardSpec](), fmt.Errorf("%w: target_kind 非法: %w", protocol.ErrInvalidParams, err)
		}
	}
	spec, err := ports.NewTypedForwardSpec(dir, bindKind, args.BindAddr, targetKind, args.TargetAddr)
	if err != nil {
		return zeroVal[ports.ForwardSpec](), fmt.Errorf("%w: %w", protocol.ErrInvalidParams, err)
	}
	return spec, nil
}

func (r *Registry) tunnelStartForward(
	ctx context.Context,
	args tunnelArgs,
	risk algebraic.Option[security.RiskLevel],
	approval algebraic.Option[gate.ApprovalSubmission],
) (protocol.CallToolResult, error) {
	resolved, err := r.resolveTarget(ctx, args.Target, option.UnsetOptionLayer())
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	spec, err := parseForwardSpecArgs(args)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	info, err := r.session.StartForward(ctx, ucsess.StartForwardRequest{
		Plan:     resolved.Plan(),
		Spec:     spec,
		NodeID:   resolved.NodeID(),
		Risk:     risk,
		Approval: approval,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	r.mu.Lock()
	tok := storeHandleMap(r.tunnelHandles, r.maxHandles, info.Handle())
	r.mu.Unlock()
	return protocol.NewToolSuccessResult(struct {
		Handle      plan.ManagedHandle[plan.KindTunnel] `json:"handle"`
		HandleToken string                              `json:"handle_token"`
		BoundAddr   string                              `json:"bound_addr"`
		Spec        ports.ForwardSpec                   `json:"spec"`
	}{info.Handle(), tok, info.BoundAddr(), info.Spec()})
}

func (r *Registry) tunnelManageForward(ctx context.Context, args tunnelArgs) (protocol.CallToolResult, error) {
	explicit, err := decodeOptionalHandle[plan.KindTunnel](args.Handle)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	h, err := resolveHandleArg(&r.mu, r.tunnelHandles, explicit, args.HandleToken)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	if args.Action == "stop_forward" {
		if err := r.session.StopForward(ctx, h); err != nil {
			return protocol.CallToolResult{}, err
		}
		r.mu.Lock()
		delete(r.tunnelHandles, h.String())
		r.mu.Unlock()
		return protocol.NewToolSuccessResult(struct {
			Stopped     bool   `json:"stopped"`
			HandleToken string `json:"handle_token"`
		}{true, h.String()})
	}
	st, err := r.session.InspectForward(ctx, h)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	errMsg := ""
	if st.Err() != nil {
		errMsg = security.SanitizePromptText(st.Err().Error())
	}
	return protocol.NewToolSuccessResult(struct {
		HandleToken string            `json:"handle_token"`
		Active      bool              `json:"active"`
		BoundAddr   string            `json:"bound_addr"`
		Spec        ports.ForwardSpec `json:"spec"`
		Error       string            `json:"error,omitzero"`
	}{h.String(), st.Active(), st.BoundAddr(), st.Spec(), errMsg})
}

func (r *Registry) tunnelStartMux(
	ctx context.Context,
	args tunnelArgs,
	risk algebraic.Option[security.RiskLevel],
	approval algebraic.Option[gate.ApprovalSubmission],
) (protocol.CallToolResult, error) {
	var directives []string
	if args.SocketPath != "" {
		directives = append(directives, "ControlPath="+args.SocketPath)
	}
	if args.ControlMaster != "" {
		directives = append(directives, "ControlMaster="+args.ControlMaster)
	}
	if args.ControlPersist != "" {
		directives = append(directives, "ControlPersist="+args.ControlPersist)
	}
	cliOpts := option.UnsetOptionLayer()
	if len(directives) > 0 {
		var err error
		cliOpts, err = option.ParseOptionLayer(directives...)
		if err != nil {
			return protocol.CallToolResult{}, fmt.Errorf("%w: ControlMaster 选项非法: %w", protocol.ErrInvalidParams, err)
		}
	}
	resolved, err := r.resolveTarget(ctx, args.Target, cliOpts)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	info, err := r.session.StartControlMaster(ctx, ucsess.ControlMasterRequest{
		Plan:     resolved.Plan(),
		NodeID:   resolved.NodeID(),
		Risk:     risk,
		Approval: approval,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	var tok string
	if h, ok := info.Handle().Get(); ok {
		r.mu.Lock()
		tok = storeHandleMap(r.muxHandles, r.maxHandles, h)
		r.mu.Unlock()
	}
	return protocol.NewToolSuccessResult(struct {
		Handle           algebraic.Option[plan.ManagedHandle[plan.KindMux]] `json:"handle,omitzero"`
		HandleToken      string                                             `json:"handle_token,omitzero"`
		SocketPath       pathalg.LocalSourcePath                            `json:"socket_path"`
		MasterPID        uint32                                             `json:"master_pid,omitzero"`
		ReusedExisting   bool                                               `json:"reused_existing"`
		EffectiveMaster  option.ControlMasterMode                           `json:"effective_master"`
		EffectivePersist option.ControlPersistSpec                          `json:"effective_persist"`
	}{info.Handle(), tok, info.SocketPath(), info.MasterPID(), info.ReusedExisting(), info.EffectiveMaster(), info.EffectivePersist()})
}

func (r *Registry) tunnelManageMux(ctx context.Context, args tunnelArgs) (protocol.CallToolResult, error) {
	explicit, err := decodeOptionalHandle[plan.KindMux](args.Handle)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	h, err := resolveHandleArg(&r.mu, r.muxHandles, explicit, args.HandleToken)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	if args.Action == "stop_mux" {
		if err := r.session.StopControlMaster(ctx, h); err != nil {
			return protocol.CallToolResult{}, err
		}
		r.mu.Lock()
		delete(r.muxHandles, h.String())
		r.mu.Unlock()
		return protocol.NewToolSuccessResult(struct {
			Stopped     bool   `json:"stopped"`
			HandleToken string `json:"handle_token"`
		}{true, h.String()})
	}
	st, err := r.session.InspectControlMaster(ctx, h)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		HandleToken      string                    `json:"handle_token"`
		Active           bool                      `json:"active"`
		SocketPath       pathalg.LocalSourcePath   `json:"socket_path"`
		EffectiveMaster  option.ControlMasterMode  `json:"effective_master"`
		EffectivePersist option.ControlPersistSpec `json:"effective_persist"`
	}{h.String(), st.Active(), st.SocketPath(), st.EffectiveMaster(), st.EffectivePersist()})
}

func (r *Registry) tunnelProbeOrControlMux(
	ctx context.Context,
	args tunnelArgs,
	risk algebraic.Option[security.RiskLevel],
	approval algebraic.Option[gate.ApprovalSubmission],
) (protocol.CallToolResult, error) {
	resolved, err := r.resolveTarget(ctx, args.Target, option.UnsetOptionLayer())
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	var sockOpt algebraic.Option[pathalg.LocalSourcePath]
	if strings.TrimSpace(args.SocketPath) != "" {
		sp, sErr := pathalg.ParseLocalSourcePath(args.SocketPath)
		if sErr != nil {
			return protocol.CallToolResult{}, fmt.Errorf("%w: socket_path 非法: %w", protocol.ErrInvalidParams, sErr)
		}
		sockOpt = algebraic.Some(sp)
	}
	muxReq := ucsess.MuxRequest{
		Plan:       resolved.Plan(),
		NodeID:     resolved.NodeID(),
		SocketPath: sockOpt,
		Risk:       risk,
		Approval:   approval,
	}
	if args.Action == "probe_mux" {
		resp, err := r.session.ProbeMux(ctx, muxReq)
		if err != nil {
			return protocol.CallToolResult{}, err
		}
		return protocol.NewToolSuccessResult(resp)
	}
	muxAct, err := ports.ParseMuxControlAction(args.MuxAction)
	if err != nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: mux_action 非法: %w", protocol.ErrInvalidParams, err)
	}
	var fwdOpt algebraic.Option[ports.ForwardSpec]
	if muxAct == ports.MuxActionForward || muxAct == ports.MuxActionCancel {
		fwd, fErr := parseForwardSpecArgs(args)
		if fErr != nil {
			return protocol.CallToolResult{}, fErr
		}
		fwdOpt = algebraic.Some(fwd)
	}
	resp, err := r.session.ControlMux(ctx, ucsess.MuxControlRequest{
		Target:  muxReq,
		Action:  muxAct,
		Forward: fwdOpt,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(resp)
}

func decodeOptionalHandle[K plan.HandleKind](raw jsontext.Value) (algebraic.Option[plan.ManagedHandle[K]], error) {
	if len(raw) == 0 {
		return algebraic.None[plan.ManagedHandle[K]](), nil
	}
	var h plan.ManagedHandle[K]
	if err := protocol.UnmarshalStrict([]byte(raw), &h); err != nil {
		return algebraic.None[plan.ManagedHandle[K]](), err
	}
	return algebraic.Some(h), nil
}
