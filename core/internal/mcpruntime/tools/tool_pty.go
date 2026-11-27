package tools

import (
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	"github.com/wentf9/xops-cli/core/ports"
)

type terminalSessionArgs struct {
	Action         string                                             `json:"action"`
	Target         string                                             `json:"target,omitzero"`
	Handle         algebraic.Option[plan.ManagedHandle[plan.KindPTY]] `json:"handle,omitzero"`
	HandleToken    string                                             `json:"handle_token,omitzero"`
	Term           string                                             `json:"term,omitzero"`
	Cols           uint16                                             `json:"cols,omitzero"`
	Rows           uint16                                             `json:"rows,omitzero"`
	MaxBufferBytes int                                                `json:"max_buffer_bytes,omitzero"`
	MaxBytes       int                                                `json:"max_bytes,omitzero"`
	Wait           bool                                               `json:"wait,omitzero"`
	Data           algebraic.Option[string]                           `json:"data,omitzero"`
	DataB64        algebraic.Option[string]                           `json:"data_b64,omitzero"`
	Signal         string                                             `json:"signal,omitzero"`
	Risk           algebraic.Option[security.RiskLevel]               `json:"risk,omitzero"`
	Approval       algebraic.Option[protocol.ApprovalSubmissionDTO]   `json:"approval,omitzero"`
}

func (r *Registry) callTerminalSession(ctx context.Context, rawArgs jsontext.Value) (protocol.CallToolResult, error) {
	if r.session == nil {
		return protocol.CallToolResult{}, domi18n.EF(ErrServiceUnavailable, domi18n.KeyCommonMissingDep, domi18n.Str("component", "SessionService"))
	}
	args, err := decodeToolArgs[terminalSessionArgs](rawArgs)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	risk, approval, err := validateApprovalAndRisk(args.Risk, args.Approval)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	if args.Action == "open" {
		return r.ptyOpen(ctx, args, risk, approval)
	}
	h, err := resolveHandleArg(&r.mu, r.ptyHandles, args.Handle, args.HandleToken)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	switch args.Action {
	case "read":
		return r.ptyRead(ctx, h, args)
	case "write":
		return r.ptyWrite(ctx, h, args)
	case "resize":
		return r.ptyResize(ctx, h, args)
	case "signal":
		if args.Signal == "" {
			return protocol.CallToolResult{}, domi18n.EF(protocol.ErrInvalidParams, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "signal"))
		}
		if err := r.session.SignalPTY(ctx, h, args.Signal); err != nil {
			return protocol.CallToolResult{}, err
		}
		return protocol.NewToolSuccessResult(struct {
			Signaled bool   `json:"signaled"`
			Signal   string `json:"signal"`
		}{true, args.Signal})
	case "inspect":
		return r.ptyInspect(ctx, h)
	case "close":
		if err := r.session.ClosePTY(ctx, h); err != nil {
			return protocol.CallToolResult{}, err
		}
		r.mu.Lock()
		delete(r.ptyHandles, h.String())
		r.mu.Unlock()
		return protocol.NewToolSuccessResult(struct {
			Closed      bool   `json:"closed"`
			HandleToken string `json:"handle_token"`
		}{true, h.String()})
	default:
		return protocol.CallToolResult{}, domi18n.EF(protocol.ErrInvalidParams, domi18n.KeyMCPUnknownToolAction, domi18n.Str("tool", protocol.ToolNameTerminalSession), domi18n.BoundStr("action", args.Action))
	}
}

func (r *Registry) ptyOpen(
	ctx context.Context,
	args terminalSessionArgs,
	risk algebraic.Option[security.RiskLevel],
	approval algebraic.Option[gate.ApprovalSubmission],
) (protocol.CallToolResult, error) {
	resolved, err := r.resolveTarget(ctx, args.Target, option.UnsetOptionLayer())
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	var szOpt algebraic.Option[ports.TerminalSize]
	if args.Cols > 0 || args.Rows > 0 {
		sz, sErr := ports.NewTerminalSize(args.Cols, args.Rows)
		if sErr != nil {
			return protocol.CallToolResult{}, domi18n.WrapSentinel(protocol.ErrInvalidParams, sErr)
		}
		szOpt = algebraic.Some(sz)
	}
	h, err := r.session.OpenPTY(ctx, ucsess.OpenPTYRequest{
		Plan:           resolved.Plan(),
		NodeID:         resolved.NodeID(),
		Term:           args.Term,
		Size:           szOpt,
		MaxBufferBytes: args.MaxBufferBytes,
		Risk:           risk,
		Approval:       approval,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	r.mu.Lock()
	tok := storeHandleMap(r.ptyHandles, r.maxHandles, h)
	r.mu.Unlock()
	return protocol.NewToolSuccessResult(struct {
		Handle      plan.ManagedHandle[plan.KindPTY] `json:"handle"`
		HandleToken string                           `json:"handle_token"`
		NodeID      string                           `json:"node_id"`
	}{h, tok, resolved.NodeID()})
}

func (r *Registry) ptyRead(ctx context.Context, h plan.ManagedHandle[plan.KindPTY], args terminalSessionArgs) (protocol.CallToolResult, error) {
	res, err := r.session.ReadPTY(ctx, ucsess.PTYReadRequest{
		Handle:   h,
		MaxBytes: args.MaxBytes,
		Wait:     args.Wait,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	raw := res.Data()
	utf8Text := ""
	if utf8.Valid(raw) {
		utf8Text = string(raw)
	}
	return protocol.NewToolSuccessResult(struct {
		Data         string `json:"data,omitzero"`
		DataB64      string `json:"data_b64"`
		EOF          bool   `json:"eof"`
		DroppedBytes uint64 `json:"dropped_bytes"`
	}{
		Data:         utf8Text,
		DataB64:      base64.StdEncoding.EncodeToString(raw),
		EOF:          res.EOF(),
		DroppedBytes: res.DroppedBytes(),
	})
}

func (r *Registry) ptyWrite(ctx context.Context, h plan.ManagedHandle[plan.KindPTY], args terminalSessionArgs) (protocol.CallToolResult, error) {
	payload, err := decodeTextOrBase64(args.Data, args.DataB64)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	n, err := r.session.WritePTY(ctx, h, payload)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		BytesWritten int `json:"bytes_written"`
	}{n})
}

func (r *Registry) ptyResize(ctx context.Context, h plan.ManagedHandle[plan.KindPTY], args terminalSessionArgs) (protocol.CallToolResult, error) {
	sz, err := ports.NewTerminalSize(args.Cols, args.Rows)
	if err != nil {
		return protocol.CallToolResult{}, domi18n.WrapSentinel(protocol.ErrInvalidParams, err)
	}
	if err := r.session.ResizePTY(ctx, h, sz); err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		Resized bool               `json:"resized"`
		Size    ports.TerminalSize `json:"size"`
	}{true, sz})
}

func (r *Registry) ptyInspect(ctx context.Context, h plan.ManagedHandle[plan.KindPTY]) (protocol.CallToolResult, error) {
	st, err := r.session.InspectPTY(ctx, h)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		HandleToken   string             `json:"handle_token"`
		Active        bool               `json:"active"`
		EOF           bool               `json:"eof"`
		Term          string             `json:"term"`
		Size          ports.TerminalSize `json:"size"`
		BufferedBytes int                `json:"buffered_bytes"`
		DroppedBytes  uint64             `json:"dropped_bytes"`
	}{
		HandleToken:   h.String(),
		Active:        st.Active(),
		EOF:           st.EOF(),
		Term:          st.Term(),
		Size:          st.Size(),
		BufferedBytes: st.BufferedBytes(),
		DroppedBytes:  st.DroppedBytes(),
	})
}
