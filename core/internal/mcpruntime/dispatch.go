package mcpruntime

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	"github.com/wentf9/xops-cli/core/ports"
)

// HandleMessage 处理单条入站 JSON-RPC 2.0 MCP 报文并返回确定性 JSON 响应字节；
// 当报文为通知（无 id）时返回 (nil, false, nil)；Gate 处于 Halted 熔断态时拒绝全部请求并返回 -32001。
func (s *Server) HandleMessage(ctx context.Context, raw []byte) ([]byte, bool, error) {
	if s == nil || !s.valid {
		return nil, false, ErrServerNotInitialized
	}
	if ctx == nil {
		return nil, false, ports.ErrNilContext
	}
	if int64(len(raw)) > s.maxMessageBytes {
		return encodeErrResp(algebraic.None[protocol.RequestID](), protocol.CodeInvalidRequest, ErrMessageTooLarge.Error(), protocol.ToolErrorPayload{
			Code: "message_too_large", Message: ErrMessageTooLarge.Error(),
		})
	}
	req, decErr := protocol.DecodeRequest(raw)
	if decErr != nil {
		return encodeErrResp(algebraic.None[protocol.RequestID](), protocol.CodeParseError, security.SanitizePromptText(decErr.Error()), protocol.ToolErrorPayload{
			Code: "parse_error", Message: security.SanitizePromptText(decErr.Error()),
		})
	}
	if s.gate.IsHalted() {
		s.registry.ClearTrackedHandles()
		if req.IsNotification() {
			return nil, false, nil
		}
		return encodeHaltedResp(req.ID)
	}
	if req.IsNotification() {
		return nil, false, nil
	}
	id, _ := req.ID.Get()
	resp, err := s.dispatchRequest(ctx, id, req)
	if err != nil {
		return nil, false, err
	}
	out, err := protocol.MarshalCanonical(resp)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func (s *Server) dispatchRequest(ctx context.Context, id protocol.RequestID, req protocol.Request) (protocol.Response, error) {
	switch req.Method {
	case protocol.MethodInitialize:
		return s.handleInitialize(id, req.Params)
	case protocol.MethodPing:
		return protocol.NewResultResponse(id, protocol.EmptyResult{})
	case protocol.MethodToolsList:
		return protocol.NewResultResponse(id, protocol.ListToolsResult{Tools: s.descriptors})
	case protocol.MethodToolsCall:
		return s.handleToolsCall(ctx, id, req.Params)
	default:
		return protocol.NewErrorResponse(algebraic.Some(id), protocol.CodeMethodNotFound, "method not found: "+security.SanitizePromptText(req.Method), protocol.ToolErrorPayload{
			Code: "method_not_found", Message: "unsupported MCP method",
		})
	}
}

func (s *Server) handleInitialize(id protocol.RequestID, params jsontext.Value) (protocol.Response, error) {
	negotiated := protocol.LatestProtocolVersion
	if len(params) > 0 {
		var p protocol.InitializeParams
		if err := protocol.UnmarshalStrict([]byte(params), &p); err != nil {
			return protocol.NewErrorResponse(algebraic.Some(id), protocol.CodeInvalidParams, security.SanitizePromptText(err.Error()), protocol.ToolErrorPayload{
				Code: "invalid_params", Message: security.SanitizePromptText(err.Error()),
			})
		}
		negotiated = protocol.NegotiateProtocolVersion(p.ProtocolVersion)
	}
	return protocol.NewResultResponse(id, protocol.InitializeResult{
		ProtocolVersion: negotiated,
		Capabilities: protocol.ServerCapabilities{
			Tools: &protocol.ToolsCapability{ListChanged: false},
		},
		ServerInfo: protocol.ImplementationInfo{
			Name:    s.serverName,
			Version: s.serverVersion,
		},
		Instructions: s.instructions,
	})
}

func (s *Server) handleToolsCall(ctx context.Context, id protocol.RequestID, params jsontext.Value) (protocol.Response, error) {
	var p protocol.CallToolParams
	if err := protocol.UnmarshalStrict([]byte(params), &p); err != nil {
		return protocol.NewErrorResponse(algebraic.Some(id), protocol.CodeInvalidParams, security.SanitizePromptText(err.Error()), protocol.ToolErrorPayload{
			Code: "invalid_params", Message: security.SanitizePromptText(err.Error()),
		})
	}
	if strings.TrimSpace(p.Name) == "" {
		return protocol.NewErrorResponse(algebraic.Some(id), protocol.CodeInvalidParams, "tools/call 缺少工具名 name", protocol.ToolErrorPayload{
			Code: "invalid_params", Message: "missing tool name",
		})
	}
	callRes, rpcCode, err := s.registry.CallTool(ctx, p.Name, p.Arguments)
	if rpcCode == protocol.CodeGateHalted || s.gate.IsHalted() {
		return protocol.NewErrorResponse(algebraic.Some(id), protocol.CodeGateHalted, gate.ErrGateHalted.Error(), protocol.ToolErrorPayload{
			Code: "gate_halted", Message: gate.ErrGateHalted.Error(), Halted: true,
		})
	}
	if err != nil && errors.Is(err, protocol.ErrToolNotFound) {
		return protocol.NewErrorResponse(algebraic.Some(id), protocol.CodeInvalidParams, security.SanitizePromptText(err.Error()), protocol.ToolErrorPayload{
			Code: "tool_not_found", Message: security.SanitizePromptText(err.Error()),
		})
	}
	return protocol.NewResultResponse(id, callRes)
}

func encodeErrResp(id algebraic.Option[protocol.RequestID], code int, msg string, data any) ([]byte, bool, error) {
	resp, err := protocol.NewErrorResponse(id, code, msg, data)
	if err != nil {
		return nil, false, err
	}
	raw, err := protocol.MarshalCanonical(resp)
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

func encodeHaltedResp(id algebraic.Option[protocol.RequestID]) ([]byte, bool, error) {
	return encodeErrResp(id, protocol.CodeGateHalted, gate.ErrGateHalted.Error(), protocol.ToolErrorPayload{
		Code: "gate_halted", Message: gate.ErrGateHalted.Error(), Halted: true,
	})
}

func (s *Server) checkReady(ctx context.Context) error {
	if s == nil || !s.valid {
		return ErrServerNotInitialized
	}
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.IsClosed() {
		return ErrServerClosed
	}
	return nil
}

func (s *Server) beginTransport(ctx context.Context) (context.Context, func(), error) {
	if err := s.checkReady(ctx); err != nil {
		return nil, nil, err
	}
	s.stateMu.Lock()
	if s.closing {
		s.stateMu.Unlock()
		return nil, nil, ErrServerClosed
	}
	s.inflight++
	s.stateMu.Unlock()

	runCtx, cancelRun := context.WithCancelCause(ctx)
	bridgeDone := make(chan struct{})
	stopBridge := context.AfterFunc(s.lifeCtx, func() {
		defer close(bridgeDone)
		cancelRun(context.Cause(s.lifeCtx))
	})
	cleanup := func() {
		if !stopBridge() {
			<-bridgeDone
		}
		cancelRun(nil)
		s.stateMu.Lock()
		s.inflight--
		if s.closing && s.inflight == 0 && s.drainCh != nil {
			close(s.drainCh)
			s.drainCh = nil
		}
		s.stateMu.Unlock()
	}
	return runCtx, cleanup, nil
}

func (s *Server) emitDiag(sev events.Severity, code, msg string, attrs map[string]string) {
	if s == nil || s.bus == nil || s.bus.IsClosed() {
		return
	}
	tid, err := trace.NewTraceIDFrom(s.entropy)
	if err != nil {
		return
	}
	meta, err := events.NewEventMeta(events.EventMetaSpec{
		TraceID:    tid,
		OccurredAt: s.clock.Now().UTC().Round(0),
		Seq:        s.diagSeq.Add(1),
	})
	if err != nil {
		return
	}
	ev, err := events.NewDiagnosticEvent(events.DiagnosticSpec{
		Meta:     meta,
		Scope:    events.DiagnosticScopeMCP,
		Severity: sev,
		Code:     code,
		Message:  security.SanitizePromptText(msg),
		Attrs:    attrs,
	})
	if err == nil {
		_ = s.bus.Publish(ev)
	}
}
