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
// 严格强制 IsClosed() 停机门禁与 Prepare 启动对账/恢复 Fail-Closed 门禁；
// 当报文为通知（无 id）时返回 (nil, false, nil)；Gate 处于 Halted 熔断态时拒绝全部请求并返回 -32001。
func (s *Server) HandleMessage(ctx context.Context, raw []byte) ([]byte, bool, error) {
	if err := s.checkReady(ctx); err != nil {
		return nil, false, err
	}
	if err := s.ensurePrepared(ctx); err != nil && !errors.Is(err, gate.ErrGateHalted) {
		return nil, false, err
	}
	if int64(len(raw)) > s.maxMessageBytes {
		return encodeErrResp(algebraic.None[protocol.RequestID](), protocol.CodeInvalidRequest, ErrMessageTooLarge.Error(), protocol.ToolErrorPayload{
			Code: "message_too_large", Message: ErrMessageTooLarge.Error(),
		})
	}
	req, decErr := protocol.DecodeRequest(raw)
	if decErr != nil {
		code, errCode := classifyDecodeError(decErr)
		clean := protocol.SanitizeErrorMessage(decErr.Error())
		return encodeErrResp(algebraic.None[protocol.RequestID](), code, clean, protocol.ToolErrorPayload{
			Code: errCode, Message: clean,
		})
	}
	resp, hasResp, err := s.handleDecodedRequest(ctx, req)
	if err != nil || !hasResp {
		return nil, false, err
	}
	out, err := protocol.MarshalCanonical(resp)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// handleDecodedRequest 处理已完成单次解码的 JSON-RPC 请求（供 HandleMessage 与 Streamable HTTP 共用，避免重复解码）。
func (s *Server) handleDecodedRequest(ctx context.Context, req protocol.Request) (protocol.Response, bool, error) {
	if s.gate.IsHalted() {
		s.registry.ClearTrackedHandles()
		if req.IsNotification() {
			return protocol.Response{}, false, nil
		}
		resp, err := protocol.NewErrorResponse(req.ID, protocol.CodeGateHalted, gate.ErrGateHalted.Error(), protocol.ToolErrorPayload{
			Code: "gate_halted", Message: gate.ErrGateHalted.Error(), Halted: true,
		})
		return resp, err == nil, err
	}
	if req.IsNotification() {
		return protocol.Response{}, false, nil
	}
	id, _ := req.ID.Get()
	resp, err := s.dispatchRequest(ctx, id, req)
	if err != nil {
		return protocol.Response{}, false, err
	}
	return resp, true, nil
}

func classifyDecodeError(err error) (int, string) {
	if errors.Is(err, protocol.ErrParseJSON) {
		return protocol.CodeParseError, "parse_error"
	}
	return protocol.CodeInvalidRequest, "invalid_request"
}

func (s *Server) isPrepared() bool {
	if s == nil || !s.valid {
		return false
	}
	s.prepMu.Lock()
	ready := s.prepared
	s.prepMu.Unlock()
	return ready
}

// ensurePrepared 在首次服务前幂等执行启动期 O(1) 崩溃审计对账与 Journal 恢复；
// 若启动期检查失败，s.prepared 保持 false 且每次后续请求均严格 Fail-Closed 拒绝。
func (s *Server) ensurePrepared(ctx context.Context) error {
	if err := s.checkReady(ctx); err != nil {
		return err
	}
	if s.isPrepared() {
		return nil
	}
	_, err := s.Prepare(ctx)
	return err
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
			clean := protocol.SanitizeErrorMessage(err.Error())
			return protocol.NewErrorResponse(algebraic.Some(id), protocol.CodeInvalidParams, clean, protocol.ToolErrorPayload{
				Code: "invalid_params", Message: clean,
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
		clean := protocol.SanitizeErrorMessage(err.Error())
		return protocol.NewErrorResponse(algebraic.Some(id), protocol.CodeInvalidParams, clean, protocol.ToolErrorPayload{
			Code: "invalid_params", Message: clean,
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
		clean := protocol.SanitizeErrorMessage(err.Error())
		return protocol.NewErrorResponse(algebraic.Some(id), protocol.CodeInvalidParams, clean, protocol.ToolErrorPayload{
			Code: "tool_not_found", Message: clean,
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
