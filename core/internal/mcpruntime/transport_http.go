package mcpruntime

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
)

const (
	headerMCPSessionID  = "Mcp-Session-Id"
	headerContentType   = "Content-Type"
	headerAccept        = "Accept"
	mimeJSON            = "application/json"
	mimeEventStream     = "text/event-stream"
	sessionIDEntropyLen = 16
)

// Handler 返回完整的 Streamable HTTP MCP 与 10 GiB 流式传输 http.Handler；
// 供 ServeHTTPListener / ListenAndServeHTTP 及本地回环集成测试直接挂载，全部端点均受 Host/Origin/Session/Halted 保护。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", s.handleMCPHTTP)
	mux.HandleFunc("/transfers/", s.handleTransferHTTP)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s == nil || !s.valid {
			writeHTTPJSONError(w, http.StatusServiceUnavailable, "server_uninitialized", ErrServerNotInitialized.Error(), false)
			return
		}
		if err := s.validateHTTPHostAndOrigin(r); err != nil {
			writeHTTPJSONError(w, http.StatusForbidden, "forbidden_origin_or_host", "rejected unauthorized Host or Origin header (DNS rebinding / CSRF protection)", false)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// ListenAndServeHTTP 校验本地回环绑定地址（默认物理禁止非回环绑定），启动 Streamable HTTP 与 10 GiB 流式传输服务。
func (s *Server) ListenAndServeHTTP(ctx context.Context, addr string) error {
	if err := validateHTTPBindAddr(addr, s.allowNonLoopbackHTTP); err != nil {
		return err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return domi18n.Wrap(err, domi18n.KeyCommonOpTargetFailed, domi18n.Str("op", "listen MCP HTTP"), domi18n.BoundStr("target", addr))
	}
	return s.ServeHTTPListener(ctx, ln)
}

// ServeHTTPListener 在调用方传入的 TCP 监听器上运行受 core/conc.Nursery 监督的 Streamable HTTP 服务：
// 启动前自动执行 Prepare（O(1) 崩溃审计对账 + RecoverJournals），取消或 Close 时同步优雅排空（0 goleak）。
func (s *Server) ServeHTTPListener(ctx context.Context, ln net.Listener) error {
	if ln == nil {
		return domi18n.EF(ErrInvalidConfig, domi18n.KeyCommonFieldNil, domi18n.Str("field", "net.Listener"))
	}
	runCtx, cleanup, err := s.beginTransport(ctx)
	if err != nil {
		_ = ln.Close()
		return err
	}
	defer cleanup()

	if _, err := s.Prepare(runCtx); err != nil {
		_ = ln.Close()
		return err
	}
	httpSrv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: s.httpReadHeaderTimeout,
		BaseContext:       func(net.Listener) context.Context { return runCtx },
	}
	return conc.RunScoped(runCtx, func(scopeCtx context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(wCtx context.Context) error {
			<-wCtx.Done()
			shutCtx, cancel := context.WithTimeout(context.WithoutCancel(wCtx), s.httpShutdownTimeout)
			defer cancel()
			_ = httpSrv.Shutdown(shutCtx)
			return nil
		}); gErr != nil {
			_ = ln.Close()
			return gErr
		}
		serveErr := httpSrv.Serve(ln)
		if errors.Is(serveErr, http.ErrServerClosed) {
			if runCtx.Err() != nil && !errors.Is(context.Cause(runCtx), ErrServerClosed) {
				return runCtx.Err()
			}
			return nil
		}
		return serveErr
	})
}

func validateHTTPBindAddr(addr string, allowNonLoopback bool) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return domi18n.WrapS(ErrInvalidConfig, err, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "listen address"), domi18n.BoundStr("value", addr))
	}
	if allowNonLoopback {
		return nil
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip, pErr := netip.ParseAddr(host)
	if pErr != nil || !ip.IsLoopback() {
		return domi18n.EF(ErrNonLoopbackAddress, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "listen address"), domi18n.BoundStr("value", addr))
	}
	return nil
}

func (s *Server) validateHTTPHostAndOrigin(r *http.Request) error {
	if err := s.validateAllowedHost(r.Host); err != nil {
		return err
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return nil
	}
	return s.validateAllowedOrigin(origin)
}

func (s *Server) validateAllowedHost(rawHost string) error {
	if rawHost == "" {
		return domi18n.E(domi18n.KeyMCPHTTPHeaderMissing, domi18n.Str("header", "Host"))
	}
	host := rawHost
	if strings.Contains(rawHost, ":") {
		if h, _, err := net.SplitHostPort(rawHost); err == nil {
			host = h
		} else if !strings.HasPrefix(rawHost, "[") {
			host = rawHost
		}
	}
	host = strings.Trim(host, "[]")
	if err := checkLoopbackHostName(host); err == nil {
		return nil
	}
	if slices.ContainsFunc(s.allowedHosts, func(allowed string) bool {
		return strings.EqualFold(strings.TrimSpace(allowed), rawHost) || strings.EqualFold(strings.TrimSpace(allowed), host)
	}) {
		return nil
	}
	return domi18n.E(domi18n.KeyMCPHTTPHeaderReject, domi18n.Str("header", "Host"), domi18n.BoundStr("value", rawHost))
}

func (s *Server) validateAllowedOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil {
		return domi18n.Wrap(err, domi18n.KeyMCPHTTPHeaderReject, domi18n.Str("header", "Origin"), domi18n.BoundStr("value", origin))
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return domi18n.E(domi18n.KeyMCPHTTPHeaderReject, domi18n.Str("header", "Origin"), domi18n.BoundStr("value", origin))
	}
	if lbErr := checkLoopbackHostName(u.Hostname()); lbErr == nil {
		return nil
	}
	if slices.ContainsFunc(s.allowedOrigins, func(allowed string) bool {
		return strings.EqualFold(strings.TrimSpace(allowed), origin)
	}) {
		return nil
	}
	return domi18n.E(domi18n.KeyMCPHTTPHeaderReject, domi18n.Str("header", "Origin"), domi18n.BoundStr("value", origin))
}

func checkLoopbackHostName(host string) error {
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	if !ip.IsLoopback() {
		return domi18n.EF(ErrNonLoopbackAddress, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "host"), domi18n.BoundStr("value", host))
	}
	return nil
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	halted := s.gate.IsHalted()
	ready := s.isPrepared() && !halted && !s.IsClosed()
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeHTTPJSON(w, status, struct {
		Ready  bool `json:"ready"`
		Halted bool `json:"halted"`
	}{Ready: ready, Halted: halted})
}

func (s *Server) ensureHTTPServiceReady(w http.ResponseWriter, r *http.Request) error {
	if s.IsClosed() {
		writeHTTPJSONError(w, http.StatusServiceUnavailable, "server_closed", ErrServerClosed.Error(), false)
		return ErrServerClosed
	}
	if s.gate.IsHalted() {
		s.registry.ClearTrackedHandles()
		writeHTTPJSONError(w, http.StatusServiceUnavailable, "gate_halted", gate.ErrGateHalted.Error(), true)
		return gate.ErrGateHalted
	}
	if err := s.ensurePrepared(r.Context()); err != nil {
		if errors.Is(err, gate.ErrGateHalted) {
			s.registry.ClearTrackedHandles()
			writeHTTPJSONError(w, http.StatusServiceUnavailable, "gate_halted", gate.ErrGateHalted.Error(), true)
			return err
		}
		writeHTTPJSONError(w, http.StatusServiceUnavailable, "startup_not_ready", protocol.SanitizeErrorMessage(err.Error()), false)
		return err
	}
	return nil
}

func (s *Server) handleMCPHTTP(w http.ResponseWriter, r *http.Request) {
	if err := s.ensureHTTPServiceReady(w, r); err != nil {
		return
	}
	switch r.Method {
	case http.MethodPost:
		s.handleMCPHTTPPost(w, r)
	case http.MethodGet:
		s.handleMCPHTTPGetSSE(w, r)
	case http.MethodDelete:
		s.handleMCPHTTPDelete(w, r)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeHTTPJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET, POST, and DELETE are allowed", false)
	}
}

func (s *Server) handleMCPHTTPPost(w http.ResponseWriter, r *http.Request) {
	if !hasMediaTypePrefix(r.Header.Get(headerContentType), mimeJSON) {
		writeHTTPJSONError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json", false)
		return
	}
	raw, readStatus, err := readBoundedHTTPBody(w, r, s.maxMessageBytes)
	if err != nil {
		errCode := "bad_request"
		if readStatus == http.StatusRequestEntityTooLarge {
			errCode = "message_too_large"
		}
		writeHTTPJSONError(w, readStatus, errCode, protocol.SanitizeErrorMessage(err.Error()), false)
		return
	}
	req, decErr := protocol.DecodeRequest(raw)
	if decErr != nil {
		rpcCode, errCode := classifyDecodeError(decErr)
		clean := protocol.SanitizeErrorMessage(decErr.Error())
		respBytes, _, _ := encodeErrResp(algebraic.None[protocol.RequestID](), rpcCode, clean, protocol.ToolErrorPayload{
			Code: errCode, Message: clean,
		})
		writeRawJSON(w, http.StatusBadRequest, respBytes)
		return
	}
	if req.Method == protocol.MethodInitialize {
		s.handleMCPHTTPInitialize(w, r, req)
		return
	}
	sessID, statusCode, sessErr := s.requireExistingHTTPSession(r)
	if sessErr != nil {
		writeHTTPJSONError(w, statusCode, "invalid_session", sessErr.Error(), false)
		return
	}
	s.dispatchAndWriteHTTPResponse(w, r, req, sessID)
}

func (s *Server) handleMCPHTTPInitialize(w http.ResponseWriter, r *http.Request, req protocol.Request) {
	if req.IsNotification() {
		respBytes, _, _ := encodeErrResp(algebraic.None[protocol.RequestID](), protocol.CodeInvalidRequest, "initialize requires request id", protocol.ToolErrorPayload{
			Code: "invalid_request", Message: "initialize requires request id",
		})
		writeRawJSON(w, http.StatusBadRequest, respBytes)
		return
	}
	resp, hasResp, handleErr := s.handleDecodedRequest(r.Context(), req)
	if handleErr != nil {
		writeHTTPJSONError(w, http.StatusInternalServerError, "internal_error", protocol.SanitizeErrorMessage(handleErr.Error()), false)
		return
	}
	// 仅在 initialize 参数严格校验通过且无错误时签发或复用 Mcp-Session-Id，防止畸形握手耗尽会话槽位。
	var sessID string
	if hasResp && resp.Error == nil {
		if given := strings.TrimSpace(r.Header.Get(headerMCPSessionID)); given != "" && s.hasHTTPSession(given) {
			sessID = given
		} else if sid, err := s.createHTTPSession(protocol.LatestProtocolVersion); err != nil {
			writeHTTPJSONError(w, http.StatusServiceUnavailable, "invalid_session", protocol.SanitizeErrorMessage(err.Error()), false)
			return
		} else {
			sessID = sid
		}
	}
	s.writeDecodedHTTPResponse(w, r, resp, hasResp, sessID)
}

func (s *Server) dispatchAndWriteHTTPResponse(w http.ResponseWriter, r *http.Request, req protocol.Request, sessID string) {
	resp, hasResp, handleErr := s.handleDecodedRequest(r.Context(), req)
	if handleErr != nil {
		writeHTTPJSONError(w, http.StatusInternalServerError, "internal_error", protocol.SanitizeErrorMessage(handleErr.Error()), false)
		return
	}
	s.writeDecodedHTTPResponse(w, r, resp, hasResp, sessID)
}

func (s *Server) writeDecodedHTTPResponse(w http.ResponseWriter, r *http.Request, resp protocol.Response, hasResp bool, sessID string) {
	if sessID != "" {
		w.Header().Set(headerMCPSessionID, sessID)
	}
	if !hasResp {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	respBytes, err := protocol.MarshalCanonical(resp)
	if err != nil {
		writeHTTPJSONError(w, http.StatusInternalServerError, "internal_error", protocol.SanitizeErrorMessage(err.Error()), false)
		return
	}
	status := http.StatusOK
	if s.gate.IsHalted() {
		status = http.StatusServiceUnavailable
	}
	if wantsSSEOnly(r.Header.Get(headerAccept)) {
		writeSSEResponse(w, status, respBytes)
		return
	}
	writeRawJSON(w, status, respBytes)
}

func (s *Server) requireExistingHTTPSession(r *http.Request) (string, int, error) {
	given := strings.TrimSpace(r.Header.Get(headerMCPSessionID))
	if given == "" {
		return "", http.StatusBadRequest, domi18n.E(domi18n.KeyMCPHTTPHeaderMissing, domi18n.Str("header", headerMCPSessionID))
	}
	if !s.hasHTTPSession(given) {
		return "", http.StatusNotFound, domi18n.E(domi18n.KeyMCPHTTPSessionMiss)
	}
	return given, 0, nil
}

func (s *Server) createHTTPSession(protoVer string) (string, error) {
	if s.IsClosed() {
		return "", ErrServerClosed
	}
	var raw [sessionIDEntropyLen]byte
	if _, err := io.ReadFull(s.entropy, raw[:]); err != nil {
		return "", domi18n.Wrap(err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "allocate MCP HTTP session ID"))
	}
	sid := hex.EncodeToString(raw[:])
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if s.IsClosed() {
		return "", ErrServerClosed
	}
	if len(s.sessions) >= s.maxHTTPSessions {
		evictOldestHTTPSessionLocked(s.sessions)
	}
	s.sessSeq++
	s.sessions[sid] = mcpHTTPSession{id: sid, protocolVersion: protoVer, seq: s.sessSeq, createdAt: s.clock.Now().UTC()}
	return sid, nil
}

func evictOldestHTTPSessionLocked(sessions map[string]mcpHTTPSession) {
	var oldestKey string
	var oldestSeq uint64
	for k, v := range sessions {
		if oldestKey == "" || v.seq < oldestSeq {
			oldestKey, oldestSeq = k, v.seq
		}
	}
	if oldestKey != "" {
		delete(sessions, oldestKey)
	}
}

func (s *Server) hasHTTPSession(id string) bool {
	s.sessMu.Lock()
	_, ok := s.sessions[id]
	s.sessMu.Unlock()
	return ok
}

func (s *Server) handleMCPHTTPGetSSE(w http.ResponseWriter, r *http.Request) {
	sid := strings.TrimSpace(r.Header.Get(headerMCPSessionID))
	if sid == "" || !s.hasHTTPSession(sid) {
		writeHTTPJSONError(w, http.StatusNotFound, "invalid_session", "missing or invalid Mcp-Session-Id", false)
		return
	}
	if !strings.Contains(strings.ToLower(r.Header.Get(headerAccept)), mimeEventStream) {
		writeHTTPJSONError(w, http.StatusNotAcceptable, "not_acceptable", "GET /mcp requires Accept: text/event-stream", false)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeHTTPJSONError(w, http.StatusInternalServerError, "streaming_unsupported", "response writer does not support streaming flush", false)
		return
	}
	w.Header().Set(headerContentType, mimeEventStream)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set(headerMCPSessionID, sid)
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, ": connected\n\n")
	flusher.Flush()
	select {
	case <-r.Context().Done():
	case <-s.lifeCtx.Done():
	}
}

func (s *Server) handleMCPHTTPDelete(w http.ResponseWriter, r *http.Request) {
	sid := strings.TrimSpace(r.Header.Get(headerMCPSessionID))
	if sid == "" || !s.hasHTTPSession(sid) {
		writeHTTPJSONError(w, http.StatusNotFound, "invalid_session", "Mcp-Session-Id session does not exist", false)
		return
	}
	s.sessMu.Lock()
	delete(s.sessions, sid)
	s.sessMu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func readBoundedHTTPBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, int, error) {
	limited := http.MaxBytesReader(w, r.Body, maxBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			return nil, http.StatusRequestEntityTooLarge, domi18n.WrapSentinel(ErrMessageTooLarge, err)
		}
		return nil, http.StatusBadRequest, domi18n.Wrap(err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "read HTTP request body"))
	}
	return data, 0, nil
}

func hasMediaTypePrefix(ct, want string) bool {
	base, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(ct)), ";")
	return strings.TrimSpace(base) == want
}

func wantsSSEOnly(accept string) bool {
	low := strings.ToLower(accept)
	return strings.Contains(low, mimeEventStream) && !strings.Contains(low, mimeJSON)
}

func writeRawJSON(w http.ResponseWriter, status int, raw []byte) {
	w.Header().Set(headerContentType, mimeJSON)
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func writeSSEResponse(w http.ResponseWriter, status int, raw []byte) {
	w.Header().Set(headerContentType, mimeEventStream)
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "event: message\ndata: ")
	_, _ = w.Write(raw)
	_, _ = io.WriteString(w, "\n\n")
}

func writeHTTPJSON(w http.ResponseWriter, status int, payload any) {
	raw, err := protocol.MarshalCanonical(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeRawJSON(w, status, raw)
}

func writeHTTPJSONError(w http.ResponseWriter, status int, code, msg string, halted bool) {
	writeHTTPJSON(w, status, protocol.ToolErrorPayload{
		Code:    code,
		Message: msg,
		Halted:  halted,
	})
}
