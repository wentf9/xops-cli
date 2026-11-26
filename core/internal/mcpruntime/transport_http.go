package mcpruntime

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
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
			writeHTTPJSONError(w, http.StatusForbidden, "forbidden_origin_or_host", "拒绝非法 Host 或 Origin 请求头（DNS Rebinding / CSRF 防护）", false)
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
		return fmt.Errorf("监听 MCP HTTP 地址 %q 失败: %w", addr, err)
	}
	return s.ServeHTTPListener(ctx, ln)
}

// ServeHTTPListener 在调用方传入的 TCP 监听器上运行受 core/conc.Nursery 监督的 Streamable HTTP 服务：
// 启动前自动执行 Prepare（O(1) 崩溃审计对账 + RecoverJournals），取消或 Close 时同步优雅排空（0 goleak）。
func (s *Server) ServeHTTPListener(ctx context.Context, ln net.Listener) error {
	if ln == nil {
		return fmt.Errorf("%w: net.Listener 不能为 nil", ErrInvalidConfig)
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
		return fmt.Errorf("%w: 无效监听地址 %q: %w", ErrInvalidConfig, addr, err)
	}
	if allowNonLoopback {
		return nil
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip, pErr := netip.ParseAddr(host)
	if pErr != nil || !ip.IsLoopback() {
		return fmt.Errorf("%w: %q", ErrNonLoopbackAddress, addr)
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
		return errors.New("缺少 Host 请求头")
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
	return fmt.Errorf("未授权的 Host 请求头 %q", rawHost)
}

func (s *Server) validateAllowedOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("无效 Origin %q: %w", origin, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("非法 Origin 协议或主机 %q", origin)
	}
	if lbErr := checkLoopbackHostName(u.Hostname()); lbErr == nil {
		return nil
	}
	if slices.ContainsFunc(s.allowedOrigins, func(allowed string) bool {
		return strings.EqualFold(strings.TrimSpace(allowed), origin)
	}) {
		return nil
	}
	return fmt.Errorf("未授权的 Origin %q", origin)
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
		return fmt.Errorf("%w: %q", ErrNonLoopbackAddress, host)
	}
	return nil
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	halted := s.gate.IsHalted()
	status := http.StatusOK
	if halted {
		status = http.StatusServiceUnavailable
	}
	writeHTTPJSON(w, status, struct {
		Ready  bool `json:"ready"`
		Halted bool `json:"halted"`
	}{Ready: !halted && !s.IsClosed(), Halted: halted})
}

func (s *Server) handleMCPHTTP(w http.ResponseWriter, r *http.Request) {
	if s.gate.IsHalted() {
		s.registry.ClearTrackedHandles()
		writeHTTPJSONError(w, http.StatusServiceUnavailable, "gate_halted", gate.ErrGateHalted.Error(), true)
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
		writeHTTPJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "仅允许 GET/POST/DELETE", false)
	}
}

func (s *Server) handleMCPHTTPPost(w http.ResponseWriter, r *http.Request) {
	if !hasMediaTypePrefix(r.Header.Get(headerContentType), mimeJSON) {
		writeHTTPJSONError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type 必须为 application/json", false)
		return
	}
	raw, err := readBoundedHTTPBody(w, r, s.maxMessageBytes)
	if err != nil {
		writeHTTPJSONError(w, http.StatusRequestEntityTooLarge, "message_too_large", err.Error(), false)
		return
	}
	req, decErr := protocol.DecodeRequest(raw)
	if decErr != nil {
		respBytes, _, _ := encodeErrResp(algebraic.None[protocol.RequestID](), protocol.CodeParseError, decErr.Error(), nil)
		writeRawJSON(w, http.StatusBadRequest, respBytes)
		return
	}
	sessID, statusCode, sessErr := s.resolveOrCreateHTTPSession(r, req)
	if sessErr != nil {
		writeHTTPJSONError(w, statusCode, "invalid_session", sessErr.Error(), false)
		return
	}
	respBytes, hasResp, handleErr := s.HandleMessage(r.Context(), raw)
	if handleErr != nil {
		writeHTTPJSONError(w, http.StatusInternalServerError, "internal_error", handleErr.Error(), false)
		return
	}
	if sessID != "" {
		w.Header().Set(headerMCPSessionID, sessID)
	}
	if !hasResp {
		w.WriteHeader(http.StatusAccepted)
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

func (s *Server) resolveOrCreateHTTPSession(r *http.Request, req protocol.Request) (string, int, error) {
	given := strings.TrimSpace(r.Header.Get(headerMCPSessionID))
	if req.Method == protocol.MethodInitialize {
		if given != "" && s.hasHTTPSession(given) {
			return given, 0, nil
		}
		sid, err := s.createHTTPSession(protocol.LatestProtocolVersion)
		if err != nil {
			return "", http.StatusServiceUnavailable, err
		}
		return sid, 0, nil
	}
	if given == "" {
		return "", http.StatusBadRequest, errors.New("缺少必需的 Mcp-Session-Id 请求头")
	}
	if !s.hasHTTPSession(given) {
		return "", http.StatusNotFound, errors.New("Mcp-Session-Id 会话不存在或已关闭")
	}
	return given, 0, nil
}

func (s *Server) createHTTPSession(protoVer string) (string, error) {
	var raw [sessionIDEntropyLen]byte
	if _, err := io.ReadFull(s.entropy, raw[:]); err != nil {
		return "", fmt.Errorf("分配 MCP HTTP 会话标识失败: %w", err)
	}
	sid := hex.EncodeToString(raw[:])
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if len(s.sessions) >= s.maxHTTPSessions {
		return "", errors.New("MCP HTTP 活跃会话数已达上限")
	}
	s.sessions[sid] = mcpHTTPSession{
		id:              sid,
		protocolVersion: protoVer,
		createdAt:       s.clock.Now().UTC(),
	}
	return sid, nil
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
		writeHTTPJSONError(w, http.StatusNotFound, "invalid_session", "缺少或无效的 Mcp-Session-Id", false)
		return
	}
	if !strings.Contains(strings.ToLower(r.Header.Get(headerAccept)), mimeEventStream) {
		writeHTTPJSONError(w, http.StatusNotAcceptable, "not_acceptable", "GET /mcp 需声明 Accept: text/event-stream", false)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeHTTPJSONError(w, http.StatusInternalServerError, "streaming_unsupported", "响应写入器不支持流式刷新", false)
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
		writeHTTPJSONError(w, http.StatusNotFound, "invalid_session", "Mcp-Session-Id 会话不存在", false)
		return
	}
	s.sessMu.Lock()
	delete(s.sessions, sid)
	s.sessMu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func readBoundedHTTPBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, error) {
	limited := http.MaxBytesReader(w, r.Body, maxBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMessageTooLarge, err)
	}
	return data, nil
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
