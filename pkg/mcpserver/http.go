package mcpserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// HTTPHandler returns the authenticated handler owned by this runtime. Every
// HTTP server using it must bind its lifecycle to this runtime and call Close.
func (r *Runtime) HTTPHandler() (http.Handler, error) {
	if r.http == nil {
		return nil, errors.New("mcp runtime is not configured for HTTP")
	}
	return r.httpHandler, nil
}

func (r *Runtime) newHTTPHandler() http.Handler {
	options := r.http
	protocol := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		if r.ctx.Err() != nil {
			return nil
		}
		return r.server
	}, &mcp.StreamableHTTPOptions{
		SessionTimeout: options.SessionTimeout, MaxRequestBodyBytes: maxMCPBodyBytes,
		// Strict configured Host/Origin checks below also support a public host
		// forwarded by a local reverse proxy; the SDK loopback-only check cannot.
		DisableLocalhostProtection: true,
	})
	initializeGate := make(chan struct{}, 1)
	r.initializeGate = initializeGate
	requests := make(chan struct{}, options.MaxRequests)
	serviceAuth := auth.RequireBearerToken(func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		digest := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(digest[:], options.tokenDigest[:]) != 1 {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{UserID: options.scope}, nil
	}, &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})(r.protocolAdmission(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/mcp" {
			http.NotFound(w, req)
			return
		}
		if req.Method == http.MethodPost && req.Header.Get("Mcp-Session-Id") == "" {
			select {
			case initializeGate <- struct{}{}:
				defer func() { <-initializeGate }()
			default:
				http.Error(w, "initialization_busy", http.StatusTooManyRequests)
				return
			}
			count := 0
			for range r.server.Sessions() {
				count++
			}
			if count >= options.MaxSessions {
				http.Error(w, "session_limit", http.StatusTooManyRequests)
				return
			}
		}
		r.serveProtocolRequest(w, req, protocol)
	}), requests))
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		controller := http.NewResponseController(w)
		w = &rejectBodyResponseWriter{ResponseWriter: w}
		// Protect early rejection paths too: net/http may otherwise try to
		// drain an unauthenticated request body without a read deadline.
		if err := controller.SetReadDeadline(time.Now().Add(options.BodyTimeout)); err != nil {
			http.Error(w, "read_deadline_unavailable", http.StatusInternalServerError)
			return
		}
		if err := controller.SetWriteDeadline(time.Now().Add(options.StreamIdle)); err != nil {
			http.Error(w, "write_deadline_unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.ctx.Err() != nil {
			http.Error(w, "service_stopping", http.StatusServiceUnavailable)
			return
		}
		if !r.allowedHTTPRequest(req) {
			http.Error(w, "host_or_origin_denied", http.StatusForbidden)
			return
		}
		if len(req.Header.Values("Authorization")) != 1 || len(req.Header.Get("Authorization")) > 8192 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="xops"`)
			http.Error(w, "authentication_required", http.StatusUnauthorized)
			return
		}
		if strings.HasPrefix(req.URL.Path, "/v1/transfers/") {
			if !acquireHTTPAdmission(w, requests, "request_limit") {
				return
			}
			defer func() { <-requests }()
			r.serveTransferHTTP(w, req)
			return
		}
		serviceAuth.ServeHTTP(w, req)
	})
}

type rejectBodyResponseWriter struct{ http.ResponseWriter }

func (w *rejectBodyResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *rejectBodyResponseWriter) WriteHeader(code int) {
	if code >= 400 {
		w.Header().Set("Connection", "close")
	}
	w.ResponseWriter.WriteHeader(code)
}

func (r *Runtime) allowedHTTPRequest(req *http.Request) bool {
	host, err := normalizeHTTPHost(req.Host, r.http.hostScheme)
	if err != nil || !slices.Contains(r.http.AllowedHosts, host) {
		return false
	}
	origins := req.Header.Values("Origin")
	if len(origins) == 0 {
		return true
	}
	if len(origins) != 1 {
		return false
	}
	origin, err := parseHTTPOrigin(origins[0])
	return err == nil && slices.Contains(r.http.AllowedOrigins, origin)
}

func (r *Runtime) serveProtocolRequest(w http.ResponseWriter, req *http.Request, protocol http.Handler) {
	controller := http.NewResponseController(w)
	if err := controller.SetReadDeadline(time.Now().Add(r.http.BodyTimeout)); err != nil {
		http.Error(w, "read_deadline_unavailable", http.StatusInternalServerError)
		return
	}
	if req.Body == nil || req.Body == http.NoBody || req.ContentLength == 0 {
		if err := controller.SetReadDeadline(time.Time{}); err != nil {
			http.Error(w, "clear_read_deadline_failed", http.StatusInternalServerError)
			return
		}
	} else {
		// Once the JSON body is complete, a background peer-disconnect read
		// must not inherit BodyTimeout and terminate a healthy SSE session.
		req.Body = &protocolRequestBody{ReadCloser: req.Body, controller: controller}
	}
	if err := controller.SetWriteDeadline(time.Now().Add(r.http.StreamIdle)); err != nil {
		http.Error(w, "write_deadline_unavailable", http.StatusInternalServerError)
		return
	}
	duration := r.http.ToolTimeout
	if req.Method == http.MethodGet {
		duration = r.http.SessionTimeout
	}
	ctx, cancel := context.WithTimeout(req.Context(), duration)
	defer cancel()
	stopRuntime := context.AfterFunc(r.ctx, cancel)
	defer stopRuntime()
	stopIO := r.interruptHTTPIO(ctx, controller)
	defer stopIO()
	// The deadline terminates an otherwise silent SSE request. Tool execution
	// has a separate middleware deadline because stateful SDK sessions detach
	// themselves from the HTTP initialization request context.
	protocol.ServeHTTP(&deadlineResponseWriter{ResponseWriter: w, idle: r.http.StreamIdle}, req.WithContext(ctx))
}

type protocolRequestBody struct {
	io.ReadCloser
	controller *http.ResponseController
}

func (b *protocolRequestBody) Read(data []byte) (int, error) {
	n, err := b.ReadCloser.Read(data)
	if errors.Is(err, io.EOF) {
		if clearErr := b.controller.SetReadDeadline(time.Time{}); clearErr != nil {
			return n, fmt.Errorf("clear completed MCP body deadline: %w", clearErr)
		}
	}
	return n, err
}

type deadlineResponseWriter struct {
	http.ResponseWriter
	idle time.Duration
}

func (w *deadlineResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *deadlineResponseWriter) Write(data []byte) (int, error) {
	if err := http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now().Add(w.idle)); err != nil {
		return 0, fmt.Errorf("renew HTTP write deadline: %w", err)
	}
	return w.ResponseWriter.Write(data)
}

func (w *deadlineResponseWriter) FlushError() error {
	controller := http.NewResponseController(w.ResponseWriter)
	if err := controller.SetWriteDeadline(time.Now().Add(w.idle)); err != nil {
		return fmt.Errorf("renew SSE write deadline: %w", err)
	}
	return controller.Flush()
}

func (r *Runtime) toolDeadline(next mcp.MethodHandler) mcp.MethodHandler {
	// SDK sessions detach calls from POST lifetimes. Retain a separate slot
	// until execution actually returns, even after disconnect or cancellation.
	executions := make(chan struct{}, r.http.MaxRequests)
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if method != "tools/call" {
			return next(ctx, method, req)
		}
		select {
		case executions <- struct{}{}:
			defer func() { <-executions }()
		default:
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "tool_execution_limit: retry after an active tool completes"}}}, nil
		}
		ctx, cancel := context.WithTimeout(ctx, r.http.ToolTimeout)
		defer cancel()
		stopRuntime := context.AfterFunc(r.ctx, cancel)
		defer stopRuntime()
		return next(ctx, method, req)
	}
}

// ServeHTTP takes ownership of listener. It stops accepting requests on runtime
// cancellation and force-closes connections if graceful shutdown times out.
func (r *Runtime) ServeHTTP(listener net.Listener) (retErr error) {
	if listener == nil {
		return errors.New("HTTP listener is required")
	}
	defer func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			retErr = errors.Join(retErr, fmt.Errorf("close MCP HTTP listener: %w", err))
		}
	}()
	handler, err := r.HTTPHandler()
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: r.http.HeaderTimeout, ReadTimeout: r.http.BodyTimeout, IdleTimeout: r.http.StreamIdle,
		MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return r.ctx },
	}
	serveCtx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	shutdownDone := make(chan error, 1)
	// Cancellation or Serve returning always stops and joins this worker.
	go func() {
		<-serveCtx.Done()
		ctx, stop := context.WithTimeout(context.WithoutCancel(r.ctx), r.http.ShutdownTimeout)
		defer stop()
		shutdownErr := server.Shutdown(ctx)
		if shutdownErr != nil {
			shutdownErr = errors.Join(shutdownErr, server.Close())
		}
		shutdownDone <- shutdownErr
	}()
	err = server.Serve(listener)
	cancel()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return errors.Join(err, <-shutdownDone)
}
