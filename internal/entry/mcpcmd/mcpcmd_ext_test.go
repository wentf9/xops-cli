package mcpcmd_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/mcpcmd"
	"github.com/wentf9/xops-cli/internal/i18n"
)

type fakeMCPServer struct {
	prepareCalls atomic.Int32
	stdioCalls   atomic.Int32
	listenCalls  atomic.Int32
	httpLnCalls  atomic.Int32
	closeCalls   atomic.Int32

	prepareReport engine.MCPStartupReport
	prepareErr    error
	closeErr      error

	serveStdioFn func(ctx context.Context, in io.Reader, out io.Writer) error
	serveHTTPFn  func(ctx context.Context, ln net.Listener) error
	listenHTTPFn func(ctx context.Context, addr string) error

	mu            sync.Mutex
	seenAddr      string
	closeDeadline bool
	closedCh      chan struct{}
	closeOnce     sync.Once
}

func newFakeMCPServer() *fakeMCPServer {
	return &fakeMCPServer{closedCh: make(chan struct{})}
}

func zeroVal[T any]() (z T) { return z }

func (f *fakeMCPServer) Prepare(ctx context.Context) (engine.MCPStartupReport, error) {
	if ctx == nil {
		return zeroVal[engine.MCPStartupReport](), errors.New("nil context")
	}
	f.prepareCalls.Add(1)
	if f.prepareErr != nil {
		return zeroVal[engine.MCPStartupReport](), f.prepareErr
	}
	return f.prepareReport, nil
}

func (f *fakeMCPServer) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	f.stdioCalls.Add(1)
	if f.serveStdioFn != nil {
		return f.serveStdioFn(ctx, in, out)
	}
	buf, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	_, wErr := out.Write(buf)
	return wErr
}

func (f *fakeMCPServer) ListenAndServeHTTP(ctx context.Context, addr string) error {
	f.listenCalls.Add(1)
	f.mu.Lock()
	f.seenAddr = addr
	f.mu.Unlock()
	if f.listenHTTPFn != nil {
		return f.listenHTTPFn(ctx, addr)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-f.closedCh:
		return http.ErrServerClosed
	}
}

func (f *fakeMCPServer) ServeHTTPListener(ctx context.Context, ln net.Listener) error {
	f.httpLnCalls.Add(1)
	if f.serveHTTPFn != nil {
		return f.serveHTTPFn(ctx, ln)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
		}),
	}
	return conc.RunScoped(ctx, func(sCtx context.Context, n *conc.Nursery) error {
		done := make(chan struct{})
		defer close(done)
		if err := n.Go(func(wCtx context.Context) error {
			select {
			case <-done:
			case <-wCtx.Done():
				_ = srv.Close()
			case <-f.closedCh:
				_ = srv.Close()
			}
			return nil
		}); err != nil {
			return err
		}
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	})
}

func (f *fakeMCPServer) Close(ctx context.Context) error {
	f.closeCalls.Add(1)
	_, hasDL := ctx.Deadline()
	f.mu.Lock()
	f.closeDeadline = hasDL && ctx.Err() == nil
	f.mu.Unlock()
	f.closeOnce.Do(func() { close(f.closedCh) })
	return f.closeErr
}

func TestParseTransportKind(t *testing.T) {
	defer goleak.VerifyNone(t)
	var zero mcpcmd.TransportKind
	if zero.IsValid() || !zero.IsZero() {
		t.Fatal("零值 TransportKind 必须无效")
	}
	if _, err := zero.MarshalText(); !errors.Is(err, mcpcmd.ErrInvalidTransport) {
		t.Fatalf("零值 MarshalText 期望 ErrInvalidTransport，实际=%v", err)
	}
	cases := []struct {
		raw  string
		want mcpcmd.TransportKind
	}{
		{"stdio", mcpcmd.TransportStdio},
		{"  HTTP ", mcpcmd.TransportHTTP},
		{"streamable-http", mcpcmd.TransportHTTP},
		{"streamable_http", mcpcmd.TransportHTTP},
	}
	for _, tc := range cases {
		got, err := mcpcmd.ParseTransportKind(tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("ParseTransportKind(%q) = (%v, %v), want %v", tc.raw, got, err, tc.want)
		}
	}
	if _, err := mcpcmd.ParseTransportKind("websocket"); !errors.Is(err, mcpcmd.ErrInvalidTransport) {
		t.Fatalf("未知传输期望 ErrInvalidTransport，实际=%v", err)
	}
}

func TestRun_FailClosedInvalidConfig(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	var nilCtx context.Context
	if err := mcpcmd.Run(nilCtx, mcpcmd.Config{}); !errors.Is(err, mcpcmd.ErrNilContext) {
		t.Fatalf("nil ctx 期望 ErrNilContext，实际=%v", err)
	}
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := mcpcmd.Run(canceledCtx, mcpcmd.Config{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("已取消 ctx 期望 context.Canceled，实际=%v", err)
	}

	srv := newFakeMCPServer()
	factory := func(engine.MCPConfig) (mcpcmd.MCPServerContract, error) { return srv, nil }

	invalidCases := []struct {
		name string
		cfg  mcpcmd.Config
		want error
	}{
		{name: "missing_engine_and_factory", cfg: mcpcmd.Config{Transport: mcpcmd.TransportStdio}, want: mcpcmd.ErrInvalidConfig},
		{name: "invalid_transport", cfg: mcpcmd.Config{ServerFactory: factory}, want: mcpcmd.ErrInvalidTransport},
		{name: "stdio_missing_io", cfg: mcpcmd.Config{ServerFactory: factory, Transport: mcpcmd.TransportStdio}, want: mcpcmd.ErrInvalidConfig},
		{name: "http_missing_addr_and_ln", cfg: mcpcmd.Config{ServerFactory: factory, Transport: mcpcmd.TransportHTTP}, want: mcpcmd.ErrInvalidConfig},
		{
			name: "zero_shutdown_timeout",
			cfg: mcpcmd.Config{
				ServerFactory:   factory,
				Transport:       mcpcmd.TransportStdio,
				Stdin:           strings.NewReader(""),
				Stdout:          &bytes.Buffer{},
				ShutdownTimeout: algebraic.Some(algebraic.ZeroDuration()),
			},
			want: mcpcmd.ErrInvalidConfig,
		},
		{
			name: "nil_server_from_factory",
			cfg: mcpcmd.Config{
				ServerFactory: func(engine.MCPConfig) (mcpcmd.MCPServerContract, error) { return nil, nil },
				Transport:     mcpcmd.TransportStdio,
				Stdin:         strings.NewReader(""),
				Stdout:        &bytes.Buffer{},
			},
			want: mcpcmd.ErrInvalidConfig,
		},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := mcpcmd.Run(ctx, tc.cfg); !errors.Is(err, tc.want) {
				t.Fatalf("%s: got err=%v, want %v", tc.name, err, tc.want)
			}
		})
	}
}

func TestRun_PrepareFailureFailsClosedAndClosesServer(t *testing.T) {
	defer goleak.VerifyNone(t)
	srv := newFakeMCPServer()
	wantPrepErr := errors.New("audit reconciler crashed")
	srv.prepareErr = wantPrepErr

	var onPreparedCalled bool
	err := mcpcmd.Run(context.Background(), mcpcmd.Config{
		ServerFactory: func(engine.MCPConfig) (mcpcmd.MCPServerContract, error) { return srv, nil },
		Transport:     mcpcmd.TransportStdio,
		Stdin:         strings.NewReader("payload"),
		Stdout:        &bytes.Buffer{},
		OnPrepared:    func(engine.MCPStartupReport) { onPreparedCalled = true },
	})
	if !errors.Is(err, wantPrepErr) {
		t.Fatalf("Prepare 失败应透传原错，实际=%v", err)
	}
	if onPreparedCalled || srv.stdioCalls.Load() != 0 || srv.closeCalls.Load() != 1 {
		t.Fatalf("Prepare 失败后不应提供服务且必须关闭一次: prepared=%v stdio=%d close=%d",
			onPreparedCalled, srv.stdioCalls.Load(), srv.closeCalls.Load())
	}
}

func TestRun_StdioRoundTripAndBlockingCancelUnblocksCleanly(t *testing.T) {
	defer goleak.VerifyNone(t)

	// 1. 正常 stdio 往返至 EOF：Prepare 必须先执行，诊断仅写 Stderr 不污染 Stdout。
	srv := newFakeMCPServer()
	var out, errBuf bytes.Buffer
	var preparedCalled bool
	err := mcpcmd.Run(context.Background(), mcpcmd.Config{
		ServerFactory: func(engine.MCPConfig) (mcpcmd.MCPServerContract, error) { return srv, nil },
		Transport:     mcpcmd.TransportStdio,
		Stdin:         strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n"),
		Stdout:        &out,
		Stderr:        &errBuf,
		OnPrepared:    func(engine.MCPStartupReport) { preparedCalled = true },
	})
	if err != nil {
		t.Fatalf("Stdio EOF 期望返回 nil，实际=%v", err)
	}
	if srv.prepareCalls.Load() != 1 || srv.stdioCalls.Load() != 1 || srv.closeCalls.Load() != 1 {
		t.Fatalf("调用计数异常: prepare=%d stdio=%d close=%d", srv.prepareCalls.Load(), srv.stdioCalls.Load(), srv.closeCalls.Load())
	}
	if !preparedCalled {
		t.Fatal("OnPrepared 未触发")
	}
	if !strings.Contains(errBuf.String(), "xops-mcp: ready transport=stdio") || strings.Contains(out.String(), "xops-mcp") {
		t.Fatalf("诊断输出边界违背: stdout=%q stderr=%q", out.String(), errBuf.String())
	}

	// 2. 阻塞式 stdio 收到 ctx 取消时，看门狗先关闭可关闭 Stdin 解除 Read 阻塞，随后 Close 在有限超时内收尾并返回 nil。
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	blockSrv := newFakeMCPServer()
	started := make(chan struct{})
	blockSrv.serveStdioFn = func(_ context.Context, in io.Reader, _ io.Writer) error {
		close(started)
		buf := make([]byte, 32)
		_, rErr := in.Read(buf)
		return rErr
	}
	runCtx, cancel := context.WithCancel(context.Background())
	var runErr error
	err = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			runErr = mcpcmd.Run(runCtx, mcpcmd.Config{
				ServerFactory: func(engine.MCPConfig) (mcpcmd.MCPServerContract, error) { return blockSrv, nil },
				Transport:     mcpcmd.TransportStdio,
				Stdin:         pr,
				Stdout:        &bytes.Buffer{},
			})
			return nil
		}); gErr != nil {
			return gErr
		}
		<-started
		cancel()
		return nil
	})
	if err != nil || runErr != nil {
		t.Fatalf("阻塞 stdio 取消期望优雅返回 nil，实际 outer=%v run=%v", err, runErr)
	}
	if blockSrv.closeCalls.Load() != 1 || !blockSrv.closeDeadline {
		t.Fatalf("取消后必须以剥离取消的有限超时调用 Close 一次: calls=%d deadline=%v", blockSrv.closeCalls.Load(), blockSrv.closeDeadline)
	}
}

func TestRun_HTTPLoopbackAndListenAddrGracefulCancel(t *testing.T) {
	defer goleak.VerifyNone(t)

	// 1. 预绑定回环 Listener 真实 HTTP 往返 + 取消优雅收尾。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()
	srv := newFakeMCPServer()
	ready := make(chan struct{})
	runCtx, cancel := context.WithCancel(context.Background())
	var runErr error
	err = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			runErr = mcpcmd.Run(runCtx, mcpcmd.Config{
				ServerFactory: func(engine.MCPConfig) (mcpcmd.MCPServerContract, error) { return srv, nil },
				Transport:     mcpcmd.TransportHTTP,
				Listener:      ln,
				OnPrepared:    func(engine.MCPStartupReport) { close(ready) },
			})
			return nil
		}); gErr != nil {
			return gErr
		}
		<-ready
		client := &http.Client{Timeout: 3 * time.Second}
		resp, reqErr := client.Get("http://" + addr + "/mcp")
		if reqErr != nil {
			cancel()
			return reqErr
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		client.CloseIdleConnections()
		cancel()
		if readErr != nil || !strings.Contains(string(body), `"ok":true`) {
			return errors.New("unexpected http response: " + string(body))
		}
		return nil
	})
	if err != nil || runErr != nil {
		t.Fatalf("Streamable HTTP 回环往返与优雅停机失败: outer=%v run=%v", err, runErr)
	}
	if srv.httpLnCalls.Load() != 1 || srv.closeCalls.Load() != 1 {
		t.Fatalf("HTTP Listener 调用计数异常: httpLn=%d close=%d", srv.httpLnCalls.Load(), srv.closeCalls.Load())
	}

	// 2. ListenAndServeHTTP 路径 + Close 错误聚合透传。
	srv2 := newFakeMCPServer()
	wantCloseErr := errors.New("close failed")
	srv2.closeErr = wantCloseErr
	runCtx2, cancel2 := context.WithCancel(context.Background())
	srv2.listenHTTPFn = func(c context.Context, _ string) error {
		cancel2()
		<-c.Done()
		return nil
	}
	gotErr := mcpcmd.Run(runCtx2, mcpcmd.Config{
		ServerFactory: func(engine.MCPConfig) (mcpcmd.MCPServerContract, error) { return srv2, nil },
		Transport:     mcpcmd.TransportHTTP,
		ListenAddr:    "127.0.0.1:18080",
	})
	if !errors.Is(gotErr, wantCloseErr) {
		t.Fatalf("Close 错误必须如实暴露，实际=%v", gotErr)
	}
	if srv2.listenCalls.Load() != 1 || srv2.seenAddr != "127.0.0.1:18080" {
		t.Fatalf("ListenAddr 透传异常: calls=%d addr=%q", srv2.listenCalls.Load(), srv2.seenAddr)
	}
}

func TestRun_ClosesPreboundListenerOnEarlyFailure(t *testing.T) {
	defer goleak.VerifyNone(t)
	newLoopbackLn := func(t *testing.T) net.Listener {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		return ln
	}
	assertListenerClosed := func(t *testing.T, ln net.Listener) {
		t.Helper()
		_, err := ln.Accept()
		if !errors.Is(err, net.ErrClosed) {
			_ = ln.Close()
			t.Fatalf("提前失败后预绑定 Listener 必须已关闭（net.ErrClosed），实际 Accept err=%v", err)
		}
	}

	t.Run("canceled_ctx", func(t *testing.T) {
		ln := newLoopbackLn(t)
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := mcpcmd.Run(canceledCtx, mcpcmd.Config{Transport: mcpcmd.TransportHTTP, Listener: ln}); !errors.Is(err, context.Canceled) {
			t.Fatalf("期望 context.Canceled，实际=%v", err)
		}
		assertListenerClosed(t, ln)
	})

	t.Run("invalid_config", func(t *testing.T) {
		ln := newLoopbackLn(t)
		srv := newFakeMCPServer()
		err := mcpcmd.Run(context.Background(), mcpcmd.Config{
			ServerFactory: func(engine.MCPConfig) (mcpcmd.MCPServerContract, error) { return srv, nil },
			Transport:     mcpcmd.TransportStdio,
			Stdin:         strings.NewReader(""),
			Stdout:        &bytes.Buffer{},
			Listener:      ln,
		})
		if !errors.Is(err, mcpcmd.ErrInvalidConfig) {
			t.Fatalf("期望 ErrInvalidConfig，实际=%v", err)
		}
		assertListenerClosed(t, ln)
	})

	t.Run("factory_error", func(t *testing.T) {
		ln := newLoopbackLn(t)
		wantErr := errors.New("factory boom")
		err := mcpcmd.Run(context.Background(), mcpcmd.Config{
			ServerFactory: func(engine.MCPConfig) (mcpcmd.MCPServerContract, error) { return nil, wantErr },
			Transport:     mcpcmd.TransportHTTP,
			Listener:      ln,
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("期望 factory 错误，实际=%v", err)
		}
		assertListenerClosed(t, ln)
	})

	t.Run("prepare_error", func(t *testing.T) {
		ln := newLoopbackLn(t)
		srv := newFakeMCPServer()
		wantErr := errors.New("prepare boom")
		srv.prepareErr = wantErr
		err := mcpcmd.Run(context.Background(), mcpcmd.Config{
			ServerFactory: func(engine.MCPConfig) (mcpcmd.MCPServerContract, error) { return srv, nil },
			Transport:     mcpcmd.TransportHTTP,
			Listener:      ln,
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("期望 prepare 错误，实际=%v", err)
		}
		assertListenerClosed(t, ln)
	})
}

func TestStructuredErrors_BilingualRender(t *testing.T) {
	defer goleak.VerifyNone(t)
	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	enLoc := cat.For(domi18n.LocaleEn)
	zhLoc := cat.For(domi18n.LocaleZh)

	_, parseErr := mcpcmd.ParseTransportKind("websocket")
	if !errors.Is(parseErr, mcpcmd.ErrInvalidTransport) {
		t.Fatalf("期望 ErrInvalidTransport，实际=%v", parseErr)
	}
	if id, ok := domi18n.ErrorID(parseErr); !ok || id != i18n.KeyMCPInvalidTransportValue {
		t.Fatalf("ErrorID = (%q, %v), want %q", id, ok, i18n.KeyMCPInvalidTransportValue)
	}
	if enLoc.RenderError(parseErr) != parseErr.Error() {
		t.Fatalf("en RenderError(%v) = %q != %q", parseErr, enLoc.RenderError(parseErr), parseErr.Error())
	}
	if zh := zhLoc.RenderError(parseErr); !strings.Contains(zh, "不支持的传输模式 websocket") {
		t.Fatalf("zh RenderError 异常: %q", zh)
	}

	cfgErr := mcpcmd.Run(context.Background(), mcpcmd.Config{Transport: mcpcmd.TransportStdio})
	if id, ok := domi18n.ErrorID(cfgErr); !ok || id != i18n.KeyMCPNoEngineOrFactory {
		t.Fatalf("ErrorID = (%q, %v), want %q", id, ok, i18n.KeyMCPNoEngineOrFactory)
	}
	if zh := zhLoc.RenderError(cfgErr); !strings.Contains(zh, "Engine 与 ServerFactory 不能同时为空") {
		t.Fatalf("zh RenderError 异常: %q", zh)
	}
}
