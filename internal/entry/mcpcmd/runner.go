package mcpcmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/i18n"
)

const defaultShutdownTimeout = 5 * time.Second

// Run 启动并监督极薄 MCP 服务端完整生命周期（stdio 或 Streamable HTTP）：
//  1. 严格校验 ctx 与 Config（失败关闭）；
//  2. 构造 MCPServer 并强制先行调用 Prepare(ctx) 完成启动期崩溃审计对账与 WAL 恢复；
//  3. 在 core/conc.Nursery（RunScoped）监督下运行传输主循环与取消看门狗；
//  4. 无论正常结束、信号取消还是异常返回，均以剥离取消的有限超时上下文幂等调用 MCPServer.Close 并聚合关闭错误。
func Run(ctx context.Context, cfg Config) (retErr error) {
	// 无论是在校验/Prepare 阶段提前失败，还是 ServeHTTPListener 结束后退出，
	// 均幂等兜底关闭调用方预绑定的 cfg.Listener（忽略已关闭的 net.ErrClosed），杜绝套接字描述符泄漏。
	defer func() {
		if cfg.Listener != nil {
			if lErr := cfg.Listener.Close(); lErr != nil && !errors.Is(lErr, net.ErrClosed) {
				retErr = errors.Join(retErr, lErr)
			}
		}
	}()
	if ctx == nil {
		return ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	factory, shutTimeout, err := validateConfig(cfg)
	if err != nil {
		return err
	}
	srv, err := factory(cfg.ServerConfig)
	if err != nil {
		return i18n.Wrap(err, i18n.KeyMCPCreateServerFailed)
	}
	if srv == nil {
		return i18n.EF(ErrInvalidConfig, i18n.KeyMCPNilServer)
	}

	var closeOnce sync.Once
	var closeErr error
	closeServer := func() error {
		closeOnce.Do(func() {
			shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutTimeout)
			defer cancel()
			closeErr = srv.Close(shutCtx)
		})
		return closeErr
	}
	defer func() {
		retErr = errors.Join(retErr, closeServer())
	}()

	report, err := srv.Prepare(ctx)
	if err != nil {
		return i18n.Wrap(err, i18n.KeyMCPPrepareFailed)
	}
	writePreparedSummary(cfg.Stderr, cfg.Transport, cfg.ListenAddr, cfg.Listener, report)
	if cfg.OnPrepared != nil {
		cfg.OnPrepared(report)
	}

	serveErr := serveSupervised(ctx, cfg, srv, closeServer)
	return normalizeServeError(ctx, serveErr)
}

func validateConfig(cfg Config) (ServerFactory, time.Duration, error) {
	factory := cfg.ServerFactory
	if factory == nil {
		if cfg.Engine == nil {
			return nil, 0, i18n.EF(ErrInvalidConfig, i18n.KeyMCPNoEngineOrFactory)
		}
		eng := cfg.Engine
		factory = func(mCfg engine.MCPConfig) (MCPServerContract, error) {
			return eng.NewMCPServer(mCfg)
		}
	}
	if err := validateTransportConfig(cfg); err != nil {
		return nil, 0, err
	}
	shutTimeout := defaultShutdownTimeout
	if d, ok := cfg.ShutdownTimeout.Get(); ok {
		if !d.IsPositive() {
			return nil, 0, i18n.EF(ErrInvalidConfig, i18n.KeyMCPShutdownTimeoutPositive)
		}
		shutTimeout = d.Std()
	}
	return factory, shutTimeout, nil
}

func validateTransportConfig(cfg Config) error {
	switch cfg.Transport {
	case TransportStdio:
		if cfg.Stdin == nil || cfg.Stdout == nil {
			return i18n.EF(ErrInvalidConfig, i18n.KeyMCPStdioNilStreams)
		}
		if cfg.Listener != nil {
			return i18n.EF(ErrInvalidConfig, i18n.KeyMCPStdioForbidsListener)
		}
		return nil
	case TransportHTTP:
		if cfg.Listener == nil && strings.TrimSpace(cfg.ListenAddr) == "" {
			return i18n.EF(ErrInvalidConfig, i18n.KeyMCPHTTPMissingEndpoint)
		}
		return nil
	default:
		return i18n.EF(ErrInvalidTransport, i18n.KeyMCPInvalidTransportValue, i18n.Str("value", cfg.Transport.String()))
	}
}

func serveSupervised(ctx context.Context, cfg Config, srv MCPServerContract, closeServer func() error) error {
	return conc.RunScoped(ctx, func(sCtx context.Context, n *conc.Nursery) error {
		serveDone := make(chan struct{})
		defer close(serveDone)

		// 监督看门狗：收到取消信号时按传输形态安全解阻主循环，避免 stdio 阻塞读拖慢 Close 排空。
		if err := n.Go(func(wCtx context.Context) error {
			select {
			case <-serveDone:
				return nil
			case <-wCtx.Done():
				switch cfg.Transport {
				case TransportStdio:
					closeIfCloser(cfg.Stdin)
				case TransportHTTP:
					_ = closeServer()
				}
				return nil
			}
		}); err != nil {
			return err
		}

		return runTransportLoop(sCtx, cfg, srv)
	})
}

func runTransportLoop(ctx context.Context, cfg Config, srv MCPServerContract) error {
	switch cfg.Transport {
	case TransportStdio:
		return srv.ServeStdio(ctx, cfg.Stdin, cfg.Stdout)
	case TransportHTTP:
		if cfg.Listener != nil {
			return srv.ServeHTTPListener(ctx, cfg.Listener)
		}
		return srv.ListenAndServeHTTP(ctx, strings.TrimSpace(cfg.ListenAddr))
	default:
		return ErrInvalidTransport
	}
}

func normalizeServeError(ctx context.Context, serveErr error) error {
	if serveErr == nil {
		return nil
	}
	if ctx.Err() != nil && isShutdownTriggerErr(serveErr) {
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil
		}
		return ctx.Err()
	}
	return serveErr
}

func isShutdownTriggerErr(err error) bool {
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, fs.ErrClosed) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, http.ErrServerClosed)
}

func closeIfCloser(r io.Reader) {
	if c, ok := r.(io.Closer); ok && c != nil {
		_ = c.Close()
	}
}

func writePreparedSummary(stderr io.Writer, transport TransportKind, listenAddr string, ln net.Listener, report engine.MCPStartupReport) {
	if stderr == nil {
		return
	}
	endpoint := transport.String()
	if transport == TransportHTTP {
		addr := strings.TrimSpace(listenAddr)
		if ln != nil && ln.Addr() != nil {
			addr = ln.Addr().String()
		}
		endpoint = fmt.Sprintf("http (%s)", addr)
	}
	scannedLocks := 0
	if ar, ok := report.AuditReport().Get(); ok {
		scannedLocks = ar.ScannedLocks()
	}
	_, _ = fmt.Fprintf(
		stderr,
		"xops-mcp: ready transport=%s scanned_locks=%d recovered_transfers=%d\n",
		endpoint,
		scannedLocks,
		len(report.RecoveredTransfers()),
	)
}
