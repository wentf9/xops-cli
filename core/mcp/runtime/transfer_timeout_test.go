package runtime

import (
	"bytes"
	"context"
	"errors"
	"github.com/wentf9/xops-cli/core/mcp/remotefile"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
)

// Real-network tests need room for filesystem and scheduler latency (especially
// Windows race builds). Exact idle boundaries are covered with virtual time.
const transferTestIdle = 2 * time.Second

type transferTestStall struct {
	entered atomic.Bool
	release chan struct{}
	once    sync.Once
}

func (s *transferTestStall) unblock() { s.once.Do(func() { close(s.release) }) }

func (s *transferTestStall) wait(ctx context.Context) error {
	s.entered.Store(true)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.release:
		return errors.New("test stall released")
	}
}

func waitTransferTestDelay(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func awaitTransferIdleFailure(t *testing.T, server *httptest.Server, prepared PreparedTransferOutput) transfer.Status {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		status := transferTestStatus(t, server, prepared)
		if (status.State == transfer.Failed || status.State == transfer.Cancelled) && !status.CleanupPending {
			if !strings.Contains(status.Error, "file stream made no progress") {
				t.Fatalf("transfer failed without stream idle expiry: %+v", status)
			}
			return status
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed-out transfer not cleaned: %+v", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type waitingDownloadRemote struct {
	transferRemote
	wait func(context.Context) error
}

func (r waitingDownloadRemote) Download(ctx context.Context, meta remoteFileMetadata, w io.Writer, progress func(int64) error) (streamResult, error) {
	if err := r.wait(ctx); err != nil {
		return streamResult{}, err
	}
	return r.transferRemote.Download(ctx, meta, w, progress)
}

func TestDownloadOutlivesRequestBodyDeadline(t *testing.T) {
	_, server, client := startTransferRuntime(t, func(o *HTTPOptions) { o.BodyTimeout = time.Second; o.StreamIdle = 5 * time.Second }, pkgsftp.InMemHandler(), func(r *Runtime) {
		r.transferDial = func(ctx context.Context, node string) (transferRemote, error) {
			c, err := r.getFixtureSFTPClient(ctx, node)
			if err != nil {
				return nil, err
			}
			return waitingDownloadRemote{remotefile.New(c), func(ctx context.Context) error {
				return waitTransferTestDelay(ctx, 2*time.Second)
			}}, nil
		}
	})
	payload := []byte("download is healthy beyond the request body deadline")
	p := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("seed", "/source", payload))
	response, _ := transferTestRequest(t, server, p.Method, p.URL, p.Headers, bytes.NewReader(payload))
	if response.StatusCode != http.StatusOK {
		t.Fatal("seed failed")
	}
	p = prepareTransferTest(t, client, "xops_prepare_download", PrepareDownloadInput{RequestID: "slow-download", NodeID: "files", RemotePath: "/source"})
	response, body := transferTestRequest(t, server, p.Method, p.URL, p.Headers, nil)
	if response.StatusCode != http.StatusOK || !bytes.Equal(body, payload) {
		t.Fatalf("download interrupted by body deadline: HTTP %d %s", response.StatusCode, body)
	}
	status := transferTestStatus(t, server, p)
	if status.State != transfer.Streamed {
		t.Fatalf("healthy download: %+v", status)
	}
}

type waitingSFTPWriter struct {
	pkgsftp.FileWriter
	wait func(context.Context) error
}

func (w waitingSFTPWriter) Filewrite(req *pkgsftp.Request) (io.WriterAt, error) {
	writer, err := w.FileWriter.Filewrite(req)
	if err != nil {
		return nil, err
	}
	return &waitingWriteAt{WriterAt: writer, ctx: req.Context(), wait: w.wait}, nil
}

type waitingWriteAt struct {
	io.WriterAt
	ctx  context.Context
	wait func(context.Context) error
}

func (w *waitingWriteAt) WriteAt(p []byte, off int64) (int, error) {
	if err := w.wait(w.ctx); err != nil {
		return 0, err
	}
	return w.WriterAt.WriteAt(p, off)
}
func (w *waitingWriteAt) Close() error {
	if c, ok := w.WriterAt.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func TestStalledSFTPWriteExpiresStreamAndReleasesCapacity(t *testing.T) {
	stall := &transferTestStall{release: make(chan struct{})}
	defer stall.unblock() // Release the server worker before runtime cleanup.
	handlers := pkgsftp.InMemHandler()
	handlers.FilePut = waitingSFTPWriter{handlers.FilePut, stall.wait}
	r, server, client := startTransferRuntime(t, func(o *HTTPOptions) {
		o.StreamIdle = transferTestIdle
		o.Transfers.MaxActive = 1
		o.Transfers.MaxPerTarget = 1
	}, handlers)
	payload := []byte("stalled remote write")
	p := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("stall", "/destination", payload))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, p.Method, p.URL, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	response, err := server.Client().Do(req)
	if response != nil {
		closeTransferTestResource(t, response.Body)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		t.Logf("timed-out response delivery: %v", err)
	}
	if !stall.entered.Load() {
		t.Fatal("test never reached the stalled SFTP write")
	}
	stall.unblock()
	// HTTP interruption can reach the caller before bounded SFTP cleanup ends.
	awaitTransferIdleFailure(t, server, p)
	next := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("after-stall", "/next", nil))
	response, body := transferTestRequest(t, server, next.Method, next.URL, next.Headers, bytes.NewReader(nil))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("capacity not released: %d %s", response.StatusCode, body)
	}
	withBoundarySFTP(t, r, func(c *pkgsftp.Client) error {
		entries, err := c.ReadDir("/")
		if err != nil {
			return err
		}
		if len(entries) != 1 || entries[0].Name() != "next" {
			t.Errorf("unexpected files after timeout: %v", entries)
		}
		return nil
	})
}

func TestSFTPProgressRenewsIdleDeadline(t *testing.T) {
	handlers := pkgsftp.InMemHandler()
	handlers.FilePut = waitingSFTPWriter{handlers.FilePut, func(ctx context.Context) error {
		return waitTransferTestDelay(ctx, 400*time.Millisecond)
	}}
	_, server, client := startTransferRuntime(t, func(o *HTTPOptions) { o.StreamIdle = transferTestIdle }, handlers)
	payload := bytes.Repeat([]byte("x"), 8*32*1024)
	p := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("progress", "/destination", payload))
	start := time.Now()
	response, body := transferTestRequest(t, server, p.Method, p.URL, p.Headers, bytes.NewReader(payload))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("progressing upload expired: %d %s", response.StatusCode, body)
	}
	if time.Since(start) < transferTestIdle {
		t.Fatal("test did not cross idle window")
	}
	status := transferTestStatus(t, server, p)
	if status.State != transfer.Completed {
		t.Fatalf("progressing upload: %+v", status)
	}
}

func TestStalledSFTPDownloadExpiresWithoutBodyDeadline(t *testing.T) {
	stall := &transferTestStall{release: make(chan struct{})}
	defer stall.unblock()
	_, server, client := startTransferRuntime(t, func(o *HTTPOptions) { o.BodyTimeout = 10 * time.Second; o.StreamIdle = transferTestIdle }, pkgsftp.InMemHandler(), func(r *Runtime) {
		r.transferDial = func(ctx context.Context, node string) (transferRemote, error) {
			c, err := r.getFixtureSFTPClient(ctx, node)
			if err != nil {
				return nil, err
			}
			return waitingDownloadRemote{remotefile.New(c), stall.wait}, nil
		}
	})
	p := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("seed", "/source", nil))
	seedResponse, seedBody := transferTestRequest(t, server, p.Method, p.URL, p.Headers, bytes.NewReader(nil))
	if seedResponse.StatusCode != http.StatusOK {
		t.Fatalf("seed upload failed: %d %s", seedResponse.StatusCode, seedBody)
	}
	p = prepareTransferTest(t, client, "xops_prepare_download", PrepareDownloadInput{RequestID: "read-stall", NodeID: "files", RemotePath: "/source"})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, p.Method, p.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	response, err := server.Client().Do(req)
	if response != nil {
		closeTransferTestResource(t, response.Body)
	}
	if err != nil {
		t.Logf("interrupted stalled download: %v", err)
	}
	if !stall.entered.Load() {
		t.Fatal("test never reached the stalled SFTP download")
	}
	awaitTransferIdleFailure(t, server, p)
}

type delayedUploadInspection struct {
	transferRemote
	stall *atomic.Bool
	gate  *transferTestStall
}

func (r delayedUploadInspection) Inspect(ctx context.Context, name string, upload, overwrite bool) (remoteFileMetadata, error) {
	if upload && r.stall.CompareAndSwap(true, false) {
		if err := r.gate.wait(ctx); err != nil {
			return remoteFileMetadata{}, err
		}
	}
	return r.transferRemote.Inspect(ctx, name, upload, overwrite)
}
func TestUploadInspectionExpiresAtStreamIdleDeadline(t *testing.T) {
	var stall atomic.Bool
	gate := &transferTestStall{release: make(chan struct{})}
	defer gate.unblock()
	r, server, client := startTransferRuntime(t, func(o *HTTPOptions) {
		o.StreamIdle = transferTestIdle
		o.Transfers.MaxActive = 1
		o.Transfers.MaxPerTarget = 1
	}, pkgsftp.InMemHandler(), func(r *Runtime) {
		r.transferDial = func(ctx context.Context, node string) (transferRemote, error) {
			c, err := r.getFixtureSFTPClient(ctx, node)
			if err != nil {
				return nil, err
			}
			return delayedUploadInspection{remotefile.New(c), &stall, gate}, nil
		}
	})
	payload := []byte("nonempty body while metadata stalls")
	p := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("inspect-stall", "/destination", payload))
	stall.Store(true)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, p.Method, p.URL, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	response, err := server.Client().Do(req)
	if response != nil {
		closeTransferTestResource(t, response.Body)
	}
	if err != nil {
		t.Logf("interrupted metadata request: %v", err)
	}
	if !gate.entered.Load() {
		t.Fatal("test never reached inspection")
	}
	status := awaitTransferIdleFailure(t, server, p)
	if status.TempOwned {
		t.Fatalf("inspection created a temporary: %+v", status)
	}
	next := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("after-inspection", "/next", nil))
	response, body := transferTestRequest(t, server, next.Method, next.URL, next.Headers, bytes.NewReader(nil))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("inspection retained capacity: %d %s", response.StatusCode, body)
	}
	withBoundarySFTP(t, r, func(c *pkgsftp.Client) error {
		entries, err := c.ReadDir("/")
		if err == nil && (len(entries) != 1 || entries[0].Name() != "next") {
			t.Errorf("inspection left files: %v", entries)
		}
		return err
	})
}
