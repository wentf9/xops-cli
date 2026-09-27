package mcpserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/pkg/mcpserver/transfer"
)

type delayedDownloadRemote struct{ transferRemote }

func (r delayedDownloadRemote) Download(ctx context.Context, meta remoteFileMetadata, w io.Writer, progress func(int64) error) (streamResult, error) {
	timer := time.NewTimer(300 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return streamResult{}, ctx.Err()
	}
	return r.transferRemote.Download(ctx, meta, w, progress)
}

func TestDownloadOutlivesRequestBodyDeadline(t *testing.T) {
	_, server, client := startTransferRuntime(t, func(o *HTTPOptions) { o.BodyTimeout = 80 * time.Millisecond; o.StreamIdle = time.Second }, pkgsftp.InMemHandler(), func(r *Runtime) {
		r.transferDial = func(ctx context.Context, node string) (transferRemote, error) {
			c, err := r.getMCPSFTPClient(ctx, node)
			if err != nil {
				return nil, err
			}
			return delayedDownloadRemote{&sftpTransferRemote{client: c}}, nil
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

type stalledSFTPWriter struct {
	pkgsftp.FileWriter
	delay time.Duration
}

func (w stalledSFTPWriter) Filewrite(req *pkgsftp.Request) (io.WriterAt, error) {
	writer, err := w.FileWriter.Filewrite(req)
	if err != nil {
		return nil, err
	}
	return &delayedWriteAt{WriterAt: writer, ctx: req.Context(), delay: w.delay}, nil
}

type delayedWriteAt struct {
	io.WriterAt
	ctx   context.Context
	delay time.Duration
}

func (w *delayedWriteAt) WriteAt(p []byte, off int64) (int, error) {
	timer := time.NewTimer(w.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return w.WriterAt.WriteAt(p, off)
	case <-w.ctx.Done():
		return 0, w.ctx.Err()
	}
}
func (w *delayedWriteAt) Close() error {
	if c, ok := w.WriterAt.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func TestStalledSFTPWriteExpiresStreamAndReleasesCapacity(t *testing.T) {
	handlers := pkgsftp.InMemHandler()
	handlers.FilePut = stalledSFTPWriter{handlers.FilePut, 600 * time.Millisecond}
	r, server, client := startTransferRuntime(t, func(o *HTTPOptions) {
		o.StreamIdle = 100 * time.Millisecond
		o.Transfers.MaxActive = 1
		o.Transfers.MaxPerTarget = 1
	}, handlers)
	payload := []byte("stalled remote write")
	p := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("stall", "/destination", payload))
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, p.Method, p.URL, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	start := time.Now()
	response, err := server.Client().Do(req)
	if response != nil {
		closeTransferTestResource(t, response.Body)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		t.Logf("timed-out response delivery: %v", err)
	}
	if time.Since(start) > 450*time.Millisecond {
		t.Fatal("SFTP write ignored stream idle timeout")
	}
	// HTTP interruption can reach the caller before bounded SFTP cleanup ends.
	deadline := time.Now().Add(2 * time.Second)
	for {
		status := transferTestStatus(t, server, p)
		if (status.State == transfer.Failed || status.State == transfer.Cancelled) && !status.CleanupPending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stalled task not cleaned: %+v", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
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
	handlers.FilePut = stalledSFTPWriter{handlers.FilePut, 60 * time.Millisecond}
	_, server, client := startTransferRuntime(t, func(o *HTTPOptions) { o.StreamIdle = 250 * time.Millisecond }, handlers)
	payload := bytes.Repeat([]byte("x"), 8*32*1024)
	p := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("progress", "/destination", payload))
	start := time.Now()
	response, body := transferTestRequest(t, server, p.Method, p.URL, p.Headers, bytes.NewReader(payload))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("progressing upload expired: %d %s", response.StatusCode, body)
	}
	if time.Since(start) < 250*time.Millisecond {
		t.Fatal("test did not cross idle window")
	}
	status := transferTestStatus(t, server, p)
	if status.State != transfer.Completed {
		t.Fatalf("progressing upload: %+v", status)
	}
}

func TestStalledSFTPDownloadExpiresWithoutBodyDeadline(t *testing.T) {
	_, server, client := startTransferRuntime(t, func(o *HTTPOptions) { o.BodyTimeout = 2 * time.Second; o.StreamIdle = 80 * time.Millisecond }, pkgsftp.InMemHandler(), func(r *Runtime) {
		r.transferDial = func(ctx context.Context, node string) (transferRemote, error) {
			c, err := r.getMCPSFTPClient(ctx, node)
			if err != nil {
				return nil, err
			}
			return delayedDownloadRemote{&sftpTransferRemote{client: c}}, nil
		}
	})
	p := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("seed", "/source", nil))
	transferTestRequest(t, server, p.Method, p.URL, p.Headers, bytes.NewReader(nil))
	p = prepareTransferTest(t, client, "xops_prepare_download", PrepareDownloadInput{RequestID: "read-stall", NodeID: "files", RemotePath: "/source"})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
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
	status := transferTestStatus(t, server, p)
	if status.State != transfer.Failed && status.State != transfer.Cancelled {
		t.Fatalf("stalled remote read not failed: %+v", status)
	}
}

type delayedUploadInspection struct {
	transferRemote
	stall   *atomic.Bool
	entered chan struct{}
}

func (r delayedUploadInspection) Inspect(ctx context.Context, name string, upload, overwrite bool) (remoteFileMetadata, error) {
	if upload && r.stall.CompareAndSwap(true, false) {
		close(r.entered)
		timer := time.NewTimer(600 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return remoteFileMetadata{}, ctx.Err()
		}
	}
	return r.transferRemote.Inspect(ctx, name, upload, overwrite)
}
func TestUploadInspectionExpiresAtStreamIdleDeadline(t *testing.T) {
	var stall atomic.Bool
	entered := make(chan struct{})
	r, server, client := startTransferRuntime(t, func(o *HTTPOptions) {
		o.StreamIdle = 100 * time.Millisecond
		o.Transfers.MaxActive = 1
		o.Transfers.MaxPerTarget = 1
	}, pkgsftp.InMemHandler(), func(r *Runtime) {
		r.transferDial = func(ctx context.Context, node string) (transferRemote, error) {
			c, err := r.getMCPSFTPClient(ctx, node)
			if err != nil {
				return nil, err
			}
			return delayedUploadInspection{&sftpTransferRemote{client: c}, &stall, entered}, nil
		}
	})
	payload := []byte("nonempty body while metadata stalls")
	p := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("inspect-stall", "/destination", payload))
	stall.Store(true)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, p.Method, p.URL, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	start := time.Now()
	response, err := server.Client().Do(req)
	if response != nil {
		closeTransferTestResource(t, response.Body)
	}
	if err != nil {
		t.Logf("interrupted metadata request: %v", err)
	}
	if time.Since(start) > 450*time.Millisecond {
		t.Fatal("metadata inspection ignored stream idle timeout")
	}
	select {
	case <-entered:
	default:
		t.Fatal("test never reached inspection")
	}
	deadline := time.Now().Add(time.Second)
	for {
		status := transferTestStatus(t, server, p)
		if status.State == transfer.Failed || status.State == transfer.Cancelled {
			if status.CleanupPending || status.TempOwned {
				t.Fatalf("inspection created a temporary: %+v", status)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("inspection did not terminate: %+v", status)
		}
		time.Sleep(5 * time.Millisecond)
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
