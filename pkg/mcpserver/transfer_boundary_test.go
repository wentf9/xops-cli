package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/pkg/mcpserver/guardrail"
	"github.com/wentf9/xops-cli/pkg/mcpserver/transfer"
)

func uploadBoundaryInput(id, name string, data []byte) PrepareUploadInput {
	digest := sha256.Sum256(data)
	return PrepareUploadInput{RequestID: id, NodeID: "files", RemotePath: name, Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:])}
}

func withBoundarySFTP(t *testing.T, r *Runtime, fn func(*pkgsftp.Client) error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := r.getMCPSFTPClient(ctx, "files")
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransferTestResource(t, client)
	if err := client.Do(ctx, fn); err != nil {
		t.Fatal(err)
	}
}

type boundaryFileCreates struct {
	pkgsftp.FileWriter
	privateModeRequests atomic.Int32
}

func (c *boundaryFileCreates) Filewrite(r *pkgsftp.Request) (io.WriterAt, error) {
	// RequestServer exposes OPEN attributes without their flags. Our client sends
	// exactly one permission attribute; v1's attr-less OPEN has no bytes here.
	flags := r.Pflags()
	if len(r.Attrs) != 4 || binary.BigEndian.Uint32(r.Attrs) != 0600 || !flags.Creat || !flags.Excl {
		return nil, errors.New("OPEN did not atomically request exclusive creation with mode 0600")
	}
	c.privateModeRequests.Add(1)
	return c.FileWriter.Filewrite(r)
}

func TestTransferDestinationBoundaries(t *testing.T) {
	handlers := pkgsftp.InMemHandler()
	commands := &boundaryFileCreates{FileWriter: handlers.FilePut}
	handlers.FilePut = commands
	r, server, client := startTransferRuntime(t, nil, handlers)
	original := []byte("original")
	input := uploadBoundaryInput("first", "/destination", original)
	first := prepareTransferTest(t, client, "xops_prepare_upload", input)
	response, body := transferTestRequest(t, server, first.Method, first.URL, first.Headers, bytes.NewReader(original))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("initial upload: %d %s", response.StatusCode, body)
	}
	input.RequestID = "no-clobber"
	result, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "xops_prepare_upload", Arguments: input})
	if err != nil || !result.IsError {
		t.Fatalf("existing destination allowed: %+v %v", result, err)
	}
	replacement := []byte("replacement")
	input = uploadBoundaryInput("replace", "/destination", replacement)
	input.Overwrite = true
	next := prepareTransferTest(t, client, "xops_prepare_upload", input)
	response, body = transferTestRequest(t, server, next.Method, next.URL, next.Headers, bytes.NewReader(replacement))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("atomic replacement: %d %s", response.StatusCode, body)
	}
	withBoundarySFTP(t, r, func(c *pkgsftp.Client) error {
		f, err := c.Open("/destination")
		if err != nil {
			return err
		}
		got, readErr := io.ReadAll(f)
		closeErr := f.Close()
		if !bytes.Equal(got, replacement) {
			t.Errorf("replacement differs: %q", got)
		}
		if err := errors.Join(readErr, closeErr); err != nil {
			return err
		}
		// The memory filesystem reports a fixed mode; inspect the initial OPEN
		// attributes rather than accepting a later chmod as proof of privacy.
		if commands.privateModeRequests.Load() != 2 {
			t.Errorf("private file mode not requested for both uploads")
		}
		if err := c.Mkdir("/directory"); err != nil {
			return err
		}
		return c.Symlink("/destination", "/link")
	})
	for _, name := range []string{"/directory", "/link"} {
		for _, direction := range []string{"upload", "download"} {
			var args any = PrepareDownloadInput{RequestID: direction + name, NodeID: "files", RemotePath: name}
			if direction == "upload" {
				u := uploadBoundaryInput(direction+name, name, nil)
				u.Overwrite = true
				args = u
			}
			result, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "xops_prepare_" + direction, Arguments: args})
			if err != nil || !result.IsError {
				t.Fatalf("%s accepted %s: %+v %v", direction, name, result, err)
			}
		}
	}
}

type boundaryFaultRemote struct {
	transferRemote
	fault string
}

func (r boundaryFaultRemote) Upload(ctx context.Context, name string, source io.Reader, size int64, confirm func() error, progress func(int64) error) (streamResult, error) {
	if r.fault == "lost-create" {
		_, err := r.transferRemote.Upload(ctx, name, bytes.NewReader(nil), 0, nil, nil)
		return streamResult{CreationAttempted: true}, errors.Join(io.ErrUnexpectedEOF, err)
	}
	result, err := r.transferRemote.Upload(ctx, name, source, size, confirm, progress)
	if r.fault == "upload-close" {
		return result, errors.Join(err, errors.New("injected SFTP close failure"))
	}
	return result, err
}
func (r boundaryFaultRemote) Download(ctx context.Context, meta remoteFileMetadata, destination io.Writer, progress func(int64) error) (streamResult, error) {
	result, err := r.transferRemote.Download(ctx, meta, destination, progress)
	if r.fault == "download-close" {
		return result, errors.Join(err, errors.New("injected source close failure"))
	}
	return result, err
}
func boundaryFaultHook(fault string) func(*Runtime) {
	return func(r *Runtime) {
		r.transferDial = func(ctx context.Context, node string) (transferRemote, error) {
			c, err := r.getMCPSFTPClient(ctx, node)
			if err != nil {
				return nil, err
			}
			return boundaryFaultRemote{&sftpTransferRemote{client: c}, fault}, nil
		}
	}
}

func TestUploadCloseFailureNeverCommits(t *testing.T) {
	r, server, client := startTransferRuntime(t, nil, pkgsftp.InMemHandler(), boundaryFaultHook("upload-close"))
	p := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("close", "/destination", []byte("bytes")))
	response, _ := transferTestRequest(t, server, p.Method, p.URL, p.Headers, bytes.NewReader([]byte("bytes")))
	status := transferTestStatus(t, server, p)
	if response.StatusCode < 400 || status.State != transfer.Failed || status.CleanupPending {
		t.Fatalf("close failure: %d %+v", response.StatusCode, status)
	}
	withBoundarySFTP(t, r, func(c *pkgsftp.Client) error {
		files, err := c.ReadDir("/")
		if len(files) != 0 {
			t.Errorf("files remain: %v", files)
		}
		return err
	})
}

func TestUnconfirmedCreationNeedsExplicitRecoveryOwnership(t *testing.T) {
	r, server, client := startTransferRuntime(t, nil, pkgsftp.InMemHandler(), boundaryFaultHook("lost-create"))
	p := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("lost-open", "/destination", nil))
	transferTestRequest(t, server, p.Method, p.URL, p.Headers, bytes.NewReader(nil))
	status := transferTestStatus(t, server, p)
	if status.State != transfer.Failed || !status.CleanupPending || status.TempOwned {
		t.Fatalf("unconfirmed creation: %+v", status)
	}
	withBoundarySFTP(t, r, func(c *pkgsftp.Client) error {
		files, err := c.ReadDir("/")
		if len(files) != 1 {
			t.Errorf("unconfirmed file deleted: %v", files)
		}
		return err
	})
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	opts := RecoveryOptions{StateDir: r.http.StateDir, TransferID: p.Task.ID, MaxRecords: 4096, Cleanup: true}
	if _, err := RecoverTransfers(t.Context(), opts, WithConfigProvider(r.provider)); err == nil {
		t.Fatal("cleanup accepted unconfirmed ownership without reason")
	}
	opts.Reason = "operator verified exclusive temporary creation in controlled target directory"
	entries, err := RecoverTransfers(t.Context(), opts, WithConfigProvider(r.provider))
	if err != nil || len(entries) != 1 || entries[0].Task.CleanupPending {
		t.Fatalf("explicit cleanup: %+v %v", entries, err)
	}
}

func TestDownloadCloseFailureDoesNotPublishLocalFile(t *testing.T) {
	_, server, client := startTransferRuntime(t, nil, pkgsftp.InMemHandler(), boundaryFaultHook("download-close"))
	data := bytes.Repeat([]byte("content"), 8192)
	p := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("seed", "/source", data))
	response, _ := transferTestRequest(t, server, p.Method, p.URL, p.Headers, bytes.NewReader(data))
	if response.StatusCode != http.StatusOK {
		t.Fatal("seed failed")
	}
	p = prepareTransferTest(t, client, "xops_prepare_download", PrepareDownloadInput{RequestID: "read-close", NodeID: "files", RemotePath: "/source"})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, p.Method, p.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range p.Headers {
		request.Header.Set(k, v)
	}
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransferTestResource(t, response.Body)
	got, err := io.ReadAll(response.Body)
	if err == nil || len(got) >= len(data) {
		t.Fatalf("source close error sent complete body: %d %v", len(got), err)
	}
	status := transferTestStatus(t, server, p)
	if status.State != transfer.Failed {
		t.Fatalf("source close failure status: %+v", status)
	}
}

type boundaryAudit struct{ failPhase string }

func (a boundaryAudit) Log(entry guardrail.AuditEntry) error {
	if entry.Outcome == a.failPhase {
		return errors.New("injected audit storage failure")
	}
	return nil
}
func TestTransferAuditFailureBeforeAndAfterCommit(t *testing.T) {
	for _, phase := range []string{"started", "commit_started", "completed"} {
		t.Run(phase, func(t *testing.T) {
			r, server, client := startTransferRuntime(t, nil, pkgsftp.InMemHandler(), func(r *Runtime) { r.guardrail.SetAuditWriter(boundaryAudit{phase}) })
			p := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("audit", "/destination", nil))
			response, _ := transferTestRequest(t, server, p.Method, p.URL, p.Headers, bytes.NewReader(nil))
			status := transferTestStatus(t, server, p)
			if phase == "completed" {
				if response.StatusCode != http.StatusOK || status.State != transfer.Completed || status.Warning == "" {
					t.Fatalf("committed audit failure encouraged retry: %d %+v", response.StatusCode, status)
				}
			} else {
				if response.StatusCode < 400 || status.State != transfer.Failed || status.CleanupPending {
					t.Fatalf("precommit audit failure: %d %+v", response.StatusCode, status)
				}
				withBoundarySFTP(t, r, func(c *pkgsftp.Client) error {
					files, err := c.ReadDir("/")
					if len(files) != 0 {
						t.Errorf("unapproved remote files: %v", files)
					}
					return err
				})
			}
		})
	}
}

func TestSlowUploadDeadlineCleansBeforeCommit(t *testing.T) {
	r, server, client := startTransferRuntime(t, func(o *HTTPOptions) { o.StreamIdle = 100 * time.Millisecond }, pkgsftp.InMemHandler())
	p := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("slow", "/destination", []byte("bytes")))
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(t.Context(), "tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransferTestResource(t, conn)
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "PUT /v1/transfers/%s/content HTTP/1.1\r\nHost: %s\r\nAuthorization: %s\r\nContent-Type: application/octet-stream\r\nContent-Length: 5\r\n\r\nb", p.Task.ID, server.Listener.Addr(), p.Headers["Authorization"]); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	// Read and write deadlines may expire together; a closed response is also
	// valid. The durable postcondition, rather than HTTP delivery, is decisive.
	if err == nil {
		closeTransferTestResource(t, response.Body)
		if response.StatusCode < 400 {
			t.Fatal("slow partial upload accepted")
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		status := transferTestStatus(t, server, p)
		if status.State == transfer.Failed || status.State == transfer.Cancelled {
			if !status.CleanupPending {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("slow upload remained active or uncleaned: %+v", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	withBoundarySFTP(t, r, func(c *pkgsftp.Client) error {
		files, err := c.ReadDir("/")
		if len(files) != 0 {
			t.Errorf("slow upload left remote files: %v", files)
		}
		return err
	})
}

func TestOverwriteRequiresAdvertisedAtomicRename(t *testing.T) {
	// No tests in this package run in parallel. Restore the upstream global
	// only after this test's runtime and all SFTP server goroutines have stopped.
	if err := pkgsftp.SetSFTPExtensions("hardlink@openssh.com", "statvfs@openssh.com"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pkgsftp.SetSFTPExtensions("hardlink@openssh.com", "posix-rename@openssh.com", "statvfs@openssh.com"); err != nil {
			t.Error(err)
		}
	})
	r, _, client := startTransferRuntime(t, nil, pkgsftp.InMemHandler())
	input := uploadBoundaryInput("unsupported-replace", "/destination", nil)
	input.Overwrite = true
	result, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "xops_prepare_upload", Arguments: input})
	if err != nil || !result.IsError {
		t.Fatalf("atomic rename unavailable but preparation allowed: %+v %v", result, err)
	}
	if len(r.transfers.Records()) != 0 {
		t.Fatal("unsupported replacement created task")
	}
}

type shutdownCommitRemote struct {
	transferRemote
	started  chan struct{}
	stopping <-chan struct{}
}

func (r shutdownCommitRemote) Commit(ctx context.Context, temporary, destination string, overwrite bool) (commitResult, error) {
	close(r.started)
	select {
	case <-r.stopping:
		return r.transferRemote.Commit(ctx, temporary, destination, overwrite)
	case <-ctx.Done():
		return commitResult{}, ctx.Err()
	}
}

func TestRuntimeShutdownPreservesInFlightCommit(t *testing.T) {
	started := make(chan struct{})
	r, server, client := startTransferRuntime(t, nil, pkgsftp.InMemHandler(), func(r *Runtime) {
		r.transferDial = func(ctx context.Context, node string) (transferRemote, error) {
			c, err := r.getMCPSFTPClient(ctx, node)
			if err != nil {
				return nil, err
			}
			return shutdownCommitRemote{&sftpTransferRemote{client: c}, started, r.ctx.Done()}, nil
		}
	})
	p := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("shutdown-commit", "/destination", nil))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, p.Method, p.URL, bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	done := make(chan error, 1)
	go func() {
		response, err := server.Client().Do(req)
		if response != nil {
			err = errors.Join(err, response.Body.Close())
		}
		done <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("commit did not begin")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Logf("HTTP delivery during shutdown: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("HTTP request leaked during shutdown")
	}
	status, err := r.transfers.Lookup(r.http.scope, p.Task.ID)
	if err != nil || status.State != transfer.Completed {
		t.Fatalf("shutdown lost confirmed commit: %+v %v", status, err)
	}
	entries, err := RecoverTransfers(t.Context(), RecoveryOptions{StateDir: r.http.StateDir, TransferID: p.Task.ID, MaxRecords: 4096, Verify: true}, WithConfigProvider(r.provider))
	if err != nil || len(entries) != 1 || !entries[0].MatchesExpected {
		t.Fatalf("shutdown destination verification: %+v %v", entries, err)
	}
}
