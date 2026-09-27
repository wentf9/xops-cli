package mcpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/pkg/mcpserver/transfer"
)

type lostCommitRemote struct{ transferRemote }

func (r lostCommitRemote) Commit(ctx context.Context, temporary, destination string, overwrite bool) (commitResult, error) {
	result, err := r.transferRemote.Commit(ctx, temporary, destination, overwrite)
	if result.Committed {
		return commitResult{Attempted: true}, io.EOF
	}
	return result, err
}

func lostCommitHook(r *Runtime) {
	r.transferDial = func(ctx context.Context, node string) (transferRemote, error) {
		client, err := r.getMCPSFTPClient(ctx, node)
		if err != nil {
			return nil, err
		}
		return lostCommitRemote{&sftpTransferRemote{client: client}}, nil
	}
}

func TestUnknownCommitRecoveryDoesNotRepeatWrite(t *testing.T) {
	r, server, client := startTransferRuntime(t, nil, pkgsftp.InMemHandler(), lostCommitHook)
	payload := []byte("committed before reply disappeared")
	digest := sha256.Sum256(payload)
	input := PrepareUploadInput{RequestID: "lost-reply", NodeID: "files", RemotePath: "/uncertain", Size: int64(len(payload)), SHA256: hex.EncodeToString(digest[:])}
	p := prepareTransferTest(t, client, "xops_prepare_upload", input)
	response, _ := transferTestRequest(t, server, p.Method, p.URL, p.Headers, bytes.NewReader(payload))
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("uncertain upload HTTP %d", response.StatusCode)
	}
	status := transferTestStatus(t, server, p)
	if status.State != transfer.Unknown {
		t.Fatalf("lost reply was misclassified: %+v", status)
	}
	retry := input
	retry.RequestID, retry.Overwrite = "new-request", true
	result, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "xops_prepare_upload", Arguments: retry})
	if err != nil || !result.IsError {
		t.Fatalf("uncertain destination was writable: %+v %v", result, err)
	}
	options := RecoveryOptions{StateDir: r.http.StateDir, TransferID: p.Task.ID, MaxRecords: 4096}
	if _, err := RecoverTransfers(t.Context(), options); !errors.Is(err, transfer.ErrStoreLocked) {
		t.Fatalf("live journal maintenance allowed: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(options.StateDir, p.Task.ID+".json")
	before, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	options.Verify = true
	entries, err := RecoverTransfers(t.Context(), options, WithConfigProvider(r.provider))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !entries[0].MatchesExpected || entries[0].Task.State != transfer.Unknown || entries[0].Task.Resolved {
		t.Fatalf("verification fabricated an execution result: %+v", entries)
	}
	after, err := os.ReadFile(recordPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("read-only recovery changed the journal")
	}
	options.Verify, options.ResolveUnknown, options.Cleanup = false, true, true
	options.Reason = "operator verified destination digest; release future writes"
	entries, err = RecoverTransfers(t.Context(), options, WithConfigProvider(r.provider))
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].Task.State != transfer.Unknown || !entries[0].Task.Resolved || entries[0].Task.CleanupPending {
		t.Fatalf("incorrect operator resolution: %+v", entries)
	}
}

func TestTransferCredentialReplayAndCancellation(t *testing.T) {
	_, server, client := startTransferRuntime(t, nil, pkgsftp.InMemHandler())
	digest := sha256.Sum256(nil)
	input := PrepareUploadInput{RequestID: "single-use", NodeID: "files", RemotePath: "/empty", SHA256: hex.EncodeToString(digest[:])}
	p := prepareTransferTest(t, client, "xops_prepare_upload", input)
	wrong := map[string]string{"Authorization": "Bearer " + httpTestToken, "Content-Type": "application/octet-stream"}
	response, _ := transferTestRequest(t, server, p.Method, p.URL, wrong, bytes.NewReader(nil))
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("service token used as a task credential")
	}
	rotated := prepareTransferTest(t, client, "xops_prepare_upload", input)
	response, _ = transferTestRequest(t, server, p.Method, p.URL, p.Headers, bytes.NewReader(nil))
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("rotated task credential remained valid")
	}
	response, _ = transferTestRequest(t, server, rotated.Method, rotated.URL, rotated.Headers, bytes.NewReader(nil))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("valid transfer failed: %d", response.StatusCode)
	}
	response, _ = transferTestRequest(t, server, rotated.Method, rotated.URL, rotated.Headers, bytes.NewReader(nil))
	if response.StatusCode != http.StatusConflict {
		t.Fatal("data transfer replayed")
	}
	input.RequestID, input.RemotePath = "cancel-ready", "/cancelled"
	p = prepareTransferTest(t, client, "xops_prepare_upload", input)
	response, _ = transferTestRequest(t, server, http.MethodDelete, p.CancelURL, p.Headers, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatal("ready cancellation failed")
	}
	if status := transferTestStatus(t, server, p); status.State != transfer.Cancelled {
		t.Fatalf("cancel status: %+v", status)
	}
	response, _ = transferTestRequest(t, server, p.Method, p.URL, p.Headers, bytes.NewReader(nil))
	if response.StatusCode != http.StatusConflict {
		t.Fatal("cancelled transfer executed")
	}
}

type blockedUploadRemote struct {
	transferRemote
	started chan struct{}
}

func (r blockedUploadRemote) Upload(ctx context.Context, _ string, _ io.Reader, _ int64, _ func() error, _ func(int64) error) (streamResult, error) {
	close(r.started)
	<-ctx.Done()
	return streamResult{}, ctx.Err()
}

func TestCancelActiveTransferStopsIOAndKeepsServiceUsable(t *testing.T) {
	started := make(chan struct{})
	r, server, client := startTransferRuntime(t, nil, pkgsftp.InMemHandler(), func(r *Runtime) {
		r.transferDial = func(ctx context.Context, node string) (transferRemote, error) {
			c, err := r.getMCPSFTPClient(ctx, node)
			if err != nil {
				return nil, err
			}
			return blockedUploadRemote{&sftpTransferRemote{client: c}, started}, nil
		}
	})
	digest := sha256.Sum256([]byte("payload"))
	p := prepareTransferTest(t, client, "xops_prepare_upload", PrepareUploadInput{RequestID: "cancel-active", NodeID: "files", RemotePath: "/never-committed", Size: 7, SHA256: hex.EncodeToString(digest[:])})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, p.Method, p.URL, strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range p.Headers {
		request.Header.Set(k, v)
	}
	done := make(chan error, 1)
	go func() {
		response, err := server.Client().Do(request)
		if response != nil {
			err = errors.Join(err, response.Body.Close())
		}
		done <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("upload did not start")
	}
	result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "xops_transfer_cancel", Arguments: TransferTaskInput{TransferID: p.Task.ID}})
	if err != nil || result.IsError {
		t.Fatalf("cancel call: %+v %v", result, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Logf("cancelled HTTP request: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("cancel did not unblock transfer")
	}
	status := transferTestStatus(t, server, p)
	if status.State != transfer.Cancelled || status.CleanupPending {
		t.Fatalf("active cancellation status: %+v", status)
	}
	tools, err := client.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 14 {
		t.Fatalf("service unavailable after cancellation: %v", err)
	}
	if records := r.transfers.Records(); len(records) != 1 {
		t.Fatalf("unexpected tasks: %d", len(records))
	}
}

func TestRecoveryMissingDirectoryIsReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")
	entries, err := RecoverTransfers(t.Context(), RecoveryOptions{StateDir: path, MaxRecords: 10})
	if err != nil || len(entries) != 0 {
		t.Fatalf("empty recovery: %+v %v", entries, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only recovery created metadata: %v", err)
	}
	data, err := json.Marshal(entries)
	if err != nil || string(data) != "[]" {
		t.Fatalf("unexpected recovery report: %s %v", data, err)
	}
}
