package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/sshexec"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
)

func publicationHTTP(t *testing.T, f *publicationFixture) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(f.runtime.serveTransferHTTP))
	t.Cleanup(server.Close)
	f.runtime.http.PublicURL = server.URL
	return server
}

func changeTransferState(t *testing.T, f *publicationFixture, change func(*ports.OperationSnapshot)) {
	t.Helper()
	view := f.coordinator.Snapshot()
	previous := view.Revision
	view.Revision = "next-" + previous
	change(&view)
	update, err := f.coordinator.BeginUpdate(f.ctx, previous, view)
	if err != nil {
		t.Fatal(err)
	}
	if err := update.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if err := update.Publish(f.ctx, f.backend.RetirePlans); err != nil {
		t.Fatal(err)
	}
}

func TestReadyTransferCannotUseEditedDependencies(t *testing.T) {
	for _, edit := range []string{"target", "credential", "trust", "policy", "disable", "delete"} {
		t.Run(edit, func(t *testing.T) {
			f := setupPublication(t, nil, false, true)
			server := publicationHTTP(t, f)
			input := uploadBoundaryInput("ready", "/destination", []byte("payload"))
			input.NodeID = "node"
			p := prepareTransferTest(t, f.client, "xops_prepare_upload", input)
			changeTransferState(t, f, func(view *ports.OperationSnapshot) {
				node := view.Targets["node"]
				switch edit {
				case "target":
					node = publicationTarget(t, f.second.Address)
				case "credential":
					node.Plan.Hops[0].AuthUpdateToken = "auth-2"
				case "trust":
					node.Plan.Hops[0].TrustVersion = "trust-2"
				case "policy":
					view.PolicyRevision = "policy-2"
				case "disable":
					node.Disabled = true
				case "delete":
					delete(view.Targets, "node")
					return
				}
				view.Targets["node"] = node
			})
			response, _ := transferTestRequest(t, server, p.Method, p.URL, p.Headers, bytes.NewBufferString("payload"))
			if response.StatusCode != http.StatusConflict {
				t.Fatalf("stale claim HTTP %d", response.StatusCode)
			}
			result, err := f.client.CallTool(f.ctx, &mcp.CallToolParams{Name: "xops_prepare_upload", Arguments: input})
			if err != nil || !result.IsError {
				t.Fatalf("stale retry minted credentials: %+v %v", result, err)
			}
			record, err := f.runtime.transfers.Record(p.Task.ID)
			if err != nil || record.State != transfer.Failed || record.TempPath != "" {
				t.Fatalf("stale task: %+v %v", record.Status(), err)
			}
			if err := f.runtime.verifyRecovery(f.ctx, record, &RecoveryEntry{}, 1024); err == nil {
				t.Fatal("stale recovery reached remote")
			}
		})
	}
}

type revocableTransferSecrets struct{ revoked atomic.Bool }

func (s *revocableTransferSecrets) ResolveSecret(ctx context.Context, request ssh.SecretRequest) ([]byte, error) {
	if s.revoked.Load() && request.VersionToken == "auth-1" {
		return nil, errors.New("old credential revoked")
	}
	return []byte(sshfixture.Password), ctx.Err()
}

type handoffBackend struct {
	ports.Backend
	at              string
	reached, resume chan struct{}
	opens, commits  atomic.Int32
	lostReply       bool
}

func (b *handoffBackend) OpenTransfer(ctx context.Context, permit ports.Permit, nodeID string) (ports.TransferSession, error) {
	remote, err := b.Backend.OpenTransfer(ctx, permit, nodeID)
	if err != nil {
		return nil, err
	}
	b.opens.Add(1)
	return &handoffRemote{TransferSession: remote, owner: b}, nil
}

type handoffRemote struct {
	ports.TransferSession
	owner *handoffBackend
}

func (s *handoffRemote) barrier(ctx context.Context, at string) error {
	if s.owner.at != at {
		return nil
	}
	close(s.owner.reached)
	select {
	case <-s.owner.resume:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *handoffRemote) Upload(ctx context.Context, path string, source io.Reader, size int64, confirm func() error, progress func(int64) error) (streamResult, error) {
	result, err := s.TransferSession.Upload(ctx, path, source, size, confirm, progress)
	if err == nil {
		err = s.barrier(ctx, "uploaded")
	}
	return result, err
}
func (s *handoffRemote) ReserveCommit(ctx context.Context, permit ports.Permit) error {
	if err := s.barrier(ctx, "reserved"); err != nil {
		return err
	}
	return s.TransferSession.ReserveCommit(ctx, permit)
}
func (s *handoffRemote) Commit(ctx context.Context, temporary, destination string, overwrite bool) (commitResult, error) {
	s.owner.commits.Add(1)
	result, err := s.TransferSession.Commit(ctx, temporary, destination, overwrite)
	if s.owner.lostReply && result.Committed {
		return commitResult{Attempted: true}, io.EOF
	}
	return result, err
}

func TestTransferRevocationOrdersCommitAndRetainsTransport(t *testing.T) {
	for _, boundary := range []string{"uploaded", "reserved"} {
		t.Run(boundary, func(t *testing.T) {
			f := setupPublication(t, nil, false, true)
			secrets := &revocableTransferSecrets{}
			if err := f.backend.Shutdown(f.ctx); err != nil {
				t.Fatal(err)
			}
			backend, err := sshexec.New(f.ctx, sshexec.Options{SSH: []ssh.Option{ssh.WithSecretResolver(secrets), ssh.WithHostKeyVerifier(publicationTrust{f.first.Address: f.first.HostKey, f.second.Address: f.second.HostKey})}})
			if err != nil {
				t.Fatal(err)
			}
			f.backend = backend
			instrumented := &handoffBackend{Backend: backend, at: boundary, reached: make(chan struct{}), resume: make(chan struct{})}
			f.runtime.backend = instrumented
			server := publicationHTTP(t, f)
			input := uploadBoundaryInput("revoke", "/destination", []byte("payload"))
			input.NodeID = "node"
			p := prepareTransferTest(t, f.client, "xops_prepare_upload", input)
			request, err := http.NewRequestWithContext(f.ctx, p.Method, p.URL, bytes.NewBufferString("payload"))
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range p.Headers {
				request.Header.Set(k, v)
			}
			done := make(chan error, 1)
			// The bounded request, runtime shutdown, and barrier release all end I/O.
			go func() {
				response, err := server.Client().Do(request)
				if response != nil {
					_, readErr := io.Copy(io.Discard, response.Body)
					err = errors.Join(err, readErr, response.Body.Close())
				}
				done <- err
			}()
			select {
			case <-instrumented.reached:
			case <-f.ctx.Done():
				t.Fatal("transfer did not reach barrier")
			}
			secrets.revoked.Store(true)
			changeTransferState(t, f, func(view *ports.OperationSnapshot) {
				node := view.Targets["node"]
				node.Plan.Hops[0].AuthUpdateToken = "auth-2"
				view.Targets["node"] = node
			})
			close(instrumented.resume)
			select {
			case <-done:
			case <-f.ctx.Done():
				t.Fatal("transfer did not terminate")
			}
			record, err := f.runtime.transfers.Record(p.Task.ID)
			if err != nil {
				t.Fatal(err)
			}
			assertRevokedTransfer(t, f, instrumented, boundary, record)
		})
	}
}

func TestTerminalTransferResultsSurviveRetargeting(t *testing.T) {
	for _, lostReply := range []bool{false, true} {
		t.Run(map[bool]string{false: "completed", true: "unknown"}[lostReply], func(t *testing.T) {
			f := setupPublication(t, nil, false, true)
			backend := &handoffBackend{Backend: f.backend, lostReply: lostReply}
			f.runtime.backend = backend
			server := publicationHTTP(t, f)
			input := uploadBoundaryInput("terminal", "/destination", []byte("payload"))
			input.NodeID = "node"
			p := prepareTransferTest(t, f.client, "xops_prepare_upload", input)
			transferTestRequest(t, server, p.Method, p.URL, p.Headers, bytes.NewBufferString("payload"))
			before, err := f.runtime.transfers.Record(p.Task.ID)
			if err != nil {
				t.Fatal(err)
			}
			want := transfer.Completed
			if lostReply {
				want = transfer.Unknown
			}
			if before.State != want {
				t.Fatalf("result = %s", before.State)
			}
			publishTarget(t, f, f.second.Address)
			retry := prepareTransferTest(t, f.client, "xops_prepare_upload", input)
			if retry.Task.State != want || retry.Task.ID != p.Task.ID || len(retry.Headers) != 0 {
				t.Fatalf("terminal replay changed outcome: %+v", retry)
			}
			after, err := f.runtime.transfers.Record(p.Task.ID)
			if err != nil {
				t.Fatal(err)
			}
			beforeJSON, err := json.Marshal(before)
			if err != nil {
				t.Fatal(err)
			}
			afterJSON, err := json.Marshal(after)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(beforeJSON, afterJSON) || backend.commits.Load() != 1 {
				t.Fatal("configuration change rewrote an execution result")
			}
		})
	}
}

func assertRevokedTransfer(t *testing.T, f *publicationFixture, instrumented *handoffBackend, boundary string, record transfer.Record) {
	t.Helper()
	if boundary == "reserved" {
		if record.State != transfer.Completed || instrumented.commits.Load() != 1 || instrumented.opens.Load() != 1 {
			t.Fatalf("reserved commit lost original transport: %+v opens=%d commits=%d", record.Status(), instrumented.opens.Load(), instrumented.commits.Load())
		}
	} else {
		if record.State == transfer.Unknown || record.State == transfer.Completed || instrumented.commits.Load() != 0 || !record.CleanupPending {
			t.Fatalf("revoked stream committed or cleaned against new authority: %+v", record.Status())
		}
		if err := f.runtime.cleanupTransfer(record.ID); err == nil {
			t.Fatal("cleanup ignored recorded credential version")
		}
	}
}
