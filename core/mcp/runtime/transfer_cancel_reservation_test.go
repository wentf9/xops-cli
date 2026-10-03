package runtime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
)

type delayedCommitAdmission struct {
	ports.ExecutionGate
	entered, release chan struct{}
}

func (g *delayedCommitAdmission) Enter(ctx context.Context, a ports.Admission) (ports.Permit, error) {
	if a.Phase == ports.Commit {
		close(g.entered)
		select {
		case <-g.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return g.ExecutionGate.Enter(ctx, a)
}

func TestTaskCancellationBeforeCommitAdmissionPreventsRename(t *testing.T) {
	f := setupPublication(t, nil, false, true)
	gate := &delayedCommitAdmission{ExecutionGate: f.coordinator, entered: make(chan struct{}), release: make(chan struct{})}
	backend := &handoffBackend{Backend: f.backend}
	f.runtime.gate = gate
	f.runtime.backend = backend
	server := publicationHTTP(t, f)
	p, done := startReservationUpload(t, f, server)
	select {
	case <-gate.entered:
	case <-f.ctx.Done():
		t.Fatal("commit gate was not reached")
	}
	status, err := f.runtime.transfers.Cancel(f.runtime.http.scope, p.Task.ID)
	if err != nil || !status.CancelRequested {
		t.Fatalf("cancel before reservation: %+v %v", status, err)
	}
	close(gate.release)
	select {
	case <-done:
	case <-f.ctx.Done():
		t.Fatal("transfer did not finish")
	}
	record, err := f.runtime.transfers.Record(p.Task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != transfer.Cancelled || backend.commits.Load() != 0 {
		t.Fatalf("cancelled task committed: %+v commits=%d", record.Status(), backend.commits.Load())
	}
}

func startReservationUpload(t *testing.T, f *publicationFixture, server *httptest.Server) (PreparedTransferOutput, <-chan error) {
	t.Helper()
	input := uploadBoundaryInput("cancel-at-gate", "/destination", []byte("payload"))
	input.NodeID = "node"
	p := prepareTransferTest(t, f.client, "xops_prepare_upload", input)
	req, err := http.NewRequestWithContext(f.ctx, p.Method, p.URL, bytes.NewBufferString("payload"))
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
			_, readErr := io.Copy(io.Discard, response.Body)
			err = errors.Join(err, readErr, response.Body.Close())
		}
		done <- err
	}()
	return p, done
}

func TestRequestCancellationBeforeCommitAdmissionPreventsRename(t *testing.T) {
	f := setupPublication(t, nil, false, true)
	gate := &delayedCommitAdmission{ExecutionGate: f.coordinator, entered: make(chan struct{}), release: make(chan struct{})}
	backend := &handoffBackend{Backend: f.backend}
	f.runtime.gate = gate
	f.runtime.backend = backend
	server := publicationHTTP(t, f)
	cancelRequest := make(chan context.CancelFunc, 1)
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		cancelRequest <- cancel
		f.runtime.serveTransferHTTP(w, req.WithContext(ctx))
	})
	p, done := startReservationUpload(t, f, server)
	select {
	case <-gate.entered:
	case <-f.ctx.Done():
		t.Fatal("commit gate was not reached")
	}
	(<-cancelRequest)()
	close(gate.release)
	select {
	case <-done:
	case <-f.ctx.Done():
		t.Fatal("transfer did not finish")
	}
	record, err := f.runtime.transfers.Record(p.Task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != transfer.Cancelled || backend.commits.Load() != 0 {
		t.Fatalf("cancelled request committed: %+v commits=%d", record.Status(), backend.commits.Load())
	}
}

func TestTaskCancellationAfterReservationCannotUndoCommit(t *testing.T) {
	f := setupPublication(t, nil, false, true)
	backend := &handoffBackend{Backend: f.backend, at: "reserved", reached: make(chan struct{}), resume: make(chan struct{})}
	f.runtime.backend = backend
	server := publicationHTTP(t, f)
	p, done := startReservationUpload(t, f, server)
	select {
	case <-backend.reached:
	case <-f.ctx.Done():
		t.Fatal("commit handoff was not reached")
	}
	status, err := f.runtime.transfers.Cancel(f.runtime.http.scope, p.Task.ID)
	if !errors.Is(err, transfer.ErrInvalidState) || status.CancelRequested {
		t.Errorf("reserved commit accepted cancellation: %+v %v", status, err)
	}
	close(backend.resume)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-f.ctx.Done():
		t.Fatal("transfer did not finish")
	}
	record, err := f.runtime.transfers.Record(p.Task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != transfer.Completed || record.CancelRequested || backend.commits.Load() != 1 {
		t.Fatalf("reserved commit changed result: %+v", record.Status())
	}
}
