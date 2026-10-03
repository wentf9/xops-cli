package runtime

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"sync/atomic"
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
)

type failingCommitStore struct {
	transfer.Store
	afterWrite bool
	writes     atomic.Int32
}

func (s *failingCommitStore) Save(record transfer.Record) error {
	if record.State != transfer.Committing {
		return s.Store.Save(record)
	}
	s.writes.Add(1)
	err := errors.New("injected commit-intent persistence failure")
	if s.afterWrite {
		err = errors.Join(err, s.Store.Save(record))
	}
	return err
}

type captureCommitGate struct {
	ports.ExecutionGate
	reserved chan ports.Permit
}

func (g *captureCommitGate) Enter(ctx context.Context, admission ports.Admission) (ports.Permit, error) {
	permit, err := g.ExecutionGate.Enter(ctx, admission)
	if err == nil && admission.Phase == ports.Commit {
		select {
		case g.reserved <- permit:
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), permit.Close())
		}
	}
	return permit, err
}

func TestCommitJournalFailureDoesNotRenameAndReleasesReservation(t *testing.T) {
	for _, afterWrite := range []bool{false, true} {
		name := "before-write"
		if afterWrite {
			name = "applied-write-returned-error"
		}
		t.Run(name, func(t *testing.T) {
			f := setupPublication(t, nil, false, true)
			store := installFailingCommitStore(t, f, afterWrite)
			gate := &captureCommitGate{ExecutionGate: f.coordinator, reserved: make(chan ports.Permit, 1)}
			backend := &handoffBackend{Backend: f.backend}
			f.runtime.gate, f.runtime.backend = gate, backend
			server := publicationHTTP(t, f)
			input := uploadBoundaryInput("journal-failure", "/destination", []byte("payload"))
			input.NodeID = "node"
			prepared := prepareTransferTest(t, f.client, "xops_prepare_upload", input)
			response, body := transferTestRequest(t, server, prepared.Method, prepared.URL, prepared.Headers, bytes.NewBufferString("payload"))
			if response.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("persistence failure HTTP %d: %s", response.StatusCode, body)
			}
			if store.writes.Load() != 1 || backend.commits.Load() != 0 {
				t.Fatalf("commit intent writes=%d remote commits=%d", store.writes.Load(), backend.commits.Load())
			}
			select {
			case permit := <-gate.reserved:
				if !errors.Is(permit.Context().Err(), context.Canceled) {
					t.Fatal("failed durable commit retained its reservation")
				}
			default:
				t.Fatal("failure was not exercised after commit reservation")
			}
			assertNoJournalFailureSideEffect(t, f, store, prepared.Task.ID)
		})
	}
}

func installFailingCommitStore(t *testing.T, f *publicationFixture, afterWrite bool) *failingCommitStore {
	t.Helper()
	// No task or HTTP request exists yet; replace the empty owned journal while
	// preserving the production Manager, durable file writes and runtime path.
	if err := f.runtime.transfers.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err := transfer.OpenJournal(f.runtime.http.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	store := &failingCommitStore{Store: journal, afterWrite: afterWrite}
	manager, err := transfer.NewManager(f.ctx, store, f.runtime.http.Transfers)
	if err != nil {
		t.Fatal(err)
	}
	f.runtime.transfers = manager
	return store
}

func assertNoJournalFailureSideEffect(t *testing.T, f *publicationFixture, store *failingCommitStore, id string) {
	t.Helper()
	record, err := f.runtime.transfers.Record(id)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != transfer.Failed || record.CleanupPending {
		t.Fatalf("unattempted commit did not settle and clean up: %+v", record.Status())
	}
	restored, err := store.Load(10)
	if err != nil || len(restored) != 1 || restored[0].State != transfer.Failed || restored[0].CleanupPending {
		t.Fatalf("durable settlement differs: %+v %v", restored, err)
	}
	permit, err := f.runtime.admitTransfer(f.ctx, record, ports.Inspect)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := permit.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, path := range []string{record.Spec.RemotePath, record.TempPath} {
		_, err := f.backend.Inspect(f.ctx, permit, record.Spec.NodeID, ports.InspectRequest{Path: path})
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected remote file after failed journal write: %q: %v", path, err)
		}
	}
}
