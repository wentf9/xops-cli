package transfer

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
)

type countedTransferStore struct {
	Store
	saves int
}

func nearLimitRecord(t *testing.T, state State) Record {
	t.Helper()
	r := boundRecord(t)
	r.State = state
	now := time.Date(2026, 10, 2, 0, 0, 0, 123456789, time.UTC)
	r.CreatedAt, r.UpdatedAt = now, now
	r.StartBefore = now.Add(DefaultLimits().StartWindow)
	r.StatusExpiresAt = now.Add(DefaultLimits().Retention)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Authorization.Snapshot.Policy.AuditLog = strings.Repeat("x", maxRecordBytes-22-len(data))
	return r
}

func TestPreparationReservesSpaceForTaskStateGrowth(t *testing.T) {
	m, _ := testManager(t, DefaultLimits())
	r := nearLimitRecord(t, Ready)
	m.now = func() time.Time { return r.CreatedAt }
	if _, err := encodeRecord(r); err != nil {
		t.Fatal(err)
	}
	if _, err := m.PrepareBound(r.Spec, r.OperationID, boundPermit(t, r, ports.Inspect)); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("ready-only size admitted a task without transition space: %v", err)
	}
}

func TestPreviouslyFullJournalDoesNotBlockRecovery(t *testing.T) {
	for _, state := range []State{Ready, Transferring, Committing} {
		t.Run(string(state), func(t *testing.T) {
			j, _ := testJournal(t)
			r := nearLimitRecord(t, state)
			if err := j.Save(r); err != nil {
				t.Fatal(err)
			}
			m, err := NewManager(t.Context(), j, DefaultLimits())
			if err != nil {
				t.Fatalf("full old record prevented startup: %v", err)
			}
			defer func() {
				if err := m.Close(); err != nil {
					t.Error(err)
				}
			}()
			got, err := m.Record(r.ID)
			if err != nil {
				t.Fatal(err)
			}
			want := map[State]State{Ready: Expired, Transferring: Failed, Committing: Unknown}[state]
			if got.State != want || got.Warning == "" {
				t.Fatalf("missing recovery outcome/diagnostic: %+v", got.Status())
			}
			if state == Committing {
				spec := r.Spec
				spec.RequestID = "new"
				if _, err := m.Prepare(spec, "new"); !errors.Is(err, ErrConflict) {
					t.Fatalf("lost uncertain destination lock: %v", err)
				}
			}
		})
	}
}

func (s *countedTransferStore) Save(r Record) error { s.saves++; return s.Store.Save(r) }

func TestOversizedAuthorizationDoesNotDisableTransferStore(t *testing.T) {
	m, journal := testManager(t, DefaultLimits())
	store := &countedTransferStore{Store: journal}
	m.store = store
	record := boundRecord(t)
	record.Authorization.Snapshot.Policy.NodeOverrides = make(map[string]policy.NodeConfig)
	for i := range 2000 {
		record.Authorization.Snapshot.Policy.NodeOverrides[fmt.Sprintf("node-%04d", i)] = policy.NodeConfig{ApprovalThreshold: "dangerous"}
	}
	binding, err := ports.Bind(record.Authorization.Snapshot, record.Spec.Scope, "xops_prepare_upload", record.Spec)
	if err != nil {
		t.Fatal(err)
	}
	record.Authorization.Binding = binding
	data, err := json.Marshal(record)
	if err != nil || len(data) <= maxRecordBytes {
		t.Fatalf("fixture must exceed journal limit: size=%d error=%v", len(data), err)
	}
	if _, err := m.PrepareBound(record.Spec, record.OperationID, boundPermit(t, record, ports.Inspect)); !errors.Is(err, ErrRecordTooLarge) || errors.Is(err, ErrStoreUnusable) {
		t.Errorf("oversized input was treated as a storage failure: %v", err)
	}
	if store.saves != 0 || len(m.Records()) != 0 {
		t.Errorf("oversized record reached persistence: saves=%d records=%d", store.saves, len(m.Records()))
	}
	valid := boundRecord(t)
	prepared, err := m.PrepareBound(valid.Spec, valid.OperationID, boundPermit(t, valid, ports.Inspect))
	if err != nil {
		t.Fatalf("valid preparation unavailable after oversized input: %v", err)
	}
	lease, err := m.ClaimBound(t.Context(), prepared.Status.ID, prepared.Token, Upload, boundPermit(t, valid, ports.TransferStart))
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptedLargeTaskFitsFailureAndResolution(t *testing.T) {
	m, journal := testManager(t, DefaultLimits())
	r := boundRecord(t)
	r.Spec.RemotePath = "/" + strings.Repeat("<", 1000) + "/file"
	r.Authorization.Snapshot.Policy.AuditLog = strings.Repeat("x", 36<<10)
	binding, err := ports.Bind(r.Authorization.Snapshot, r.Spec.Scope, "xops_prepare_upload", r.Spec)
	if err != nil {
		t.Fatal(err)
	}
	r.Authorization.Binding = binding
	p, err := m.PrepareBound(r.Spec, r.OperationID, boundPermit(t, r, ports.Inspect))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := m.ClaimBound(t.Context(), p.Status.ID, p.Token, Upload, boundPermit(t, r, ports.TransferStart))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	}()
	verifyTestTransfer(t, lease)
	if _, err := lease.BeginCommitBound(boundPermit(t, r, ports.Commit)); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.Fail(errors.New(strings.Repeat("\x00", 4096))); err != nil {
		t.Fatal(err)
	}
	if err := m.Warn(p.Status.ID, strings.Repeat("<", 4096)); err != nil {
		t.Fatal(err)
	}
	stored, err := m.Record(p.Status.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored.Resolution = strings.Repeat("&", 4096/6)
	stored.Resolved = true
	if err := ValidateDiagnostic(stored.Resolution); err != nil {
		t.Fatal(err)
	}
	if err := journal.Save(stored); err != nil {
		t.Fatalf("reserved growth did not fit: %v", err)
	}
	loaded, err := journal.Load(10)
	if err != nil || len(loaded) != 1 || !loaded[0].Resolved {
		t.Fatalf("large record could not be reopened: %v", err)
	}
	if err := ValidateDiagnostic(strings.Repeat("\x00", 4096)); err == nil {
		t.Fatal("operator reason bypassed encoded-size budget")
	}
}
