package transfer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
)

func boundRecord(t *testing.T) Record {
	t.Helper()
	r := sampleRecord(t)
	r.Version = recordVersion
	r.Spec.RequestDigest = strings.Repeat("a", 64)
	view := ports.OperationSnapshot{DomainID: "test", Targets: map[string]ports.Target{"node": {Info: ports.NodeInfo{ID: "node"}, Plan: ssh.ConnectionPlan{Scope: "test", Hops: []ssh.ConnectionConfig{{NodeID: "node", Address: "localhost", User: "fixture", AuthUpdateToken: "\xff\x00\x80", SudoUpdateToken: "\xfe\x00\x81"}}}}}}
	binding, err := ports.Bind(view, r.Spec.Scope, "xops_prepare_upload", r.Spec)
	if err != nil {
		t.Fatal(err)
	}
	r.Authorization = &Authorization{Snapshot: view, Binding: binding}
	return r
}

func boundPermit(t *testing.T, record Record, phase ports.Phase) ports.Permit {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	p, err := ports.NewPermit(ctx, ports.Admission{OperationID: record.OperationID, Phase: phase, Snapshot: record.Authorization.Snapshot, Binding: record.Authorization.Binding}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p
}

func TestJournalV2AuthorizationRoundTrip(t *testing.T) {
	j, _ := testJournal(t)
	record := boundRecord(t)
	if err := j.Save(record); err != nil {
		t.Fatal(err)
	}
	got, err := j.Load(10)
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], record) {
		t.Fatalf("lossy authorization roundtrip: %v", err)
	}
	if err := got[0].validate(); err != nil {
		t.Fatal(err)
	}
	public, err := json.Marshal(record.Status())
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"authorization", "snapshot", "binding", "AuthUpdateToken", "tokenDigest"} {
		if bytes.Contains(public, []byte(field)) {
			t.Fatalf("private %s leaked in status", field)
		}
	}
}

func TestBoundTaskRequiresMatchingPhaseAndDefensiveSnapshot(t *testing.T) {
	m, _ := testManager(t, DefaultLimits())
	record := boundRecord(t)
	p, err := m.PrepareBound(record.Spec, record.OperationID, boundPermit(t, record, ports.Inspect))
	if err != nil {
		t.Fatal(err)
	}
	copy, err := m.Record(p.Status.ID)
	if err != nil {
		t.Fatal(err)
	}
	target := copy.Authorization.Snapshot.Targets["node"]
	target.Plan.Hops[0].Address = "other"
	copy.Authorization.Snapshot.Targets["node"] = target
	actual, err := m.Record(p.Status.ID)
	if err != nil {
		t.Fatal(err)
	}
	if actual.Authorization.Snapshot.Targets["node"].Plan.Hops[0].Address != "localhost" {
		t.Fatal("Record leaked mutable snapshot")
	}
	if _, _, err := m.Retry(record.Spec.Scope, record.Spec.RequestID, record.Spec.RequestDigest); !errors.Is(err, ErrBindingRequired) {
		t.Fatal("legacy retry rotated a bound credential")
	}
	if _, err := m.Claim(t.Context(), p.Status.ID, p.Token, Upload); err == nil {
		t.Fatal("bound claim bypassed gate")
	}
	if _, err := m.ClaimBound(t.Context(), p.Status.ID, p.Token, Upload, boundPermit(t, record, ports.Inspect)); err == nil {
		t.Fatal("inspect permit claimed data")
	}
	stream := boundPermit(t, record, ports.TransferStart)
	lease, err := m.ClaimBound(t.Context(), p.Status.ID, p.Token, Upload, stream)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	}()
	verifyTestTransfer(t, lease)
	if _, err := lease.BeginCommit(); err == nil {
		t.Fatal("bound commit bypassed reservation")
	}
	commit := boundPermit(t, record, ports.Commit)
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	// Reservation already won at the gate; stream revocation cannot undo it.
	if _, err := lease.BeginCommitBound(commit); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.Fail(errors.New("lost reply")); err != nil {
		t.Fatal(err)
	}
	if err := m.InvalidateReady(p.Status.ID, ports.ErrStaleBinding); err != nil {
		t.Fatal(err)
	}
	after, err := m.Lookup(record.Spec.Scope, p.Status.ID)
	if err != nil || after.State != Unknown {
		t.Fatalf("invalidation reset uncertain result: %+v %v", after, err)
	}
	record.Spec.RequestID = "different-request"
	if _, err := m.Prepare(record.Spec, record.OperationID); !errors.Is(err, ErrConflict) {
		t.Fatalf("unknown destination lock lost: %v", err)
	}
}

func TestFutureJournalVersionDoesNotOverwriteAnyRecord(t *testing.T) {
	j, directory := testJournal(t)
	record := boundRecord(t)
	if err := j.Save(record); err != nil {
		t.Fatal(err)
	}
	record.Version = 99
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(directory, record.ID+".json")
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	if manager, err := NewManager(t.Context(), j, DefaultLimits()); err == nil {
		t.Error("future version accepted")
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	}
	after, err := os.ReadFile(name)
	if err != nil || !bytes.Equal(data, after) {
		t.Fatal("future journal was rewritten")
	}
}

func TestLegacyJournalRemainsReadableButCannotAcquireBoundAuthority(t *testing.T) {
	j, _ := testJournal(t)
	for _, state := range []State{Ready, Transferring, Committing, Completed, Unknown} {
		record := sampleRecord(t)
		record.Spec.RequestID = string(state)
		record.State = state
		if state == Completed {
			record.SHA256 = record.Spec.SHA256
		}
		if err := j.Save(record); err != nil {
			t.Fatal(err)
		}
	}
	m, err := NewManager(t.Context(), j, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, record := range m.Records() {
		if record.Version != legacyRecordVersion || record.Authorization != nil {
			t.Fatal("legacy record falsely gained authorization")
		}
		if err := record.CheckPermit(boundPermit(t, boundRecord(t), ports.Recovery), ports.Recovery); !errors.Is(err, ErrBindingRequired) {
			t.Fatal("legacy task acquired recovery authority")
		}
		want := map[string]State{"ready": Expired, "transferring": Failed, "committing": Unknown, "completed": Completed, "unknown": Unknown}[record.Spec.RequestID]
		if record.State != want {
			t.Fatalf("legacy state = %s want %s", record.State, want)
		}
	}
}
