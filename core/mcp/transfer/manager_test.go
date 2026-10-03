package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func testManager(t *testing.T, limits Limits) (*Manager, *Journal) {
	t.Helper()
	j, _ := testJournal(t)
	m, err := NewManager(t.Context(), j, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	return m, j
}

func prepareTestTransfer(t *testing.T, m *Manager, requestID string) Prepared {
	t.Helper()
	r := sampleRecord(t)
	r.Spec.RequestID = requestID
	prepared, err := m.Prepare(r.Spec, r.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func claimTestTransfer(t *testing.T, m *Manager, p Prepared) *Lease {
	t.Helper()
	l, err := m.Claim(t.Context(), p.Status.ID, p.Token, Upload)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	})
	return l
}

func verifyTestTransfer(t *testing.T, lease *Lease) {
	t.Helper()
	if _, err := lease.Temporary(); err != nil {
		t.Fatal(err)
	}
	if err := lease.ConfirmTemporary(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Verify(0, lease.Spec().SHA256); err != nil {
		t.Fatal(err)
	}
}

func TestManagerIdempotencyRotationAndSingleClaim(t *testing.T) {
	m, _ := testManager(t, DefaultLimits())
	record := sampleRecord(t)
	first, err := m.Prepare(record.Spec, record.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.Prepare(record.Spec, "new-handler-operation")
	if err != nil {
		t.Fatal(err)
	}
	if first.Status.ID != second.Status.ID || first.Status.OperationID != second.Status.OperationID || first.Token == second.Token || first.Status.StartBefore != second.Status.StartBefore {
		t.Fatal("retry did not preserve task/operation/window and rotate credential")
	}
	if _, err := m.Authenticate(first.Status.ID, first.Token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old token remained valid: %v", err)
	}
	if _, err := m.Claim(t.Context(), second.Status.ID, second.Token, Download); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong direction accepted: %v", err)
	}
	changed := record.Spec
	changed.RemotePath = "/files/other"
	if _, err := m.Prepare(changed, "op"); !errors.Is(err, ErrConflict) {
		t.Fatalf("same key changed parameters: %v", err)
	}
	claimTestTransfer(t, m, second)
	afterStart, err := m.Prepare(record.Spec, "retry")
	if err != nil || afterStart.Token != "" || afterStart.Status.ID != first.Status.ID {
		t.Fatalf("started task was reopened: %+v err=%v", afterStart, err)
	}
	status, err := m.Authenticate(second.Status.ID, second.Token)
	if err != nil || status.State != Transferring {
		t.Fatalf("repeat status after claim: %+v %v", status, err)
	}
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{second.Token, "tokenDigest", `"scope"`} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("status exposed credential information: %s", data)
		}
	}
}

func TestManagerCapacityFailureDoesNotConsumeTask(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxActive, limits.MaxPerTarget = 1, 1
	m, _ := testManager(t, limits)
	p1 := prepareTestTransfer(t, m, "one")
	p2 := prepareTestTransfer(t, m, "two")
	lease := claimTestTransfer(t, m, p1)
	if _, err := m.Claim(t.Context(), p2.Status.ID, p2.Token, Upload); !errors.Is(err, ErrBusy) {
		t.Fatalf("expected busy: %v", err)
	}
	status, err := m.Authenticate(p2.Status.ID, p2.Token)
	if err != nil || status.State != Ready {
		t.Fatalf("busy consumed task: %+v %v", status, err)
	}
	if _, err := lease.Fail(errors.New("test interruption")); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	claimTestTransfer(t, m, p2)
}

func TestManagerCommitSurvivesRequestCancellation(t *testing.T) {
	m, _ := testManager(t, DefaultLimits())
	p := prepareTestTransfer(t, m, "commit")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	lease, err := m.Claim(ctx, p.Status.ID, p.Token, Upload)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	}()
	verifyTestTransfer(t, lease)
	commitCtx, err := lease.BeginCommit()
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := commitCtx.Err(); err != nil {
		t.Fatalf("request cancellation reached remote commit: %v", err)
	}
	if status, err := m.CancelWithToken(p.Status.ID, p.Token); !errors.Is(err, ErrInvalidState) || status.State != Committing {
		t.Fatalf("commit cancellation reported success: %+v %v", status, err)
	}
	status, err := lease.Complete()
	if err != nil || status.State != Completed || status.CleanupPending {
		t.Fatalf("commit completion: %+v %v", status, err)
	}
	if _, err := m.Claim(t.Context(), p.Status.ID, p.Token, Upload); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("committed transfer replayed: %v", err)
	}
}

func TestManagerUnknownCommitBlocksDestinationAndRetention(t *testing.T) {
	m, _ := testManager(t, DefaultLimits())
	p := prepareTestTransfer(t, m, "uncertain")
	lease := claimTestTransfer(t, m, p)
	verifyTestTransfer(t, lease)
	if _, err := lease.BeginCommit(); err != nil {
		t.Fatal(err)
	}
	status, err := lease.Fail(errors.New("rename response lost"))
	if err != nil || status.State != Unknown {
		t.Fatalf("uncertain commit: %+v %v", status, err)
	}
	if err := m.Cleaned(p.Status.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("uncertain temporary file cleanup allowed: %v", err)
	}
	m.now = func() time.Time { return p.Status.StatusExpiresAt.Add(time.Hour) }
	r := sampleRecord(t)
	r.Spec.RequestID = "new-request"
	if _, err := m.Prepare(r.Spec, "op"); !errors.Is(err, ErrConflict) {
		t.Fatalf("uncertain destination accepted overwrite after retention: %v", err)
	}
	if got := m.Records(); len(got) != 1 || got[0].State != Unknown {
		t.Fatalf("unresolved evidence discarded: %+v", got)
	}
}

func TestManagerKnownCommitRemainsCompletedOnJournalFailure(t *testing.T) {
	m, journal := testManager(t, DefaultLimits())
	p := prepareTestTransfer(t, m, "disk-failure")
	lease := claimTestTransfer(t, m, p)
	verifyTestTransfer(t, lease)
	if _, err := lease.BeginCommit(); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("metadata disk unavailable")
	journal.replace = func(*os.Root, string, string) error { return wantErr }
	status, err := lease.Complete()
	if !errors.Is(err, wantErr) || status.State != Completed {
		t.Fatalf("known remote commit downgraded to failure: %+v %v", status, err)
	}
	got, err := m.Lookup("scope", p.Status.ID)
	if err != nil || got.State != Completed {
		t.Fatalf("in-memory known result lost: %+v %v", got, err)
	}
	records, err := journal.Load(10)
	if err != nil || len(records) != 1 || records[0].State != Committing {
		t.Fatalf("durable commit intent lost: %+v %v", records, err)
	}
	r := sampleRecord(t)
	r.Spec.RequestID = "another"
	if _, err := m.Prepare(r.Spec, "op"); !errors.Is(err, ErrStoreUnusable) {
		t.Fatalf("storage failure did not stop new mutations: %v", err)
	}
}

func TestManagerRecoveryNeverResumesOrRecommits(t *testing.T) {
	journal, _ := testJournal(t)
	states := []State{Ready, Transferring, Verifying, Committing, Completed}
	for i, state := range states {
		r := sampleRecord(t)
		r.Spec.RequestID = string(rune('a' + i))
		r.State = state
		if state == Completed {
			r.SHA256 = r.Spec.SHA256
		}
		if err := journal.Save(r); err != nil {
			t.Fatal(err)
		}
	}
	m, err := NewManager(t.Context(), journal, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	}()
	want := map[string]State{"a": Expired, "b": Failed, "c": Failed, "d": Unknown, "e": Completed}
	for _, record := range m.Records() {
		if record.State != want[record.Spec.RequestID] {
			t.Errorf("recovery %s = %s", record.Spec.RequestID, record.State)
		}
	}
}

func TestManagerDownloadRequiresFullVerifiedStream(t *testing.T) {
	m, _ := testManager(t, DefaultLimits())
	r := sampleRecord(t)
	r.Spec.Direction, r.Spec.SHA256, r.Spec.Size = Download, "", 3
	p, err := m.Prepare(r.Spec, r.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := m.Claim(t.Context(), p.Status.ID, p.Token, Download)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := lease.Complete(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("unverified download succeeded: %v", err)
	}
	digest := sha256.Sum256([]byte("abc"))
	if err := lease.Verify(2, hex.EncodeToString(digest[:])); err == nil {
		t.Fatal("short download accepted")
	}
	if err := lease.Progress(3); err != nil {
		t.Fatal(err)
	}
	if err := lease.Verify(3, hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	status, err := lease.Complete()
	if err != nil || status.State != Streamed {
		t.Fatalf("download must report streamed, not client saved: %+v %v", status, err)
	}
}

func TestManagerClaimIsSingleUseUnderConcurrency(t *testing.T) {
	m, _ := testManager(t, DefaultLimits())
	p := prepareTestTransfer(t, m, "concurrent")
	var wg sync.WaitGroup
	leases := make(chan *Lease, 8)
	errorsCh := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			lease, err := m.Claim(t.Context(), p.Status.ID, p.Token, Upload)
			if err != nil {
				errorsCh <- err
				return
			}
			leases <- lease
		})
	}
	wg.Wait()
	close(leases)
	close(errorsCh)
	if len(leases) != 1 || len(errorsCh) != 7 {
		t.Fatalf("claims won=%d lost=%d", len(leases), len(errorsCh))
	}
	for err := range errorsCh {
		if !errors.Is(err, ErrInvalidState) {
			t.Errorf("duplicate claim error: %v", err)
		}
	}
	for lease := range leases {
		t.Cleanup(func() {
			if err := lease.Close(); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestExpiredClaimKeepsStableErrorAndQueryableStatus(t *testing.T) {
	m, _ := testManager(t, DefaultLimits())
	p := prepareTestTransfer(t, m, "expiry")
	m.now = func() time.Time { return p.Status.StartBefore.Add(time.Second) }
	for range 2 {
		if _, err := m.Claim(t.Context(), p.Status.ID, p.Token, Upload); !errors.Is(err, ErrExpired) {
			t.Fatalf("expired claim: %v", err)
		}
		status, err := m.Authenticate(p.Status.ID, p.Token)
		if err != nil || status.State != Expired {
			t.Fatalf("expired task lost status access: %+v %v", status, err)
		}
	}
}

func TestTargetPathOwnershipLastsThroughCleanup(t *testing.T) {
	m, _ := testManager(t, DefaultLimits())
	first := prepareTestTransfer(t, m, "first-owner")
	second := prepareTestTransfer(t, m, "second-owner")
	lease := claimTestTransfer(t, m, first)
	if _, err := m.Claim(t.Context(), second.Status.ID, second.Token, Upload); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent destination accepted: %v", err)
	}
	if _, err := lease.Fail(errors.New("stream failed; cleanup running")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Claim(t.Context(), second.Status.ID, second.Token, Upload); !errors.Is(err, ErrBusy) {
		t.Fatalf("destination released before cleanup finished: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	claimTestTransfer(t, m, second)
}

func TestShutdownCancelsStreamButWaitsForCommitOwner(t *testing.T) {
	m, _ := testManager(t, DefaultLimits())
	p := prepareTestTransfer(t, m, "committing-shutdown")
	lease := claimTestTransfer(t, m, p)
	verifyTestTransfer(t, lease)
	commitCtx, err := lease.BeginCommit()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.Shutdown(ctx) }()
	// Shutdown must await the lease even after the confirmed result; cleanup
	// and resource closure remain the handler's responsibility.
	if _, err := lease.Complete(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("shutdown released active lease: %v", err)
	default:
	}
	if commitCtx.Err() != context.Canceled {
		t.Fatalf("completed commit context not released: %v", commitCtx.Err())
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("shutdown leaked after lease close")
	}
}
