package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func sampleRecord(t *testing.T) Record {
	t.Helper()
	id, err := randomHex(16)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	emptyDigest := sha256.Sum256(nil)
	digest := hex.EncodeToString(emptyDigest[:])
	return Record{
		Version: legacyRecordVersion, ID: id, OperationID: id,
		Spec: Spec{RequestID: "request", Scope: "scope", Direction: Upload, NodeID: "node",
			TargetID: "target-account", RemotePath: "/files/document", Size: 0, SHA256: digest},
		TokenDigest: digest, State: Ready, CreatedAt: now, UpdatedAt: now,
		StartBefore: now.Add(5 * time.Minute), StatusExpiresAt: now.Add(24 * time.Hour),
	}
}

func testJournal(t *testing.T) (*Journal, string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "state", "transfers")
	j, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := j.Close(); err != nil {
			t.Error(err)
		}
	})
	return j, directory
}

func TestJournalDurableRoundTripAndLock(t *testing.T) {
	j, directory := testJournal(t)
	record := sampleRecord(t)
	if err := j.Save(record); err != nil {
		t.Fatal(err)
	}
	if other, err := OpenJournal(directory); !errors.Is(err, ErrStoreLocked) {
		if other != nil {
			if err := other.Close(); err != nil {
				t.Error(err)
			}
		}
		t.Fatalf("second process lock = %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	}()
	records, err := reopened.Load(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0] != record {
		t.Fatalf("journal changed record: %+v", records)
	}
	if runtime.GOOS != "windows" {
		for name, mode := range map[string]os.FileMode{"": 0700, record.ID + ".json": 0600, "service.lock": 0600} {
			info, err := os.Stat(filepath.Join(directory, name))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != mode {
				t.Errorf("%s permissions = %o, want %o", name, info.Mode().Perm(), mode)
			}
		}
	}
	if err := reopened.Remove(record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, "service.lock")); err != nil {
		t.Fatalf("permanent lock removed: %v", err)
	}
}

func TestJournalFailedReplacementPreservesPreviousRecord(t *testing.T) {
	j, directory := testJournal(t)
	record := sampleRecord(t)
	if err := j.Save(record); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("replacement unavailable")
	j.replace = func(*os.Root, string, string) error { return wantErr }
	next := record
	next.State = Committing
	if err := j.Save(next); !errors.Is(err, wantErr) {
		t.Fatalf("Save = %v", err)
	}
	records, err := j.Load(10)
	if err != nil || len(records) != 1 || records[0].State != Ready {
		t.Fatalf("previous record lost: records=%+v err=%v", records, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("failed replacement leaked temporary metadata: %v", entries)
	}
}

func TestJournalSyncFailureCanFollowAppliedReplacement(t *testing.T) {
	j, _ := testJournal(t)
	record := sampleRecord(t)
	if err := j.Save(record); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("directory sync unavailable")
	j.syncDirectory = func(string) error { return wantErr }
	record.State = Committing
	if err := j.Save(record); !errors.Is(err, wantErr) {
		t.Fatalf("Save = %v", err)
	}
	records, err := j.Load(10)
	if err != nil || len(records) != 1 || records[0].State != Committing {
		t.Fatalf("failed Save must not imply unapplied: records=%+v err=%v", records, err)
	}
}

func TestJournalRejectsCorruptionAndEscapingCleanupPaths(t *testing.T) {
	for name, content := range map[string]string{"truncated": "{", "oversized": strings.Repeat("x", maxRecordBytes+1)} {
		t.Run(name, func(t *testing.T) {
			j, directory := testJournal(t)
			record := sampleRecord(t)
			if err := os.WriteFile(filepath.Join(directory, record.ID+".json"), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := j.Load(10); err == nil {
				t.Fatal("corrupt journal accepted")
			}
		})
	}
	j, _ := testJournal(t)
	record := sampleRecord(t)
	record.TempPath = "/unrelated/user-data"
	record.CleanupPending = true
	if err := j.Save(record); err == nil {
		t.Fatal("unowned temporary path accepted")
	}
	record = sampleRecord(t)
	record.Version++
	if err := j.Save(record); err == nil {
		t.Fatal("future journal version accepted")
	}
	if err := j.Remove("../../outside"); err == nil {
		t.Fatal("escaping record name accepted")
	}
}

func TestJournalRejectsSymlinkRecord(t *testing.T) {
	j, directory := testJournal(t)
	record := sampleRecord(t)
	outside := filepath.Join(t.TempDir(), "unrelated")
	if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, record.ID+".json")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symbolic links unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := j.Load(10); err == nil {
		t.Fatal("symbolic link accepted")
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "keep" {
		t.Fatalf("unrelated file changed: data=%q err=%v", data, err)
	}
}

func TestJournalProcessExitReleasesLock(t *testing.T) {
	if directory := os.Getenv("XOPS_TEST_TRANSFER_JOURNAL"); directory != "" {
		journal, err := OpenJournal(directory)
		if err != nil {
			t.Fatal(err)
		}
		if err := journal.Save(sampleRecord(t)); err != nil {
			t.Fatal(err)
		}
		// Deliberately bypass defers to model abrupt process exit with a live lock.
		os.Exit(0)
	}
	directory := filepath.Join(t.TempDir(), "journal")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestJournalProcessExitReleasesLock$")
	command.Env = append(os.Environ(), "XOPS_TEST_TRANSFER_JOURNAL="+directory)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("journal subprocess: %v\n%s", err, out)
	}
	journal, err := OpenJournal(directory)
	if err != nil {
		t.Fatalf("process exit left a stale lock: %v", err)
	}
	defer func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	}()
	records, err := journal.Load(10)
	if err != nil || len(records) != 1 {
		t.Fatalf("durable record lost after process exit: records=%+v err=%v", records, err)
	}
}
