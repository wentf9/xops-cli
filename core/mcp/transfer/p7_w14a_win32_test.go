package transfer

import (
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/core/winsec"
)

// TestP7W14a_AB14M3_SameTransferRemotePath verifies AB14-M3 path equivalence:
// canonical Windows drive paths compare case-insensitively while POSIX paths
// remain strictly case-sensitive.
func TestP7W14a_AB14M3_SameTransferRemotePath(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{"windows_sftp_case_diff", "/C:/Data/report.csv", "/C:/Data/REPORT.CSV", true},
		{"windows_drive_letter_case_diff", "/c:/Data/report.csv", "/C:/data/report.csv", true},
		{"windows_bare_and_sftp_mixed", `C:\Data\report.csv`, "/C:/DATA/Report.CSV", true},
		{"windows_trailing_slash", "/C:/Data/report.csv/", "/c:/data/REPORT.CSV", true},
		{"windows_different_drive", "/C:/Data/report.csv", "/D:/Data/report.csv", false},
		{"windows_different_file", "/C:/Data/report.csv", "/C:/Data/other.csv", false},
		{"posix_exact_match", "/var/data/report.csv", "/var/data/report.csv", true},
		{"posix_case_sensitive", "/var/data/report.csv", "/var/data/REPORT.CSV", false},
		{"windows_vs_posix", "/C:/Data/report.csv", "/Data/report.csv", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameTransferRemotePath(tc.a, tc.b); got != tc.want {
				t.Errorf("sameTransferRemotePath(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
			if got := sameTransferRemotePath(tc.b, tc.a); got != tc.want {
				t.Errorf("sameTransferRemotePath(%q, %q) = %v, want %v (symmetry)", tc.b, tc.a, got, tc.want)
			}
		})
	}
}

// TestP7W14a_AB14M3_ConcurrentUploadCaseFoldingLock verifies AB14-M3 in
// Manager.hasCapacity: concurrent uploads to case-variant Windows drive paths
// conflict with ErrBusy, while case-variant POSIX paths remain independent.
func TestP7W14a_AB14M3_ConcurrentUploadCaseFoldingLock(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxActive = 4
	limits.MaxPerTarget = 4
	m, _ := testManager(t, limits)

	prepUpload := func(reqID, remotePath string) Prepared {
		t.Helper()
		r := sampleRecord(t)
		r.Spec.RequestID = reqID
		r.Spec.RemotePath = remotePath
		p, err := m.Prepare(r.Spec, r.OperationID)
		if err != nil {
			t.Fatalf("Prepare(%q, %q): %v", reqID, remotePath, err)
		}
		return p
	}

	win1 := prepUpload("win-1", "/C:/Data/report.csv")
	win2 := prepUpload("win-2", "/C:/Data/REPORT.CSV")
	win3 := prepUpload("win-3", "/c:/data/Report.CSV")

	lease1 := claimTestTransfer(t, m, win1)
	if _, err := m.Claim(t.Context(), win2.Status.ID, win2.Token, Upload); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent upload to /C:/Data/REPORT.CSV = %v, want ErrBusy", err)
	}
	if _, err := m.Claim(t.Context(), win3.Status.ID, win3.Token, Upload); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent upload to /c:/data/Report.CSV = %v, want ErrBusy", err)
	}

	// POSIX paths with different case must NOT conflict with each other.
	posix1 := prepUpload("posix-1", "/var/data/report.csv")
	posix2 := prepUpload("posix-2", "/var/data/REPORT.CSV")
	pLease1 := claimTestTransfer(t, m, posix1)
	pLease2 := claimTestTransfer(t, m, posix2)
	if err := pLease1.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pLease2.Close(); err != nil {
		t.Fatal(err)
	}

	// Releasing win1 allows win2 to proceed.
	if err := lease1.Close(); err != nil {
		t.Fatal(err)
	}
	claimTestTransfer(t, m, win2)
}

// TestP7W14a_AB14M3_UnknownStateCaseFoldingBlock verifies AB14-M3 in
// Manager.pathBlocked: an unresolved Unknown commit on a Windows drive path
// blocks Prepare and Claim for case-variant paths on the same target, while
// leaving case-variant POSIX paths unaffected.
func TestP7W14a_AB14M3_UnknownStateCaseFoldingBlock(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxActive = 4
	limits.MaxPerTarget = 4
	m, _ := testManager(t, limits)

	// Prepare both a Windows upload and a pre-prepared case-variant upload before Unknown.
	r1 := sampleRecord(t)
	r1.Spec.RequestID = "win-unknown-1"
	r1.Spec.RemotePath = "/C:/Data/report.csv"
	p1, err := m.Prepare(r1.Spec, r1.OperationID)
	if err != nil {
		t.Fatal(err)
	}

	rPre := sampleRecord(t)
	rPre.Spec.RequestID = "win-pre-prepared-upper"
	rPre.Spec.RemotePath = "/C:/Data/REPORT.CSV"
	pPre, err := m.Prepare(rPre.Spec, rPre.OperationID)
	if err != nil {
		t.Fatal(err)
	}

	// Transition win-unknown-1 to Unknown.
	lease := claimTestTransfer(t, m, p1)
	verifyTestTransfer(t, lease)
	if _, err := lease.BeginCommit(); err != nil {
		t.Fatal(err)
	}
	st, err := lease.Fail(errors.New("rename status lost"))
	if err != nil || st.State != Unknown {
		t.Fatalf("expected Unknown state, got (%+v, %v)", st, err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}

	// Pre-prepared case-variant upload must fail Claim with ErrConflict.
	if _, err := m.Claim(t.Context(), pPre.Status.ID, pPre.Token, Upload); !errors.Is(err, ErrConflict) {
		t.Fatalf("Claim on case-variant path during Unknown = %v, want ErrConflict", err)
	}

	// New Prepare on case-variant paths must fail with ErrConflict.
	for i, variant := range []string{"/C:/Data/REPORT.CSV", "/c:/data/Report.csv", "/C:/DATA/report.csv"} {
		rNew := sampleRecord(t)
		rNew.Spec.RequestID = "win-after-unknown-" + string(rune('a'+i))
		rNew.Spec.RemotePath = variant
		if _, err := m.Prepare(rNew.Spec, rNew.OperationID); !errors.Is(err, ErrConflict) {
			t.Fatalf("Prepare(%q) during Unknown on /C:/Data/report.csv = %v, want ErrConflict", variant, err)
		}
	}

	// Different drive or different file on same drive is unaffected.
	rOtherDrive := sampleRecord(t)
	rOtherDrive.Spec.RequestID = "win-other-drive"
	rOtherDrive.Spec.RemotePath = "/D:/Data/report.csv"
	if _, err := m.Prepare(rOtherDrive.Spec, rOtherDrive.OperationID); err != nil {
		t.Fatalf("Prepare on /D:/Data/report.csv failed: %v", err)
	}

	// POSIX Unknown on /var/data/report.csv does NOT block /var/data/REPORT.CSV.
	rPosix := sampleRecord(t)
	rPosix.Spec.RequestID = "posix-unknown"
	rPosix.Spec.RemotePath = "/var/data/report.csv"
	pPosix, err := m.Prepare(rPosix.Spec, rPosix.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	pLease := claimTestTransfer(t, m, pPosix)
	verifyTestTransfer(t, pLease)
	if _, err := pLease.BeginCommit(); err != nil {
		t.Fatal(err)
	}
	if _, err := pLease.Fail(errors.New("lost")); err != nil {
		t.Fatal(err)
	}
	if err := pLease.Close(); err != nil {
		t.Fatal(err)
	}

	rPosixUpper := sampleRecord(t)
	rPosixUpper.Spec.RequestID = "posix-upper-ok"
	rPosixUpper.Spec.RemotePath = "/var/data/REPORT.CSV"
	if _, err := m.Prepare(rPosixUpper.Spec, rPosixUpper.OperationID); err != nil {
		t.Fatalf("Prepare(/var/data/REPORT.CSV) blocked by /var/data/report.csv: %v", err)
	}
}

// TestP7W14a_AB14M2_WinsecOwnerOnlyEvaluators verifies the cross-platform
// core/winsec owner-only directory and ACE evaluators used by journal_windows.go.
func TestP7W14a_AB14M2_WinsecOwnerOnlyEvaluators(t *testing.T) {
	trustedAll := winsec.ParsedACE{
		ACEType:    winsec.AccessAllowedACEType,
		Mask:       winsec.AccessGenericAll,
		SIDValid:   true,
		SIDTrusted: true,
	}
	untrustedRead := winsec.ParsedACE{
		ACEType:    winsec.AccessAllowedACEType,
		Mask:       0x00120089, // FILE_GENERIC_READ
		SIDValid:   true,
		SIDTrusted: false,
	}
	untrustedInheritOnly := winsec.ParsedACE{
		ACEType:    winsec.AccessAllowedACEType,
		ACEFlags:   winsec.ObjectInheritACEFlag | winsec.InheritOnlyACEFlag,
		Mask:       winsec.AccessGenericAll,
		SIDValid:   true,
		SIDTrusted: false,
	}

	if !winsec.EvaluateOwnerOnlyDirectorySecurity(winsec.FileAttributeDirectory, true, true, []winsec.ParsedACE{trustedAll}) {
		t.Fatal("trusted owner-only directory rejected")
	}
	if winsec.EvaluateOwnerOnlyDirectorySecurity(winsec.FileAttributeDirectory|winsec.FileAttributeReparsePoint, true, true, []winsec.ParsedACE{trustedAll}) {
		t.Fatal("reparse point directory accepted")
	}
	if winsec.EvaluateOwnerOnlyDirectorySecurity(winsec.FileAttributeDirectory, true, true, []winsec.ParsedACE{trustedAll, untrustedRead}) {
		t.Fatal("directory readable by untrusted principal accepted")
	}
	if winsec.EvaluateOwnerOnlyDirectorySecurity(winsec.FileAttributeDirectory, true, true, []winsec.ParsedACE{trustedAll, untrustedInheritOnly}) {
		t.Fatal("directory with untrusted INHERIT_ONLY_ACE accepted")
	}
	if !winsec.EvaluateOwnerOnlyACE(trustedAll) {
		t.Fatal("trusted file ACE rejected")
	}
	if winsec.EvaluateOwnerOnlyACE(untrustedRead) {
		t.Fatal("untrusted read ACE accepted on private journal file")
	}
}
