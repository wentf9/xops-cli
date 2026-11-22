//go:build windows

package transfer

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/winsec"
	"golang.org/x/sys/windows"
)

func TestP7W14a_AB14M2_EvaluateOwnerOnlyRegularFileSecurity(t *testing.T) {
	trustedAll := winsec.ParsedACE{
		ACEType:    winsec.AccessAllowedACEType,
		Mask:       winsec.AccessGenericAll,
		SIDValid:   true,
		SIDTrusted: true,
	}
	untrustedRead := winsec.ParsedACE{
		ACEType:    winsec.AccessAllowedACEType,
		Mask:       windows.FILE_GENERIC_READ,
		SIDValid:   true,
		SIDTrusted: false,
	}
	untrustedWrite := winsec.ParsedACE{
		ACEType:    winsec.AccessAllowedACEType,
		Mask:       winsec.AccessFileWriteData,
		SIDValid:   true,
		SIDTrusted: false,
	}

	if !evaluateOwnerOnlyRegularFileSecurity(windows.FILE_ATTRIBUTE_NORMAL, true, true, []winsec.ParsedACE{trustedAll}) {
		t.Fatal("valid private regular file rejected")
	}
	if evaluateOwnerOnlyRegularFileSecurity(windows.FILE_ATTRIBUTE_DIRECTORY, true, true, []winsec.ParsedACE{trustedAll}) {
		t.Fatal("directory accepted as regular file")
	}
	if evaluateOwnerOnlyRegularFileSecurity(windows.FILE_ATTRIBUTE_REPARSE_POINT, true, true, []winsec.ParsedACE{trustedAll}) {
		t.Fatal("reparse point accepted as regular file")
	}
	if evaluateOwnerOnlyRegularFileSecurity(windows.FILE_ATTRIBUTE_NORMAL, false, true, []winsec.ParsedACE{trustedAll}) {
		t.Fatal("untrusted owner accepted")
	}
	if evaluateOwnerOnlyRegularFileSecurity(windows.FILE_ATTRIBUTE_NORMAL, true, false, nil) {
		t.Fatal("nil DACL accepted")
	}
	if evaluateOwnerOnlyRegularFileSecurity(windows.FILE_ATTRIBUTE_NORMAL, true, true, []winsec.ParsedACE{trustedAll, untrustedRead}) {
		t.Fatal("file readable by untrusted principal accepted")
	}
	if evaluateOwnerOnlyRegularFileSecurity(windows.FILE_ATTRIBUTE_NORMAL, true, true, []winsec.ParsedACE{trustedAll, untrustedWrite}) {
		t.Fatal("file writable by untrusted principal accepted")
	}
}

func setTestACL(t *testing.T, target string, entries []windows.EXPLICIT_ACCESS) {
	t.Helper()
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("ACLFromEntries: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		target,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatalf("SetNamedSecurityInfo(%q): %v", target, err)
	}
	runtime.KeepAlive(acl)
}

func assertProtectedOwnerOnlySD(t *testing.T, target string) {
	t.Helper()
	h, _, err := winsec.OpenObjectHandleNoFollow(target, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		t.Fatalf("OpenObjectHandleNoFollow(%q): %v", target, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	sd, err := winsec.GetSecurityInfoByHandle(h)
	if err != nil {
		t.Fatalf("GetSecurityInfoByHandle(%q): %v", target, err)
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		t.Fatalf("sd.Control(%q): %v", target, err)
	}
	if ctrl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("%q missing SE_DACL_PROTECTED (control=%#x)", target, ctrl)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%q missing DACL: %v", target, err)
	}
	if dacl.AceCount != 2 {
		t.Fatalf("%q AceCount = %d, want 2 (CurrentUser + SYSTEM)", target, dacl.AceCount)
	}
}

func makeTestExplicitAccess(sid *windows.SID, tt windows.TRUSTEE_TYPE, perm windows.ACCESS_MASK, inh uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: perm,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inh,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  tt,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func TestP7W14a_AB14M2_WindowsJournalDirectoryAndFileACLPrivacy(t *testing.T) {
	currSID, err := winsec.CurrentProcessUserSID()
	if err != nil {
		t.Fatalf("CurrentProcessUserSID: %v", err)
	}
	everyoneSID, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(WinWorldSid): %v", err)
	}
	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(currSID)
	pinner.Pin(everyoneSID)

	t.Run("new_journal_under_permissive_parent_blocks_inheritance", func(t *testing.T) {
		testWindowsJournalBlocksParentInheritance(t, currSID, everyoneSID)
	})
	t.Run("rejects_existing_multiuser_directory_and_inherit_only_ace", func(t *testing.T) {
		testWindowsJournalRejectsInsecureDirectories(t, currSID, everyoneSID)
	})
	t.Run("rejects_tampered_lock_and_record_file_acls", func(t *testing.T) {
		testWindowsJournalRejectsTamperedFileACLs(t, currSID, everyoneSID)
	})
}

func testWindowsJournalBlocksParentInheritance(t *testing.T, currSID, everyoneSID *windows.SID) {
	parent := filepath.Join(t.TempDir(), "shared-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	setTestACL(t, parent, []windows.EXPLICIT_ACCESS{
		makeTestExplicitAccess(currSID, windows.TRUSTEE_IS_USER, windows.GENERIC_ALL, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
		makeTestExplicitAccess(everyoneSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.GENERIC_ALL, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
	})

	dir := filepath.Join(parent, "mcp-transfers")
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatalf("OpenJournal under permissive parent failed: %v", err)
	}
	record := sampleRecord(t)
	if err := j.Save(record); err != nil {
		_ = j.Close()
		t.Fatalf("Save failed: %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	assertProtectedOwnerOnlySD(t, dir)
	assertProtectedOwnerOnlySD(t, filepath.Join(dir, "service.lock"))
	assertProtectedOwnerOnlySD(t, filepath.Join(dir, record.ID+".json"))
}

func testWindowsJournalRejectsInsecureDirectories(t *testing.T, currSID, everyoneSID *windows.SID) {
	for name, inh := range map[string]uint32{
		"everyone_read":         windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		"everyone_inherit_only": windows.OBJECT_INHERIT_ACE | windows.INHERIT_ONLY_ACE,
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), name)
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			setTestACL(t, dir, []windows.EXPLICIT_ACCESS{
				makeTestExplicitAccess(currSID, windows.TRUSTEE_IS_USER, windows.GENERIC_ALL, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
				makeTestExplicitAccess(everyoneSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.FILE_GENERIC_READ, inh),
			})
			j, err := OpenJournal(dir)
			if j != nil {
				_ = j.Close()
			}
			if !errors.Is(err, winsec.ErrInsecureControlDir) || !strings.Contains(err.Error(), "private directory") {
				t.Fatalf("OpenJournal(%s) = %v, want ErrInsecureControlDir/private directory", name, err)
			}
		})
	}
}

func testWindowsJournalRejectsTamperedFileACLs(t *testing.T, currSID, everyoneSID *windows.SID) {
	j, dir := testJournal(t)
	record := sampleRecord(t)
	if err := j.Save(record); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	recordPath := filepath.Join(dir, record.ID+".json")
	setTestACL(t, recordPath, []windows.EXPLICIT_ACCESS{
		makeTestExplicitAccess(currSID, windows.TRUSTEE_IS_USER, windows.GENERIC_ALL, windows.NO_INHERITANCE),
		makeTestExplicitAccess(everyoneSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.FILE_GENERIC_READ, windows.NO_INHERITANCE),
	})

	reopened, err := OpenJournal(dir)
	if err != nil {
		t.Fatalf("reopen before Load failed: %v", err)
	}
	if _, loadErr := reopened.Load(10); !errors.Is(loadErr, winsec.ErrInsecureControlDir) || !strings.Contains(loadErr.Error(), "transfer metadata must be a private regular file") {
		_ = reopened.Close()
		t.Fatalf("Load(tampered record ACL) = %v, want private regular file / ErrInsecureControlDir", loadErr)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	lockPath := filepath.Join(dir, "service.lock")
	setTestACL(t, lockPath, []windows.EXPLICIT_ACCESS{
		makeTestExplicitAccess(currSID, windows.TRUSTEE_IS_USER, windows.GENERIC_ALL, windows.NO_INHERITANCE),
		makeTestExplicitAccess(everyoneSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.FILE_GENERIC_READ, windows.NO_INHERITANCE),
	})
	if bad, openErr := OpenJournal(dir); !errors.Is(openErr, winsec.ErrInsecureControlDir) || !strings.Contains(openErr.Error(), "transfer metadata must be a private regular file") {
		if bad != nil {
			_ = bad.Close()
		}
		t.Fatalf("OpenJournal(tampered service.lock ACL) = %v, want private regular file / ErrInsecureControlDir", openErr)
	}
}
