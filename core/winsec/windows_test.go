//go:build windows

package winsec

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestEnsureOwnerOnlyDirectory_CreatesProtectedTwoSIDDACLAndRejectsInsecureDir(t *testing.T) {
	base := t.TempDir()
	newDir := filepath.Join(base, "mux", "nested")
	if err := EnsureOwnerOnlyDirectory(newDir); err != nil {
		t.Fatalf("EnsureOwnerOnlyDirectory(%q) failed: %v", newDir, err)
	}

	sd, err := windows.GetNamedSecurityInfo(
		newDir,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%q) failed: %v", newDir, err)
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		t.Fatalf("sd.Control failed: %v", err)
	}
	if ctrl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("expected SE_DACL_PROTECTED on newly created directory, got control=%#x", ctrl)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("sd.DACL failed: %v", err)
	}
	if dacl.AceCount != 2 {
		t.Fatalf("expected exactly 2 ACEs (CurrentUser + SYSTEM), got %d", dacl.AceCount)
	}

	// Pre-create a directory granting Everyone write access; EnsureOwnerOnlyDirectory
	// MUST fail closed with ErrInsecureControlDir and MUST NOT repair its DACL.
	insecureDir := filepath.Join(base, "everyone_writable")
	if err := os.Mkdir(insecureDir, 0o700); err != nil {
		t.Fatal(err)
	}
	everyoneSID, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	currSID, err := CurrentProcessUserSID()
	if err != nil {
		t.Fatal(err)
	}
	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(currSID)
	pinner.Pin(everyoneSID)

	insecureACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(currSID),
			},
		},
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(everyoneSID),
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		insecureDir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		insecureACL,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(insecureACL)

	err = EnsureOwnerOnlyDirectory(insecureDir)
	if !errors.Is(err, ErrInsecureControlDir) {
		t.Fatalf("EnsureOwnerOnlyDirectory(Everyone-writable) = %v, want ErrInsecureControlDir", err)
	}
	// Confirm the existing directory DACL was NOT silently mutated/repaired.
	if verifyErr := VerifyOwnerOnlyDirectory(insecureDir, currSID); !errors.Is(verifyErr, ErrInsecureControlDir) {
		t.Fatalf("existing insecure directory DACL appears to have been mutated: %v", verifyErr)
	}
}

func TestEnsureOwnerOnlyDirectory_RejectsInheritableInheritOnlyACE(t *testing.T) {
	base := t.TempDir()
	inheritBypassDir := filepath.Join(base, "everyone_inherit_only")
	if err := os.Mkdir(inheritBypassDir, 0o700); err != nil {
		t.Fatal(err)
	}
	everyoneSID, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	currSID, err := CurrentProcessUserSID()
	if err != nil {
		t.Fatal(err)
	}
	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(currSID)
	pinner.Pin(everyoneSID)

	inheritOnlyACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(currSID),
			},
		},
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.OBJECT_INHERIT_ACE | windows.INHERIT_ONLY_ACE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(everyoneSID),
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		inheritBypassDir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		inheritOnlyACL,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(inheritOnlyACL)

	if err := EnsureOwnerOnlyDirectory(inheritBypassDir); !errors.Is(err, ErrInsecureControlDir) {
		t.Fatalf("EnsureOwnerOnlyDirectory(INHERIT_ONLY_ACE Everyone) = %v, want ErrInsecureControlDir", err)
	}
}

func TestVerifyAFUnixPeerCurrentUser_SameUserAndFailClosedOnInvalidHandle(t *testing.T) {
	if err := VerifyAFUnixPeerCurrentUser(uintptr(windows.InvalidHandle)); !errors.Is(err, ErrUnauthorizedControlPeer) {
		t.Fatalf("VerifyAFUnixPeerCurrentUser(InvalidHandle) = %v, want ErrUnauthorizedControlPeer", err)
	}

	dir := filepath.Join(t.TempDir(), "unix-peer")
	if err := EnsureOwnerOnlyDirectory(dir); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(dir, "peer.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Listen(unix) failed: %v", err)
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	}()

	if err := HardenFileOwnerOnly(sockPath); err != nil {
		t.Fatalf("HardenFileOwnerOnly failed: %v", err)
	}
	if err := VerifyOwnerOnlySocketFile(sockPath); err != nil {
		t.Fatalf("VerifyOwnerOnlySocketFile failed: %v", err)
	}

	acceptedCh := make(chan net.Conn, 1)
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr == nil {
			acceptedCh <- c
		}
	}()

	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Dial(unix) failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	serverConn := <-acceptedCh
	defer func() { _ = serverConn.Close() }()

	for name, conn := range map[string]net.Conn{"client": clientConn, "server": serverConn} {
		sc, ok := conn.(syscall.Conn)
		if !ok {
			t.Fatalf("%s conn does not implement syscall.Conn", name)
		}
		raw, err := sc.SyscallConn()
		if err != nil {
			t.Fatalf("%s SyscallConn: %v", name, err)
		}
		var verifyErr error
		if ctrlErr := raw.Control(func(fd uintptr) {
			verifyErr = VerifyAFUnixPeerCurrentUser(fd)
		}); ctrlErr != nil {
			t.Fatalf("%s raw.Control: %v", name, ctrlErr)
		}
		if verifyErr != nil {
			t.Fatalf("%s VerifyAFUnixPeerCurrentUser failed: %v", name, verifyErr)
		}
	}
}

func buildTestSDWithOwnerAndACL(t *testing.T, owner *windows.SID, entries []windows.EXPLICIT_ACCESS) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("ACLFromEntries: %v", err)
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		t.Fatalf("NewSecurityDescriptor: %v", err)
	}
	if err := sd.SetOwner(owner, false); err != nil {
		t.Fatalf("SetOwner: %v", err)
	}
	if err := sd.SetDACL(acl, true, false); err != nil {
		t.Fatalf("SetDACL: %v", err)
	}
	selfRel, err := sd.ToSelfRelative()
	runtime.KeepAlive(acl)
	runtime.KeepAlive(owner)
	runtime.KeepAlive(sd)
	if err != nil {
		t.Fatalf("ToSelfRelative: %v", err)
	}
	return selfRel
}

func mustCreateWellKnownSID(t *testing.T, sidType windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(sidType)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(%d): %v", sidType, err)
	}
	return sid
}

func makeSIDExplicitAccess(sid *windows.SID, tt windows.TRUSTEE_TYPE, perm windows.ACCESS_MASK, inh uint32) windows.EXPLICIT_ACCESS {
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

func TestIsSecureSystemGlobalSSHObjectAndAncestorDir_RejectsCurrentUser(t *testing.T) {
	currSID, err := CurrentProcessUserSID()
	if err != nil || currSID == nil {
		t.Fatalf("CurrentProcessUserSID: %v", err)
	}
	systemSID := mustCreateWellKnownSID(t, windows.WinLocalSystemSid)
	adminsSID := mustCreateWellKnownSID(t, windows.WinBuiltinAdministratorsSid)
	usersSID := mustCreateWellKnownSID(t, windows.WinBuiltinUsersSid)
	creatorOwnerSID := mustCreateWellKnownSID(t, windows.WinCreatorOwnerSid)

	if !IsTrustedPrincipalSID(systemSID, nil) || !IsTrustedPrincipalSID(adminsSID, nil) {
		t.Fatal("SYSTEM and Builtin\\Administrators must be trusted when currSID == nil")
	}
	if IsTrustedPrincipalSID(usersSID, nil) {
		t.Fatal("Builtin\\Users must not be trusted when currSID == nil")
	}
	if !IsTrustedPrincipalSID(currSID, currSID) {
		t.Fatal("currSID must remain trusted in user-scoped check")
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(currSID)
	pinner.Pin(systemSID)
	pinner.Pin(adminsSID)
	pinner.Pin(usersSID)
	pinner.Pin(creatorOwnerSID)

	sysGlobalEntries := []windows.EXPLICIT_ACCESS{
		makeSIDExplicitAccess(systemSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.GENERIC_ALL, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
		makeSIDExplicitAccess(adminsSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.GENERIC_ALL, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
		makeSIDExplicitAccess(usersSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_EXECUTE, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
	}
	sysGlobalSD := buildTestSDWithOwnerAndACL(t, systemSID, sysGlobalEntries)
	if !IsSecureSecurityDescriptor(windows.FILE_ATTRIBUTE_DIRECTORY, true, sysGlobalSD, nil) {
		t.Fatal("SYSTEM/Admins dir SD must pass IsSecureSecurityDescriptor(..., nil)")
	}
	if !IsSecureSecurityDescriptor(windows.FILE_ATTRIBUTE_NORMAL, false, sysGlobalSD, nil) {
		t.Fatal("SYSTEM/Admins file SD must pass IsSecureSecurityDescriptor(..., nil)")
	}

	programDataEntries := append(append([]windows.EXPLICIT_ACCESS(nil), sysGlobalEntries...),
		makeSIDExplicitAccess(creatorOwnerSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.GENERIC_ALL, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT|windows.INHERIT_ONLY_ACE),
		makeSIDExplicitAccess(usersSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA, windows.CONTAINER_INHERIT_ACE),
	)
	programDataSD := buildTestSDWithOwnerAndACL(t, systemSID, programDataEntries)
	if !IsSecureSystemAncestorDirDescriptor(windows.FILE_ATTRIBUTE_DIRECTORY, programDataSD) {
		t.Fatal("standard ProgramData ancestor SD must pass IsSecureSystemAncestorDirDescriptor")
	}
	if IsSecureSecurityDescriptor(windows.FILE_ATTRIBUTE_DIRECTORY, true, programDataSD, nil) {
		t.Fatal("ProgramData ancestor SD must NOT pass strict ssh dir IsSecureSecurityDescriptor(..., nil)")
	}

	ancestorDeleteChildSD := buildTestSDWithOwnerAndACL(t, systemSID, append(append([]windows.EXPLICIT_ACCESS(nil), programDataEntries...),
		makeSIDExplicitAccess(usersSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.ACCESS_MASK(AccessFileDeleteChild), windows.NO_INHERITANCE),
	))
	if IsSecureSystemAncestorDirDescriptor(windows.FILE_ATTRIBUTE_DIRECTORY, ancestorDeleteChildSD) {
		t.Fatal("ancestor SD granting FILE_DELETE_CHILD to Users must fail closed")
	}

	if !IsTrustedPrincipalSID(currSID, nil) {
		assertCurrentUserRejectedBySystemGlobalChecks(t, currSID, systemSID, sysGlobalEntries)
	}
}

func assertCurrentUserRejectedBySystemGlobalChecks(
	t *testing.T,
	currSID *windows.SID,
	systemSID *windows.SID,
	sysGlobalEntries []windows.EXPLICIT_ACCESS,
) {
	t.Helper()

	currUserOwnedSD := buildTestSDWithOwnerAndACL(t, currSID, sysGlobalEntries)
	if IsSecureSecurityDescriptor(windows.FILE_ATTRIBUTE_NORMAL, false, currUserOwnedSD, nil) {
		t.Fatal("current-user-owned SD must fail IsSecureSecurityDescriptor(..., nil)")
	}
	if IsSecureSystemAncestorDirDescriptor(windows.FILE_ATTRIBUTE_DIRECTORY, currUserOwnedSD) {
		t.Fatal("current-user-owned ancestor SD must fail IsSecureSystemAncestorDirDescriptor")
	}

	currUserWritableSD := buildTestSDWithOwnerAndACL(t, systemSID, append(append([]windows.EXPLICIT_ACCESS(nil), sysGlobalEntries...),
		makeSIDExplicitAccess(currSID, windows.TRUSTEE_IS_USER, windows.FILE_WRITE_DATA, windows.NO_INHERITANCE),
	))
	if IsSecureSecurityDescriptor(windows.FILE_ATTRIBUTE_NORMAL, false, currUserWritableSD, nil) {
		t.Fatal("current-user-writable SD must fail IsSecureSecurityDescriptor(..., nil)")
	}
	if !IsSecureSecurityDescriptor(windows.FILE_ATTRIBUTE_NORMAL, false, currUserWritableSD, currSID) {
		t.Fatal("current-user-writable SD should still pass user-scoped IsSecureSecurityDescriptor(..., currSID)")
	}

	base := t.TempDir()
	userDir := filepath.Join(base, "ssh")
	if err := os.Mkdir(userDir, 0o700); err != nil {
		t.Fatal(err)
	}
	userFile := filepath.Join(userDir, "ssh_known_hosts")
	if err := os.WriteFile(userFile, []byte("host ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	currACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		makeSIDExplicitAccess(currSID, windows.TRUSTEE_IS_USER, windows.GENERIC_ALL, windows.NO_INHERITANCE),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{userDir, userFile} {
		if err := windows.SetNamedSecurityInfo(
			target,
			windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, currACL, nil,
		); err != nil {
			t.Fatalf("SetNamedSecurityInfo(%s): %v", target, err)
		}
	}
	runtime.KeepAlive(currACL)

	if IsSecureSystemGlobalSSHObject(userDir, true) || IsSecureSystemGlobalSSHObject(userFile, false) {
		t.Fatal("IsSecureSystemGlobalSSHObject must reject currSID-writable directory and file")
	}
	if !IsSecureSystemSSHObject(userDir, true, currSID) || !IsSecureSystemSSHObject(userFile, false, currSID) {
		t.Fatal("user-scoped IsSecureSystemSSHObject must still accept currSID-only directory and file")
	}
}
