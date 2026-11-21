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
