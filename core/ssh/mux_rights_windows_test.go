//go:build windows

package ssh

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/winsec"
	"golang.org/x/sys/windows"
)

func TestWindowsMuxSocket_BindHardensDACLAndRejectsInsecureDir(t *testing.T) {
	base := t.TempDir()

	// 1. Overlong path rejected before directory creation or bind.
	tooLong := filepath.Join(base, strings.Repeat("a", MaxControlPathLength()))
	if _, err := bindAndLinkSocket(tooLong); err == nil {
		t.Fatal("expected overlong ControlPath to fail bindAndLinkSocket")
	}

	// 2. Fresh subdirectory gets owner-only protected DACL and allows same-user peer check.
	sockPath := filepath.Join(base, "secure-mux", "cm.sock")
	slot, err := bindAndLinkSocket(sockPath)
	if err != nil {
		t.Fatalf("bindAndLinkSocket(%q) failed: %v", sockPath, err)
	}
	defer func() { _ = slot.Release() }()
	ln, fi := slot.Listener(), slot.FileInfo()
	if !isControlSocketFileInfo(fi) {
		t.Fatalf("expected socket FileInfo, got mode %v", fi.Mode())
	}

	acceptedCh := make(chan net.Conn, 1)
	go func() {
		if c, aErr := ln.Accept(); aErr == nil {
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

	if err := checkPeerUID(clientConn, localPeerUID()); err != nil {
		t.Fatalf("client checkPeerUID failed: %v", err)
	}
	if err := checkPeerUID(serverConn, localPeerUID()); err != nil {
		t.Fatalf("server checkPeerUID failed: %v", err)
	}

	// 3. Non-syscall.Conn fails closed with ErrUnauthorizedPeer.
	p1, p2 := net.Pipe()
	defer func() { _ = p1.Close(); _ = p2.Close() }()
	if err := checkPeerUID(p1, 0); !errors.Is(err, ErrUnauthorizedPeer) {
		t.Fatalf("checkPeerUID(net.Pipe) = %v, want ErrUnauthorizedPeer", err)
	}

	// 4. Pre-existing Everyone-writable directory fails closed with ErrInsecureControlDir.
	insecureDir := filepath.Join(base, "shared-dir")
	if err := os.Mkdir(insecureDir, 0o700); err != nil {
		t.Fatal(err)
	}
	currSID, err := winsec.CurrentProcessUserSID()
	if err != nil {
		t.Fatal(err)
	}
	everyoneSID, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(currSID)
	pinner.Pin(everyoneSID)

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
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
		nil, nil, acl, nil,
	); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(acl)

	if _, err := bindAndLinkSocket(filepath.Join(insecureDir, "cm.sock")); !errors.Is(err, winsec.ErrInsecureControlDir) {
		t.Fatalf("bindAndLinkSocket(insecureDir) = %v, want winsec.ErrInsecureControlDir", err)
	}
}

func TestWindowsMuxSocket_ReplaceStaleSocketAndRejectLive(t *testing.T) {
	base := t.TempDir()
	stalePath := filepath.Join(base, "stale-mux", "cm.sock")
	firstSlot, err := bindAndLinkSocket(stalePath)
	if err != nil {
		t.Fatalf("initial bindAndLinkSocket(%q) failed: %v", stalePath, err)
	}
	if _, dupErr := bindAndLinkSocket(stalePath); !errors.Is(dupErr, ErrMasterAlreadyExists) {
		_ = firstSlot.Release()
		t.Fatalf("bindAndLinkSocket(live %q) = %v, want ErrMasterAlreadyExists", stalePath, dupErr)
	}
	// Close listener directly without unlinking to simulate a crashed master leaving a stale socket file.
	if err := firstSlot.Listener().Close(); err != nil {
		t.Fatalf("close listener to create stale socket: %v", err)
	}
	replacedSlot, err := bindAndLinkSocket(stalePath)
	if err != nil {
		t.Fatalf("bindAndLinkSocket(stale %q) failed: %v", stalePath, err)
	}
	defer func() { _ = replacedSlot.Release() }()
}
