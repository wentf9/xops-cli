//go:build windows

package sshenv

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsSecurityHelpersCompileAndRejectMissingOrInsecurePaths(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing_known_hosts")
	if isSecureWindowsGlobalKnownHostsFile(missing) {
		t.Fatal("missing global known_hosts must not be accepted")
	}

	dirPath := t.TempDir()
	if isSecureWindowsGlobalKnownHostsFile(dirPath) {
		t.Fatal("directory must not be accepted as global known_hosts")
	}

	var sa6 windows.RawSockaddrInet6
	sa6.Family = windows.AF_INET6
	sa6.Addr[0] = 0xfe
	sa6.Addr[1] = 0x80
	sa6.Addr[15] = 0x01
	sa6.Scope_id = 7
	got, ok := formatWindowsSocketAddressDNS(windows.SocketAddress{
		Sockaddr:       (*syscall.RawSockaddrAny)(unsafe.Pointer(&sa6)),
		SockaddrLength: int32(unsafe.Sizeof(sa6)),
	})
	if !ok || got != "[fe80::1%7]:53" {
		t.Fatalf("formatWindowsSocketAddressDNS = (%q, %v), want ([fe80::1%%7]:53, true)", got, ok)
	}

	currSID, err := currentWindowsProcessUserSID()
	if err != nil || currSID == nil {
		t.Fatalf("currentWindowsProcessUserSID failed: %v", err)
	}
	if !isTrustedWindowsPrincipalSID(currSID, currSID) {
		t.Fatal("current user SID must be trusted")
	}
	worldSID, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	if !isBroadWindowsPrincipalSID(worldSID) {
		t.Fatal("Everyone (WinWorldSid) must be classified as broad principal")
	}
	_ = os.DevNull
}
