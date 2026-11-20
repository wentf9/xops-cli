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

func TestWindowsSecurityHelpersAndSocketAddr(t *testing.T) {
	baseDir := t.TempDir()
	sshDir := filepath.Join(baseDir, "ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}

	missing := filepath.Join(sshDir, "missing_known_hosts")
	if isSecureWindowsGlobalKnownHostsFile(missing) {
		t.Fatal("missing global known_hosts must not be accepted")
	}
	if isSecureWindowsGlobalKnownHostsFile(sshDir) {
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
	assertTrustedAndUntrustedWellKnownSIDs(t, currSID)
}

func assertTrustedAndUntrustedWellKnownSIDs(t *testing.T, currSID *windows.SID) {
	t.Helper()
	for _, trustedType := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid,
		windows.WinBuiltinAdministratorsSid,
	} {
		sid, err := windows.CreateWellKnownSid(trustedType)
		if err != nil {
			t.Fatal(err)
		}
		if !isTrustedWindowsPrincipalSID(sid, currSID) {
			t.Fatalf("well-known SID type %d must be trusted", trustedType)
		}
	}
	for _, untrustedType := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinWorldSid,
		windows.WinBuiltinUsersSid,
		windows.WinAuthenticatedUserSid,
		windows.WinInteractiveSid,
		windows.WinBuiltinGuestsSid,
		windows.WinAnonymousSid,
		windows.WinLocalServiceSid,
	} {
		sid, err := windows.CreateWellKnownSid(untrustedType)
		if err != nil {
			t.Fatal(err)
		}
		if isTrustedWindowsPrincipalSID(sid, currSID) {
			t.Fatalf("untrusted well-known SID type %d must NOT be trusted", untrustedType)
		}
	}
}

func TestWindowsACLAllowlistAndObjectACEFailClosed(t *testing.T) {
	currSID, err := currentWindowsProcessUserSID()
	if err != nil || currSID == nil {
		t.Fatalf("currentWindowsProcessUserSID failed: %v", err)
	}
	interactiveSID, err := windows.CreateWellKnownSid(windows.WinInteractiveSid)
	if err != nil {
		t.Fatal(err)
	}
	daclInteractiveWrite, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(currSID),
			},
		},
		{
			AccessPermissions: windows.FILE_WRITE_DATA,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(interactiveSID),
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsedInteractive, ok := parseWindowsACL(daclInteractiveWrite, currSID)
	if !ok {
		t.Fatal("parseWindowsACL failed on valid ACL")
	}
	if evaluateWindowsObjectSecurity(windows.FILE_ATTRIBUTE_NORMAL, false, true, true, parsedInteractive) {
		t.Fatal("ACL granting FILE_WRITE_DATA to INTERACTIVE must be rejected")
	}

	rawACL := make([]byte, 8+16)
	rawACL[0] = 2  // AclRevision
	rawACL[2] = 24 // AclSize low byte
	rawACL[4] = 1  // AceCount = 1
	rawACL[8] = windowsAccessAllowedObjectACEType
	rawACL[10] = 16 // AceSize = 16
	objACL := (*windows.ACL)(unsafe.Pointer(&rawACL[0]))
	parsedObj, ok := parseWindowsACL(objACL, currSID)
	if !ok {
		t.Fatal("parseWindowsACL should parse header of object ACE for evaluator rejection")
	}
	if evaluateWindowsObjectSecurity(windows.FILE_ATTRIBUTE_NORMAL, false, true, true, parsedObj) {
		t.Fatal("ACCESS_ALLOWED_OBJECT_ACE_TYPE must fail closed")
	}
}

func TestWindowsGlobalKnownHostsAndPipeOwnerFailClosed(t *testing.T) {
	currSID, err := currentWindowsProcessUserSID()
	if err != nil || currSID == nil {
		t.Fatalf("currentWindowsProcessUserSID failed: %v", err)
	}
	interactiveSID, err := windows.CreateWellKnownSid(windows.WinInteractiveSid)
	if err != nil {
		t.Fatal(err)
	}

	baseDir := t.TempDir()
	sshDir := filepath.Join(baseDir, "ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(sshDir, "ssh_known_hosts")
	if err := os.WriteFile(knownHosts, []byte("example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA==\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	daclOwnerOnly, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(currSID),
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{sshDir, knownHosts} {
		if err := windows.SetNamedSecurityInfo(
			target,
			windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, daclOwnerOnly, nil,
		); err != nil {
			t.Fatalf("SetNamedSecurityInfo(%s): %v", target, err)
		}
	}
	if resolved, ok := resolveSecureWindowsGlobalKnownHostsPath(baseDir); !ok || resolved != knownHosts {
		t.Fatalf("resolveSecureWindowsGlobalKnownHostsPath(%q) = (%q, %v), want (%q, true)", baseDir, resolved, ok, knownHosts)
	}
	if !isSecureWindowsGlobalKnownHostsFile(knownHosts) {
		t.Fatal("owner-only ssh directory and ssh_known_hosts must be accepted")
	}

	daclDirDeleteChild, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.ACCESS_MASK(windowsAccessFileDeleteChild),
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(interactiveSID),
			},
		},
	}, daclOwnerOnly)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		sshDir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, daclDirDeleteChild, nil,
	); err != nil {
		t.Fatal(err)
	}
	if _, ok := resolveSecureWindowsGlobalKnownHostsPath(baseDir); ok {
		t.Fatal("parent ssh directory granting FILE_DELETE_CHILD to INTERACTIVE must be rejected")
	}

	if err := verifyWindowsAgentPipeServerOwner(windows.InvalidHandle); err == nil {
		t.Fatal("verifyWindowsAgentPipeServerOwner(InvalidHandle) must fail closed")
	}

	// R5 P3-7: truncated SockaddrLength < unsafe.Sizeof(Family) must return false safely.
	var tinySa windows.RawSockaddrInet4
	tinySa.Family = windows.AF_INET
	if _, ok := formatWindowsSocketAddressDNS(windows.SocketAddress{
		Sockaddr:       (*syscall.RawSockaddrAny)(unsafe.Pointer(&tinySa)),
		SockaddrLength: 1,
	}); ok {
		t.Fatal("truncated SockaddrLength must return false")
	}

	// R5 P3-6: defaultAgentSocket preserves trailing control chars instead of silently trimming them.
	t.Setenv("SSH_AUTH_SOCK", `\\.\pipe\openssh-ssh-agent`+"\n")
	if gotSock := defaultAgentSocket(); gotSock != `\\.\pipe\openssh-ssh-agent`+"\n" {
		t.Fatalf("defaultAgentSocket trimmed control char: got %q", gotSock)
	}

	// R6 P3-4: defaultAgentSocket also preserves Unicode C1 NEL (\u0085) so dial rejects it.
	t.Setenv("SSH_AUTH_SOCK", "\u0085")
	if gotSock := defaultAgentSocket(); gotSock != "\u0085" {
		t.Fatalf("defaultAgentSocket trimmed U+0085 NEL: got %q", gotSock)
	}

	// R6 P3-3: synthetic ACL with AceSize in [12, 15] (< Offsetof(SidStart)+8 = 16) must fail closed
	// without calling IsValidSid past the ACE buffer.
	const aclHeaderSize = 8
	const truncAceSize = 12
	var rawACL [aclHeaderSize + truncAceSize]byte
	rawACL[0] = 2 // ACL_REVISION
	rawACL[2] = byte(len(rawACL))
	rawACL[4] = 1 // AceCount = 1
	rawACL[aclHeaderSize+0] = windowsAccessAllowedACEType
	rawACL[aclHeaderSize+1] = 0 // AceFlags
	rawACL[aclHeaderSize+2] = truncAceSize
	aclPtr := (*windows.ACL)(unsafe.Pointer(&rawACL[0]))
	if _, ok := parseWindowsACL(aclPtr, currSID); ok {
		t.Fatal("parseWindowsACL accepted 12-byte truncated ACE smaller than 16-byte minimum SID header")
	}
}
