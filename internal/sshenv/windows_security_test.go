//go:build windows

package sshenv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/wentf9/xops-cli/core/winsec"
	"golang.org/x/sys/windows"
)

var testWindowsPipeSeq atomic.Uint64

type testACESpec struct {
	sid         *windows.SID
	trusteeType windows.TRUSTEE_TYPE
	permissions windows.ACCESS_MASK
}

// buildPinnedTestACL pins every SID for the full duration of windows.ACLFromEntries
// because TrusteeValueFromSID stores an opaque pointer hidden from Go's GC.
func buildPinnedTestACL(t *testing.T, oldACL *windows.ACL, specs ...testACESpec) *windows.ACL {
	t.Helper()
	var pinner runtime.Pinner
	defer pinner.Unpin()

	entries := make([]windows.EXPLICIT_ACCESS, 0, len(specs))
	for _, spec := range specs {
		pinner.Pin(spec.sid)
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: spec.permissions,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  spec.trusteeType,
				TrusteeValue: windows.TrusteeValueFromSID(spec.sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, oldACL)
	if err != nil {
		t.Fatalf("ACLFromEntries failed: %v", err)
	}
	return acl
}

func TestWindowsSecurityHelpersAndSocketAddr(t *testing.T) {
	baseDir := t.TempDir()
	sshDir := filepath.Join(baseDir, "ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}

	missing := filepath.Join(sshDir, "missing_known_hosts")
	if v, _ := isSecureWindowsGlobalKnownHostsFile(missing); v.Allowed() {
		t.Fatal("missing global known_hosts must not be accepted")
	}
	if v, _ := isSecureWindowsGlobalKnownHostsFile(sshDir); v.Allowed() {
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
	daclInteractiveWrite := buildPinnedTestACL(t, nil,
		testACESpec{sid: currSID, trusteeType: windows.TRUSTEE_IS_USER, permissions: windows.GENERIC_ALL},
		testACESpec{sid: interactiveSID, trusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, permissions: windows.FILE_WRITE_DATA},
	)
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

func mustSetProtectedTestDACL(t *testing.T, target string, acl *windows.ACL) {
	t.Helper()
	err := windows.SetNamedSecurityInfo(
		target,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	)
	runtime.KeepAlive(acl)
	if err != nil {
		t.Fatalf("SetNamedSecurityInfo(%s): %v", target, err)
	}
}

func assertWindowsGlobalKnownHostsSystemTrust(
	t *testing.T,
	baseDir, sshDir, knownHosts string,
	currSID, interactiveSID *windows.SID,
) {
	t.Helper()

	daclCurrUserOnly := buildPinnedTestACL(t, nil,
		testACESpec{sid: currSID, trusteeType: windows.TRUSTEE_IS_USER, permissions: windows.GENERIC_ALL},
	)
	mustSetProtectedTestDACL(t, sshDir, daclCurrUserOnly)
	mustSetProtectedTestDACL(t, knownHosts, daclCurrUserOnly)

	// R6 / Finding 4.12c: global known_hosts MUST trust ONLY SYSTEM and
	// Builtin\Administrators (never currSID), while user-scoped checks retain currSID.
	if !isTrustedWindowsPrincipalSID(currSID, nil) {
		if resolved, ok := resolveSecureWindowsGlobalKnownHostsPath(baseDir); ok {
			t.Fatalf("resolveSecureWindowsGlobalKnownHostsPath(%q) = (%q, true), want false for currSID-writable global known_hosts", baseDir, resolved)
		}
		if v, _ := isSecureWindowsGlobalKnownHostsFile(knownHosts); v.Allowed() {
			t.Fatal("currSID-writable ssh directory and ssh_known_hosts must be rejected by global known_hosts check")
		}
		vDir, dirErr := winsec.IsSecureSystemSSHObject(sshDir, true, currSID)
		vFile, fileErr := winsec.IsSecureSystemSSHObject(knownHosts, false, currSID)
		if dirErr != nil || !vDir.Allowed() || fileErr != nil || !vFile.Allowed() {
			t.Fatalf("user-scoped winsec.IsSecureSystemSSHObject must still accept currSID-only directory and file: dir=(%v,%v) file=(%v,%v)", vDir, dirErr, vFile, fileErr)
		}
	}

	// Verify ProgramData env var tampering is ignored (KnownFolderPath is used instead).
	t.Setenv("ProgramData", baseDir)
	if slices.Contains(defaultGlobalKnownHostsFiles(), knownHosts) {
		t.Fatalf("defaultGlobalKnownHostsFiles() followed untrusted ProgramData env var %q", baseDir)
	}

	// When running elevated (e.g. GitHub Actions windows-latest where Administrators owns TempDir),
	// also test full SYSTEM/Administrators global acceptance and INTERACTIVE FILE_DELETE_CHILD rejection.
	if isWindowsDirSystemOwned(baseDir) {
		assertElevatedWindowsGlobalKnownHosts(t, baseDir, sshDir, knownHosts, currSID, interactiveSID)
		return
	}
	daclDirDeleteChild := buildPinnedTestACL(t, daclCurrUserOnly,
		testACESpec{sid: interactiveSID, trusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, permissions: windows.ACCESS_MASK(windowsAccessFileDeleteChild)},
	)
	mustSetProtectedTestDACL(t, sshDir, daclDirDeleteChild)
	if _, ok := resolveSecureWindowsGlobalKnownHostsPath(baseDir); ok {
		t.Fatal("parent ssh directory granting FILE_DELETE_CHILD to INTERACTIVE must be rejected")
	}
	if v, _ := winsec.IsSecureSystemSSHObject(sshDir, true, currSID); v.Allowed() {
		t.Fatal("user-scoped check must reject parent ssh directory granting FILE_DELETE_CHILD to INTERACTIVE")
	}
}

func isWindowsDirSystemOwned(dir string) bool {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return false
	}
	owner, _, err := sd.Owner()
	return err == nil && owner != nil && isTrustedWindowsPrincipalSID(owner, nil)
}

func assertElevatedWindowsGlobalKnownHosts(
	t *testing.T,
	baseDir, sshDir, knownHosts string,
	currSID, interactiveSID *windows.SID,
) {
	t.Helper()

	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	adminsSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	usersSID, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	daclCleanup := buildPinnedTestACL(t, nil,
		testACESpec{sid: systemSID, trusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, permissions: windows.GENERIC_ALL},
		testACESpec{sid: adminsSID, trusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, permissions: windows.GENERIC_ALL},
		testACESpec{sid: currSID, trusteeType: windows.TRUSTEE_IS_USER, permissions: windows.GENERIC_ALL},
	)
	t.Cleanup(func() {
		for _, target := range []string{knownHosts, sshDir, baseDir} {
			_ = windows.SetNamedSecurityInfo(
				target,
				windows.SE_FILE_OBJECT,
				windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
				nil, nil, daclCleanup, nil,
			)
		}
		runtime.KeepAlive(daclCleanup)
	})

	daclProgramDataRoot := buildPinnedTestACL(t, nil,
		testACESpec{sid: systemSID, trusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, permissions: windows.GENERIC_ALL},
		testACESpec{sid: adminsSID, trusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, permissions: windows.GENERIC_ALL},
		testACESpec{sid: usersSID, trusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, permissions: windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA},
	)
	daclSystemAdmins := buildPinnedTestACL(t, nil,
		testACESpec{sid: systemSID, trusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, permissions: windows.GENERIC_ALL},
		testACESpec{sid: adminsSID, trusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, permissions: windows.GENERIC_ALL},
		testACESpec{sid: usersSID, trusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, permissions: windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE},
	)
	mustSetProtectedTestDACL(t, baseDir, daclProgramDataRoot)
	mustSetProtectedTestDACL(t, sshDir, daclSystemAdmins)
	mustSetProtectedTestDACL(t, knownHosts, daclSystemAdmins)

	if resolved, ok := resolveSecureWindowsGlobalKnownHostsPath(baseDir); !ok || resolved != knownHosts {
		t.Fatalf("resolveSecureWindowsGlobalKnownHostsPath(%q) = (%q, %v), want (%q, true)", baseDir, resolved, ok, knownHosts)
	}
	if v, err := isSecureWindowsGlobalKnownHostsFile(knownHosts); err != nil || !v.Allowed() {
		t.Fatalf("SYSTEM/Administrators ssh directory and ssh_known_hosts must be accepted: (%v, %v)", v, err)
	}

	daclDirDeleteChild := buildPinnedTestACL(t, daclSystemAdmins,
		testACESpec{sid: interactiveSID, trusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, permissions: windows.ACCESS_MASK(windowsAccessFileDeleteChild)},
	)
	mustSetProtectedTestDACL(t, sshDir, daclDirDeleteChild)
	if _, ok := resolveSecureWindowsGlobalKnownHostsPath(baseDir); ok {
		t.Fatal("parent ssh directory granting FILE_DELETE_CHILD to INTERACTIVE must be rejected")
	}
	if v, _ := isSecureWindowsGlobalKnownHostsFile(knownHosts); v.Allowed() {
		t.Fatal("isSecureWindowsGlobalKnownHostsFile must reject FILE_DELETE_CHILD for INTERACTIVE")
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

	assertWindowsGlobalKnownHostsSystemTrust(t, baseDir, sshDir, knownHosts, currSID, interactiveSID)

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

func startTestWindowsNamedPipeServer(t *testing.T, acl *windows.ACL) (string, <-chan error, func()) {
	t.Helper()
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		t.Fatalf("NewSecurityDescriptor: %v", err)
	}
	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(acl)
	pinner.Pin(sd)
	if err := sd.SetDACL(acl, true, false); err != nil {
		t.Fatalf("SetDACL: %v", err)
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	pipeName := fmt.Sprintf(`\\.\pipe\xops-test-agent-%d-%d-%d`, os.Getpid(), time.Now().UnixNano(), testWindowsPipeSeq.Add(1))
	namePtr, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		_ = windows.CloseHandle(ev)
		t.Fatalf("UTF16PtrFromString: %v", err)
	}
	h, err := windows.CreateNamedPipe(
		namePtr,
		windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		1,
		4096,
		4096,
		0,
		sa,
	)
	if err != nil {
		_ = windows.CloseHandle(ev)
		t.Fatalf("CreateNamedPipe(%s): %v", pipeName, err)
	}

	var ioMu sync.Mutex
	closed := false
	srvDone := make(chan error, 1)
	exited := make(chan struct{})

	runOverlapped := func(op func(ov *windows.Overlapped) error, okIfErr ...error) (uint32, error) {
		ioMu.Lock()
		if closed || h == windows.InvalidHandle {
			ioMu.Unlock()
			return 0, windows.ERROR_OPERATION_ABORTED
		}
		_ = windows.ResetEvent(ev)
		ov := windows.Overlapped{HEvent: ev}
		opErr := op(&ov)
		ioMu.Unlock()

		for _, benign := range okIfErr {
			if errors.Is(opErr, benign) {
				return 0, nil
			}
		}
		if opErr == nil || errors.Is(opErr, windows.ERROR_IO_PENDING) {
			var n uint32
			waitErr := windows.GetOverlappedResult(h, &ov, &n, true)
			return n, waitErr
		}
		return 0, opErr
	}

	var once sync.Once
	go func() {
		defer func() {
			ioMu.Lock()
			closed = true
			if h != windows.InvalidHandle {
				_ = windows.CloseHandle(h)
				h = windows.InvalidHandle
			}
			if ev != windows.InvalidHandle {
				_ = windows.CloseHandle(ev)
				ev = windows.InvalidHandle
			}
			ioMu.Unlock()
			close(srvDone)
			close(exited)
		}()
		if _, cErr := runOverlapped(func(ov *windows.Overlapped) error {
			return windows.ConnectNamedPipe(h, ov)
		}, windows.ERROR_PIPE_CONNECTED); cErr != nil {
			srvDone <- cErr
			return
		}
		var buf [4]byte
		readOff := 0
		for readOff < len(buf) {
			n, rErr := runOverlapped(func(ov *windows.Overlapped) error {
				var immediate uint32
				return windows.ReadFile(h, buf[readOff:], &immediate, ov)
			})
			readOff += int(n)
			if rErr != nil {
				srvDone <- rErr
				return
			}
			if n == 0 {
				srvDone <- windows.ERROR_BROKEN_PIPE
				return
			}
		}
		reply := []byte("pong:" + string(buf[:]))
		for len(reply) > 0 {
			n, wErr := runOverlapped(func(ov *windows.Overlapped) error {
				var immediate uint32
				return windows.WriteFile(h, reply, &immediate, ov)
			})
			if wErr != nil {
				srvDone <- wErr
				return
			}
			if n == 0 {
				srvDone <- windows.ERROR_BROKEN_PIPE
				return
			}
			reply = reply[int(n):]
		}
	}()
	cleanup := func() {
		once.Do(func() {
			ioMu.Lock()
			closed = true
			if h != windows.InvalidHandle {
				_ = windows.CancelIoEx(h, nil)
			}
			ioMu.Unlock()
			<-exited
		})
	}
	return pipeName, srvDone, cleanup
}

func TestWindowsAgentPipeLiveDialAndDACLEnforcement(t *testing.T) {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	auSID, err := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
	if err != nil {
		t.Fatal(err)
	}
	interactiveSID, err := windows.CreateWellKnownSid(windows.WinInteractiveSid)
	if err != nil {
		t.Fatal(err)
	}

	// (a) Win32-OpenSSH style DACL: SYSTEM gets GENERIC_ALL, Authenticated Users gets ONLY
	// 0x0012019b (no FILE_CREATE_PIPE_INSTANCE, currSID not explicitly granted GENERIC_ALL).
	// dialWindowsNamedPipe must succeed using 0x0012008b and support full-duplex pipe I/O.
	win32OpenSSHACL := buildPinnedTestACL(t, nil,
		testACESpec{sid: systemSID, trusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, permissions: windows.GENERIC_ALL},
		testACESpec{sid: auSID, trusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, permissions: windows.ACCESS_MASK(win32OpenSSHAgentAUAccessMask)},
	)
	pipeOK, srvDone, cleanupOK := startTestWindowsNamedPipeServer(t, win32OpenSSHACL)
	defer cleanupOK()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, dialErr := dialWindowsNamedPipe(ctx, pipeOK)
	if dialErr != nil {
		t.Fatalf("dialWindowsNamedPipe on Win32-OpenSSH 0x0012019b DACL failed: %v", dialErr)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		_ = conn.Close()
		t.Fatalf("pipe Write failed: %v", err)
	}
	var reply [9]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		_ = conn.Close()
		t.Fatalf("pipe Read failed: %v", err)
	}
	_ = conn.Close()
	if string(reply[:]) != "pong:ping" {
		t.Fatalf("pipe reply = %q, want pong:ping", string(reply[:]))
	}
	if sErr := <-srvDone; sErr != nil {
		t.Fatalf("pipe server error: %v", sErr)
	}

	// (b) Untrusted principal granted FILE_CREATE_PIPE_INSTANCE must fail closed with errInsecureAgentPipeDACL.
	insecureACL := buildPinnedTestACL(t, win32OpenSSHACL,
		testACESpec{sid: interactiveSID, trusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, permissions: windows.ACCESS_MASK(windowsAccessFileCreatePipeInstance | windows.FILE_GENERIC_READ)},
	)
	pipeBad, _, cleanupBad := startTestWindowsNamedPipeServer(t, insecureACL)
	defer cleanupBad()

	if badConn, badErr := dialWindowsNamedPipe(ctx, pipeBad); !errors.Is(badErr, errInsecureAgentPipeDACL) {
		if badConn != nil {
			_ = badConn.Close()
		}
		t.Fatalf("dialWindowsNamedPipe on insecure DACL = %v, want errInsecureAgentPipeDACL", badErr)
	}
}
