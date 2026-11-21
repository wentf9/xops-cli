//go:build windows

package winsec

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestHandleBasedACLHelpers_DirAndSocket(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "secure-dir")
	if err := EnsureOwnerOnlyDirectory(dir); err != nil {
		t.Fatalf("EnsureOwnerOnlyDirectory failed: %v", err)
	}
	currSID, err := CurrentProcessUserSID()
	if err != nil {
		t.Fatalf("CurrentProcessUserSID failed: %v", err)
	}
	if err := VerifyOwnerOnlyDirectoryByHandle(dir, currSID); err != nil {
		t.Fatalf("VerifyOwnerOnlyDirectoryByHandle failed: %v", err)
	}
	if err := VerifyAncestorChainNoReparse(dir); err != nil {
		t.Fatalf("VerifyAncestorChainNoReparse failed: %v", err)
	}
	if !IsSecureSystemSSHObjectByHandle(dir, true, currSID) {
		t.Fatalf("IsSecureSystemSSHObjectByHandle(dir) = false, want true")
	}

	sockPath := filepath.Join(dir, "handle.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Listen(unix) failed: %v", err)
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	}()

	if err := HardenSocketOwnerOnlyByHandle(sockPath); err != nil {
		t.Fatalf("HardenSocketOwnerOnlyByHandle failed: %v", err)
	}
	if err := VerifyOwnerOnlySocketByHandle(sockPath); err != nil {
		t.Fatalf("VerifyOwnerOnlySocketByHandle failed: %v", err)
	}

	// Regular file must be rejected by socket handle helpers.
	regPath := filepath.Join(dir, "not-a-socket.txt")
	if err := os.WriteFile(regPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyOwnerOnlySocketByHandle(regPath); !errors.Is(err, ErrInsecureControlDir) {
		t.Fatalf("VerifyOwnerOnlySocketByHandle(regular file) = %v, want ErrInsecureControlDir", err)
	}
	if err := HardenSocketOwnerOnlyByHandle(regPath); !errors.Is(err, ErrInsecureControlDir) {
		t.Fatalf("HardenSocketOwnerOnlyByHandle(regular file) = %v, want ErrInsecureControlDir", err)
	}

	// OpenObjectHandleNoFollow on regular file returns a valid disk handle.
	h, attrs, err := OpenObjectHandleNoFollow(regPath, windows.READ_CONTROL)
	if err != nil {
		t.Fatalf("OpenObjectHandleNoFollow failed: %v", err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if !EvaluateAttributes(attrs, false) {
		t.Fatalf("EvaluateAttributes(%#x, false) = false, want true", attrs)
	}
	sd, err := GetSecurityInfoByHandle(h)
	if err != nil || sd == nil {
		t.Fatalf("GetSecurityInfoByHandle failed: sd=%v err=%v", sd, err)
	}
}
