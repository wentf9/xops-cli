//go:build windows

package mcphost

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/fsx"
	"golang.org/x/sys/windows"
)

func TestInspectCertificateBinding_LongPathAndDirectoryWindows(t *testing.T) {
	base := t.TempDir()
	// Create a nested path exceeding MAX_PATH (260 chars).
	nested := base
	for len(nested) < 265 {
		nested = filepath.Join(nested, strings.Repeat("d", 32))
	}
	longNested := `\\?\` + nested
	if err := os.MkdirAll(longNested, 0o700); err != nil {
		t.Fatalf("MkdirAll long path: %v", err)
	}

	certPath := filepath.Join(nested, "cert.pem")
	if err := os.WriteFile(`\\?\`+certPath, []byte("test-cert"), 0o600); err != nil {
		t.Fatalf("WriteFile long path: %v", err)
	}

	rf, err := fsx.OpenRegular(certPath, fsx.Limits{MaxBytes: math.MaxInt64}, fsx.FollowSymlinks())
	if err != nil || rf == nil {
		t.Fatalf("fsx.OpenRegular(long regular file) = (%v, %v)", rf, err)
	}
	_ = rf.Close()

	// Directory must be flagged as non-regular without dereferencing errors.
	binding, admitted, ok := inspectCertificateBindingWithRaw(base, true)
	if !ok || !binding.NonRegular || !admitted.NonRegular {
		t.Fatalf("inspectCertificateBindingWithRaw(directory) = (%+v, %+v, %v), want NonRegular=true", binding, admitted, ok)
	}
}

func createTestNamedPipe(t *testing.T, pipeName string, openMode uint32) windows.Handle {
	t.Helper()
	pName16, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		t.Fatalf("UTF16PtrFromString: %v", err)
	}
	h, err := windows.CreateNamedPipe(
		pName16,
		openMode,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		1, 64, 64, 0, nil,
	)
	if err != nil {
		t.Skipf("CreateNamedPipe failed: %v", err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(h) })
	return h
}

func TestInspectCertificateBinding_NamedPipeNonRegularWindows(t *testing.T) {
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	basePipe := fmt.Sprintf(`\\.\pipe\xops-test-cert-sqos-%d-%s`, os.Getpid(), hex.EncodeToString(nonce[:]))

	t.Run("DUPLEX_AvailableSlot", func(t *testing.T) {
		pipeName := basePipe + "-duplex-avail"
		createTestNamedPipe(t, pipeName, windows.PIPE_ACCESS_DUPLEX)
		binding, admitted, ok := inspectCertificateBindingWithRaw(pipeName, true)
		if !ok || !binding.NonRegular || !admitted.NonRegular {
			t.Fatalf("inspectCertificateBindingWithRaw(available duplex pipe) = (%+v, %+v, %v), want NonRegular=true", binding, admitted, ok)
		}
	})

	t.Run("DUPLEX_OccupiedSlot_PipeBusy", func(t *testing.T) {
		pipeName := basePipe + "-duplex-busy"
		createTestNamedPipe(t, pipeName, windows.PIPE_ACCESS_DUPLEX)
		pName16, err := windows.UTF16PtrFromString(pipeName)
		if err != nil {
			t.Fatalf("UTF16PtrFromString: %v", err)
		}
		clientHandle, dialErr := windows.CreateFile(pName16, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
		if dialErr != nil {
			t.Skipf("occupying named pipe slot failed: %v", dialErr)
		}
		defer func() { _ = windows.CloseHandle(clientHandle) }()

		rf, openErr := fsx.OpenRegular(pipeName, fsx.Limits{MaxBytes: math.MaxInt64}, fsx.FollowSymlinks())
		if rf != nil {
			_ = rf.Close()
		}
		if !errors.Is(openErr, fsx.ErrNonRegular) || !errors.Is(openErr, windows.ERROR_PIPE_BUSY) {
			t.Fatalf("fsx.OpenRegular(busy duplex pipe) = %v, want ErrNonRegular wrapping ERROR_PIPE_BUSY", openErr)
		}
	})

	t.Run("INBOUND_AccessDenied_FailClosed", func(t *testing.T) {
		pipeName := basePipe + "-inbound-denied"
		createTestNamedPipe(t, pipeName, windows.PIPE_ACCESS_INBOUND)
		rf, openErr := fsx.OpenRegular(pipeName, fsx.Limits{MaxBytes: math.MaxInt64}, fsx.FollowSymlinks())
		if rf != nil {
			_ = rf.Close()
		}
		if !errors.Is(openErr, windows.ERROR_ACCESS_DENIED) {
			t.Fatalf("fsx.OpenRegular(inbound pipe) = %v, want ERROR_ACCESS_DENIED", openErr)
		}
		keyBinding, admitted, ok := inspectKeyFileBinding(pipeName, true)
		if !ok || !keyBinding.Unreadable || admitted.SHA256 != "" {
			t.Fatalf("inspectKeyFileBinding(inbound pipe) = (%+v, %+v, %v), want Unreadable fail-closed", keyBinding, admitted, ok)
		}
	})
}
