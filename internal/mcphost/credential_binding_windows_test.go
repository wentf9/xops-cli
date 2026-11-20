//go:build windows

package mcphost

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestFixLongPathWindows(t *testing.T) {
	shortPath := `C:\certs\client.crt`
	if got := fixLongPathWindows(shortPath); got != shortPath {
		t.Fatalf("short path modified: got %q, want %q", got, shortPath)
	}

	alreadyExtended := `\\?\` + strings.Repeat("a", 260) + `\client.crt`
	if got := fixLongPathWindows(alreadyExtended); got != alreadyExtended {
		t.Fatalf("extended path modified: got %q, want %q", got, alreadyExtended)
	}

	longDrivePath := `C:\` + strings.Repeat(`dir\`, 70) + `client.crt`
	gotLong := fixLongPathWindows(longDrivePath)
	if !strings.HasPrefix(gotLong, `\\?\`) {
		t.Fatalf("long drive path %q did not receive \\\\?\\ prefix: got %q", longDrivePath, gotLong)
	}

	longUNCPath := `\\server\share\` + strings.Repeat(`dir\`, 70) + `client.crt`
	gotUNC := fixLongPathWindows(longUNCPath)
	if !strings.HasPrefix(gotUNC, `\\?\UNC\server\share\`) {
		t.Fatalf("long UNC path %q did not receive \\\\?\\UNC\\ prefix: got %q", longUNCPath, gotUNC)
	}
}

func TestOpenRegularCertFile_LongPathAndDirectoryWindows(t *testing.T) {
	base := t.TempDir()
	// Create a nested path exceeding MAX_PATH (260 chars).
	nested := base
	for len(nested) < 265 {
		nested = filepath.Join(nested, strings.Repeat("d", 32))
	}
	if err := os.MkdirAll(fixLongPathWindows(nested), 0o700); err != nil {
		t.Fatalf("MkdirAll long path: %v", err)
	}

	certPath := filepath.Join(nested, "cert.pem")
	if err := os.WriteFile(fixLongPathWindows(certPath), []byte("test-cert"), 0o600); err != nil {
		t.Fatalf("WriteFile long path: %v", err)
	}

	f, info, nonReg, err := openRegularCertFile(certPath)
	if err != nil || nonReg || f == nil || info == nil {
		if f != nil {
			_ = f.Close()
		}
		t.Fatalf("openRegularCertFile(long regular file) = (file=%v, info=%v, nonReg=%v, err=%v)", f != nil, info != nil, nonReg, err)
	}
	_ = f.Close()

	// Directory must be flagged as non-regular without dereferencing errors.
	dirFile, _, dirNonReg, dirErr := openRegularCertFile(base)
	if dirFile != nil {
		_ = dirFile.Close()
	}
	if !dirNonReg || dirErr == nil {
		t.Fatalf("openRegularCertFile(directory) = (file=%v, nonReg=%v, err=%v), want nonReg=true and error", dirFile != nil, dirNonReg, dirErr)
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

func TestProbeZeroAccessSQOS_NamedPipeNonRegular(t *testing.T) {
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	basePipe := fmt.Sprintf(`\\.\pipe\xops-test-cert-sqos-%d-%s`, os.Getpid(), hex.EncodeToString(nonce[:]))

	t.Run("DUPLEX_AvailableSlot", func(t *testing.T) {
		pipeName := basePipe + "-duplex-avail"
		createTestNamedPipe(t, pipeName, windows.PIPE_ACCESS_DUPLEX)
		f, _, nonReg, openErr := openRegularCertFile(pipeName)
		if f != nil {
			_ = f.Close()
		}
		if !nonReg || openErr != nil {
			t.Fatalf("openRegularCertFile(available duplex pipe) = (nonReg=%v, err=%v), want nonReg=true and err=nil", nonReg, openErr)
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

		f, _, nonReg, openErr := openRegularCertFile(pipeName)
		if f != nil {
			_ = f.Close()
		}
		if !nonReg || !errors.Is(openErr, windows.ERROR_PIPE_BUSY) {
			t.Fatalf("openRegularCertFile(busy duplex pipe) = (nonReg=%v, err=%v), want nonReg=true and ERROR_PIPE_BUSY", nonReg, openErr)
		}
	})

	t.Run("INBOUND_AccessDenied_SQOSProbe", func(t *testing.T) {
		pipeName := basePipe + "-inbound-denied"
		createTestNamedPipe(t, pipeName, windows.PIPE_ACCESS_INBOUND)
		f, _, nonReg, openErr := openRegularCertFile(pipeName)
		if f != nil {
			_ = f.Close()
		}
		if !nonReg || !errors.Is(openErr, windows.ERROR_ACCESS_DENIED) {
			t.Fatalf("openRegularCertFile(inbound pipe) = (nonReg=%v, err=%v), want nonReg=true and ERROR_ACCESS_DENIED", nonReg, openErr)
		}
	})
}

func pickUnusedDriveLetterForTest(t *testing.T) string {
	t.Helper()
	wdVol := ""
	if wd, err := os.Getwd(); err == nil {
		wdVol = strings.ToUpper(filepath.VolumeName(wd))
	}
	for ch := byte('Z'); ch >= 'D'; ch-- {
		drive := string(ch) + ":"
		if drive == wdVol {
			continue
		}
		if _, exists := os.LookupEnv("=" + drive); exists {
			continue
		}
		return drive
	}
	t.Skip("no unused drive letter available without existing =X: environment mapping")
	return ""
}

func TestFixLongPathWindows_DriveRelative(t *testing.T) {
	drive := pickUnusedDriveLetterForTest(t)
	t.Setenv("="+drive, drive+`\short`)
	if got := fixLongPathWindows(drive + `cert.pub`); got != drive+`cert.pub` {
		t.Fatalf("fixLongPathWindows(short drive-relative) = %q, want %q", got, drive+`cert.pub`)
	}

	longDir := drive + `\` + strings.Repeat("d", 240)
	t.Setenv("="+drive, longDir)
	got := fixLongPathWindows(drive + `cert.pub`)
	want := `\\?\` + longDir + `\cert.pub`
	if got != want {
		t.Fatalf("fixLongPathWindows(long drive-relative) = %q, want %q", got, want)
	}
}

func TestIsExtendedOrDeviceWindowsPath_RejectsForwardSlashNTPrefix(t *testing.T) {
	if isExtendedOrDeviceWindowsPath("/??/C:/Users/alice/cert.pem") {
		t.Fatal("forward-slash /??/ must not be treated as a Win32 NT device prefix")
	}
	if !isExtendedOrDeviceWindowsPath(`\??\C:\Users\alice\cert.pem`) {
		t.Fatal(`backslash \??\ must be recognized as an NT device prefix`)
	}
}
