//go:build unix

package sftp

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"golang.org/x/sys/unix"
)

type readObserveReaderAt struct {
	io.ReaderAt
	onRead func()
}

func (r *readObserveReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if r.onRead != nil {
		r.onRead()
	}
	return r.ReaderAt.ReadAt(p, off)
}

type readObserveSFTPHandler struct {
	maliciousSFTPHandler
	onRead func(path string)
}

func (h *readObserveSFTPHandler) Fileread(r *pkgsftp.Request) (io.ReaderAt, error) {
	rd, err := h.maliciousSFTPHandler.Fileread(r)
	if err != nil {
		return nil, err
	}
	return &readObserveReaderAt{
		ReaderAt: rd,
		onRead: func() {
			if h.onRead != nil {
				h.onRead(r.Filepath)
			}
		},
	}, nil
}

func TestP7W6a_AB6H1_UnixDownloadStripsSetuidSetgidStickyAndStagesAt0600(t *testing.T) {
	t.Run("single_file_strips_setuid_setgid_sticky_size_zero_and_nonzero", testP7W6aUnixSingleFileStripsSpecialBits)
	t.Run("recursive_dir_and_files_strip_setuid_setgid_sticky", testP7W6aUnixRecursiveDirStripsSpecialBits)
	t.Run("mid_transfer_staging_file_is_strictly_0600_then_transitions_to_wide_perm", testP7W6aUnixMidTransferStaging0600)
	t.Run("resumed_wide_staging_file_tightened_to_0600_before_prefix_validation", testP7W6aUnixResumedStagingTightenedTo0600)
}

func testP7W6aUnixSingleFileStripsSpecialBits(t *testing.T) {
	t.Helper()
	cases := []struct {
		name     string
		mode     os.FileMode
		payload  []byte
		wantPerm os.FileMode
	}{
		{name: "setuid_0555_zero", mode: specialModeBits | 0o555, payload: nil, wantPerm: 0o555},
		{name: "setuid_0555_nonzero", mode: specialModeBits | 0o555, payload: []byte("suid-payload"), wantPerm: 0o555},
		{name: "setuid_0755_zero", mode: specialModeBits | 0o755, payload: nil, wantPerm: 0o755},
		{name: "setuid_0755_nonzero", mode: specialModeBits | 0o755, payload: []byte("suid-elf"), wantPerm: 0o755},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			remoteName := "/remote/" + tc.name
			handler := &maliciousSFTPHandler{
				statInfos: map[string]os.FileInfo{
					remoteName: syntheticFileInfo{name: tc.name, size: int64(len(tc.payload)), mode: tc.mode},
				},
				files: map[string][]byte{
					remoteName: tc.payload,
				},
			}
			client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
				FileGet:  handler,
				FilePut:  handler,
				FileCmd:  handler,
				FileList: handler,
			})

			localDir := t.TempDir()
			remotePath, _ := ParseRemotePath(remoteName)
			dest, _ := LocalDestPath(localDir)
			if err := client.Download(t.Context(), remotePath, dest, DownloadOptions{}); err != nil {
				t.Fatalf("Download(%s): %v", tc.name, err)
			}

			localPath := filepath.Join(localDir, tc.name)
			t.Cleanup(func() { _ = os.Chmod(localPath, 0o600) })
			fi, err := os.Lstat(localPath)
			if err != nil {
				t.Fatalf("Lstat(%q): %v", localPath, err)
			}
			if fi.Mode()&specialModeBits != 0 {
				t.Fatalf("downloaded file %q retained special bits: %v", localPath, fi.Mode())
			}
			if fi.Mode().Perm() != tc.wantPerm {
				t.Fatalf("downloaded file %q perm = %04o, want %04o", localPath, fi.Mode().Perm(), tc.wantPerm)
			}
		})
	}
}

func testP7W6aUnixRecursiveDirStripsSpecialBits(t *testing.T) {
	t.Helper()
	handler := &maliciousSFTPHandler{
		statInfos: map[string]os.FileInfo{
			"/tree":                     syntheticFileInfo{name: "tree", mode: os.ModeDir | specialModeBits | 0o755},
			"/tree/sgid_dir":            syntheticFileInfo{name: "sgid_dir", mode: os.ModeDir | specialModeBits | 0o755},
			"/tree/sgid_dir/empty_suid": syntheticFileInfo{name: "empty_suid", size: 0, mode: specialModeBits | 0o555},
			"/tree/sgid_dir/full_suid":  syntheticFileInfo{name: "full_suid", size: 7, mode: specialModeBits | 0o755},
		},
		dirLists: map[string][]os.FileInfo{
			"/tree": {
				syntheticFileInfo{name: "sgid_dir", mode: os.ModeDir | specialModeBits | 0o755},
			},
			"/tree/sgid_dir": {
				syntheticFileInfo{name: "empty_suid", size: 0, mode: specialModeBits | 0o555},
				syntheticFileInfo{name: "full_suid", size: 7, mode: specialModeBits | 0o755},
			},
		},
		files: map[string][]byte{
			"/tree/sgid_dir/empty_suid": nil,
			"/tree/sgid_dir/full_suid":  []byte("payload"),
		},
	}
	client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
		FileGet:  handler,
		FilePut:  handler,
		FileCmd:  handler,
		FileList: handler,
	})

	localDst := t.TempDir()
	remoteRoot, _ := ParseRemotePath("/tree")
	dest, _ := LocalDestPath(localDst)
	if err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{}); err != nil {
		t.Fatalf("Download recursive dir: %v", err)
	}

	subDir := filepath.Join(localDst, "sgid_dir")
	dirInfo, err := os.Lstat(subDir)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", subDir, err)
	}
	if !dirInfo.IsDir() {
		t.Fatalf("%q is not a directory: %v", subDir, dirInfo.Mode())
	}
	if dirInfo.Mode()&specialModeBits != 0 {
		t.Fatalf("downloaded directory %q retained special bits (S_ISUID/S_ISGID/S_ISVTX): %v", subDir, dirInfo.Mode())
	}

	for name, wantPerm := range map[string]os.FileMode{
		"empty_suid": 0o555,
		"full_suid":  0o755,
	} {
		p := filepath.Join(subDir, name)
		t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
		fi, statErr := os.Lstat(p)
		if statErr != nil {
			t.Fatalf("Lstat(%q): %v", p, statErr)
		}
		if fi.Mode()&specialModeBits != 0 {
			t.Fatalf("downloaded file %q retained special bits: %v", p, fi.Mode())
		}
		if fi.Mode().Perm() != wantPerm {
			t.Fatalf("downloaded file %q perm = %04o, want %04o", p, fi.Mode().Perm(), wantPerm)
		}
	}
}

func testP7W6aUnixMidTransferStaging0600(t *testing.T) {
	t.Helper()
	for _, widePerm := range []os.FileMode{0o777, 0o666} {
		t.Run(widePerm.String(), func(t *testing.T) {
			payload := bytes.Repeat([]byte("S"), 96*1024)
			handler := &maliciousSFTPHandler{
				statInfos: map[string]os.FileInfo{
					"/wide.bin": syntheticFileInfo{name: "wide.bin", size: int64(len(payload)), mode: widePerm},
				},
				files: map[string][]byte{
					"/wide.bin": payload,
				},
			}
			client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
				FileGet:  handler,
				FilePut:  handler,
				FileCmd:  handler,
				FileList: handler,
			})
			client.config.ThreadsPerFile = 1

			localDst := filepath.Join(t.TempDir(), "wide.bin")
			tempPath := localDst + client.config.TempSuffix

			var mu sync.Mutex
			var observed []os.FileMode
			remotePath, _ := ParseRemotePath("/wide.bin")
			dest, _ := LocalDestPath(localDst)
			err := client.Download(t.Context(), remotePath, dest, DownloadOptions{
				Progress: func(int64) {
					if fi, lstatErr := os.Lstat(tempPath); lstatErr == nil {
						mu.Lock()
						observed = append(observed, fi.Mode())
						mu.Unlock()
					}
				},
			})
			if err != nil {
				t.Fatalf("Download(%04o): %v", widePerm, err)
			}
			mu.Lock()
			snapshot := append([]os.FileMode(nil), observed...)
			mu.Unlock()
			if len(snapshot) == 0 {
				t.Fatal("failed to observe staging temp file mid-transfer")
			}
			for i, mode := range snapshot {
				if mode.Perm() != 0o600 || mode&specialModeBits != 0 {
					t.Fatalf("mid-transfer observation %d saw staging mode %v (%04o), want strictly 0600", i, mode, mode.Perm())
				}
			}
			finalInfo, err := os.Lstat(localDst)
			if err != nil {
				t.Fatalf("Lstat(%q): %v", localDst, err)
			}
			if finalInfo.Mode().Perm() != widePerm {
				t.Fatalf("final file perm = %04o, want %04o", finalInfo.Mode().Perm(), widePerm)
			}
		})
	}
}

func testP7W6aUnixResumedStagingTightenedTo0600(t *testing.T) {
	t.Helper()
	payload := []byte("0123456789abcdef")
	localDst := filepath.Join(t.TempDir(), "resume.bin")
	tempPath := localDst + DefaultTempSuffix
	if err := os.WriteFile(tempPath, []byte("01234567"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tempPath, 0o666); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var observedDuringRead []os.FileMode
	handler := &readObserveSFTPHandler{
		maliciousSFTPHandler: maliciousSFTPHandler{
			statInfos: map[string]os.FileInfo{
				"/resume.bin": syntheticFileInfo{name: "resume.bin", size: int64(len(payload)), mode: 0o666},
			},
			files: map[string][]byte{
				"/resume.bin": payload,
			},
		},
		onRead: func(string) {
			if fi, lstatErr := os.Lstat(tempPath); lstatErr == nil {
				mu.Lock()
				observedDuringRead = append(observedDuringRead, fi.Mode())
				mu.Unlock()
			}
		},
	}
	client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
		FileGet:  handler,
		FilePut:  handler,
		FileCmd:  handler,
		FileList: handler,
	})
	client.config.EnableResume = true
	client.config.ResumeMinSize = 4

	remotePath, _ := ParseRemotePath("/resume.bin")
	dest, _ := LocalDestPath(localDst)
	if err := client.Download(t.Context(), remotePath, dest, DownloadOptions{}); err != nil {
		t.Fatalf("resumed Download: %v", err)
	}

	mu.Lock()
	reads := append([]os.FileMode(nil), observedDuringRead...)
	mu.Unlock()
	if len(reads) == 0 {
		t.Fatal("expected at least one remote read during resume prefix validation/append")
	}
	for i, mode := range reads {
		if mode.Perm() != 0o600 || mode&specialModeBits != 0 {
			t.Fatalf("read %d observed staging mode %v (%04o), want strictly 0600 before prefix validation/append", i, mode, mode.Perm())
		}
	}
	finalInfo, err := os.Lstat(localDst)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", localDst, err)
	}
	if finalInfo.Mode().Perm() != 0o666 {
		t.Fatalf("final file perm = %04o, want 0666", finalInfo.Mode().Perm())
	}
}

func TestP7W6a_AB6M1_UnixRealFSRemoteFIFORejectedWithoutBlocking(t *testing.T) {
	remoteDir := t.TempDir()
	fifoPath := filepath.Join(remoteDir, "trap.fifo")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo(%q): %v", fifoPath, err)
	}
	if err := os.WriteFile(filepath.Join(remoteDir, "ok.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}

	client := newRealFSSFTPClient(t, remoteDir)

	t.Run("single_target_real_fifo", func(t *testing.T) {
		localDst := t.TempDir()
		remotePath, _ := ParseRemotePath(fifoPath)
		dest, _ := LocalDestPath(localDst)
		done := make(chan error, 1)
		go func() {
			done <- client.Download(t.Context(), remotePath, dest, DownloadOptions{})
		}()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "non-regular remote entry") {
				t.Fatalf("Download(real FIFO) = %v, want non-regular remote entry error", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Download blocked on real remote FIFO instead of rejecting before Open")
		}
	})

	t.Run("recursive_dir_with_real_fifo", func(t *testing.T) {
		localDst := t.TempDir()
		remotePath, _ := ParseRemotePath(remoteDir)
		dest, _ := LocalDestPath(localDst)
		done := make(chan error, 1)
		go func() {
			done <- client.Download(t.Context(), remotePath, dest, DownloadOptions{})
		}()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "non-regular remote entry") {
				t.Fatalf("Download dir(real FIFO) = %v, want non-regular remote entry error", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Download dir blocked on real remote FIFO instead of rejecting before Open")
		}
		entries, readErr := os.ReadDir(localDst)
		if readErr != nil || len(entries) != 0 {
			t.Fatalf("localDst must remain empty after pre-pass FIFO rejection, got %d entries (err=%v)", len(entries), readErr)
		}
	})
}
