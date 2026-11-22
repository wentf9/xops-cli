package sftp

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/fsx"
)

type customReadLinkHandler struct {
	maliciousSFTPHandler
	mu            sync.Mutex
	readLinks     map[string][]string
	readLinkCalls map[string]int
}

func (h *customReadLinkHandler) Readlink(p string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.readLinkCalls == nil {
		h.readLinkCalls = make(map[string]int)
	}
	idx := h.readLinkCalls[p]
	h.readLinkCalls[p] = idx + 1
	targets, ok := h.readLinks[p]
	if !ok || len(targets) == 0 {
		return "", os.ErrNotExist
	}
	if idx >= len(targets) {
		return targets[len(targets)-1], nil
	}
	return targets[idx], nil
}

func (h *customReadLinkHandler) Lstat(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	return h.Filelist(r)
}

// TestP7W4a_H1_ChainedRelativeSymlinksRejected proves P7-AB-H1 is fixed:
// chained in-tree symlinks that appear lexically safe in isolation (such as
// a/b/c/up -> ../../.. combined with escape -> a/b/c/up/../../../../.ssh/id_ed25519)
// are resolved step-by-step against the complete staged symlink map before any
// symlink is created, failing closed with ErrUnsafeDownloadSymlink.
func TestP7W4a_H1_ChainedRelativeSymlinksRejected(t *testing.T) {
	t.Run("exact_chained_escape_forward_order", func(t *testing.T) {
		testP7W4aChainedEscapeOrder(t, false)
	})
	t.Run("exact_chained_escape_reverse_order", func(t *testing.T) {
		testP7W4aChainedEscapeOrder(t, true)
	})
	t.Run("multi_hop_chain_escape_rejected", testP7W4aMultiHopChainEscape)
	t.Run("symlink_cycle_rejected_by_hop_cap", testP7W4aSymlinkCycleRejected)
	t.Run("safe_chained_in_root_symlinks_preserved", testP7W4aSafeChainedSymlinks)
}

func testP7W4aChainedEscapeOrder(t *testing.T, reverse bool) {
	t.Helper()
	rootEntries := []os.FileInfo{
		syntheticFileInfo{name: "a", mode: os.ModeDir | 0o755},
		syntheticFileInfo{name: "escape", mode: os.ModeSymlink | 0o777},
	}
	if reverse {
		rootEntries[0], rootEntries[1] = rootEntries[1], rootEntries[0]
	}
	handler := &customReadLinkHandler{
		maliciousSFTPHandler: maliciousSFTPHandler{
			statInfos: map[string]os.FileInfo{
				"/remote":       syntheticFileInfo{name: "remote", mode: os.ModeDir | 0o755},
				"/remote/a":     syntheticFileInfo{name: "a", mode: os.ModeDir | 0o755},
				"/remote/a/b":   syntheticFileInfo{name: "b", mode: os.ModeDir | 0o755},
				"/remote/a/b/c": syntheticFileInfo{name: "c", mode: os.ModeDir | 0o755},
			},
			dirLists: map[string][]os.FileInfo{
				"/remote":       rootEntries,
				"/remote/a":     {syntheticFileInfo{name: "b", mode: os.ModeDir | 0o755}},
				"/remote/a/b":   {syntheticFileInfo{name: "c", mode: os.ModeDir | 0o755}},
				"/remote/a/b/c": {syntheticFileInfo{name: "up", mode: os.ModeSymlink | 0o777}},
			},
		},
		readLinks: map[string][]string{
			"/remote/a/b/c/up": {"../../.."},
			"/remote/escape":   {"a/b/c/up/../../../../.ssh/id_ed25519"},
		},
	}
	client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
		FileGet:  handler,
		FilePut:  handler,
		FileCmd:  handler,
		FileList: handler,
	})

	localDst := t.TempDir()
	remoteRoot, _ := ParseRemotePath("/remote")
	dest, _ := LocalDestPath(localDst)
	err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{})
	if !errors.Is(err, ErrUnsafeDownloadSymlink) {
		t.Fatalf("Download chained symlink escape = %v, want ErrUnsafeDownloadSymlink", err)
	}
	for _, p := range []string{
		filepath.Join(localDst, "escape"),
		filepath.Join(localDst, "a", "b", "c", "up"),
	} {
		if _, lstatErr := os.Lstat(p); !errors.Is(lstatErr, os.ErrNotExist) {
			t.Fatalf("symlink %q must not exist after fail-closed Phase 2 rejection: %v", p, lstatErr)
		}
	}
}

func testP7W4aMultiHopChainEscape(t *testing.T) {
	t.Helper()
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
	for _, dir := range []string{"/mh/a/b", "/mh/x/y"} {
		if err := client.state.sftpClient.MkdirAll(dir); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		"/mh/a/b/s1": "../..",
		"/mh/x/y/s2": "../../a/b/s1",
		"/mh/escape": "x/y/s2/../secret",
	} {
		if err := client.state.sftpClient.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}

	localDst := t.TempDir()
	remoteRoot, _ := ParseRemotePath("/mh")
	dest, _ := LocalDestPath(localDst)
	if err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{}); !errors.Is(err, ErrUnsafeDownloadSymlink) {
		t.Fatalf("multi-hop chained escape = %v, want ErrUnsafeDownloadSymlink", err)
	}
	if _, err := os.Lstat(filepath.Join(localDst, "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("escape symlink created locally: %v", err)
	}
}

func testP7W4aSymlinkCycleRejected(t *testing.T) {
	t.Helper()
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
	if err := client.state.sftpClient.MkdirAll("/cycle"); err != nil {
		t.Fatal(err)
	}
	if err := client.state.sftpClient.Symlink("b", "/cycle/a"); err != nil {
		t.Fatal(err)
	}
	if err := client.state.sftpClient.Symlink("a", "/cycle/b"); err != nil {
		t.Fatal(err)
	}

	localDst := t.TempDir()
	remoteRoot, _ := ParseRemotePath("/cycle")
	dest, _ := LocalDestPath(localDst)
	if err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{}); !errors.Is(err, ErrUnsafeDownloadSymlink) {
		t.Fatalf("symlink cycle = %v, want ErrUnsafeDownloadSymlink", err)
	}
}

func testP7W4aSafeChainedSymlinks(t *testing.T) {
	t.Helper()
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
	for _, dir := range []string{"/safe_chain/a/b", "/safe_chain/c"} {
		if err := client.state.sftpClient.MkdirAll(dir); err != nil {
			t.Fatal(err)
		}
	}
	f, err := client.state.sftpClient.Create("/safe_chain/a/target.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("chained-ok"))
	_ = f.Close()
	if err := client.state.sftpClient.Symlink("../target.txt", "/safe_chain/a/b/link1"); err != nil {
		t.Fatal(err)
	}
	if err := client.state.sftpClient.Symlink("../a/b/link1", "/safe_chain/c/link2"); err != nil {
		t.Fatal(err)
	}

	localDst := t.TempDir()
	remoteRoot, _ := ParseRemotePath("/safe_chain")
	dest, _ := LocalDestPath(localDst)
	if err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{}); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("skipping local symlink creation check on Windows")
		}
		t.Fatalf("safe chained symlinks failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(localDst, "c", "link2"))
	if err != nil || string(got) != "chained-ok" {
		t.Fatalf("reading through safe chained symlink = (%q, %v), want \"chained-ok\"", string(got), err)
	}
}

func TestP7W4a_H1_PreExistingLocalSymlinkBounceRejected(t *testing.T) {
	t.Run("preexisting_relative_up_symlink_in_dest_dir", func(t *testing.T) {
		localDst := t.TempDir()
		if err := os.MkdirAll(filepath.Join(localDst, "a", "b"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../..", filepath.Join(localDst, "a", "b", "pre_up")); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlink creation unavailable on Windows: %v", err)
			}
			t.Fatal(err)
		}

		client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
		if err := client.state.sftpClient.MkdirAll("/r"); err != nil {
			t.Fatal(err)
		}
		if err := client.state.sftpClient.Symlink("a/b/pre_up/../outside", "/r/escape"); err != nil {
			t.Fatal(err)
		}

		remoteRoot, _ := ParseRemotePath("/r")
		dest, _ := LocalDestPath(localDst)
		if err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{}); !errors.Is(err, ErrUnsafeDownloadSymlink) {
			t.Fatalf("Download bouncing through pre-existing local symlink = %v, want ErrUnsafeDownloadSymlink", err)
		}
		if _, err := os.Lstat(filepath.Join(localDst, "escape")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("escape symlink must not be created: %v", err)
		}
	})

	t.Run("preexisting_absolute_symlink_in_dest_dir", func(t *testing.T) {
		outsideDir := t.TempDir()
		localDst := t.TempDir()
		if err := os.Symlink(outsideDir, filepath.Join(localDst, "ext")); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlink creation unavailable on Windows: %v", err)
			}
			t.Fatal(err)
		}

		client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
		if err := client.state.sftpClient.MkdirAll("/r_abs"); err != nil {
			t.Fatal(err)
		}
		if err := client.state.sftpClient.Symlink("ext/secret.txt", "/r_abs/leak"); err != nil {
			t.Fatal(err)
		}

		remoteRoot, _ := ParseRemotePath("/r_abs")
		dest, _ := LocalDestPath(localDst)
		if err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{}); !errors.Is(err, ErrUnsafeDownloadSymlink) {
			t.Fatalf("Download through pre-existing absolute symlink = %v, want ErrUnsafeDownloadSymlink", err)
		}
	})
}

func TestP7W4a_H1_DuplicateReadDirEntriesAndReadLinkBaitSwitch(t *testing.T) {
	t.Run("duplicate_readdir_entry_names_rejected", func(t *testing.T) {
		handler := &customReadLinkHandler{
			maliciousSFTPHandler: maliciousSFTPHandler{
				statInfos: map[string]os.FileInfo{
					"/dup": syntheticFileInfo{name: "dup", mode: os.ModeDir | 0o755},
				},
				dirLists: map[string][]os.FileInfo{
					"/dup": {
						syntheticFileInfo{name: "same", size: 4, mode: 0o644},
						syntheticFileInfo{name: "same", mode: os.ModeSymlink | 0o777},
					},
				},
				files: map[string][]byte{
					"/dup/same": []byte("data"),
				},
			},
			readLinks: map[string][]string{
				"/dup/same": {"safe.txt"},
			},
		}
		client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
			FileGet:  handler,
			FilePut:  handler,
			FileCmd:  handler,
			FileList: handler,
		})

		localDst := t.TempDir()
		remoteRoot, _ := ParseRemotePath("/dup")
		dest, _ := LocalDestPath(localDst)
		err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{})
		if err == nil || !strings.Contains(err.Error(), "duplicate remote directory entry") {
			t.Fatalf("duplicate ReadDir entry error = %v, want duplicate remote directory entry", err)
		}
	})

	t.Run("readlink_called_once_preventing_bait_and_switch", func(t *testing.T) {
		handler := &customReadLinkHandler{
			maliciousSFTPHandler: maliciousSFTPHandler{
				statInfos: map[string]os.FileInfo{
					"/once": syntheticFileInfo{name: "once", mode: os.ModeDir | 0o755},
				},
				dirLists: map[string][]os.FileInfo{
					"/once": {
						syntheticFileInfo{name: "link", mode: os.ModeSymlink | 0o777},
					},
				},
			},
			readLinks: map[string][]string{
				"/once/link": {"safe.txt", "../../../../etc/passwd"},
			},
		}
		client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
			FileGet:  handler,
			FilePut:  handler,
			FileCmd:  handler,
			FileList: handler,
		})

		localDst := t.TempDir()
		remoteRoot, _ := ParseRemotePath("/once")
		dest, _ := LocalDestPath(localDst)
		if err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{}); err != nil {
			if runtime.GOOS == "windows" {
				t.Skip("skipping local symlink creation check on Windows")
			}
			t.Fatalf("Download failed: %v", err)
		}
		got, err := os.Readlink(filepath.Join(localDst, "link"))
		if err != nil || filepath.ToSlash(got) != "safe.txt" {
			t.Fatalf("created symlink target = (%q, %v), want \"safe.txt\"", got, err)
		}
		handler.mu.Lock()
		calls := handler.readLinkCalls["/once/link"]
		handler.mu.Unlock()
		if calls != 1 {
			t.Fatalf("ReadLink called %d times, want exactly 1", calls)
		}
	})
}

func TestP7W4a_H2_PrepareDownloadFileRefusesSymlinkNoTruncate(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
	f, err := client.state.sftpClient.Create("/remote.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("new-remote-payload")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("precious-victim-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "remote.bin")
	stagingLink := dst + client.config.TempSuffix
	if err := os.Symlink(victim, stagingLink); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable on Windows: %v", err)
		}
		t.Fatal(err)
	}

	remotePath, _ := ParseRemotePath("/remote.bin")
	dest, _ := LocalDestPath(dst)
	err = client.Download(t.Context(), remotePath, dest, DownloadOptions{})
	if !errors.Is(err, fsx.ErrSymlink) {
		t.Fatalf("Download with symlink staging temp file = %v, want fsx.ErrSymlink", err)
	}
	after, readErr := os.ReadFile(victim)
	if readErr != nil || string(after) != "precious-victim-data" {
		t.Fatalf("victim file was truncated or corrupted: (%q, %v)", string(after), readErr)
	}
}

func TestP7W4a_H2_DownloadResumeWithOpenStagingFile(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
	client.config.EnableResume = true
	client.config.ResumeMinSize = 4

	payload := []byte("0123456789abcdef")
	f, err := client.state.sftpClient.Create("/resume.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	t.Run("matching_prefix_resumes", func(t *testing.T) {
		dir := t.TempDir()
		dst := filepath.Join(dir, "resume.bin")
		tempPath := dst + client.config.TempSuffix
		if err := os.WriteFile(tempPath, []byte("01234567"), 0o600); err != nil {
			t.Fatal(err)
		}

		remotePath, _ := ParseRemotePath("/resume.bin")
		dest, _ := LocalDestPath(dst)
		if err := client.Download(t.Context(), remotePath, dest, DownloadOptions{}); err != nil {
			t.Fatalf("Download resume failed: %v", err)
		}
		got, err := os.ReadFile(dst)
		if err != nil || string(got) != string(payload) {
			t.Fatalf("resumed download = (%q, %v), want %q", string(got), err, string(payload))
		}
	})

	t.Run("mismatched_prefix_truncates_after_verification", func(t *testing.T) {
		dir := t.TempDir()
		dst := filepath.Join(dir, "resume.bin")
		tempPath := dst + client.config.TempSuffix
		if err := os.WriteFile(tempPath, []byte("XXXXXXXX"), 0o600); err != nil {
			t.Fatal(err)
		}

		remotePath, _ := ParseRemotePath("/resume.bin")
		dest, _ := LocalDestPath(dst)
		if err := client.Download(t.Context(), remotePath, dest, DownloadOptions{}); err != nil {
			t.Fatalf("Download after mismatch failed: %v", err)
		}
		got, err := os.ReadFile(dst)
		if err != nil || string(got) != string(payload) {
			t.Fatalf("re-downloaded file = (%q, %v), want %q", string(got), err, string(payload))
		}
	})
}
