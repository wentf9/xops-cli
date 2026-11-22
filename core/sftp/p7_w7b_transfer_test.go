package sftp

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	pkgsftp "github.com/pkg/sftp"
)

func requireLocalSymlinkSupport(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	probe := filepath.Join(dir, "probe")
	if err := os.Symlink("target", probe); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable on Windows without developer mode/privileges: %v", err)
		}
		t.Fatalf("create probe symlink: %v", err)
	}
}

// TestP7W7b_AB7M1_UploadTopLevelSymlinkDirectory covers AB7-M1:
// Upload and UploadDirectory dereference a top-level local directory symlink
// while preserving child symlinks inside the target directory, and fail closed
// on broken symlinks, symlink loops, and file symlinks before creating any
// remote directory.
func TestP7W7b_AB7M1_UploadTopLevelSymlinkDirectory(t *testing.T) {
	requireLocalSymlinkSupport(t)
	t.Run("upload_top_level_dir_symlink_preserves_child_symlinks", testP7W7bAB7M1UploadTopLevelDirSymlink)
	t.Run("broken_loop_and_file_symlinks_fail_closed_before_creating_remote_dir", testP7W7bAB7M1FailClosedBeforeRemoteDir)
}

func testP7W7bAB7M1UploadTopLevelDirSymlink(t *testing.T) {
	t.Helper()
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())

	base := t.TempDir()
	realDir := filepath.Join(base, "real_dir")
	outsideDir := filepath.Join(base, "outside_dir")
	if err := os.MkdirAll(filepath.Join(realDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outsideDir, "secret.txt"), []byte("do-not-follow"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "root.txt"), []byte("root-data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "sub", "nested.txt"), []byte("nested-data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../root.txt", filepath.Join(realDir, "sub", "child_link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing.txt", filepath.Join(realDir, "dangling_link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(realDir, "dir_link")); err != nil {
		t.Fatal(err)
	}

	linkDir := filepath.Join(base, "link_dir")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	chainedLink := filepath.Join(base, "chained_link")
	if err := os.Symlink(linkDir, chainedLink); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		localPath  string
		remotePath string
		useDirAPI  bool
	}{
		{name: "Upload_symlink", localPath: linkDir, remotePath: "/uploaded_via_upload"},
		{name: "Upload_symlink_trailing_sep", localPath: linkDir + string(os.PathSeparator), remotePath: "/uploaded_trailing"},
		{name: "Upload_chained_symlink", localPath: chainedLink, remotePath: "/uploaded_chained"},
		{name: "UploadDirectory_symlink", localPath: linkDir, remotePath: "/uploaded_via_dir_api", useDirAPI: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.useDirAPI {
				err = client.UploadDirectory(t.Context(), tc.localPath, tc.remotePath, nil)
			} else {
				err = client.Upload(t.Context(), tc.localPath, tc.remotePath, nil)
			}
			if err != nil {
				t.Fatalf("upload failed: %v", err)
			}
			assertUploadedSymlinkTree(t, client, tc.remotePath, outsideDir)
		})
	}
}

func assertUploadedSymlinkTree(t *testing.T, client *Client, remotePath, outsideDir string) {
	t.Helper()
	for rel, want := range map[string]string{
		"root.txt":       "root-data",
		"sub/nested.txt": "nested-data",
	} {
		f, openErr := client.state.sftpClient.Open(path.Join(remotePath, rel))
		if openErr != nil {
			t.Fatalf("open remote %s: %v", rel, openErr)
		}
		got, readErr := io.ReadAll(f)
		_ = f.Close()
		if readErr != nil || string(got) != want {
			t.Fatalf("remote %s = (%q, %v), want %q", rel, string(got), readErr, want)
		}
	}

	for rel, wantTarget := range map[string]string{
		"sub/child_link": "../root.txt",
		"dangling_link":  "missing.txt",
		"dir_link":       filepath.ToSlash(outsideDir),
	} {
		remoteLink := path.Join(remotePath, rel)
		fi, lstatErr := client.state.sftpClient.Lstat(remoteLink)
		if lstatErr != nil {
			t.Fatalf("lstat remote link %s: %v", remoteLink, lstatErr)
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("remote %s mode = %v, want symlink", remoteLink, fi.Mode())
		}
		target, rlErr := client.state.sftpClient.ReadLink(remoteLink)
		if rlErr != nil {
			t.Fatalf("readlink %s: %v", remoteLink, rlErr)
		}
		if target != wantTarget {
			t.Fatalf("remote link %s target = %q, want %q", remoteLink, target, wantTarget)
		}
	}
}

func testP7W7bAB7M1FailClosedBeforeRemoteDir(t *testing.T) {
	t.Helper()
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
	base := t.TempDir()

	broken := filepath.Join(base, "broken")
	if err := os.Symlink(filepath.Join(base, "does-not-exist"), broken); err != nil {
		t.Fatal(err)
	}
	loopA := filepath.Join(base, "loop_a")
	loopB := filepath.Join(base, "loop_b")
	if err := os.Symlink(loopB, loopA); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(loopA, loopB); err != nil {
		t.Fatal(err)
	}
	regFile := filepath.Join(base, "regular.txt")
	if err := os.WriteFile(regFile, []byte("plain"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileLink := filepath.Join(base, "file_link")
	if err := os.Symlink(regFile, fileLink); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		localPath  string
		remotePath string
		useDirAPI  bool
	}{
		{name: "Upload_broken", localPath: broken, remotePath: "/no_mkdir_broken"},
		{name: "UploadDirectory_broken", localPath: broken, remotePath: "/no_mkdir_dir_broken", useDirAPI: true},
		{name: "Upload_loop", localPath: loopA, remotePath: "/no_mkdir_loop"},
		{name: "UploadDirectory_loop", localPath: loopA, remotePath: "/no_mkdir_dir_loop", useDirAPI: true},
		{name: "UploadDirectory_file_symlink", localPath: fileLink, remotePath: "/no_mkdir_file_link", useDirAPI: true},
		{name: "UploadDirectory_regular_file", localPath: regFile, remotePath: "/no_mkdir_reg_file", useDirAPI: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.useDirAPI {
				err = client.UploadDirectory(t.Context(), tc.localPath, tc.remotePath, nil)
			} else {
				err = client.Upload(t.Context(), tc.localPath, tc.remotePath, nil)
			}
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if _, lstatErr := client.state.sftpClient.Lstat(tc.remotePath); !errors.Is(lstatErr, os.ErrNotExist) {
				t.Fatalf("remote dir %q must not be created on failure, Lstat err = %v", tc.remotePath, lstatErr)
			}
		})
	}
}

// TestP7W7b_AB7M2_ClientGlobRejectsHostileEntries covers the core/sftp side of
// AB7-M2: Client.Glob and Client.Download(ExpandGlob=true) reject hostile server
// entries such as "x/..", "x/.", "/", control characters, and duplicates instead
// of resolving above the globbed parent directory.
func TestP7W7b_AB7M2_ClientGlobRejectsHostileEntries(t *testing.T) {
	t.Run("hostile_readdir_entries_fail_closed", func(t *testing.T) {
		hostileNames := []struct {
			name      string
			rawEntry  string
			pattern   string
			parentDir string
		}{
			{name: "slash_dotdot", rawEntry: "x/..", pattern: "/remote/safe/*", parentDir: "/remote/safe"},
			{name: "nested_dotdot", rawEntry: "a/b/..", pattern: "/remote/safe/*", parentDir: "/remote/safe"},
			{name: "slash_dot", rawEntry: "x/.", pattern: "/remote/safe/*", parentDir: "/remote/safe"},
			{name: "root_slash", rawEntry: "/", pattern: "/remote/safe/*", parentDir: "/remote/safe"},
			{name: "control_newline", rawEntry: "evil\nfile", pattern: "/remote/safe/*", parentDir: "/remote/safe"},
			{name: "multilevel_slash_dotdot", rawEntry: "x/..", pattern: "/remote/*/child", parentDir: "/remote"},
		}
		for _, tc := range hostileNames {
			t.Run(tc.name, func(t *testing.T) {
				handler := &maliciousSFTPHandler{
					statInfos: map[string]os.FileInfo{
						"/remote":       syntheticFileInfo{name: "remote", mode: os.ModeDir | 0o755},
						"/remote/safe":  syntheticFileInfo{name: "safe", mode: os.ModeDir | 0o755},
						"/remote/other": syntheticFileInfo{name: "other", mode: os.ModeDir | 0o755},
					},
					dirLists: map[string][]os.FileInfo{
						tc.parentDir: {
							syntheticFileInfo{name: "good.txt", size: 2, mode: 0o644},
							syntheticFileInfo{name: tc.rawEntry, mode: os.ModeDir | 0o755},
						},
					},
					files: map[string][]byte{
						tc.parentDir + "/good.txt": []byte("ok"),
					},
				}
				client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
					FileGet:  handler,
					FilePut:  handler,
					FileCmd:  handler,
					FileList: handler,
				})

				matches, err := client.Glob(t.Context(), tc.pattern)
				if !errors.Is(err, ErrInvalidRemoteName) {
					t.Fatalf("Client.Glob(%q) = (%v, %v), want ErrInvalidRemoteName", tc.pattern, matches, err)
				}

				localDir := t.TempDir()
				pat, parseErr := ParseRemotePath(tc.pattern)
				if parseErr != nil {
					t.Fatalf("ParseRemotePath(%q): %v", tc.pattern, parseErr)
				}
				dest, destErr := LocalDestInto(localDir)
				if destErr != nil {
					t.Fatalf("LocalDestInto: %v", destErr)
				}
				dlErr := client.Download(t.Context(), pat, dest, DownloadOptions{ExpandGlob: true})
				if !errors.Is(dlErr, ErrInvalidRemoteName) {
					t.Fatalf("Download(ExpandGlob=true, %q) = %v, want ErrInvalidRemoteName", tc.pattern, dlErr)
				}
				entries, readErr := os.ReadDir(localDir)
				if readErr != nil || len(entries) != 0 {
					t.Fatalf("localDir must remain empty on hostile glob rejection: entries=%d err=%v", len(entries), readErr)
				}
			})
		}
	})

	t.Run("duplicate_entries_and_bad_pattern_and_valid_multilevel_glob", func(t *testing.T) {
		dupHandler := &maliciousSFTPHandler{
			statInfos: map[string]os.FileInfo{
				"/dup": syntheticFileInfo{name: "dup", mode: os.ModeDir | 0o755},
			},
			dirLists: map[string][]os.FileInfo{
				"/dup": {
					syntheticFileInfo{name: "a.txt", size: 1, mode: 0o644},
					syntheticFileInfo{name: "a.txt", size: 1, mode: 0o644},
				},
			},
		}
		dupClient := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
			FileGet:  dupHandler,
			FilePut:  dupHandler,
			FileCmd:  dupHandler,
			FileList: dupHandler,
		})
		if _, err := dupClient.Glob(t.Context(), "/dup/*"); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("Client.Glob duplicate entries err = %v, want duplicate error", err)
		}

		client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
		if _, err := client.Glob(t.Context(), "/nonexistent/["); !errors.Is(err, path.ErrBadPattern) {
			t.Fatalf("Client.Glob malformed pattern err = %v, want path.ErrBadPattern", err)
		}
		if _, err := client.Glob(t.Context(), "/bad\x00/*"); !errors.Is(err, ErrInvalidRemotePath) {
			t.Fatalf("Client.Glob NUL pattern err = %v, want ErrInvalidRemotePath", err)
		}

		for _, dir := range []string{"/tree/a", "/tree/b"} {
			if err := client.state.sftpClient.MkdirAll(dir); err != nil {
				t.Fatal(err)
			}
			f, err := client.state.sftpClient.Create(dir + "/item.log")
			if err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
		}
		got, err := client.Glob(t.Context(), "/tree/*/*.log")
		if err != nil {
			t.Fatalf("Client.Glob valid multi-level failed: %v", err)
		}
		want := []string{"/tree/a/item.log", "/tree/b/item.log"}
		if !slices.Equal(got, want) {
			t.Fatalf("Client.Glob(/tree/*/*.log) = %v, want %v", got, want)
		}
	})
}

type toctouRemoteCopyHandler struct {
	mu          sync.Mutex
	srcPath     string
	lstatInfo   os.FileInfo
	fstatInfo   os.FileInfo
	fstatErr    error
	opened      bool
	payload     []byte
	writeOpens  atomic.Int64
	cmdCalls    atomic.Int64
	delegatePut pkgsftp.FileWriter
}

func (h *toctouRemoteCopyHandler) Fileread(r *pkgsftp.Request) (io.ReaderAt, error) {
	if r.Filepath != h.srcPath {
		return nil, os.ErrNotExist
	}
	h.mu.Lock()
	h.opened = true
	h.mu.Unlock()
	return bytes.NewReader(h.payload), nil
}

func (h *toctouRemoteCopyHandler) Filewrite(r *pkgsftp.Request) (io.WriterAt, error) {
	h.writeOpens.Add(1)
	if h.delegatePut != nil {
		return h.delegatePut.Filewrite(r)
	}
	return nil, os.ErrPermission
}

func (h *toctouRemoteCopyHandler) OpenFile(r *pkgsftp.Request) (pkgsftp.WriterAtReaderAt, error) {
	h.writeOpens.Add(1)
	if ofw, ok := h.delegatePut.(pkgsftp.OpenFileWriter); ok {
		return ofw.OpenFile(r)
	}
	return nil, os.ErrPermission
}

func (h *toctouRemoteCopyHandler) Filecmd(*pkgsftp.Request) error {
	h.cmdCalls.Add(1)
	return os.ErrPermission
}

func (h *toctouRemoteCopyHandler) Filelist(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	switch r.Method {
	case "Lstat":
		if r.Filepath == h.srcPath {
			return customListerAt{h.lstatInfo}, nil
		}
		if r.Filepath == "/" {
			return customListerAt{syntheticFileInfo{name: "/", mode: os.ModeDir | 0o755}}, nil
		}
		return nil, os.ErrNotExist
	case "Stat":
		if r.Filepath == h.srcPath {
			h.mu.Lock()
			opened := h.opened
			h.mu.Unlock()
			if opened {
				if h.fstatErr != nil {
					return nil, h.fstatErr
				}
				return customListerAt{h.fstatInfo}, nil
			}
			return customListerAt{h.lstatInfo}, nil
		}
		if r.Filepath == "/" {
			return customListerAt{syntheticFileInfo{name: "/", mode: os.ModeDir | 0o755}}, nil
		}
		return nil, os.ErrNotExist
	default:
		return nil, os.ErrNotExist
	}
}

// TestP7W7b_AB7M3_RemoteCopyFileFstatTOCTOU covers AB7-M3:
// remoteCopyFile must verify srcFile.Stat() (SSH_FXP_FSTAT) immediately after
// Open, rejecting non-regular replacement (FIFO/device/socket/dir) or size
// mutation before creating or opening any remote temporary file.
func TestP7W7b_AB7M3_RemoteCopyFileFstatTOCTOU(t *testing.T) {
	basePayload := []byte("0123456789")
	baseLstat := syntheticFileInfo{name: "src.bin", size: int64(len(basePayload)), mode: 0o644}

	cases := []struct {
		name      string
		fstatInfo os.FileInfo
		fstatErr  error
		wantSub   string
	}{
		{
			name:      "replaced_with_fifo",
			fstatInfo: syntheticFileInfo{name: "src.bin", size: int64(len(basePayload)), mode: os.ModeNamedPipe | 0o600},
			wantSub:   "not a regular file",
		},
		{
			name:      "replaced_with_char_device",
			fstatInfo: syntheticFileInfo{name: "src.bin", size: int64(len(basePayload)), mode: os.ModeDevice | os.ModeCharDevice | 0o600},
			wantSub:   "not a regular file",
		},
		{
			name:      "replaced_with_block_device",
			fstatInfo: syntheticFileInfo{name: "src.bin", size: int64(len(basePayload)), mode: os.ModeDevice | 0o600},
			wantSub:   "not a regular file",
		},
		{
			name:      "replaced_with_socket",
			fstatInfo: syntheticFileInfo{name: "src.bin", size: int64(len(basePayload)), mode: os.ModeSocket | 0o600},
			wantSub:   "not a regular file",
		},
		{
			name:      "replaced_with_directory",
			fstatInfo: syntheticFileInfo{name: "src.bin", size: int64(len(basePayload)), mode: os.ModeDir | 0o755},
			wantSub:   "not a regular file",
		},
		{
			name:      "size_mutated_larger",
			fstatInfo: syntheticFileInfo{name: "src.bin", size: int64(len(basePayload) + 5), mode: 0o644},
			wantSub:   "remote source size changed",
		},
		{
			name:      "size_mutated_smaller",
			fstatInfo: syntheticFileInfo{name: "src.bin", size: 3, mode: 0o644},
			wantSub:   "remote source size changed",
		},
		{
			name:     "fstat_error",
			fstatErr: os.ErrPermission,
			wantSub:  "stat remote source file failed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &toctouRemoteCopyHandler{
				srcPath:   "/src.bin",
				lstatInfo: baseLstat,
				fstatInfo: tc.fstatInfo,
				fstatErr:  tc.fstatErr,
				payload:   basePayload,
			}
			client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
				FileGet:  h,
				FilePut:  h,
				FileCmd:  h,
				FileList: h,
			})

			err := client.RemoteCopy(t.Context(), "/src.bin", "/dst.bin")
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("RemoteCopy(%s) err = %v, want substring %q", tc.name, err, tc.wantSub)
			}
			if got := h.writeOpens.Load(); got != 0 {
				t.Fatalf("RemoteCopy(%s) opened/created remote temp file %d times after FSTAT failure, want 0", tc.name, got)
			}
			if got := h.cmdCalls.Load(); got != 0 {
				t.Fatalf("RemoteCopy(%s) issued %d Filecmd calls after FSTAT failure, want 0", tc.name, got)
			}
		})
	}
}

// TestP7W7b_AB7L1_DownloadDirectoryPreservesSanitizedRootMode covers AB7-L1:
// downloadDirectory creates the local root directory using the sanitized remote
// root mode (e.g. 0700 / 0750 / 0500, stripping special bits) instead of
// widening to hardcoded 0755, while leaving pre-existing local roots untouched.
func TestP7W7b_AB7L1_DownloadDirectoryPreservesSanitizedRootMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permission bits are not enforced on Windows")
	}

	probeDir := filepath.Join(t.TempDir(), "probe750")
	if err := os.Mkdir(probeDir, 0o750); err != nil {
		t.Fatal(err)
	}
	probeInfo, err := os.Lstat(probeDir)
	if err != nil {
		t.Fatal(err)
	}
	expected750 := probeInfo.Mode().Perm()

	cases := []struct {
		name       string
		remoteMode os.FileMode
		wantPerm   os.FileMode
	}{
		{name: "private_0700", remoteMode: os.ModeDir | 0o700, wantPerm: 0o700},
		{name: "group_0750", remoteMode: os.ModeDir | 0o750, wantPerm: expected750},
		{name: "special_bits_stripped_0700", remoteMode: os.ModeDir | os.ModeSetuid | os.ModeSetgid | os.ModeSticky | 0o700, wantPerm: 0o700},
		{name: "readonly_0500", remoteMode: os.ModeDir | 0o500, wantPerm: 0o500},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("secret-payload")
			handler := &maliciousSFTPHandler{
				statInfos: map[string]os.FileInfo{
					"/secret":          syntheticFileInfo{name: "secret", mode: tc.remoteMode},
					"/secret/data.txt": syntheticFileInfo{name: "data.txt", size: int64(len(payload)), mode: 0o600},
				},
				dirLists: map[string][]os.FileInfo{
					"/secret": {
						syntheticFileInfo{name: "data.txt", size: int64(len(payload)), mode: 0o600},
					},
				},
				files: map[string][]byte{
					"/secret/data.txt": payload,
				},
			}
			client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
				FileGet:  handler,
				FilePut:  handler,
				FileCmd:  handler,
				FileList: handler,
			})

			parent := t.TempDir()
			localRootPath := filepath.Join(parent, "secret")
			t.Cleanup(func() { _ = os.Chmod(localRootPath, 0o700) })

			remoteRoot, _ := ParseRemotePath("/secret")
			dest, _ := LocalDestInto(parent)
			if err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{}); err != nil {
				t.Fatalf("Download(%s): %v", tc.name, err)
			}

			fi, lstatErr := os.Lstat(localRootPath)
			if lstatErr != nil {
				t.Fatalf("Lstat(%q): %v", localRootPath, lstatErr)
			}
			if fi.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
				t.Fatalf("downloaded root dir %q retained special bits: %v", localRootPath, fi.Mode())
			}
			if fi.Mode().Perm() != tc.wantPerm {
				t.Fatalf("downloaded root dir %q perm = %04o, want %04o", localRootPath, fi.Mode().Perm(), tc.wantPerm)
			}
			if fi.Mode().Perm()&0o007 != 0 {
				t.Fatalf("downloaded root dir %q widened world permissions: %04o", localRootPath, fi.Mode().Perm())
			}

			got, readErr := os.ReadFile(filepath.Join(localRootPath, "data.txt"))
			if readErr != nil || string(got) != string(payload) {
				t.Fatalf("downloaded child = (%q, %v), want %q", string(got), readErr, string(payload))
			}
		})
	}

	t.Run("preexisting_local_root_mode_preserved", func(t *testing.T) {
		handler := &maliciousSFTPHandler{
			statInfos: map[string]os.FileInfo{
				"/ro_remote": syntheticFileInfo{name: "ro_remote", mode: os.ModeDir | 0o500},
			},
			dirLists: map[string][]os.FileInfo{
				"/ro_remote": {},
			},
		}
		client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
			FileGet:  handler,
			FilePut:  handler,
			FileCmd:  handler,
			FileList: handler,
		})
		existing := filepath.Join(t.TempDir(), "existing")
		if err := os.Mkdir(existing, 0o755); err != nil {
			t.Fatal(err)
		}
		beforeInfo, err := os.Lstat(existing)
		if err != nil {
			t.Fatal(err)
		}
		remoteRoot, _ := ParseRemotePath("/ro_remote")
		dest, _ := LocalDestPath(existing)
		if err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{}); err != nil {
			t.Fatalf("Download into existing dir: %v", err)
		}
		afterInfo, err := os.Lstat(existing)
		if err != nil {
			t.Fatal(err)
		}
		if afterInfo.Mode().Perm() != beforeInfo.Mode().Perm() {
			t.Fatalf("existing local root mode changed from %04o to %04o", beforeInfo.Mode().Perm(), afterInfo.Mode().Perm())
		}
	})
}
