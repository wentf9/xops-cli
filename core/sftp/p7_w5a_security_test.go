package sftp

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
)

func TestP7W5a_AB5H1_CaseFoldedChainedSymlinksRejected(t *testing.T) {
	t.Run("ascii_case_folded_chained_escape_rejected", func(t *testing.T) {
		handler := &customReadLinkHandler{
			maliciousSFTPHandler: maliciousSFTPHandler{
				statInfos: map[string]os.FileInfo{
					"/remote":       syntheticFileInfo{name: "remote", mode: os.ModeDir | 0o755},
					"/remote/a":     syntheticFileInfo{name: "a", mode: os.ModeDir | 0o755},
					"/remote/a/b":   syntheticFileInfo{name: "b", mode: os.ModeDir | 0o755},
					"/remote/a/b/c": syntheticFileInfo{name: "c", mode: os.ModeDir | 0o755},
				},
				dirLists: map[string][]os.FileInfo{
					"/remote": {
						syntheticFileInfo{name: "a", mode: os.ModeDir | 0o755},
						syntheticFileInfo{name: "escape", mode: os.ModeSymlink | 0o777},
					},
					"/remote/a":     {syntheticFileInfo{name: "b", mode: os.ModeDir | 0o755}},
					"/remote/a/b":   {syntheticFileInfo{name: "c", mode: os.ModeDir | 0o755}},
					"/remote/a/b/c": {syntheticFileInfo{name: "up", mode: os.ModeSymlink | 0o777}},
				},
			},
			readLinks: map[string][]string{
				"/remote/a/b/c/up": {"../../.."},
				"/remote/escape":   {"a/b/c/UP/../../.ssh/id_ed25519"},
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
			t.Fatalf("Download case-folded chained symlink escape = %v, want ErrUnsafeDownloadSymlink", err)
		}
		for _, p := range []string{
			filepath.Join(localDst, "escape"),
			filepath.Join(localDst, "a", "b", "c", "up"),
		} {
			if _, lstatErr := os.Lstat(p); !errors.Is(lstatErr, os.ErrNotExist) {
				t.Fatalf("symlink %q must not exist after rejection: %v", p, lstatErr)
			}
		}
	})

	t.Run("case_folded_parent_dir_and_unicode_fold_rejected", func(t *testing.T) {
		cases := []struct {
			name   string
			links  map[string]string
			rel    string
			target string
		}{
			{
				name: "upper_dir_and_leaf",
				links: map[string]string{
					"a/b/c/up": "../../..",
					"escape":   "a/B/c/UP/../../.ssh/id_ed25519",
				},
				rel:    "escape",
				target: "a/B/c/UP/../../.ssh/id_ed25519",
			},
			{
				name: "unicode_greek_sigma_fold",
				links: map[string]string{
					"a/b/c/σ": "../../..",
					"escape":  "a/b/c/ς/../../.ssh/id_ed25519",
				},
				rel:    "escape",
				target: "a/b/c/ς/../../.ssh/id_ed25519",
			},
			{
				name: "unicode_kelvin_sign_fold",
				links: map[string]string{
					"a/b/c/k": "../../..",
					"escape":  "a/b/c/\u212A/../../.ssh/id_ed25519",
				},
				rel:    "escape",
				target: "a/b/c/\u212A/../../.ssh/id_ed25519",
			},
			{
				name: "unicode_long_s_fold",
				links: map[string]string{
					"a/b/c/s": "../../..",
					"escape":  "a/b/c/\u017F/../../.ssh/id_ed25519",
				},
				rel:    "escape",
				target: "a/b/c/\u017F/../../.ssh/id_ed25519",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := validateDownloadSymlinkInTree(t.TempDir(), tc.rel, tc.target, tc.links)
				if !errors.Is(err, ErrUnsafeDownloadSymlink) {
					t.Fatalf("validateDownloadSymlinkInTree(%q -> %q) = %v, want ErrUnsafeDownloadSymlink", tc.rel, tc.target, err)
				}
			})
		}
	})

	t.Run("case_colliding_staged_symlinks_rejected_fail_closed", func(t *testing.T) {
		for _, links := range []map[string]string{
			{"up": "safe", "UP": "../.."},
			{"a/b/up": "safe", "a/B/up": "other"},
			{"a/σ": "safe", "a/ς": "other"},
		} {
			if err := validateDownloadSymlinkInTree(t.TempDir(), "escape", "safe", links); !errors.Is(err, ErrUnsafeDownloadSymlink) {
				t.Fatalf("colliding inTreeSymlinks %v = %v, want ErrUnsafeDownloadSymlink", links, err)
			}
		}

		// Even on case-sensitive Linux (walkDir probe false), Phase 2 symlink indexing
		// must fail closed on case-colliding staged symlinks.
		handler := &customReadLinkHandler{
			maliciousSFTPHandler: maliciousSFTPHandler{
				statInfos: map[string]os.FileInfo{
					"/col": syntheticFileInfo{name: "col", mode: os.ModeDir | 0o755},
				},
				dirLists: map[string][]os.FileInfo{
					"/col": {
						syntheticFileInfo{name: "up", mode: os.ModeSymlink | 0o777},
						syntheticFileInfo{name: "UP", mode: os.ModeSymlink | 0o777},
					},
				},
			},
			readLinks: map[string][]string{
				"/col/up": {"safe1"},
				"/col/UP": {"safe2"},
			},
		}
		client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
			FileGet:  handler,
			FilePut:  handler,
			FileCmd:  handler,
			FileList: handler,
		})
		client.caseInsensitiveDirProbe = func(string) bool { return false }

		localDst := t.TempDir()
		remoteRoot, _ := ParseRemotePath("/col")
		dest, _ := LocalDestPath(localDst)
		err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{})
		if !errors.Is(err, ErrUnsafeDownloadSymlink) {
			t.Fatalf("Download case-colliding staged symlinks = %v, want ErrUnsafeDownloadSymlink", err)
		}
		entries, readErr := os.ReadDir(localDst)
		if readErr != nil || len(entries) != 0 {
			t.Fatalf("localDst must remain empty after collision rejection: entries=%d err=%v", len(entries), readErr)
		}
	})

	t.Run("case_insensitive_walkdir_rejects_colliding_siblings", testP7W5aCaseInsensitiveWalkDirRejectsCollidingSiblings)

	t.Run("probeCaseInsensitiveDir_leaves_no_temp_entries_and_matches_fs", func(t *testing.T) {
		dir := t.TempDir()
		got := probeCaseInsensitiveDir(dir)

		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("ReadDir(%q): %v", dir, err)
		}
		if len(entries) != 0 {
			t.Fatalf("probeCaseInsensitiveDir left entries behind: %v", entries)
		}

		// Ground-truth check on this filesystem.
		lower := filepath.Join(dir, "probe_check_dir")
		upper := filepath.Join(dir, "PROBE_CHECK_DIR")
		if err := os.Mkdir(lower, 0o700); err != nil {
			t.Fatal(err)
		}
		fi1, err1 := os.Lstat(lower)
		fi2, err2 := os.Lstat(upper)
		want := err1 == nil && err2 == nil && os.SameFile(fi1, fi2)
		if got != want {
			t.Fatalf("probeCaseInsensitiveDir(%q) = %v, want %v", dir, got, want)
		}
	})
}

func testP7W5aCaseInsensitiveWalkDirRejectsCollidingSiblings(t *testing.T) {
	t.Helper()
	cases := []struct {
		name    string
		entries []os.FileInfo
	}{
		{
			name: "regular_files_foo_and_FOO",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "foo", size: 3, mode: 0o644},
				syntheticFileInfo{name: "FOO", size: 3, mode: 0o644},
			},
		},
		{
			name: "symlinks_up_and_UP",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "up", mode: os.ModeSymlink | 0o777},
				syntheticFileInfo{name: "UP", mode: os.ModeSymlink | 0o777},
			},
		},
		{
			name: "dir_and_file_collision",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
				syntheticFileInfo{name: "SUB", size: 3, mode: 0o644},
			},
		},
		{
			name: "unicode_sigma_collision",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "σ", size: 3, mode: 0o644},
				syntheticFileInfo{name: "ς", size: 3, mode: 0o644},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &customReadLinkHandler{
				maliciousSFTPHandler: maliciousSFTPHandler{
					statInfos: map[string]os.FileInfo{
						"/ci":     syntheticFileInfo{name: "ci", mode: os.ModeDir | 0o755},
						"/ci/sub": syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
						"/ci/foo": syntheticFileInfo{name: "foo", size: 3, mode: 0o644},
						"/ci/FOO": syntheticFileInfo{name: "FOO", size: 3, mode: 0o644},
						"/ci/SUB": syntheticFileInfo{name: "SUB", size: 3, mode: 0o644},
						"/ci/σ":   syntheticFileInfo{name: "σ", size: 3, mode: 0o644},
						"/ci/ς":   syntheticFileInfo{name: "ς", size: 3, mode: 0o644},
					},
					dirLists: map[string][]os.FileInfo{
						"/ci":     tc.entries,
						"/ci/sub": {},
					},
					files: map[string][]byte{
						"/ci/foo": []byte("one"),
						"/ci/FOO": []byte("two"),
						"/ci/SUB": []byte("two"),
						"/ci/σ":   []byte("one"),
						"/ci/ς":   []byte("two"),
					},
				},
				readLinks: map[string][]string{
					"/ci/up": {"safe"},
					"/ci/UP": {"../.."},
				},
			}
			client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
				FileGet:  handler,
				FilePut:  handler,
				FileCmd:  handler,
				FileList: handler,
			})
			client.caseInsensitiveDirProbe = func(string) bool { return true }

			localDst := t.TempDir()
			remoteRoot, _ := ParseRemotePath("/ci")
			dest, _ := LocalDestPath(localDst)
			err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{})
			if err == nil || !strings.Contains(err.Error(), "case-colliding remote directory entries") {
				t.Fatalf("Download on case-insensitive root = %v, want case-colliding remote directory entries error", err)
			}
			entries, readErr := os.ReadDir(localDst)
			if readErr != nil {
				t.Fatalf("ReadDir(%q): %v", localDst, readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("localDst must remain empty after sibling collision rejection, got %d entries", len(entries))
			}
		})
	}
}

func TestP7W5a_AB5M1_WindowsJunctionAndUnreplacedDiskSymlink(t *testing.T) {
	t.Run("non_regular_non_dir_modes_including_ntfs_junction_rejected", testP7W5aNonRegularModesRejected)
	t.Run("staged_symlink_does_not_mask_escaping_ondisk_symlink", testP7W5aStagedDoesNotMaskEscapingDiskSymlink)
	t.Run("staged_symlink_does_not_mask_relative_escaping_ondisk_symlink", testP7W5aStagedDoesNotMaskRelativeEscapingDiskSymlink)
	t.Run("orderStagedDownloadSymlinks_places_preexisting_before_new", testP7W5aOrderStagedPreexistingFirst)
	t.Run("safe_overlapping_ondisk_and_staged_symlink_succeeds", testP7W5aSafeOverlappingSymlinkSucceeds)
}

func testP7W5aNonRegularModesRejected(t *testing.T) {
	t.Helper()
	modes := []struct {
		name string
		mode os.FileMode
	}{
		{name: "ntfs_junction_mode_irregular", mode: os.ModeIrregular | 0o755},
		{name: "dir_plus_mode_irregular", mode: os.ModeDir | os.ModeIrregular | 0o755},
		{name: "fifo_named_pipe", mode: os.ModeNamedPipe | 0o600},
		{name: "unix_socket", mode: os.ModeSocket | 0o600},
		{name: "device_node", mode: os.ModeDevice | 0o600},
	}

	localRoot := t.TempDir()
	juncDiskPath := filepath.Join(localRoot, "junc")

	for _, tc := range modes {
		t.Run(tc.name, func(t *testing.T) {
			inspector := downloadDiskInspector{
				lstat: func(p string) (os.FileInfo, error) {
					if filepath.Clean(p) == filepath.Clean(juncDiskPath) {
						return syntheticFileInfo{name: "junc", mode: tc.mode}, nil
					}
					return nil, os.ErrNotExist
				},
				readlink: os.Readlink,
			}

			// 1. Traversing through junction directly.
			idx, err := buildDownloadSymlinkIndex(map[string]string{
				"escape": "junc/secret",
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := validateDownloadSymlinkInTreeWithIndex(localRoot, "escape", "junc/secret", idx, inspector); !errors.Is(err, ErrUnsafeDownloadSymlink) {
				t.Fatalf("traversing %s = %v, want ErrUnsafeDownloadSymlink", tc.name, err)
			}

			// 2. Staged symlink at same path must NOT mask on-disk junction.
			maskedIdx, err := buildDownloadSymlinkIndex(map[string]string{
				"junc":   "safe",
				"escape": "junc/secret",
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := validateDownloadSymlinkInTreeWithIndex(localRoot, "escape", "junc/secret", maskedIdx, inspector); !errors.Is(err, ErrUnsafeDownloadSymlink) {
				t.Fatalf("staged symlink masking %s = %v, want ErrUnsafeDownloadSymlink", tc.name, err)
			}

			// 3. Parent component is a junction.
			parentIdx, err := buildDownloadSymlinkIndex(map[string]string{
				"junc/child": "safe",
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := validateDownloadSymlinkInTreeWithIndex(localRoot, "junc/child", "safe", parentIdx, inspector); !errors.Is(err, ErrUnsafeDownloadSymlink) {
				t.Fatalf("parent %s = %v, want ErrUnsafeDownloadSymlink", tc.name, err)
			}
		})
	}
}

func testP7W5aStagedDoesNotMaskEscapingDiskSymlink(t *testing.T) {
	t.Helper()
	outsideDir := t.TempDir()
	localDst := t.TempDir()
	if err := os.MkdirAll(filepath.Join(localDst, "ro"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(localDst, "ro", "ext")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable on Windows: %v", err)
		}
		t.Fatal(err)
	}

	handler := &customReadLinkHandler{
		maliciousSFTPHandler: maliciousSFTPHandler{
			statInfos: map[string]os.FileInfo{
				"/mask":    syntheticFileInfo{name: "mask", mode: os.ModeDir | 0o755},
				"/mask/ro": syntheticFileInfo{name: "ro", mode: os.ModeDir | 0o755},
			},
			dirLists: map[string][]os.FileInfo{
				"/mask": {
					syntheticFileInfo{name: "a_escape", mode: os.ModeSymlink | 0o777},
					syntheticFileInfo{name: "ro", mode: os.ModeDir | 0o755},
				},
				"/mask/ro": {
					syntheticFileInfo{name: "ext", mode: os.ModeSymlink | 0o777},
				},
			},
		},
		readLinks: map[string][]string{
			"/mask/a_escape": {"ro/ext/secret"},
			"/mask/ro/ext":   {"safe"},
		},
	}
	client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
		FileGet:  handler,
		FilePut:  handler,
		FileCmd:  handler,
		FileList: handler,
	})

	remoteRoot, _ := ParseRemotePath("/mask")
	dest, _ := LocalDestPath(localDst)
	err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{})
	if !errors.Is(err, ErrUnsafeDownloadSymlink) {
		t.Fatalf("Download with staged symlink masking escaping on-disk symlink = %v, want ErrUnsafeDownloadSymlink", err)
	}
	if _, lstatErr := os.Lstat(filepath.Join(localDst, "a_escape")); !errors.Is(lstatErr, os.ErrNotExist) {
		t.Fatalf("a_escape must not be created: %v", lstatErr)
	}
}

func testP7W5aStagedDoesNotMaskRelativeEscapingDiskSymlink(t *testing.T) {
	t.Helper()
	localDst := t.TempDir()
	if err := os.MkdirAll(filepath.Join(localDst, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../..", filepath.Join(localDst, "a", "b", "up")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable on Windows: %v", err)
		}
		t.Fatal(err)
	}
	links := map[string]string{
		"a/b/up": "safe",
		"escape": "a/b/up/../outside",
	}
	if err := validateDownloadSymlinkInTree(localDst, "escape", "a/b/up/../outside", links); !errors.Is(err, ErrUnsafeDownloadSymlink) {
		t.Fatalf("validateDownloadSymlinkInTree masking relative escaping disk symlink = %v, want ErrUnsafeDownloadSymlink", err)
	}
}

func testP7W5aOrderStagedPreexistingFirst(t *testing.T) {
	t.Helper()
	localDst := t.TempDir()
	if err := os.MkdirAll(filepath.Join(localDst, "ro"), 0o755); err != nil {
		t.Fatal(err)
	}
	existingPath := filepath.Join(localDst, "ro", "ext")
	if err := os.Symlink("safe_old", existingPath); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable on Windows: %v", err)
		}
		t.Fatal(err)
	}
	newPath := filepath.Join(localDst, "a_new")

	ordered, err := orderStagedDownloadSymlinks([]stagedDownloadSymlink{
		{remotePath: "/r/a_new", localPath: newPath, relPath: "a_new", target: "ro/ext/file"},
		{remotePath: "/r/ro/ext", localPath: existingPath, relPath: "ro/ext", target: "safe_new"},
	})
	if err != nil {
		t.Fatalf("orderStagedDownloadSymlinks: %v", err)
	}
	if len(ordered) != 2 || ordered[0].relPath != "ro/ext" || ordered[1].relPath != "a_new" {
		t.Fatalf("ordered = [%s, %s], want [ro/ext, a_new]", ordered[0].relPath, ordered[1].relPath)
	}
}

func testP7W5aSafeOverlappingSymlinkSucceeds(t *testing.T) {
	t.Helper()
	localDst := t.TempDir()
	if err := os.MkdirAll(filepath.Join(localDst, "ro"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("safe_old", filepath.Join(localDst, "ro", "ext")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable on Windows: %v", err)
		}
		t.Fatal(err)
	}

	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
	if err := client.state.sftpClient.MkdirAll("/ok/ro/safe_new"); err != nil {
		t.Fatal(err)
	}
	f, err := client.state.sftpClient.Create("/ok/ro/safe_new/data.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("safe-replacement"))
	_ = f.Close()
	if err := client.state.sftpClient.Symlink("ro/ext/data.txt", "/ok/a_ref"); err != nil {
		t.Fatal(err)
	}
	if err := client.state.sftpClient.Symlink("safe_new", "/ok/ro/ext"); err != nil {
		t.Fatal(err)
	}

	remoteRoot, _ := ParseRemotePath("/ok")
	dest, _ := LocalDestPath(localDst)
	if err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{}); err != nil {
		t.Fatalf("Download safe overlapping symlink replacement failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(localDst, "a_ref"))
	if err != nil || string(got) != "safe-replacement" {
		t.Fatalf("reading through replaced safe symlink = (%q, %v), want \"safe-replacement\"", string(got), err)
	}
}

type orderedRelayOpRecorder struct {
	mu     sync.Mutex
	events []string
}

func (r *orderedRelayOpRecorder) record(ev string) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
}

func (r *orderedRelayOpRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.events))
	copy(out, r.events)
	return out
}

type relayRecordingCmder struct {
	delegate pkgsftp.FileCmder
	rec      *orderedRelayOpRecorder
}

func (c *relayRecordingCmder) Filecmd(r *pkgsftp.Request) error {
	switch r.Method {
	case "Setstat":
		if r.AttrFlags().Permissions {
			c.rec.record("chmod:" + r.Filepath + ":" + r.Attributes().FileMode().Perm().String())
		}
		if r.AttrFlags().Acmodtime {
			c.rec.record("chtimes:" + r.Filepath)
		}
	case "Rename":
		c.rec.record("rename:" + r.Filepath + "->" + r.Target)
	}
	return c.delegate.Filecmd(r)
}

func (c *relayRecordingCmder) PosixRename(r *pkgsftp.Request) error {
	c.rec.record("posix-rename:" + r.Filepath + "->" + r.Target)
	if pr, ok := c.delegate.(pkgsftp.PosixRenameFileCmder); ok {
		return pr.PosixRename(r)
	}
	return pkgsftp.ErrSSHFxOpUnsupported
}

type relayRecordingWriterAt struct {
	io.WriterAt
	path string
	rec  *orderedRelayOpRecorder
}

func (w *relayRecordingWriterAt) WriteAt(p []byte, off int64) (int, error) {
	w.rec.record("write:" + w.path)
	return w.WriterAt.WriteAt(p, off)
}

func (w *relayRecordingWriterAt) Close() error {
	if cl, ok := w.WriterAt.(io.Closer); ok {
		return cl.Close()
	}
	return nil
}

type relayRecordingFilePut struct {
	delegate pkgsftp.FileWriter
	rec      *orderedRelayOpRecorder
}

func (p *relayRecordingFilePut) Filewrite(r *pkgsftp.Request) (io.WriterAt, error) {
	w, err := p.delegate.Filewrite(r)
	if err != nil {
		return nil, err
	}
	return &relayRecordingWriterAt{WriterAt: w, path: r.Filepath, rec: p.rec}, nil
}

func TestP7W5a_AB5M2_RelayFileFromStagingAndPermissions(t *testing.T) {
	t.Run("chmods_staging_0600_before_write_and_applies_source_perm_and_chtimes_before_replace", testP7W5aRelayStagingChmodAndFinalPerm)
	t.Run("rejects_preexisting_symlink_temp_file_without_truncating_victim", testP7W5aRelayRejectsSymlinkTemp)
	t.Run("resume_matching_prefix_and_mismatched_prefix_truncate", testP7W5aRelayResumeAndMismatch)
	t.Run("rejects_directory_source_and_size_mismatch", testP7W5aRelayRejectsDirAndSizeMismatch)
}

func testP7W5aRelayStagingChmodAndFinalPerm(t *testing.T) {
	t.Helper()
	for _, tc := range []struct {
		name     string
		srcPerm  os.FileMode
		wantPerm string
	}{
		{name: "secret_0600", srcPerm: 0o600, wantPerm: os.FileMode(0o600).String()},
		{name: "readonly_0400", srcPerm: 0o400, wantPerm: os.FileMode(0o400).String()},
		{name: "exec_0750", srcPerm: 0o750, wantPerm: os.FileMode(0o750).String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runP7W5aRelayPermCase(t, tc.srcPerm, tc.wantPerm)
		})
	}
}

func runP7W5aRelayPermCase(t *testing.T, srcPerm os.FileMode, wantPerm string) {
	t.Helper()
	srcHandlers := pkgsftp.InMemHandler()
	srcHandlers.FileList = &customModeFileLister{
		delegate:      srcHandlers.FileList,
		modeOverrides: map[string]os.FileMode{"/secret.key": srcPerm},
	}
	srcClient := newTestSFTPClientWithHandlers(t, srcHandlers)
	f, err := srcClient.state.sftpClient.Create("/secret.key")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("super-secret-key-material")
	if _, err := f.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	rec := &orderedRelayOpRecorder{}
	dstHandlers := pkgsftp.InMemHandler()
	dstHandlers.FileCmd = &relayRecordingCmder{delegate: dstHandlers.FileCmd, rec: rec}
	dstHandlers.FilePut = &relayRecordingFilePut{delegate: dstHandlers.FilePut, rec: rec}
	dstClient := newTestSFTPClientWithHandlers(t, dstHandlers)

	srcPath, _ := ParseRemotePath("/secret.key")
	dstPath, _ := ParseRemotePath("/relayed.key")
	if err := dstClient.RelayFileFrom(t.Context(), srcClient, srcPath, dstPath, nil, nil); err != nil {
		t.Fatalf("RelayFileFrom failed: %v", err)
	}

	rf, err := dstClient.state.sftpClient.Open("/relayed.key")
	if err != nil {
		t.Fatal(err)
	}
	gotBytes, err := io.ReadAll(rf)
	_ = rf.Close()
	if err != nil || string(gotBytes) != string(payload) {
		t.Fatalf("relayed content = (%q, %v), want %q", string(gotBytes), err, string(payload))
	}

	assertP7W5aRelayEventOrder(t, rec.snapshot(), "/relayed.key"+dstClient.config.TempSuffix, wantPerm)
}

func assertP7W5aRelayEventOrder(t *testing.T, events []string, tempPath, wantPerm string) {
	t.Helper()
	idxStagingChmod := -1
	idxFirstWrite := -1
	idxChtimes := -1
	idxFinalChmod := -1
	idxReplace := -1
	for i, ev := range events {
		switch ev {
		case "chmod:" + tempPath + ":" + os.FileMode(0o600).String():
			if idxStagingChmod == -1 {
				idxStagingChmod = i
			}
			if wantPerm == os.FileMode(0o600).String() {
				idxFinalChmod = i
			}
		case "chmod:" + tempPath + ":" + wantPerm:
			idxFinalChmod = i
		case "write:" + tempPath:
			if idxFirstWrite == -1 {
				idxFirstWrite = i
			}
		case "chtimes:" + tempPath:
			idxChtimes = i
		case "posix-rename:" + tempPath + "->/relayed.key", "rename:" + tempPath + "->/relayed.key":
			idxReplace = i
		}
	}
	if idxStagingChmod == -1 || idxFirstWrite == -1 || idxStagingChmod > idxFirstWrite {
		t.Fatalf("staging Chmod(0600) must precede first write; events=%v", events)
	}
	if idxChtimes == -1 || idxReplace == -1 || idxChtimes > idxReplace {
		t.Fatalf("Chtimes must precede replace; events=%v", events)
	}
	if idxFinalChmod == -1 || idxFinalChmod > idxReplace {
		t.Fatalf("final Chmod(%s) must precede replace; events=%v", wantPerm, events)
	}
}

func testP7W5aRelayRejectsSymlinkTemp(t *testing.T) {
	t.Helper()
	srcClient := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
	sf, err := srcClient.state.sftpClient.Create("/src.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = sf.Write([]byte("attacker-overwrite"))
	_ = sf.Close()

	dstClient := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
	vf, err := dstClient.state.sftpClient.Create("/victim.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = vf.Write([]byte("precious-victim"))
	_ = vf.Close()

	tempPath := "/dst.txt" + dstClient.config.TempSuffix
	if err := dstClient.state.sftpClient.Symlink("/victim.txt", tempPath); err != nil {
		t.Fatal(err)
	}

	srcPath, _ := ParseRemotePath("/src.txt")
	dstPath, _ := ParseRemotePath("/dst.txt")
	err = dstClient.RelayFileFrom(t.Context(), srcClient, srcPath, dstPath, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("RelayFileFrom with symlink temp path = %v, want not a regular file error", err)
	}

	check, err := dstClient.state.sftpClient.Open("/victim.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(check)
	_ = check.Close()
	if err != nil || string(got) != "precious-victim" {
		t.Fatalf("victim corrupted = (%q, %v), want \"precious-victim\"", string(got), err)
	}
	if _, err := dstClient.state.sftpClient.Lstat("/dst.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("/dst.txt must not exist after rejected relay: %v", err)
	}
}

func testP7W5aRelayResumeAndMismatch(t *testing.T) {
	t.Helper()
	srcClient := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
	payload := []byte("0123456789abcdef")
	sf, err := srcClient.state.sftpClient.Create("/resume.bin")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = sf.Write(payload)
	_ = sf.Close()

	for _, tc := range []struct {
		name   string
		prefix string
	}{
		{name: "matching_prefix", prefix: "01234567"},
		{name: "mismatched_prefix", prefix: "XXXXXXXX"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dstClient := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
			dstClient.config.EnableResume = true
			dstClient.config.ResumeMinSize = 4

			tempPath := "/out.bin" + dstClient.config.TempSuffix
			tf, err := dstClient.state.sftpClient.Create(tempPath)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = tf.Write([]byte(tc.prefix))
			_ = tf.Close()

			srcPath, _ := ParseRemotePath("/resume.bin")
			dstPath, _ := ParseRemotePath("/out.bin")
			var reported int64
			if err := dstClient.RelayFileFrom(t.Context(), srcClient, srcPath, dstPath, nil, func(n int64) {
				reported += n
			}); err != nil {
				t.Fatalf("RelayFileFrom(%s) failed: %v", tc.name, err)
			}
			if reported != int64(len(payload)) {
				t.Fatalf("reported progress = %d, want %d", reported, len(payload))
			}
			rf, err := dstClient.state.sftpClient.Open("/out.bin")
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(rf)
			_ = rf.Close()
			if err != nil || string(got) != string(payload) {
				t.Fatalf("relayed content = (%q, %v), want %q", string(got), err, string(payload))
			}
		})
	}
}

func testP7W5aRelayRejectsDirAndSizeMismatch(t *testing.T) {
	t.Helper()
	srcClient := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
	if err := srcClient.state.sftpClient.MkdirAll("/srcdir"); err != nil {
		t.Fatal(err)
	}
	sf, err := srcClient.state.sftpClient.Create("/sized.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = sf.Write([]byte("hello"))
	_ = sf.Close()

	dstClient := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
	dirSrc, _ := ParseRemotePath("/srcdir")
	dstPath, _ := ParseRemotePath("/dst.txt")
	if err := dstClient.RelayFileFrom(t.Context(), srcClient, dirSrc, dstPath, nil, nil); err == nil || !strings.Contains(strings.ToLower(err.Error()), "directory") {
		t.Fatalf("RelayFileFrom(dir) = %v, want directory error", err)
	}

	fileSrc, _ := ParseRemotePath("/sized.txt")
	wrongInfo := syntheticFileInfo{name: "sized.txt", size: 99, mode: 0o600}
	if err := dstClient.RelayFileFrom(t.Context(), srcClient, fileSrc, dstPath, wrongInfo, nil); err == nil || !strings.Contains(err.Error(), "size changed") {
		t.Fatalf("RelayFileFrom(size mismatch) = %v, want size changed error", err)
	}
}

func TestP7W5a_AB5L1_PrepareDownloadFileReturnsOpenedInfoAndCleansUp(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
	client.config.EnableResume = true
	client.config.ResumeMinSize = 4

	payload := []byte("0123456789abcdef")
	f, err := client.state.sftpClient.Create("/file.bin")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write(payload)
	_ = f.Close()

	srcFile, err := client.state.sftpClient.Open("/file.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srcFile.Close() }()

	t.Run("returns_handle_verified_openedInfo_on_create_and_resume_and_mismatch", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			seed       string
			wantOffset int64
		}{
			{name: "fresh_create", seed: "", wantOffset: 0},
			{name: "resume_match", seed: "01234567", wantOffset: 8},
			{name: "mismatch_truncate", seed: "XXXXXXXX", wantOffset: 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				tempPath := filepath.Join(dir, "file.bin"+client.config.TempSuffix)
				if tc.seed != "" {
					if err := os.WriteFile(tempPath, []byte(tc.seed), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				offset, dstFile, openedInfo, err := client.prepareDownloadFile(t.Context(), tempPath, int64(len(payload)), 0o600, srcFile)
				if err != nil {
					t.Fatalf("prepareDownloadFile(%s): %v", tc.name, err)
				}
				defer func() {
					if closeErr := dstFile.Close(); closeErr != nil {
						t.Errorf("close dstFile: %v", closeErr)
					}
				}()
				if offset != tc.wantOffset {
					t.Fatalf("offset = %d, want %d", offset, tc.wantOffset)
				}
				if openedInfo == nil {
					t.Fatal("prepareDownloadFile returned nil openedInfo")
				}
				diskInfo, err := os.Lstat(tempPath)
				if err != nil {
					t.Fatalf("Lstat(%q): %v", tempPath, err)
				}
				if !os.SameFile(openedInfo, diskInfo) {
					t.Fatal("returned openedInfo does not match staged file identity via os.SameFile")
				}
			})
		}
	})

	t.Run("canceled_context_returns_nil_handle", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		defer cancel()
		dir := t.TempDir()
		tempPath := filepath.Join(dir, "canceled"+client.config.TempSuffix)
		_, dstFile, openedInfo, err := client.prepareDownloadFile(ctx, tempPath, int64(len(payload)), 0o600, srcFile)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("prepareDownloadFile(expired ctx) = %v, want DeadlineExceeded", err)
		}
		if dstFile != nil || openedInfo != nil {
			t.Fatalf("expected nil handle and info on canceled context, got (%v, %v)", dstFile, openedInfo)
		}
	})
}
