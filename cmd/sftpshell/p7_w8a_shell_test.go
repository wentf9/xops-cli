package sftpshell

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/sftp"
)

type w8aShellTrackingHandler struct {
	mu           sync.Mutex
	stats        map[string]os.FileInfo
	lstats       map[string]os.FileInfo
	dirLists     map[string][]os.FileInfo
	files        map[string][]byte
	readLinks    map[string]string
	listCalls    map[string]int
	maxListCalls int
}

func newW8aShellTrackingHandler() *w8aShellTrackingHandler {
	return &w8aShellTrackingHandler{
		stats:        make(map[string]os.FileInfo),
		lstats:       make(map[string]os.FileInfo),
		dirLists:     make(map[string][]os.FileInfo),
		files:        make(map[string][]byte),
		readLinks:    make(map[string]string),
		listCalls:    make(map[string]int),
		maxListCalls: 5,
	}
}

func (h *w8aShellTrackingHandler) Fileread(r *pkgsftp.Request) (io.ReaderAt, error) {
	h.mu.Lock()
	data, ok := h.files[r.Filepath]
	h.mu.Unlock()
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.NewReader(data), nil
}

func (h *w8aShellTrackingHandler) Filewrite(*pkgsftp.Request) (io.WriterAt, error) {
	return nil, os.ErrPermission
}

func (h *w8aShellTrackingHandler) Filecmd(*pkgsftp.Request) error {
	return os.ErrPermission
}

func (h *w8aShellTrackingHandler) Filelist(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch r.Method {
	case "Stat":
		if fi, ok := h.stats[r.Filepath]; ok {
			return p7ReproListerAt{fi}, nil
		}
		if fi, ok := h.lstats[r.Filepath]; ok {
			return p7ReproListerAt{fi}, nil
		}
		return nil, os.ErrNotExist
	case "List":
		h.listCalls[r.Filepath]++
		if h.maxListCalls > 0 && h.listCalls[r.Filepath] > h.maxListCalls {
			return nil, errors.New("test circuit breaker: excessive ReadDir recursion")
		}
		if entries, ok := h.dirLists[r.Filepath]; ok {
			return p7ReproListerAt(entries), nil
		}
		return nil, os.ErrNotExist
	default:
		return nil, os.ErrInvalid
	}
}

func (h *w8aShellTrackingHandler) Lstat(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if fi, ok := h.lstats[r.Filepath]; ok {
		return p7ReproListerAt{fi}, nil
	}
	if fi, ok := h.stats[r.Filepath]; ok {
		return p7ReproListerAt{fi}, nil
	}
	return nil, os.ErrNotExist
}

func (h *w8aShellTrackingHandler) Readlink(p string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if target, ok := h.readLinks[p]; ok {
		return target, nil
	}
	return "", os.ErrNotExist
}

func (h *w8aShellTrackingHandler) handlers() pkgsftp.Handlers {
	return pkgsftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	}
}

type failingWriter struct {
	err error
}

func (w failingWriter) Write([]byte) (int, error) {
	return 0, w.err
}

// TestP7W8a_AB8M1_GetPrepareHooksRejectsHostileReadDirEntries verifies AB8-M1
// in cmd/sftpshell: prepareDownloadTransferHooks no longer uses kr/fs
// client.Walk and fails closed via ParseRemoteName-validated ReadDir before
// downloadDirectory starts, preventing infinite loops on "x/." or "/" and
// parent traversal on "x/..".
func TestP7W8a_AB8M1_GetPrepareHooksRejectsHostileReadDirEntries(t *testing.T) {
	cases := []struct {
		name       string
		entries    []os.FileInfo
		wantErrIs  error
		wantSubstr string
	}{
		{
			name: "slash_dotdot",
			entries: []os.FileInfo{
				p7ReproFileInfo{name: "good.txt", size: 2, mode: 0o644},
				p7ReproFileInfo{name: "x/..", mode: os.ModeDir | 0o755},
			},
			wantErrIs: sftp.ErrInvalidRemoteName,
		},
		{
			name: "slash_dot",
			entries: []os.FileInfo{
				p7ReproFileInfo{name: "x/.", mode: os.ModeDir | 0o755},
			},
			wantErrIs: sftp.ErrInvalidRemoteName,
		},
		{
			name: "root_slash",
			entries: []os.FileInfo{
				p7ReproFileInfo{name: "/", mode: os.ModeDir | 0o755},
			},
			wantErrIs: sftp.ErrInvalidRemoteName,
		},
		{
			name: "control_char",
			entries: []os.FileInfo{
				p7ReproFileInfo{name: "bad\nentry", size: 2, mode: 0o644},
			},
			wantErrIs: sftp.ErrInvalidRemoteName,
		},
		{
			name: "duplicate_entries",
			entries: []os.FileInfo{
				p7ReproFileInfo{name: "dup.txt", size: 2, mode: 0o644},
				p7ReproFileInfo{name: "dup.txt", size: 2, mode: 0o644},
			},
			wantSubstr: "duplicate",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newW8aShellTrackingHandler()
			h.stats["/remote"] = p7ReproFileInfo{name: "remote", mode: os.ModeDir | 0o755}
			h.stats["/remote/dir"] = p7ReproFileInfo{name: "dir", mode: os.ModeDir | 0o755}
			h.dirLists["/remote"] = []os.FileInfo{
				p7ReproFileInfo{name: "secret.txt", size: 6, mode: 0o644},
				p7ReproFileInfo{name: "dir", mode: os.ModeDir | 0o755},
			}
			h.dirLists["/remote/dir"] = tc.entries
			h.files["/remote/dir/good.txt"] = []byte("ok")
			h.files["/remote/secret.txt"] = []byte("secret")

			localDst := t.TempDir()
			sh := newP7W7bShellWithHandlers(t, h.handlers(), "/remote", localDst)

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			exit, err := sh.dispatchCommand(ctx, "get", []string{"/remote/dir", localDst})
			if exit {
				t.Fatalf("dispatchCommand(get) unexpectedly signaled exit")
			}
			if err == nil {
				t.Fatalf("dispatchCommand(get /remote/dir) succeeded for hostile %s, want error", tc.name)
			}
			if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
				t.Fatalf("dispatchCommand(get %s) err = %v, want errors.Is(_, %v)", tc.name, err, tc.wantErrIs)
			}
			if tc.wantSubstr != "" && !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("dispatchCommand(get %s) err = %v, want substring %q", tc.name, err, tc.wantSubstr)
			}
			if dispErr := sh.takeDisplayError(); dispErr != nil {
				t.Fatalf("unexpected display error on rejected hostile get: %v", dispErr)
			}

			h.mu.Lock()
			dirLists := h.listCalls["/remote/dir"]
			parentLists := h.listCalls["/remote"]
			h.mu.Unlock()
			if dirLists != 1 {
				t.Fatalf("hostile %s listed /remote/dir %d times, want 1", tc.name, dirLists)
			}
			if parentLists != 0 {
				t.Fatalf("hostile %s escaped into parent /remote (%d list calls), want 0", tc.name, parentLists)
			}

			localEntries, readErr := os.ReadDir(localDst)
			if readErr != nil || len(localEntries) != 0 {
				t.Fatalf("localDst must remain empty after hostile get rejection: entries=%d err=%v", len(localEntries), readErr)
			}
		})
	}
}

// TestP7W8a_AB8M2_PutSingleSymlinkFileAndDirNoProgressOverflow verifies AB8-M2
// for putSingle via Shell.dispatchCommand:
//   - Top-level symlink to a 100B file sizes via os.Stat (100B, not Lstat's 8B/0B)
//     and completes with zero display error (no "current number exceeds max").
//   - Directory upload (direct and via top-level dir symlink) sizes child symlinks
//     via os.Readlink + filepath.ToSlash matching uploadLink and completes with
//     zero display error.
func TestP7W8a_AB8M2_PutSingleSymlinkFileAndDirNoProgressOverflow(t *testing.T) {
	requireShellSymlinkSupport(t)
	t.Run("top_level_file_symlink_100B_no_overflow", testP7W8aPutTopLevelFileSymlinkNoOverflow)
	t.Run("directory_with_child_symlinks_exact_readlink_sizing", testP7W8aPutDirWithChildSymlinksSizing)
}

func testP7W8aPutTopLevelFileSymlinkNoOverflow(t *testing.T) {
	base := t.TempDir()
	payload := bytes.Repeat([]byte("A"), 100)
	realFile := filepath.Join(base, "real.txt")
	writeTestFile(t, realFile, payload)

	fileLink := filepath.Join(base, "file_link")
	if err := os.Symlink("real.txt", fileLink); err != nil {
		t.Fatal(err)
	}

	sh := newP7W7bInMemShell(t, "/remote", base)
	raw := sh.client.SFTPClient()
	if err := raw.MkdirAll("/remote"); err != nil {
		t.Fatal(err)
	}

	exit, err := sh.dispatchCommand(t.Context(), "put", []string{"file_link", "/remote/uploaded.txt"})
	if exit || err != nil {
		t.Fatalf("dispatchCommand(put file_link) = (exit=%v, err=%v), want (false, nil)", exit, err)
	}
	if dispErr := sh.takeDisplayError(); dispErr != nil {
		t.Fatalf("takeDisplayError() = %v, want nil", dispErr)
	}

	f, openErr := raw.Open("/remote/uploaded.txt")
	if openErr != nil {
		t.Fatalf("open uploaded remote file: %v", openErr)
	}
	got, readErr := io.ReadAll(f)
	_ = f.Close()
	if readErr != nil || !bytes.Equal(got, payload) {
		t.Fatalf("uploaded payload len=%d err=%v, want 100 matching bytes", len(got), readErr)
	}
}

func testP7W8aPutDirWithChildSymlinksSizing(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "real_dir")
	if err := os.MkdirAll(filepath.Join(realDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(realDir, "a.txt"), bytes.Repeat([]byte("X"), 50))
	writeTestFile(t, filepath.Join(realDir, "sub", "b.txt"), bytes.Repeat([]byte("Y"), 30))

	childTarget1 := "a.txt"
	childTarget2 := "../a.txt"
	longTarget := "sub/" + strings.Repeat("segment_", 12) + "missing.txt"
	for pathToLink, target := range map[string]string{
		filepath.Join(realDir, "link_a"):         childTarget1,
		filepath.Join(realDir, "sub", "link_up"): childTarget2,
		filepath.Join(realDir, "long_link"):      longTarget,
	} {
		if err := os.Symlink(target, pathToLink); err != nil {
			t.Fatal(err)
		}
	}

	linkDir := filepath.Join(base, "link_dir")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}

	sh := newP7W7bInMemShell(t, "/remote", base)
	raw := sh.client.SFTPClient()
	if err := raw.MkdirAll("/remote"); err != nil {
		t.Fatal(err)
	}

	wantSize := int64(50 + 30 + len(childTarget1) + len(childTarget2) + len(longTarget))
	gotSize, sizeErr := sh.computeLocalUploadDirSize(linkDir)
	if sizeErr != nil {
		t.Fatalf("computeLocalUploadDirSize(%q): %v", linkDir, sizeErr)
	}
	if gotSize != wantSize {
		t.Fatalf("computeLocalUploadDirSize(%q) = %d, want %d", linkDir, gotSize, wantSize)
	}

	exit, err := sh.dispatchCommand(t.Context(), "put", []string{"link_dir", "/remote"})
	if exit || err != nil {
		t.Fatalf("dispatchCommand(put link_dir) = (exit=%v, err=%v), want (false, nil)", exit, err)
	}
	if dispErr := sh.takeDisplayError(); dispErr != nil {
		t.Fatalf("takeDisplayError() = %v, want nil", dispErr)
	}

	for rel, wantTarget := range map[string]string{
		"link_a":      childTarget1,
		"sub/link_up": childTarget2,
		"long_link":   longTarget,
	} {
		gotTarget, rlErr := raw.ReadLink("/remote/link_dir/" + rel)
		if rlErr != nil || gotTarget != wantTarget {
			t.Fatalf("remote symlink %s = (%q, %v), want %q", rel, gotTarget, rlErr, wantTarget)
		}
	}
}

// TestP7W8a_AB8M2_GetRemoteSymlinkDirAndChildSymlinksNoProgressOverflow verifies
// AB8-M2 for prepareDownloadTransferHooks and progressbar clamping via
// Shell.dispatchCommand:
//   - Remote top-level symlink-to-directory dereferences via Stat and sizes full
//     directory contents without progress overflow.
//   - Remote directory with child symlinks whose Lstat.Size()==0 (InMemHandler /
//     Windows OpenSSH SFTP) counts int64(len(ReadLink(child))) without overflow.
//   - Progress bar clamping guards against unexpected file growth / concurrent
//     overshoot while preserving genuine display write errors.
func TestP7W8a_AB8M2_GetRemoteSymlinkDirAndChildSymlinksNoProgressOverflow(t *testing.T) {
	t.Run("top_level_remote_symlink_dir_and_file_no_overflow", testP7W8aGetTopLevelRemoteSymlinksNoOverflow)
	t.Run("inmem_child_symlinks_zero_lstat_size_no_overflow", testP7W8aGetInMemChildSymlinksNoOverflow)
	t.Run("clamped_progress_callback_concurrent_overshoot_and_io_error", testP7W8aClampedProgressCallback)
}

func testP7W8aGetTopLevelRemoteSymlinksNoOverflow(t *testing.T) {
	payload := bytes.Repeat([]byte("D"), 128)
	h := newW8aShellTrackingHandler()
	// Top-level symlink /remote/link_dir -> /remote/real_dir:
	// Lstat reports symlink (size 16), Stat follows to ModeDir.
	h.lstats["/remote/link_dir"] = p7ReproFileInfo{name: "link_dir", size: 16, mode: os.ModeSymlink | 0o777}
	h.stats["/remote/link_dir"] = p7ReproFileInfo{name: "link_dir", mode: os.ModeDir | 0o755}
	h.readLinks["/remote/link_dir"] = "/remote/real_dir"
	h.dirLists["/remote/link_dir"] = []os.FileInfo{
		p7ReproFileInfo{name: "payload.bin", size: int64(len(payload)), mode: 0o644},
	}
	h.stats["/remote/link_dir/payload.bin"] = p7ReproFileInfo{name: "payload.bin", size: int64(len(payload)), mode: 0o644}
	h.files["/remote/link_dir/payload.bin"] = payload

	// Top-level symlink /remote/file_link -> /remote/real.bin (128B, Lstat size 8B).
	h.lstats["/remote/file_link"] = p7ReproFileInfo{name: "file_link", size: 8, mode: os.ModeSymlink | 0o777}
	h.stats["/remote/file_link"] = p7ReproFileInfo{name: "file_link", size: int64(len(payload)), mode: 0o644}
	h.files["/remote/file_link"] = payload

	localDst := t.TempDir()
	sh := newP7W7bShellWithHandlers(t, h.handlers(), "/remote", localDst)

	exit, err := sh.dispatchCommand(t.Context(), "get", []string{"/remote/link_dir", localDst})
	if exit || err != nil {
		t.Fatalf("dispatchCommand(get /remote/link_dir) = (exit=%v, err=%v), want (false, nil)", exit, err)
	}
	if dispErr := sh.takeDisplayError(); dispErr != nil {
		t.Fatalf("takeDisplayError() after get /remote/link_dir = %v, want nil", dispErr)
	}
	if got := readTestFile(t, filepath.Join(localDst, "link_dir", "payload.bin")); !bytes.Equal(got, payload) {
		t.Fatalf("downloaded payload len=%d, want %d", len(got), len(payload))
	}

	exit, err = sh.dispatchCommand(t.Context(), "get", []string{"/remote/file_link", localDst})
	if exit || err != nil {
		t.Fatalf("dispatchCommand(get /remote/file_link) = (exit=%v, err=%v), want (false, nil)", exit, err)
	}
	if dispErr := sh.takeDisplayError(); dispErr != nil {
		t.Fatalf("takeDisplayError() after get /remote/file_link = %v, want nil", dispErr)
	}
	if gotFile := readTestFile(t, filepath.Join(localDst, "file_link")); !bytes.Equal(gotFile, payload) {
		t.Fatalf("downloaded file_link len=%d, want %d", len(gotFile), len(payload))
	}
}

func testP7W8aGetInMemChildSymlinksNoOverflow(t *testing.T) {
	requireShellSymlinkSupport(t)
	localDst := t.TempDir()
	sh := newP7W7bInMemShell(t, "/remote", localDst)
	raw := sh.client.SFTPClient()

	if err := raw.MkdirAll("/remote/dir/sub"); err != nil {
		t.Fatal(err)
	}
	f, err := raw.Create("/remote/dir/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	// InMemHandler reports Lstat.Size() == 0 for symlinks, while
	// createDownloadLink emits progress(int64(len(target))).
	if err := raw.Symlink("a.txt", "/remote/dir/link_a"); err != nil {
		t.Fatal(err)
	}
	if err := raw.Symlink("../a.txt", "/remote/dir/sub/link_up"); err != nil {
		t.Fatal(err)
	}

	exit, err := sh.dispatchCommand(t.Context(), "get", []string{"/remote/dir", localDst})
	if exit || err != nil {
		t.Fatalf("dispatchCommand(get /remote/dir) = (exit=%v, err=%v), want (false, nil)", exit, err)
	}
	if dispErr := sh.takeDisplayError(); dispErr != nil {
		t.Fatalf("takeDisplayError() = %v, want nil", dispErr)
	}

	if got := string(readTestFile(t, filepath.Join(localDst, "dir", "a.txt"))); got != "0123456789" {
		t.Fatalf("downloaded a.txt = %q, want %q", got, "0123456789")
	}
	if got, err := os.Readlink(filepath.Join(localDst, "dir", "link_a")); err != nil || filepath.ToSlash(got) != "a.txt" {
		t.Fatalf("downloaded link_a = (%q, %v), want %q", got, err, "a.txt")
	}
	if got, err := os.Readlink(filepath.Join(localDst, "dir", "sub", "link_up")); err != nil || filepath.ToSlash(got) != "../a.txt" {
		t.Fatalf("downloaded sub/link_up = (%q, %v), want %q", got, err, "../a.txt")
	}
}

func testP7W8aClampedProgressCallback(t *testing.T) {
	sh := &Shell{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	bar, _ := sh.newTransferProgressBar("Total", 10, true)
	cb := sh.newClampedProgressCallback(bar, 10, "update download progress failed")

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				cb(7)
			}
		}()
	}
	wg.Wait()

	if err := bar.Finish(); err != nil {
		t.Fatalf("bar.Finish() after clamped overshoot: %v", err)
	}
	if dispErr := sh.takeDisplayError(); dispErr != nil {
		t.Fatalf("clamped progress callback recorded display error on overshoot: %v", dispErr)
	}
	if state := bar.State(); state.CurrentNum != 10 {
		t.Fatalf("bar.State().CurrentNum = %d, want 10", state.CurrentNum)
	}

	// Real output writer errors must still surface via recordDisplayError.
	ioErr := errors.New("broken stdout pipe")
	shFail := &Shell{stdout: failingWriter{err: ioErr}, stderr: &bytes.Buffer{}}
	barFail, _ := shFail.newTransferProgressBar("Downloading", 10, false)
	cbFail := shFail.newClampedProgressCallback(barFail, 10, "update download progress failed")
	cbFail(5)
	if got := shFail.takeDisplayError(); !errors.Is(got, ioErr) {
		t.Fatalf("real stdout write error was not recorded: got %v, want %v", got, ioErr)
	}
}

// TestP7W8a_AB8L1_PutSingleRejectsIrregularWalkRootBeforeRemoteMkdir verifies
// AB8-L1 in cmd/sftpshell: putSingle resolves the directory upload root via
// sftp.ResolveLocalUploadRootDir (re-checking os.Lstat after EvalSymlinks) and
// fails closed before creating any remote directory.
func TestP7W8a_AB8L1_PutSingleRejectsIrregularWalkRootBeforeRemoteMkdir(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "junction_like")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(realDir, "a.txt"), []byte("payload"))

	sh := newP7W7bInMemShell(t, "/remote", base)
	raw := sh.client.SFTPClient()
	if err := raw.MkdirAll("/remote"); err != nil {
		t.Fatal(err)
	}
	sh.resolveLocalUploadRootFn = func(dir string) (string, error) {
		return "", errors.New("resolved local upload root " + dir + " is not a directory (mode Lrwxrwxrwx)")
	}

	exit, err := sh.dispatchCommand(t.Context(), "put", []string{"junction_like", "/remote/should_not_exist"})
	if exit {
		t.Fatal("dispatchCommand(put) unexpectedly signaled exit")
	}
	if err == nil || !strings.Contains(err.Error(), "is not a directory") {
		t.Fatalf("dispatchCommand(put junction_like) err = %v, want not-a-directory error", err)
	}
	if dispErr := sh.takeDisplayError(); dispErr != nil {
		t.Fatalf("takeDisplayError() = %v, want nil", dispErr)
	}
	if _, lstatErr := raw.Lstat("/remote/should_not_exist"); !errors.Is(lstatErr, os.ErrNotExist) {
		t.Fatalf("putSingle created remote directory despite AB8-L1 rejection: Lstat err = %v", lstatErr)
	}
}

// TestP7W8a_AB8L2_SelfContainedSameFileAndAtomicCopyLocalLink verifies AB8-L2:
//   - checkLocalDirNotSelfContained walks existing ancestors of filepath.Abs(dst)
//     checking os.SameFile(srcInfo, ancestorInfo), catching case-insensitive
//     APFS aliases, Windows NTFS junctions, and Linux bind mounts even when
//     canonicalLocalPath / filepath.Rel sees distinct lexical paths.
//   - copyLocalLink rejects pre-existing directories (empty and non-empty) and
//     stages a temporary symlink in filepath.Dir(dst) promoted via atomic
//     ReplaceLocalLink so dst is never unlinked if os.Symlink or rename fails.
func TestP7W8a_AB8L2_SelfContainedSameFileAndAtomicCopyLocalLink(t *testing.T) {
	initTestI18n(t)
	t.Run("samefile_ancestor_walk_catches_case_junction_and_bind_aliases", testP7W8aSelfContainedSameFileWalk)
	t.Run("copyLocalLink_rejects_directories", testP7W8aCopyLocalLinkRejectsDirectories)
	t.Run("copyLocalLink_preserves_dst_on_failure_and_replaces_atomically", testP7W8aCopyLocalLinkAtomicReplace)
}

func testP7W8aSelfContainedSameFileWalk(t *testing.T) {
	base := t.TempDir()
	srcDir := filepath.Join(base, "dir")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	srcInfo, err := os.Stat(srcDir)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate aliases that canonicalLocalPath leaves lexically distinct
	// (macOS APFS case-insensitive "DIR", Windows NTFS junction "junc",
	// Linux bind mount "bind"), while os.Stat + os.SameFile recognizes
	// them as the exact same directory inode/file ID.
	aliases := []string{
		filepath.Join(base, "DIR"),
		filepath.Join(base, "junc"),
		filepath.Join(base, "bind"),
	}
	aliasSet := make(map[string]bool, len(aliases))
	for _, a := range aliases {
		aliasSet[filepath.Clean(a)] = true
	}

	canonicalNoDeref := func(p string) (string, error) {
		return filepath.Abs(p)
	}
	statAlias := func(p string) (os.FileInfo, error) {
		clean := filepath.Clean(p)
		if aliasSet[clean] {
			return srcInfo, nil
		}
		return os.Stat(clean)
	}

	for _, alias := range aliases {
		name := path.Base(filepath.ToSlash(alias))
		t.Run(name+"_into_itself", func(t *testing.T) {
			err := checkLocalDirNotSelfContainedWith(srcDir, alias, canonicalNoDeref, statAlias, os.SameFile)
			if err == nil || !strings.Contains(err.Error(), "into itself") {
				t.Fatalf("checkLocalDirNotSelfContainedWith(%q, %q) = %v, want into-itself error", srcDir, alias, err)
			}
		})
		t.Run(name+"_into_nested_subdir", func(t *testing.T) {
			dstSub := filepath.Join(alias, "sub", "deep")
			err := checkLocalDirNotSelfContainedWith(srcDir, dstSub, canonicalNoDeref, statAlias, os.SameFile)
			if err == nil || !strings.Contains(err.Error(), "inside source directory") {
				t.Fatalf("checkLocalDirNotSelfContainedWith(%q, %q) = %v, want inside-source error", srcDir, dstSub, err)
			}
		})
	}

	// Sibling directory sharing prefix must NOT trigger a false positive.
	sibling := filepath.Join(base, "dir2", "sub")
	if err := checkLocalDirNotSelfContainedWith(srcDir, sibling, canonicalNoDeref, statAlias, os.SameFile); err != nil {
		t.Fatalf("checkLocalDirNotSelfContainedWith sibling %q unexpectedly failed: %v", sibling, err)
	}

	// On native case-insensitive filesystems (macOS APFS, Windows NTFS),
	// also exercise real lcp -f dir DIR and lcp -f dir DIR/sub.
	upperPath := filepath.Join(base, "DIR")
	if upperInfo, statErr := os.Stat(upperPath); statErr == nil && os.SameFile(srcInfo, upperInfo) {
		sh := &Shell{localCwd: base, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, batch: true}
		if _, err := sh.dispatchCommand(t.Context(), "lcp", []string{"-f", "dir", "DIR"}); err == nil {
			t.Fatal("native case-insensitive lcp -f dir DIR succeeded, want self-containment error")
		}
		if _, err := sh.dispatchCommand(t.Context(), "lcp", []string{"-f", "dir", filepath.Join("DIR", "sub")}); err == nil {
			t.Fatal("native case-insensitive lcp -f dir DIR/sub succeeded, want self-containment error")
		}
	}
}

func testP7W8aCopyLocalLinkRejectsDirectories(t *testing.T) {
	requireShellSymlinkSupport(t)
	base := t.TempDir()

	srcLink := filepath.Join(base, "src_link")
	if err := os.Symlink("target.txt", srcLink); err != nil {
		t.Fatal(err)
	}

	// 1. Pre-existing empty directory at dst must be rejected and left intact.
	emptyDir := filepath.Join(base, "empty_dir")
	if err := os.Mkdir(emptyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyLocalLink(srcLink, emptyDir); err == nil || !strings.Contains(err.Error(), "cannot overwrite local destination directory") {
		t.Fatalf("copyLocalLink onto empty dir err = %v, want directory rejection", err)
	}
	if fi, err := os.Lstat(emptyDir); err != nil || fi.Mode()&os.ModeType != os.ModeDir {
		t.Fatalf("empty_dir must remain a directory after rejected copyLocalLink: fi=%v err=%v", fi, err)
	}

	// 2. Pre-existing non-empty directory at dst must be rejected and left intact.
	nonEmptyDir := filepath.Join(base, "non_empty_dir")
	if err := os.Mkdir(nonEmptyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(nonEmptyDir, "keep.txt"), []byte("keep"))
	if err := copyLocalLink(srcLink, nonEmptyDir); err == nil || !strings.Contains(err.Error(), "cannot overwrite local destination directory") {
		t.Fatalf("copyLocalLink onto non-empty dir err = %v, want directory rejection", err)
	}
	if got := string(readTestFile(t, filepath.Join(nonEmptyDir, "keep.txt"))); got != "keep" {
		t.Fatalf("non_empty_dir/keep.txt = %q, want %q", got, "keep")
	}

	// 3. Recursive lcp -f src_tree dst_tree places src_tree inside existing
	//    dst_tree/src_tree, where dst_tree/src_tree/entry is an existing dir
	//    and must not be overwritten by src_tree/entry symlink.
	srcTree := filepath.Join(base, "src_tree")
	dstTree := filepath.Join(base, "dst_tree")
	if err := os.MkdirAll(srcTree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dstTree, "src_tree", "entry"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.txt", filepath.Join(srcTree, "entry")); err != nil {
		t.Fatal(err)
	}
	shTree := &Shell{localCwd: base, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, batch: true}
	if _, err := shTree.dispatchCommand(t.Context(), "lcp", []string{"-f", "src_tree", "dst_tree"}); err == nil {
		t.Fatal("dispatchCommand(lcp -f src_tree dst_tree) succeeded when symlink collided with existing directory, want error")
	}
	if dispErr := shTree.takeDisplayError(); dispErr != nil {
		t.Fatalf("takeDisplayError() = %v, want nil", dispErr)
	}
}

func assertNoLeftoverLinkTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".xops-lcp-link-") {
			t.Fatalf("leftover staged temp symlink in %q: %q", dir, e.Name())
		}
	}
}

func testP7W8aCopyLocalLinkAtomicReplace(t *testing.T) {
	requireShellSymlinkSupport(t)
	base := t.TempDir()
	srcLink := filepath.Join(base, "src_link")
	if err := os.Symlink("target.txt", srcLink); err != nil {
		t.Fatal(err)
	}

	workDir := filepath.Join(base, "preserve_on_fail")
	if err := os.Mkdir(workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	existingFile := filepath.Join(workDir, "existing_file")
	writeTestFile(t, existingFile, []byte("precious-data"))
	existingLink := filepath.Join(workDir, "existing_link")
	if err := os.Symlink("original_target", existingLink); err != nil {
		t.Fatal(err)
	}

	// 1. When os.Symlink fails, pre-existing regular file and symlink at dst
	//    must NEVER be unlinked.
	symlinkErr := errors.New("injected symlink permission denied")
	err := copyLocalLinkWith(srcLink, existingFile, func(string, string) error {
		return symlinkErr
	}, sftp.ReplaceLocalLink)
	if !errors.Is(err, symlinkErr) {
		t.Fatalf("copyLocalLinkWith symlink failure err = %v, want %v", err, symlinkErr)
	}
	if got := string(readTestFile(t, existingFile)); got != "precious-data" {
		t.Fatalf("existing_file lost after os.Symlink failure: got %q", got)
	}

	err = copyLocalLinkWith(srcLink, existingLink, func(string, string) error {
		return symlinkErr
	}, sftp.ReplaceLocalLink)
	if !errors.Is(err, symlinkErr) {
		t.Fatalf("copyLocalLinkWith symlink failure on link err = %v, want %v", err, symlinkErr)
	}
	if got, rlErr := os.Readlink(existingLink); rlErr != nil || got != "original_target" {
		t.Fatalf("existing_link lost after os.Symlink failure: (%q, %v)", got, rlErr)
	}

	// 2. When promotion (ReplaceLocalLink) fails, dst stays intact and the
	//    staged temporary symlink is cleaned up.
	replaceErr := errors.New("injected rename failure")
	err = copyLocalLinkWith(srcLink, existingFile, os.Symlink, func(string, string) error {
		return replaceErr
	})
	if !errors.Is(err, replaceErr) {
		t.Fatalf("copyLocalLinkWith replace failure err = %v, want %v", err, replaceErr)
	}
	if got := string(readTestFile(t, existingFile)); got != "precious-data" {
		t.Fatalf("existing_file lost after replace failure: got %q", got)
	}
	assertNoLeftoverLinkTempFiles(t, workDir)

	// 3. End-to-end atomic replacement via Shell.dispatchCommand("lcp", ...).
	sh := &Shell{localCwd: workDir, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, batch: true}
	exit, err := sh.dispatchCommand(t.Context(), "lcp", []string{"-f", srcLink, existingFile})
	if exit || err != nil {
		t.Fatalf("dispatchCommand(lcp -f src_link existing_file) = (exit=%v, err=%v), want (false, nil)", exit, err)
	}
	if dispErr := sh.takeDisplayError(); dispErr != nil {
		t.Fatalf("takeDisplayError() = %v, want nil", dispErr)
	}
	if got, rlErr := os.Readlink(existingFile); rlErr != nil || got != "target.txt" {
		t.Fatalf("replaced existing_file symlink = (%q, %v), want %q", got, rlErr, "target.txt")
	}
	assertNoLeftoverLinkTempFiles(t, workDir)
}
