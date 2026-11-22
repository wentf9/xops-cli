package sftp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
)

type w8aHostileTrackingHandler struct {
	mu           sync.Mutex
	stats        map[string]os.FileInfo
	lstats       map[string]os.FileInfo
	dirLists     map[string][]os.FileInfo
	files        map[string][]byte
	readLinks    map[string]string
	listCalls    map[string]int
	removeCalls  []string
	rmdirCalls   []string
	mkdirCalls   []string
	writeCalls   []string
	maxListCalls int
}

func newW8aHostileTrackingHandler() *w8aHostileTrackingHandler {
	return &w8aHostileTrackingHandler{
		stats:        make(map[string]os.FileInfo),
		lstats:       make(map[string]os.FileInfo),
		dirLists:     make(map[string][]os.FileInfo),
		files:        make(map[string][]byte),
		readLinks:    make(map[string]string),
		listCalls:    make(map[string]int),
		maxListCalls: 5,
	}
}

func (h *w8aHostileTrackingHandler) Fileread(r *pkgsftp.Request) (io.ReaderAt, error) {
	h.mu.Lock()
	data, ok := h.files[r.Filepath]
	h.mu.Unlock()
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.NewReader(data), nil
}

func (h *w8aHostileTrackingHandler) Filewrite(r *pkgsftp.Request) (io.WriterAt, error) {
	h.mu.Lock()
	h.writeCalls = append(h.writeCalls, r.Filepath)
	h.mu.Unlock()
	return nil, os.ErrPermission
}

func (h *w8aHostileTrackingHandler) OpenFile(r *pkgsftp.Request) (pkgsftp.WriterAtReaderAt, error) {
	h.mu.Lock()
	h.writeCalls = append(h.writeCalls, r.Filepath)
	h.mu.Unlock()
	return nil, os.ErrPermission
}

func (h *w8aHostileTrackingHandler) Filecmd(r *pkgsftp.Request) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch r.Method {
	case "Remove":
		h.removeCalls = append(h.removeCalls, r.Filepath)
		return nil
	case "Rmdir":
		h.rmdirCalls = append(h.rmdirCalls, r.Filepath)
		return nil
	case "Mkdir":
		h.mkdirCalls = append(h.mkdirCalls, r.Filepath)
		return nil
	default:
		return os.ErrPermission
	}
}

func (h *w8aHostileTrackingHandler) Filelist(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch r.Method {
	case "Stat":
		if fi, ok := h.stats[r.Filepath]; ok {
			return customListerAt{fi}, nil
		}
		if fi, ok := h.lstats[r.Filepath]; ok {
			return customListerAt{fi}, nil
		}
		return nil, os.ErrNotExist
	case "List":
		h.listCalls[r.Filepath]++
		if h.maxListCalls > 0 && h.listCalls[r.Filepath] > h.maxListCalls {
			return nil, errors.New("test circuit breaker: excessive ReadDir recursion")
		}
		if entries, ok := h.dirLists[r.Filepath]; ok {
			return customListerAt(entries), nil
		}
		return nil, os.ErrNotExist
	default:
		return nil, os.ErrInvalid
	}
}

func (h *w8aHostileTrackingHandler) Lstat(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if fi, ok := h.lstats[r.Filepath]; ok {
		return customListerAt{fi}, nil
	}
	if fi, ok := h.stats[r.Filepath]; ok {
		return customListerAt{fi}, nil
	}
	return nil, os.ErrNotExist
}

func (h *w8aHostileTrackingHandler) Readlink(p string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if target, ok := h.readLinks[p]; ok {
		return target, nil
	}
	return "", os.ErrNotExist
}

func (h *w8aHostileTrackingHandler) handlers() pkgsftp.Handlers {
	return pkgsftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	}
}

// TestP7W8a_AB8M1_RemoveAllRejectsHostileReadDirEntries verifies AB8-M1:
// RemoveAll validates every ReadDir entry through ParseRemoteName, rejects
// duplicates, and enforces strict parent/root containment before deleting any
// entry, preventing parent escape ("x/..") and infinite recursion ("x/.", "/").
func TestP7W8a_AB8M1_RemoveAllRejectsHostileReadDirEntries(t *testing.T) {
	cases := []struct {
		name       string
		entries    []os.FileInfo
		wantErrIs  error
		wantSubstr string
	}{
		{
			name: "slash_dotdot_escapes_parent",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "good.txt", size: 4, mode: 0o644},
				syntheticFileInfo{name: "x/..", mode: os.ModeDir | 0o755},
			},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "nested_dotdot_escapes_parent",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "a/b/..", mode: os.ModeDir | 0o755},
			},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "slash_dot_infinite_recursion",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "good.txt", size: 4, mode: 0o644},
				syntheticFileInfo{name: "x/.", mode: os.ModeDir | 0o755},
			},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "root_slash_infinite_recursion",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "/", mode: os.ModeDir | 0o755},
			},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "control_char_entry",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "evil\nname", size: 2, mode: 0o644},
			},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "duplicate_entries",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "good.txt", size: 4, mode: 0o644},
				syntheticFileInfo{name: "good.txt", size: 4, mode: 0o644},
			},
			wantSubstr: "duplicate",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newW8aHostileTrackingHandler()
			h.lstats["/root"] = syntheticFileInfo{name: "root", mode: os.ModeDir | 0o755}
			h.lstats["/root/sibling.txt"] = syntheticFileInfo{name: "sibling.txt", size: 7, mode: 0o644}
			h.lstats["/root/victim"] = syntheticFileInfo{name: "victim", mode: os.ModeDir | 0o755}
			h.lstats["/root/victim/good.txt"] = syntheticFileInfo{name: "good.txt", size: 4, mode: 0o644}
			h.dirLists["/root"] = []os.FileInfo{
				syntheticFileInfo{name: "sibling.txt", size: 7, mode: 0o644},
				syntheticFileInfo{name: "victim", mode: os.ModeDir | 0o755},
			}
			h.dirLists["/root/victim"] = tc.entries

			client := newTestSFTPClientWithHandlers(t, h.handlers())
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			err := client.RemoveAll(ctx, "/root/victim")
			if err == nil {
				t.Fatalf("RemoveAll(/root/victim) succeeded for %s, want fail-closed error", tc.name)
			}
			if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
				t.Fatalf("RemoveAll(%s) err = %v, want errors.Is(_, %v)", tc.name, err, tc.wantErrIs)
			}
			if tc.wantSubstr != "" && !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("RemoveAll(%s) err = %v, want substring %q", tc.name, err, tc.wantSubstr)
			}

			h.mu.Lock()
			defer h.mu.Unlock()
			if len(h.removeCalls) != 0 {
				t.Fatalf("RemoveAll(%s) issued Remove calls despite hostile ReadDir: %v", tc.name, h.removeCalls)
			}
			if len(h.rmdirCalls) != 0 {
				t.Fatalf("RemoveAll(%s) issued Rmdir calls despite hostile ReadDir: %v", tc.name, h.rmdirCalls)
			}
			if got := h.listCalls["/root/victim"]; got != 1 {
				t.Fatalf("RemoveAll(%s) listed /root/victim %d times, want 1", tc.name, got)
			}
			if got := h.listCalls["/root"]; got != 0 {
				t.Fatalf("RemoveAll(%s) escaped into parent /root (%d list calls), want 0", tc.name, got)
			}
		})
	}
}

// TestP7W8a_AB8M1_RemoteCopyRejectsHostileReadDirEntries verifies AB8-M1:
// RemoteCopy validates every ReadDir entry through ParseRemoteName, rejects
// duplicates, and enforces strict parent containment before creating any
// destination directory or copying any sibling/child file.
func TestP7W8a_AB8M1_RemoteCopyRejectsHostileReadDirEntries(t *testing.T) {
	cases := []struct {
		name       string
		entries    []os.FileInfo
		wantErrIs  error
		wantSubstr string
	}{
		{
			name: "slash_dotdot_escapes_dst",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "good.txt", size: 4, mode: 0o644},
				syntheticFileInfo{name: "x/..", mode: os.ModeDir | 0o755},
			},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "slash_dot_infinite_recursion",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "x/.", mode: os.ModeDir | 0o755},
			},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "root_slash_infinite_recursion",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "/", mode: os.ModeDir | 0o755},
			},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "control_char_entry",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "bad\rfile", size: 2, mode: 0o644},
			},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "duplicate_entries",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "a.txt", size: 2, mode: 0o644},
				syntheticFileInfo{name: "a.txt", size: 2, mode: 0o644},
			},
			wantSubstr: "duplicate",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newW8aHostileTrackingHandler()
			h.lstats["/"] = syntheticFileInfo{name: "/", mode: os.ModeDir | 0o755}
			h.lstats["/src"] = syntheticFileInfo{name: "src", mode: os.ModeDir | 0o755}
			h.lstats["/src/good.txt"] = syntheticFileInfo{name: "good.txt", size: 4, mode: 0o644}
			h.lstats["/dst_parent"] = syntheticFileInfo{name: "dst_parent", mode: os.ModeDir | 0o755}
			h.lstats["/dst_parent/keep.txt"] = syntheticFileInfo{name: "keep.txt", size: 4, mode: 0o644}
			h.dirLists["/src"] = tc.entries
			h.files["/src/good.txt"] = []byte("good")

			client := newTestSFTPClientWithHandlers(t, h.handlers())
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			err := client.RemoteCopy(ctx, "/src", "/dst_parent/dst")
			if err == nil {
				t.Fatalf("RemoteCopy(/src, /dst_parent/dst) succeeded for %s, want error", tc.name)
			}
			if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
				t.Fatalf("RemoteCopy(%s) err = %v, want errors.Is(_, %v)", tc.name, err, tc.wantErrIs)
			}
			if tc.wantSubstr != "" && !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("RemoteCopy(%s) err = %v, want substring %q", tc.name, err, tc.wantSubstr)
			}

			h.mu.Lock()
			defer h.mu.Unlock()
			if len(h.mkdirCalls) != 0 {
				t.Fatalf("RemoteCopy(%s) created destination directory despite hostile ReadDir: %v", tc.name, h.mkdirCalls)
			}
			if len(h.writeCalls) != 0 {
				t.Fatalf("RemoteCopy(%s) opened destination files despite hostile ReadDir: %v", tc.name, h.writeCalls)
			}
			if got := h.listCalls["/src"]; got != 1 {
				t.Fatalf("RemoteCopy(%s) listed /src %d times, want 1", tc.name, got)
			}
		})
	}
}

// TestP7W8a_AB8M1_AB8M2_WalkAndDownloadTransferSize verifies AB8-M1 & AB8-M2 in
// core/sftp:
//   - Walk and DownloadTransferSize reject hostile ReadDir entries ("x/..",
//     "x/.", "/", control chars, duplicates) without looping or escaping.
//   - Top-level remote symlink-to-directory and symlink-to-file are dereferenced
//     via Stat (matching downloadOne), while child symlinks are NEVER followed
//     and contribute int64(len(ReadLink(child))) even when Lstat.Size() == 0.
func TestP7W8a_AB8M1_AB8M2_WalkAndDownloadTransferSize(t *testing.T) {
	t.Run("hostile_readdir_rejected", testP7W8aWalkHostileReadDirRejected)
	t.Run("top_level_symlink_deref_and_child_symlink_readlink_sizing", testP7W8aWalkSymlinkDerefAndSizing)
	t.Run("unsupported_non_regular_child_rejected", testP7W8aWalkUnsupportedChildRejected)
}

func testP7W8aWalkHostileReadDirRejected(t *testing.T) {
	for _, tc := range []struct {
		name       string
		entries    []os.FileInfo
		wantErrIs  error
		wantSubstr string
	}{
		{
			name:      "slash_dotdot",
			entries:   []os.FileInfo{syntheticFileInfo{name: "x/..", mode: os.ModeDir | 0o755}},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name:      "slash_dot",
			entries:   []os.FileInfo{syntheticFileInfo{name: "x/.", mode: os.ModeDir | 0o755}},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name:      "root_slash",
			entries:   []os.FileInfo{syntheticFileInfo{name: "/", mode: os.ModeDir | 0o755}},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "duplicate",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "f.txt", size: 3, mode: 0o644},
				syntheticFileInfo{name: "f.txt", size: 3, mode: 0o644},
			},
			wantSubstr: "duplicate",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newW8aHostileTrackingHandler()
			h.stats["/remote"] = syntheticFileInfo{name: "remote", mode: os.ModeDir | 0o755}
			h.stats["/remote/dir"] = syntheticFileInfo{name: "dir", mode: os.ModeDir | 0o755}
			h.dirLists["/remote/dir"] = tc.entries

			client := newTestSFTPClientWithHandlers(t, h.handlers())
			root, err := ParseRemotePath("/remote/dir")
			if err != nil {
				t.Fatal(err)
			}

			walkErr := client.Walk(t.Context(), root, func(RemotePath, os.FileInfo) error { return nil })
			if walkErr == nil {
				t.Fatalf("Walk(%s) succeeded, want error", tc.name)
			}
			if tc.wantErrIs != nil && !errors.Is(walkErr, tc.wantErrIs) {
				t.Fatalf("Walk(%s) err = %v, want %v", tc.name, walkErr, tc.wantErrIs)
			}
			if tc.wantSubstr != "" && !strings.Contains(walkErr.Error(), tc.wantSubstr) {
				t.Fatalf("Walk(%s) err = %v, want substring %q", tc.name, walkErr, tc.wantSubstr)
			}

			size, sizeErr := client.DownloadTransferSize(t.Context(), root)
			if sizeErr == nil {
				t.Fatalf("DownloadTransferSize(%s) = %d, nil; want error", tc.name, size)
			}
			if tc.wantErrIs != nil && !errors.Is(sizeErr, tc.wantErrIs) {
				t.Fatalf("DownloadTransferSize(%s) err = %v, want %v", tc.name, sizeErr, tc.wantErrIs)
			}
			if tc.wantSubstr != "" && !strings.Contains(sizeErr.Error(), tc.wantSubstr) {
				t.Fatalf("DownloadTransferSize(%s) err = %v, want substring %q", tc.name, sizeErr, tc.wantSubstr)
			}

			h.mu.Lock()
			parentLists := h.listCalls["/remote"]
			h.mu.Unlock()
			if parentLists != 0 {
				t.Fatalf("hostile %s escaped into parent /remote (%d list calls)", tc.name, parentLists)
			}
		})
	}
}

func testP7W8aWalkSymlinkDerefAndSizing(t *testing.T) {
	h := newW8aHostileTrackingHandler()
	// Top-level symlink /remote/link_dir -> /remote/real_dir:
	// Lstat reports symlink (size 16), Stat follows to real_dir (ModeDir).
	h.lstats["/remote/link_dir"] = syntheticFileInfo{name: "link_dir", size: 16, mode: os.ModeSymlink | 0o777}
	h.stats["/remote/link_dir"] = syntheticFileInfo{name: "link_dir", mode: os.ModeDir | 0o755}
	h.readLinks["/remote/link_dir"] = "/remote/real_dir"

	// Top-level symlink to regular file: Lstat size 8, Stat size 100.
	h.lstats["/remote/file_link"] = syntheticFileInfo{name: "file_link", size: 8, mode: os.ModeSymlink | 0o777}
	h.stats["/remote/file_link"] = syntheticFileInfo{name: "file_link", size: 100, mode: 0o644}

	// Directory entries under /remote/link_dir:
	//   - data.bin: 100 bytes regular file
	//   - zero_size_link: symlink with Size()==0 (like InMemHandler & Windows OpenSSH) -> "data.bin" (8B)
	//   - dir_link: symlink to /outside (must NOT be followed into /outside's 9999B file!) -> "/outside" (8B)
	//   - sub/nested.txt: 25 bytes regular file
	//   - sub/up_link: symlink with Size()==0 -> "../data.bin" (11B)
	h.dirLists["/remote/link_dir"] = []os.FileInfo{
		syntheticFileInfo{name: "data.bin", size: 100, mode: 0o644},
		syntheticFileInfo{name: "zero_size_link", size: 0, mode: os.ModeSymlink | 0o777},
		syntheticFileInfo{name: "dir_link", size: 0, mode: os.ModeSymlink | 0o777},
		syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
	}
	h.dirLists["/remote/link_dir/sub"] = []os.FileInfo{
		syntheticFileInfo{name: "nested.txt", size: 25, mode: 0o644},
		syntheticFileInfo{name: "up_link", size: 0, mode: os.ModeSymlink | 0o777},
	}
	h.readLinks["/remote/link_dir/zero_size_link"] = "data.bin"
	h.readLinks["/remote/link_dir/dir_link"] = "/outside"
	h.readLinks["/remote/link_dir/sub/up_link"] = "../data.bin"

	// Trap /outside if a broken walker followed dir_link.
	h.stats["/remote/link_dir/dir_link"] = syntheticFileInfo{name: "dir_link", mode: os.ModeDir | 0o755}
	h.dirLists["/remote/link_dir/dir_link"] = []os.FileInfo{
		syntheticFileInfo{name: "secret.bin", size: 9999, mode: 0o644},
	}

	client := newTestSFTPClientWithHandlers(t, h.handlers())

	fileLinkRoot, _ := ParseRemotePath("/remote/file_link")
	fileSize, err := client.DownloadTransferSize(t.Context(), fileLinkRoot)
	if err != nil {
		t.Fatalf("DownloadTransferSize(/remote/file_link): %v", err)
	}
	if fileSize != 100 {
		t.Fatalf("DownloadTransferSize(/remote/file_link) = %d, want 100", fileSize)
	}

	dirLinkRoot, _ := ParseRemotePath("/remote/link_dir")
	var visited []string
	if err := client.Walk(t.Context(), dirLinkRoot, func(p RemotePath, _ os.FileInfo) error {
		visited = append(visited, p.String())
		return nil
	}); err != nil {
		t.Fatalf("Walk(/remote/link_dir): %v", err)
	}
	wantVisited := []string{
		"/remote/link_dir",
		"/remote/link_dir/data.bin",
		"/remote/link_dir/zero_size_link",
		"/remote/link_dir/dir_link",
		"/remote/link_dir/sub",
		"/remote/link_dir/sub/nested.txt",
		"/remote/link_dir/sub/up_link",
	}
	if !slices.Equal(visited, wantVisited) {
		t.Fatalf("Walk visited = %v, want %v", visited, wantVisited)
	}

	gotSize, err := client.DownloadTransferSize(t.Context(), dirLinkRoot)
	if err != nil {
		t.Fatalf("DownloadTransferSize(/remote/link_dir): %v", err)
	}
	wantSize := int64(100 + len("data.bin") + len("/outside") + 25 + len("../data.bin"))
	if gotSize != wantSize {
		t.Fatalf("DownloadTransferSize(/remote/link_dir) = %d, want %d", gotSize, wantSize)
	}

	h.mu.Lock()
	outsideLists := h.listCalls["/remote/link_dir/dir_link"]
	h.mu.Unlock()
	if outsideLists != 0 {
		t.Fatalf("Walk/DownloadTransferSize followed child symlink dir_link (%d list calls), want 0", outsideLists)
	}
}

func testP7W8aWalkUnsupportedChildRejected(t *testing.T) {
	h := newW8aHostileTrackingHandler()
	h.stats["/remote/fifo_dir"] = syntheticFileInfo{name: "fifo_dir", mode: os.ModeDir | 0o755}
	h.dirLists["/remote/fifo_dir"] = []os.FileInfo{
		syntheticFileInfo{name: "pipe", mode: os.ModeNamedPipe | 0o600},
	}
	client := newTestSFTPClientWithHandlers(t, h.handlers())
	root, _ := ParseRemotePath("/remote/fifo_dir")
	if _, err := client.DownloadTransferSize(t.Context(), root); err == nil || !strings.Contains(err.Error(), "unsupported non-regular") {
		t.Fatalf("DownloadTransferSize(fifo_dir) err = %v, want unsupported non-regular error", err)
	}
}

// TestP7W8a_AB8L1_ResolveLocalUploadRootDirRejectsIrregularWalkRoot verifies AB8-L1:
// when filepath.EvalSymlinks leaves a top-level os.ModeIrregular entry (such as
// a Windows Go 1.26 NTFS junction) unchanged while os.Stat reports IsDir()==true,
// ResolveLocalUploadRootDir re-checks os.Lstat(walkRoot) and fails closed BEFORE
// Upload/UploadDirectory creates any empty remote directory.
func TestP7W8a_AB8L1_ResolveLocalUploadRootDirRejectsIrregularWalkRoot(t *testing.T) {
	t.Run("simulated_windows_ntfs_junction_rejected_by_resolver", func(t *testing.T) {
		junctionPath := filepath.Join(t.TempDir(), "ntfs_junction")
		cases := []struct {
			name          string
			initialLstat  os.FileMode
			resolvedLstat os.FileMode
		}{
			{
				name:          "irregular_unchanged_after_evalsymlinks",
				initialLstat:  os.ModeIrregular | 0o755,
				resolvedLstat: os.ModeIrregular | 0o755,
			},
			{
				name:          "dir_plus_irregular_unchanged_after_evalsymlinks",
				initialLstat:  os.ModeDir | os.ModeIrregular | 0o755,
				resolvedLstat: os.ModeDir | os.ModeIrregular | 0o755,
			},
			{
				name:          "symlink_still_symlink_after_evalsymlinks",
				initialLstat:  os.ModeSymlink | 0o777,
				resolvedLstat: os.ModeSymlink | 0o777,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				var lstatCalls atomic.Int32
				lstatFn := func(p string) (os.FileInfo, error) {
					if lstatCalls.Add(1) == 1 {
						return syntheticFileInfo{name: path.Base(filepath.ToSlash(p)), mode: tc.initialLstat}, nil
					}
					return syntheticFileInfo{name: path.Base(filepath.ToSlash(p)), mode: tc.resolvedLstat}, nil
				}
				evalFn := func(p string) (string, error) {
					// Simulate Go 1.26 Windows EvalSymlinks returning junction unchanged.
					return p, nil
				}
				statFn := func(p string) (os.FileInfo, error) {
					// os.Stat follows the NTFS junction and reports IsDir()==true.
					return syntheticFileInfo{name: path.Base(filepath.ToSlash(p)), mode: os.ModeDir | 0o755}, nil
				}

				got, err := resolveLocalUploadRootDirWith(junctionPath, lstatFn, evalFn, statFn)
				if err == nil || !strings.Contains(err.Error(), "is not a directory") {
					t.Fatalf("resolveLocalUploadRootDirWith(%s) = (%q, %v), want not-a-directory error", tc.name, got, err)
				}
				if lstatCalls.Load() < 2 {
					t.Fatalf("expected post-EvalSymlinks os.Lstat re-check, got %d lstat calls", lstatCalls.Load())
				}
			})
		}
	})

	t.Run("upload_and_upload_directory_create_no_remote_dir_on_irregular_root", func(t *testing.T) {
		localDir := filepath.Join(t.TempDir(), "real_dir")
		if err := os.MkdirAll(localDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(localDir, "a.txt"), []byte("hello"), 0o600); err != nil {
			t.Fatal(err)
		}

		client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
		client.resolveUploadRoot = func(dir string) (string, error) {
			return resolveLocalUploadRootDirWith(
				dir,
				func(p string) (os.FileInfo, error) {
					return syntheticFileInfo{name: path.Base(filepath.ToSlash(p)), mode: os.ModeIrregular | 0o755}, nil
				},
				func(p string) (string, error) { return p, nil },
				func(p string) (os.FileInfo, error) {
					return syntheticFileInfo{name: path.Base(filepath.ToSlash(p)), mode: os.ModeDir | 0o755}, nil
				},
			)
		}

		if err := client.Upload(t.Context(), localDir, "/remote_upload_junction", nil); err == nil {
			t.Fatal("Upload with irregular resolved walkRoot succeeded, want error")
		}
		if _, err := client.SFTPClient().Lstat("/remote_upload_junction"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Upload created empty remote directory despite AB8-L1 rejection: Lstat err = %v", err)
		}

		if err := client.UploadDirectory(t.Context(), localDir, "/remote_dir_junction", nil); err == nil {
			t.Fatal("UploadDirectory with irregular resolved walkRoot succeeded, want error")
		}
		if _, err := client.SFTPClient().Lstat("/remote_dir_junction"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("UploadDirectory created empty remote directory despite AB8-L1 rejection: Lstat err = %v", err)
		}
	})

	t.Run("valid_top_level_symlink_resolves_to_real_dir", func(t *testing.T) {
		requireLocalSymlinkSupport(t)
		base := t.TempDir()
		realDir := filepath.Join(base, "real")
		if err := os.MkdirAll(realDir, 0o755); err != nil {
			t.Fatal(err)
		}
		linkDir := filepath.Join(base, "link")
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Fatal(err)
		}

		resolved, err := ResolveLocalUploadRootDir(linkDir)
		if err != nil {
			t.Fatalf("ResolveLocalUploadRootDir(%q): %v", linkDir, err)
		}
		wantReal, err := filepath.EvalSymlinks(realDir)
		if err != nil {
			t.Fatal(err)
		}
		if resolved != wantReal {
			t.Fatalf("ResolveLocalUploadRootDir(%q) = %q, want %q", linkDir, resolved, wantReal)
		}
	})
}
