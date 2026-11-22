package sftp

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
)

type w10aRealPathHandler struct {
	*w8aHostileTrackingHandler
	realPathMu sync.Mutex
	realPathFn func(string) (string, error)
	statSeqMu  sync.Mutex
	statSeq    map[string][]os.FileInfo
	statSeqIdx map[string]int
}

func newW10aRealPathHandler(realPathFn func(string) (string, error)) *w10aRealPathHandler {
	return &w10aRealPathHandler{
		w8aHostileTrackingHandler: newW8aHostileTrackingHandler(),
		realPathFn:                realPathFn,
		statSeq:                   make(map[string][]os.FileInfo),
		statSeqIdx:                make(map[string]int),
	}
}

func (h *w10aRealPathHandler) RealPath(p string) (string, error) {
	h.realPathMu.Lock()
	fn := h.realPathFn
	h.realPathMu.Unlock()
	if fn != nil {
		return fn(p)
	}
	return p, nil
}

func (h *w10aRealPathHandler) Filelist(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	if r.Method == "Stat" {
		h.statSeqMu.Lock()
		seq := h.statSeq[r.Filepath]
		if len(seq) > 0 {
			idx := h.statSeqIdx[r.Filepath]
			if idx >= len(seq) {
				idx = len(seq) - 1
			}
			h.statSeqIdx[r.Filepath]++
			fi := seq[idx]
			h.statSeqMu.Unlock()
			return customListerAt{fi}, nil
		}
		h.statSeqMu.Unlock()
	}
	return h.w8aHostileTrackingHandler.Filelist(r)
}

func (h *w10aRealPathHandler) handlers() pkgsftp.Handlers {
	return pkgsftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	}
}

// TestP7W10a_AB10M1_RejectsNegativeRemoteSize verifies AB10-M1 fail-closed
// rejection of negative remote regular-file sizes (wire uint64 >= 1<<63)
// across Download, validateDirEntries, downloadFile, doDownload, RelayFileFrom,
// copyRelayContent, RemoteCopy, remoteCopyFile, and openVerifiedRemoteCopySource.
func TestP7W10a_AB10M1_RejectsNegativeRemoteSize(t *testing.T) {
	t.Run("download_single_file_preserves_existing_local", testP7W10aDownloadSingleNegativeSize)
	t.Run("download_directory_rejects_negative_regular_entry", testP7W10aDownloadDirNegativeSize)
	t.Run("downloadFile_and_doDownload_reject_negative_size", testP7W10aDownloadFileAndDoDownloadNegativeSize)
	t.Run("relayFileFrom_and_copyRelayContent_preserve_remote_dst", testP7W10aRelayNegativeSize)
	t.Run("remoteCopy_and_openVerifiedRemoteCopySource_reject_negative_size", testP7W10aRemoteCopyNegativeSize)
}

func testP7W10aDownloadSingleNegativeSize(t *testing.T) {
	for _, negSize := range []int64{-1, -50, math.MinInt64} {
		h := newW8aHostileTrackingHandler()
		h.stats["/remote/victim.txt"] = syntheticFileInfo{name: "victim.txt", size: negSize, mode: 0o644}
		h.files["/remote/victim.txt"] = []byte("never-read")

		client := newTestSFTPClientWithHandlers(t, h.handlers())
		localDir := t.TempDir()
		localPath := filepath.Join(localDir, "victim.txt")
		const sentinel = "precious-local-data"
		if err := os.WriteFile(localPath, []byte(sentinel), 0o600); err != nil {
			t.Fatal(err)
		}

		remotePath, err := ParseRemotePath("/remote/victim.txt")
		if err != nil {
			t.Fatal(err)
		}
		localDest, err := LocalDestPath(localPath)
		if err != nil {
			t.Fatal(err)
		}

		var confirmCalled, beforeCalled atomic.Bool
		err = client.WithForce(true).Download(t.Context(), remotePath, localDest, DownloadOptions{
			ConfirmOverwrite: func(context.Context, DownloadTargetInfo) (DownloadOverwriteDecision, error) {
				confirmCalled.Store(true)
				return DownloadOverwriteForce, nil
			},
			BeforeTransfer: func(context.Context, DownloadTargetInfo) (*DownloadTransferHooks, error) {
				beforeCalled.Store(true)
				return nil, nil
			},
		})
		if !errors.Is(err, ErrInvalidRemoteSize) {
			t.Fatalf("Download(size=%d) err = %v, want ErrInvalidRemoteSize", negSize, err)
		}
		if confirmCalled.Load() {
			t.Fatalf("Download(size=%d) unexpectedly invoked ConfirmOverwrite", negSize)
		}
		if beforeCalled.Load() {
			t.Fatalf("Download(size=%d) unexpectedly invoked BeforeTransfer", negSize)
		}
		got, readErr := os.ReadFile(localPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(got) != sentinel {
			t.Fatalf("Download(size=%d) corrupted local file: got %q, want %q", negSize, got, sentinel)
		}
	}
}

func testP7W10aDownloadDirNegativeSize(t *testing.T) {
	h := newW8aHostileTrackingHandler()
	h.stats["/remote/dir"] = syntheticFileInfo{name: "dir", mode: os.ModeDir | 0o755}
	h.dirLists["/remote/dir"] = []os.FileInfo{
		syntheticFileInfo{name: "good.txt", size: 4, mode: 0o644},
		syntheticFileInfo{name: "neg.bin", size: -50, mode: 0o644},
	}
	h.stats["/remote/dir/good.txt"] = syntheticFileInfo{name: "good.txt", size: 4, mode: 0o644}
	h.files["/remote/dir/good.txt"] = []byte("good")
	h.stats["/remote/dir/neg.bin"] = syntheticFileInfo{name: "neg.bin", size: -50, mode: 0o644}
	h.files["/remote/dir/neg.bin"] = []byte("evil")

	client := newTestSFTPClientWithHandlers(t, h.handlers())
	localDir := filepath.Join(t.TempDir(), "out")
	remotePath, err := ParseRemotePath("/remote/dir")
	if err != nil {
		t.Fatal(err)
	}
	localDest, err := LocalDestPath(localDir)
	if err != nil {
		t.Fatal(err)
	}

	err = client.WithForce(true).Download(t.Context(), remotePath, localDest, DownloadOptions{})
	if !errors.Is(err, ErrInvalidRemoteSize) {
		t.Fatalf("Download(dir with neg.bin) err = %v, want ErrInvalidRemoteSize", err)
	}
	if _, statErr := os.Lstat(filepath.Join(localDir, "good.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("good.txt was created despite negative-size sibling pre-validation: err=%v", statErr)
	}

	// Direct validateDirEntries unit check.
	rootTarget, err := ResolveLocalTarget(localDir)
	if err != nil {
		t.Fatal(err)
	}
	walker := &downloadDirWalkState{
		client:     client,
		remoteRoot: remotePath,
		groupCtx:   t.Context(),
	}
	if _, valErr := walker.validateDirEntries(remotePath, rootTarget, h.dirLists["/remote/dir"]); !errors.Is(valErr, ErrInvalidRemoteSize) {
		t.Fatalf("validateDirEntries err = %v, want ErrInvalidRemoteSize", valErr)
	}
}

func testP7W10aDownloadFileAndDoDownloadNegativeSize(t *testing.T) {
	h := newW10aRealPathHandler(nil)
	h.stats["/remote/neg.bin"] = syntheticFileInfo{name: "neg.bin", size: -50, mode: 0o644}
	h.files["/remote/neg.bin"] = []byte("payload")
	client := newTestSFTPClientWithHandlers(t, h.handlers())

	localPath := filepath.Join(t.TempDir(), "existing.bin")
	const sentinel = "keep-me-intact"
	if err := os.WriteFile(localPath, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. Caller passes size=-50 matching server f.Stat().Size()=-50.
	if err := client.WithForce(true).downloadFile(t.Context(), "/remote/neg.bin", localPath, -50, 0o644, nil); !errors.Is(err, ErrInvalidRemoteSize) {
		t.Fatalf("downloadFile(size=-50) err = %v, want ErrInvalidRemoteSize", err)
	}
	// 2. Caller passes positive size=7, but opened handle Stat() returns -50.
	if err := client.WithForce(true).downloadFile(t.Context(), "/remote/neg.bin", localPath, 7, 0o644, nil); !errors.Is(err, ErrInvalidRemoteSize) {
		t.Fatalf("downloadFile(srcStat=-50) err = %v, want ErrInvalidRemoteSize", err)
	}
	got, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sentinel {
		t.Fatalf("localPath modified on rejected downloadFile: got %q, want %q", got, sentinel)
	}

	// 3. Direct doDownload invalid-range checks.
	for _, tc := range []struct {
		name        string
		startOffset int64
		size        int64
	}{
		{"negative_size", 0, -50},
		{"negative_start", -1, 10},
		{"start_exceeds_size", 20, 10},
	} {
		if err := client.doDownload(t.Context(), nil, nil, tc.startOffset, tc.size, nil); !errors.Is(err, ErrInvalidRemoteSize) {
			t.Fatalf("doDownload(%s) err = %v, want ErrInvalidRemoteSize", tc.name, err)
		}
	}
}

func testP7W10aRelayNegativeSize(t *testing.T) {
	dstClient := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
	if err := dstClient.SFTPClient().MkdirAll("/dst"); err != nil {
		t.Fatal(err)
	}
	const sentinel = "precious-remote-data"
	f, err := dstClient.SFTPClient().Create("/dst/target.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(f, sentinel); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	srcPath, err := ParseRemotePath("/src/neg.bin")
	if err != nil {
		t.Fatal(err)
	}
	dstPath, err := ParseRemotePath("/dst/target.bin")
	if err != nil {
		t.Fatal(err)
	}

	// Case A: srcInfo != nil with negative size.
	hA := newW8aHostileTrackingHandler()
	hA.stats["/src/neg.bin"] = syntheticFileInfo{name: "neg.bin", size: -50, mode: 0o644}
	hA.files["/src/neg.bin"] = []byte("src")
	srcClientA := newTestSFTPClientWithHandlers(t, hA.handlers())
	if err := dstClient.RelayFileFrom(t.Context(), srcClientA, srcPath, dstPath, hA.stats["/src/neg.bin"], nil); !errors.Is(err, ErrInvalidRemoteSize) {
		t.Fatalf("RelayFileFrom(srcInfo=-50) err = %v, want ErrInvalidRemoteSize", err)
	}

	// Case B: srcInfo == nil and server Stat returns -1.
	hB := newW8aHostileTrackingHandler()
	hB.stats["/src/neg.bin"] = syntheticFileInfo{name: "neg.bin", size: -1, mode: 0o644}
	hB.files["/src/neg.bin"] = []byte("src")
	srcClientB := newTestSFTPClientWithHandlers(t, hB.handlers())
	if err := dstClient.RelayFileFrom(t.Context(), srcClientB, srcPath, dstPath, nil, nil); !errors.Is(err, ErrInvalidRemoteSize) {
		t.Fatalf("RelayFileFrom(nil srcInfo, Stat=-1) err = %v, want ErrInvalidRemoteSize", err)
	}

	// Case C: preStat returns +10, but opened handle Stat() returns -50.
	hC := newW10aRealPathHandler(nil)
	hC.statSeq["/src/neg.bin"] = []os.FileInfo{
		syntheticFileInfo{name: "neg.bin", size: 10, mode: 0o644},
		syntheticFileInfo{name: "neg.bin", size: -50, mode: 0o644},
	}
	hC.files["/src/neg.bin"] = []byte("0123456789")
	srcClientC := newTestSFTPClientWithHandlers(t, hC.handlers())
	if err := dstClient.RelayFileFrom(t.Context(), srcClientC, srcPath, dstPath, nil, nil); !errors.Is(err, ErrInvalidRemoteSize) {
		t.Fatalf("RelayFileFrom(opened f.Stat=-50) err = %v, want ErrInvalidRemoteSize", err)
	}

	// Verify destination file was never overwritten with 0 bytes.
	rf, err := dstClient.SFTPClient().Open("/dst/target.bin")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rf)
	_ = rf.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sentinel {
		t.Fatalf("RelayFileFrom corrupted remote destination: got %q, want %q", got, sentinel)
	}

	// Direct copyRelayContent range rejection checks.
	var transferred atomic.Int64
	for _, tc := range []struct {
		name        string
		startOffset int64
		size        int64
	}{
		{"negative_size", 0, -50},
		{"negative_start", -1, 10},
		{"start_exceeds_size", 20, 10},
	} {
		if err := dstClient.copyRelayContent(t.Context(), "/dst/target.bin.tmp", nil, nil, tc.startOffset, tc.size, &transferred, nil); !errors.Is(err, ErrInvalidRemoteSize) {
			t.Fatalf("copyRelayContent(%s) err = %v, want ErrInvalidRemoteSize", tc.name, err)
		}
	}
}

func testP7W10aRemoteCopyNegativeSize(t *testing.T) {
	h := newW10aRealPathHandler(nil)
	h.lstats["/"] = syntheticFileInfo{name: "/", mode: os.ModeDir | 0o755}
	h.lstats["/src"] = syntheticFileInfo{name: "src", mode: os.ModeDir | 0o755}
	h.lstats["/dst"] = syntheticFileInfo{name: "dst", mode: os.ModeDir | 0o755}
	h.lstats["/src/neg.bin"] = syntheticFileInfo{name: "neg.bin", size: -50, mode: 0o644}
	h.stats["/src/neg.bin"] = syntheticFileInfo{name: "neg.bin", size: -50, mode: 0o644}
	h.files["/src/neg.bin"] = []byte("ignored")

	client := newTestSFTPClientWithHandlers(t, h.handlers())
	if err := client.RemoteCopy(t.Context(), "/src/neg.bin", "/dst/target.bin"); !errors.Is(err, ErrInvalidRemoteSize) {
		t.Fatalf("RemoteCopy(size=-50) err = %v, want ErrInvalidRemoteSize", err)
	}
	h.mu.Lock()
	writes := append([]string(nil), h.writeCalls...)
	h.mu.Unlock()
	if len(writes) != 0 {
		t.Fatalf("RemoteCopy opened destination files despite negative size: %v", writes)
	}

	// Direct openVerifiedRemoteCopySource checks: negative srcStat AND negative openedStat.
	if _, _, err := client.openVerifiedRemoteCopySource("/src/neg.bin", syntheticFileInfo{name: "neg.bin", size: -50, mode: 0o644}); !errors.Is(err, ErrInvalidRemoteSize) {
		t.Fatalf("openVerifiedRemoteCopySource(srcStat=-50) err = %v, want ErrInvalidRemoteSize", err)
	}
	if _, _, err := client.openVerifiedRemoteCopySource("/src/neg.bin", syntheticFileInfo{name: "neg.bin", size: 7, mode: 0o644}); !errors.Is(err, ErrInvalidRemoteSize) {
		t.Fatalf("openVerifiedRemoteCopySource(openedStat=-50) err = %v, want ErrInvalidRemoteSize", err)
	}
}

// TestP7W10a_AB10L1_CwdAndRealPathValidateViaParseRemotePath verifies AB10-L1:
// (*Client).Cwd and (*Client).RealPath validate and normalize server-returned
// paths through ParseRemotePath, rejecting empty strings and NUL/C0/DEL/C1/
// line-separator control characters while normalizing valid printable POSIX paths.
func TestP7W10a_AB10L1_CwdAndRealPathValidateViaParseRemotePath(t *testing.T) {
	rejectCases := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"nul_byte", "/home/alice\x00/dir"},
		{"osc_52_escape", "/home/\x1b]52;c;aGVsbG8=\x07alice"},
		{"csi_escape", "/home/\x1b[31malice"},
		{"newline", "/home/alice\n/evil"},
		{"carriage_return", "/home/alice\r/evil"},
		{"del_char", "/home/alice\x7f"},
		{"c1_csi", "/home/alice\u009b2J"},
		{"unicode_line_sep", "/home/alice\u2028dir"},
		{"unicode_para_sep", "/home/alice\u2029dir"},
	}

	for _, tc := range rejectCases {
		t.Run("reject_"+tc.name, func(t *testing.T) {
			h := newW10aRealPathHandler(func(string) (string, error) {
				return tc.raw, nil
			})
			client := newTestSFTPClientWithHandlers(t, h.handlers())
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			cwd, err := client.Cwd(ctx)
			if !errors.Is(err, ErrInvalidRemotePath) || cwd != "" {
				t.Fatalf("Cwd(%s) = (%q, %v), want (\"\", ErrInvalidRemotePath)", tc.name, cwd, err)
			}
			rp, err := client.RealPath(ctx, ".")
			if !errors.Is(err, ErrInvalidRemotePath) || rp != "" {
				t.Fatalf("RealPath(%s) = (%q, %v), want (\"\", ErrInvalidRemotePath)", tc.name, rp, err)
			}
		})
	}

	acceptCases := []struct {
		name string
		raw  string
		want string
	}{
		{"clean_abs", "/home/alice", "/home/alice"},
		{"normalizes_slashes_and_dotdot", "/home/alice//sub/../work/", "/home/alice/work"},
		{"printable_spaces_and_unicode", "/home/alice/my dir/中文", "/home/alice/my dir/中文"},
		{"root", "/", "/"},
	}

	for _, tc := range acceptCases {
		t.Run("accept_"+tc.name, func(t *testing.T) {
			h := newW10aRealPathHandler(func(string) (string, error) {
				return tc.raw, nil
			})
			client := newTestSFTPClientWithHandlers(t, h.handlers())
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			cwd, err := client.Cwd(ctx)
			if err != nil || cwd != tc.want {
				t.Fatalf("Cwd(%s) = (%q, %v), want (%q, nil)", tc.name, cwd, err, tc.want)
			}
			rp, err := client.RealPath(ctx, "/input")
			if err != nil || rp != tc.want {
				t.Fatalf("RealPath(%s) = (%q, %v), want (%q, nil)", tc.name, rp, err, tc.want)
			}
		})
	}
}

// TestP7W10a_ExportedReadDirHelpersValidateEntries verifies ValidateRemoteDirEntries
// and ReadValidatedDir accept clean entries and fail closed with
// ErrUnsafeRemoteDirEntry on hostile entries.
func TestP7W10a_ExportedReadDirHelpersValidateEntries(t *testing.T) {
	validEntries := []os.FileInfo{
		syntheticFileInfo{name: "alpha.txt", size: 5, mode: 0o644},
		syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
	}
	got, err := ValidateRemoteDirEntries("/remote/dir", validEntries)
	if err != nil || len(got) != 2 {
		t.Fatalf("ValidateRemoteDirEntries(valid) = (%d, %v), want (2, nil)", len(got), err)
	}

	hostileSets := []struct {
		name      string
		entries   []os.FileInfo
		wantErrIs error
	}{
		{"slash_dotdot", []os.FileInfo{syntheticFileInfo{name: "x/..", mode: os.ModeDir | 0o755}}, ErrInvalidRemoteName},
		{"duplicate", []os.FileInfo{
			syntheticFileInfo{name: "dup.txt", size: 1, mode: 0o644},
			syntheticFileInfo{name: "dup.txt", size: 1, mode: 0o644},
		}, ErrUnsafeRemoteDirEntry},
		{"nil_entry", []os.FileInfo{nil}, ErrInvalidRemoteName},
	}
	for _, tc := range hostileSets {
		if out, valErr := ValidateRemoteDirEntries("/remote/dir", tc.entries); valErr == nil || !errors.Is(valErr, ErrUnsafeRemoteDirEntry) || !errors.Is(valErr, tc.wantErrIs) || len(out) != 0 {
			t.Fatalf("ValidateRemoteDirEntries(%s) = (%d, %v), want ErrUnsafeRemoteDirEntry & %v", tc.name, len(out), valErr, tc.wantErrIs)
		}
	}

	if _, err := ReadValidatedDir(nil, "/"); err == nil {
		t.Fatal("ReadValidatedDir(nil, \"/\") succeeded, want error")
	}

	h := newW8aHostileTrackingHandler()
	h.dirLists["/ok"] = validEntries
	h.dirLists["/evil"] = []os.FileInfo{syntheticFileInfo{name: "x/..", mode: os.ModeDir | 0o755}}
	client := newTestSFTPClientWithHandlers(t, h.handlers())

	if out, err := ReadValidatedDir(client.SFTPClient(), "/ok"); err != nil || len(out) != 2 {
		t.Fatalf("ReadValidatedDir(/ok) = (%d, %v), want (2, nil)", len(out), err)
	}
	if out, err := ReadValidatedDir(client.SFTPClient(), "/evil"); !errors.Is(err, ErrUnsafeRemoteDirEntry) || !errors.Is(err, ErrInvalidRemoteName) || len(out) != 0 {
		t.Fatalf("ReadValidatedDir(/evil) = (%d, %v), want ErrUnsafeRemoteDirEntry & ErrInvalidRemoteName", len(out), err)
	}
}

// TestP7W10a_NoRawPkgSFTPReadDirRepoWide verifies #393 §6.2 architecturally
// across the entire module root (all of cmd/, core/, internal/, pkg/ in the
// monorepo, or all of extracted core/ under scripts/check_core.py): ZERO
// production files outside core/sftp/readdir.go may call ReadDir or
// ReadDirContext on *github.com/pkg/sftp.Client.
func TestP7W10a_NoRawPkgSFTPReadDirRepoWide(t *testing.T) {
	modRoot, err := findModuleRootFromWD()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}
	fset := token.NewFileSet()
	var scanned int
	walkErr := filepath.WalkDir(modRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "vendor" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(modRoot, p)
		if relErr != nil {
			return relErr
		}
		relSlash := filepath.ToSlash(rel)
		if relSlash == "core/sftp/readdir.go" || relSlash == "sftp/readdir.go" {
			return nil
		}
		scanned++
		file, parseErr := parser.ParseFile(fset, p, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		checkFileNoRawPkgSFTPReadDir(t, fset, relSlash, file)
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk module root %q: %v", modRoot, walkErr)
	}
	if scanned == 0 {
		t.Fatalf("expected to scan production Go files under %q, scanned 0", modRoot)
	}
}

func findModuleRootFromWD() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found")
		}
		dir = parent
	}
}

func checkFileNoRawPkgSFTPReadDir(t *testing.T, fset *token.FileSet, relSlash string, file *ast.File) {
	t.Helper()
	pkgSFTPAlias := ""
	for _, imp := range file.Imports {
		if strings.Trim(imp.Path.Value, `"`) == "github.com/pkg/sftp" {
			if imp.Name != nil {
				pkgSFTPAlias = imp.Name.Name
			} else {
				pkgSFTPAlias = "sftp"
			}
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pos := fset.Position(call.Pos())
		if sel.Sel.Name == "ReadDirContext" {
			t.Errorf("forbidden raw ReadDirContext call outside core/sftp/readdir.go at %s:%d", relSlash, pos.Line)
			return true
		}
		if sel.Sel.Name != "ReadDir" {
			return true
		}
		if ident, isIdent := sel.X.(*ast.Ident); isIdent && ident.Name == "os" {
			return true
		}
		if subCall, isCall := sel.X.(*ast.CallExpr); isCall {
			if subSel, isSel := subCall.Fun.(*ast.SelectorExpr); isSel && subSel.Sel.Name == "SFTPClient" {
				t.Errorf("forbidden raw SFTPClient().ReadDir call at %s:%d", relSlash, pos.Line)
				return true
			}
		}
		if pkgSFTPAlias == "" {
			return true
		}
		// Any file importing github.com/pkg/sftp must never invoke 1-arg ReadDir
		// on a *pkgsftp.Client (only validated 2-arg (*core/sftp.Client).ReadDir(ctx, dir)
		// is permitted).
		if len(call.Args) != 2 {
			t.Errorf("forbidden raw *github.com/pkg/sftp.Client ReadDir call (%d args) at %s:%d", len(call.Args), relSlash, pos.Line)
		}
		return true
	})
}
