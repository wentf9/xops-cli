package runtime

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/sftp"
)

type w10aSynthFileInfo struct {
	name string
	size int64
	mode os.FileMode
}

func (f w10aSynthFileInfo) Name() string       { return f.name }
func (f w10aSynthFileInfo) Size() int64        { return f.size }
func (f w10aSynthFileInfo) Mode() os.FileMode  { return f.mode }
func (f w10aSynthFileInfo) ModTime() time.Time { return time.Unix(1700000000, 0) }
func (f w10aSynthFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f w10aSynthFileInfo) Sys() any           { return nil }

type w10aListerAt []os.FileInfo

func (l w10aListerAt) ListAt(dst []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(dst, l[offset:])
	if offset+int64(n) >= int64(len(l)) {
		return n, io.EOF
	}
	return n, nil
}

type w10aHostileSFTPHandler struct {
	mu          sync.Mutex
	stats       map[string]os.FileInfo
	dirLists    map[string][]os.FileInfo
	dirErrs     map[string]error
	listCalls   map[string]int
	removeCalls []string
}

func newW10aHostileSFTPHandler() *w10aHostileSFTPHandler {
	return &w10aHostileSFTPHandler{
		stats:     make(map[string]os.FileInfo),
		dirLists:  make(map[string][]os.FileInfo),
		dirErrs:   make(map[string]error),
		listCalls: make(map[string]int),
	}
}

func (h *w10aHostileSFTPHandler) Fileread(*pkgsftp.Request) (io.ReaderAt, error) {
	return bytes.NewReader(nil), nil
}

func (h *w10aHostileSFTPHandler) Filewrite(*pkgsftp.Request) (io.WriterAt, error) {
	return nil, os.ErrPermission
}

func (h *w10aHostileSFTPHandler) Filecmd(r *pkgsftp.Request) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if r.Method == "Remove" {
		h.removeCalls = append(h.removeCalls, r.Filepath)
		return nil
	}
	return os.ErrPermission
}

func (h *w10aHostileSFTPHandler) Filelist(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch r.Method {
	case "Stat":
		if fi, ok := h.stats[r.Filepath]; ok {
			return w10aListerAt{fi}, nil
		}
		return nil, os.ErrNotExist
	case "List":
		h.listCalls[r.Filepath]++
		if err, ok := h.dirErrs[r.Filepath]; ok {
			return nil, err
		}
		if entries, ok := h.dirLists[r.Filepath]; ok {
			return w10aListerAt(entries), nil
		}
		return nil, os.ErrNotExist
	default:
		return nil, os.ErrInvalid
	}
}

func newW10aHostileClient(t *testing.T, h *w10aHostileSFTPHandler) (*pkgsftp.Client, *pipeFileSession) {
	t.Helper()
	cConn, sConn := net.Pipe()
	srv := pkgsftp.NewRequestServer(sConn, pkgsftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	})
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = sConn.Close()
	})
	client, err := pkgsftp.NewClientPipe(cConn, cConn)
	if err != nil {
		t.Fatalf("NewClientPipe: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = cConn.Close()
	})
	return client, &pipeFileSession{client: client}
}

// TestP7W10a_MCPReadDir_BuildDirTreeFailsClosedOnHostileEntries verifies #393
// §6.2: buildDirTree and fileStat route through sftp.ReadValidatedDir and fail
// closed on "x/..", "x/.", "/", control chars, and duplicate entries without
// escaping parent directories, while still marking genuine unreadable subdirs.
func TestP7W10a_MCPReadDir_BuildDirTreeFailsClosedOnHostileEntries(t *testing.T) {
	cases := []struct {
		name      string
		entries   []os.FileInfo
		wantErrIs error
	}{
		{
			name: "slash_dotdot_escape",
			entries: []os.FileInfo{
				w10aSynthFileInfo{name: "good.txt", size: 4, mode: 0o644},
				w10aSynthFileInfo{name: "x/..", mode: os.ModeDir | 0o755},
			},
			wantErrIs: sftp.ErrInvalidRemoteName,
		},
		{
			name: "slash_dot_loop",
			entries: []os.FileInfo{
				w10aSynthFileInfo{name: "x/.", mode: os.ModeDir | 0o755},
			},
			wantErrIs: sftp.ErrInvalidRemoteName,
		},
		{
			name: "duplicate_entries",
			entries: []os.FileInfo{
				w10aSynthFileInfo{name: "dup.txt", size: 4, mode: 0o644},
				w10aSynthFileInfo{name: "dup.txt", size: 4, mode: 0o644},
			},
			wantErrIs: sftp.ErrUnsafeRemoteDirEntry,
		},
		{
			name: "osc_escape_name",
			entries: []os.FileInfo{
				w10aSynthFileInfo{name: "bad\x1b]52;c;x\x07", size: 4, mode: 0o644},
			},
			wantErrIs: sftp.ErrInvalidRemoteName,
		},
	}

	for _, tc := range cases {
		t.Run("root_"+tc.name, func(t *testing.T) {
			h := newW10aHostileSFTPHandler()
			h.stats["/root"] = w10aSynthFileInfo{name: "root", mode: os.ModeDir | 0o755}
			h.stats["/root/target"] = w10aSynthFileInfo{name: "target", mode: os.ModeDir | 0o755}
			h.dirLists["/root"] = []os.FileInfo{w10aSynthFileInfo{name: "secret.txt", size: 9, mode: 0o644}}
			h.dirLists["/root/target"] = tc.entries

			client, session := newW10aHostileClient(t, h)

			var b strings.Builder
			count := 0
			err := buildDirTree(client, "/root/target", "", 1, &b, &count)
			if !errors.Is(err, sftp.ErrUnsafeRemoteDirEntry) || !errors.Is(err, tc.wantErrIs) {
				t.Fatalf("buildDirTree(%s) err = %v, want ErrUnsafeRemoteDirEntry & %v", tc.name, err, tc.wantErrIs)
			}
			if b.Len() != 0 {
				t.Fatalf("buildDirTree(%s) emitted output on hostile dir: %q", tc.name, b.String())
			}

			out, statErr := fileStat(t.Context(), session, FileInput{Path: "/root/target"})
			if !errors.Is(statErr, sftp.ErrUnsafeRemoteDirEntry) || !errors.Is(statErr, tc.wantErrIs) {
				t.Fatalf("fileStat(%s) = (%+v, %v), want ErrUnsafeRemoteDirEntry & %v", tc.name, out, statErr, tc.wantErrIs)
			}

			h.mu.Lock()
			parentLists := h.listCalls["/root"]
			h.mu.Unlock()
			if parentLists != 0 {
				t.Fatalf("hostile %s traversed into parent /root (%d list calls)", tc.name, parentLists)
			}
		})
	}

	t.Run("child_subdir_hostile_fails_closed_while_permission_denied_renders_unreadable", func(t *testing.T) {
		h := newW10aHostileSFTPHandler()
		h.stats["/root"] = w10aSynthFileInfo{name: "root", mode: os.ModeDir | 0o755}
		h.dirLists["/root"] = []os.FileInfo{
			w10aSynthFileInfo{name: "restricted", mode: os.ModeDir | 0o700},
			w10aSynthFileInfo{name: "ok.txt", size: 3, mode: 0o644},
		}
		h.dirErrs["/root/restricted"] = os.ErrPermission
		client, session := newW10aHostileClient(t, h)

		out, err := fileStat(t.Context(), session, FileInput{Path: "/root"})
		if err != nil {
			t.Fatalf("fileStat with unreadable child failed unexpectedly: %v", err)
		}
		if !strings.Contains(out.Content, "[unreadable:") || !strings.Contains(out.Content, "ok.txt") {
			t.Fatalf("unexpected tree output for unreadable child:\n%s", out.Content)
		}

		// Now poison /root/restricted with hostile x/.. -> must fail closed.
		h.mu.Lock()
		delete(h.dirErrs, "/root/restricted")
		h.dirLists["/root/restricted"] = []os.FileInfo{w10aSynthFileInfo{name: "x/..", mode: os.ModeDir | 0o755}}
		h.mu.Unlock()

		var b strings.Builder
		count := 0
		if err := buildDirTree(client, "/root", "", 1, &b, &count); !errors.Is(err, sftp.ErrInvalidRemoteName) {
			t.Fatalf("buildDirTree with hostile child err = %v, want ErrInvalidRemoteName", err)
		}
	})
}

// TestP7W10a_MCPReadDir_PruneFoldedLogsFailsClosedOnHostileEntries verifies
// #393 §6.2: pruneFoldedLogs validates ReadDir entries through
// sftp.ReadValidatedDir and issues ZERO Remove calls when the server injects
// traversal ("x/..", "cmd-x/../../victim.log") or duplicate entries.
func TestP7W10a_MCPReadDir_PruneFoldedLogsFailsClosedOnHostileEntries(t *testing.T) {
	cases := []struct {
		name      string
		entries   []os.FileInfo
		wantErrIs error
	}{
		{
			name: "slash_dotdot_entry",
			entries: []os.FileInfo{
				w10aSynthFileInfo{name: "cmd-20260101T000001-000000.log", size: 10, mode: 0o600},
				w10aSynthFileInfo{name: "cmd-20260101T000002-000000.log", size: 10, mode: 0o600},
				w10aSynthFileInfo{name: "x/..", mode: os.ModeDir | 0o755},
			},
			wantErrIs: sftp.ErrInvalidRemoteName,
		},
		{
			name: "slash_dot_entry",
			entries: []os.FileInfo{
				w10aSynthFileInfo{name: "x/.", mode: os.ModeDir | 0o755},
				w10aSynthFileInfo{name: "cmd-20260101T000001-000000.log", size: 10, mode: 0o600},
				w10aSynthFileInfo{name: "cmd-20260101T000002-000000.log", size: 10, mode: 0o600},
			},
			wantErrIs: sftp.ErrInvalidRemoteName,
		},
		{
			name: "root_slash_entry",
			entries: []os.FileInfo{
				w10aSynthFileInfo{name: "/", mode: os.ModeDir | 0o755},
				w10aSynthFileInfo{name: "cmd-20260101T000001-000000.log", size: 10, mode: 0o600},
				w10aSynthFileInfo{name: "cmd-20260101T000002-000000.log", size: 10, mode: 0o600},
			},
			wantErrIs: sftp.ErrInvalidRemoteName,
		},
		{
			name: "control_char_cmd_log_entry",
			entries: []os.FileInfo{
				w10aSynthFileInfo{name: "cmd-20260101\n-evil.log", size: 10, mode: 0o600},
				w10aSynthFileInfo{name: "cmd-20260101T000001-000000.log", size: 10, mode: 0o600},
				w10aSynthFileInfo{name: "cmd-20260101T000002-000000.log", size: 10, mode: 0o600},
			},
			wantErrIs: sftp.ErrInvalidRemoteName,
		},
		{
			name: "duplicate_log_entries",
			entries: []os.FileInfo{
				w10aSynthFileInfo{name: "cmd-20260101T000001-000000.log", size: 10, mode: 0o600},
				w10aSynthFileInfo{name: "cmd-20260101T000001-000000.log", size: 10, mode: 0o600},
				w10aSynthFileInfo{name: "cmd-20260101T000002-000000.log", size: 10, mode: 0o600},
			},
			wantErrIs: sftp.ErrUnsafeRemoteDirEntry,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newW10aHostileSFTPHandler()
			dir := "/home/user/.cache/xops-mcp"
			h.dirLists[dir] = tc.entries
			client, _ := newW10aHostileClient(t, h)

			err := pruneFoldedLogs(client, dir, 1)
			if !errors.Is(err, sftp.ErrUnsafeRemoteDirEntry) || !errors.Is(err, tc.wantErrIs) {
				t.Fatalf("pruneFoldedLogs(%s) err = %v, want ErrUnsafeRemoteDirEntry & %v", tc.name, err, tc.wantErrIs)
			}
			h.mu.Lock()
			removed := append([]string(nil), h.removeCalls...)
			h.mu.Unlock()
			if len(removed) != 0 {
				t.Fatalf("pruneFoldedLogs(%s) issued Remove calls despite hostile ReadDir: %v", tc.name, removed)
			}
		})
	}
}

// TestP7W10a_MCPReadDir_NoRawPkgSFTPReadDirInRuntime verifies no production
// file in core/mcp/runtime invokes ReadDir or ReadDirContext on *pkgsftp.Client.
func TestP7W10a_MCPReadDir_NoRawPkgSFTPReadDirInRuntime(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("os.ReadDir(.): %v", err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
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
			if sel.Sel.Name != "ReadDir" && sel.Sel.Name != "ReadDirContext" {
				return true
			}
			if ident, isIdent := sel.X.(*ast.Ident); isIdent && ident.Name == "os" {
				return true
			}
			pos := fset.Position(call.Pos())
			t.Errorf("forbidden raw %s call in core/mcp/runtime/%s:%d", sel.Sel.Name, name, pos.Line)
			return true
		})
	}
}
