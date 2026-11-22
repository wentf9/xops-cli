package sftp

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestP7W9a_ReadDirValidatesEntries verifies AB9-M1:
// Client.ReadDir routes through readValidatedRemoteDir, accepts clean entries,
// and fails closed on hostile SSH_FXP_NAME entries ("x/..", "x/.", "/", ".",
// "..", NUL/control/CSI/OSC escapes, duplicates), invalid paths, nil client/ctx,
// and context cancellation.
func TestP7W9a_ReadDirValidatesEntries(t *testing.T) {
	t.Run("accepts_valid_entries", testP7W9aReadDirAcceptsValid)
	t.Run("rejects_hostile_entries", testP7W9aReadDirRejectsHostile)
	t.Run("rejects_nil_and_invalid_inputs", testP7W9aReadDirRejectsInvalidInputs)
}

func testP7W9aReadDirAcceptsValid(t *testing.T) {
	h := newW8aHostileTrackingHandler()
	h.dirLists["/remote/dir"] = []os.FileInfo{
		syntheticFileInfo{name: "alpha.txt", size: 12, mode: 0o644},
		syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
		syntheticFileInfo{name: `rep\ -f`, size: 4, mode: 0o644},
	}

	client := newTestSFTPClientWithHandlers(t, h.handlers())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	entries, err := client.ReadDir(ctx, "/remote/dir")
	if err != nil {
		t.Fatalf("ReadDir(/remote/dir) unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("ReadDir(/remote/dir) len = %d, want 3", len(entries))
	}
	if entries[0].Name() != "alpha.txt" || entries[1].Name() != "sub" || entries[2].Name() != `rep\ -f` {
		t.Fatalf("ReadDir(/remote/dir) names = [%q %q %q]", entries[0].Name(), entries[1].Name(), entries[2].Name())
	}
}

func testP7W9aReadDirRejectsHostile(t *testing.T) {
	cases := []struct {
		name       string
		entries    []os.FileInfo
		wantErrIs  error
		wantSubstr string
	}{
		{
			name: "slash_dotdot",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "good.txt", size: 4, mode: 0o644},
				syntheticFileInfo{name: "x/..", mode: os.ModeDir | 0o755},
			},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "slash_dot",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "x/.", mode: os.ModeDir | 0o755},
			},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "root_slash",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "/", mode: os.ModeDir | 0o755},
			},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "newline_flag_injection",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "rep\n-f", size: 4, mode: 0o644},
			},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "osc_52_escape",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "rep\x1b]52;c;aGVsbG8=\x07", size: 4, mode: 0o644},
			},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "csi_escape",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "rep\x1b[31mred", size: 4, mode: 0o644},
			},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "c1_csi_control",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "rep\u009b2J", size: 4, mode: 0o644},
			},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "del_control",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "rep\x7fname", size: 4, mode: 0o644},
			},
			wantErrIs: ErrInvalidRemoteName,
		},
		{
			name: "duplicate_entry",
			entries: []os.FileInfo{
				syntheticFileInfo{name: "dup.txt", size: 4, mode: 0o644},
				syntheticFileInfo{name: "dup.txt", size: 4, mode: 0o644},
			},
			wantSubstr: "duplicate",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newW8aHostileTrackingHandler()
			h.dirLists["/remote/dir"] = tc.entries

			client := newTestSFTPClientWithHandlers(t, h.handlers())
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			entries, err := client.ReadDir(ctx, "/remote/dir")
			if err == nil {
				t.Fatalf("ReadDir(%s) succeeded with %d entries, want error", tc.name, len(entries))
			}
			if len(entries) != 0 {
				t.Fatalf("ReadDir(%s) returned %d entries on error, want 0", tc.name, len(entries))
			}
			if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
				t.Fatalf("ReadDir(%s) err = %v, want errors.Is(_, %v)", tc.name, err, tc.wantErrIs)
			}
			if tc.wantSubstr != "" && !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("ReadDir(%s) err = %v, want substring %q", tc.name, err, tc.wantSubstr)
			}
		})
	}
}

func testP7W9aReadDirRejectsInvalidInputs(t *testing.T) {
	var nilClient *Client
	if _, err := nilClient.ReadDir(t.Context(), "/"); err == nil {
		t.Fatal("nilClient.ReadDir succeeded, want error")
	}

	h := newW8aHostileTrackingHandler()
	h.dirLists["/"] = []os.FileInfo{syntheticFileInfo{name: "ok.txt", size: 1, mode: 0o644}}
	client := newTestSFTPClientWithHandlers(t, h.handlers())

	//nolint:staticcheck // intentionally testing nil context fail-closed handling
	if _, err := client.ReadDir(nil, "/"); err == nil {
		t.Fatal("ReadDir(nil, \"/\") succeeded, want error")
	}
	if _, err := client.ReadDir(t.Context(), ""); !errors.Is(err, ErrInvalidRemotePath) {
		t.Fatalf("ReadDir(\"\") err = %v, want ErrInvalidRemotePath", err)
	}
	if _, err := client.ReadDir(t.Context(), "/bad\npath"); !errors.Is(err, ErrInvalidRemotePath) {
		t.Fatalf("ReadDir(\"/bad\\npath\") err = %v, want ErrInvalidRemotePath", err)
	}

	canceledCtx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := client.ReadDir(canceledCtx, "/"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadDir(canceled) err = %v, want context.Canceled", err)
	}
}

// TestP7W9a_NoRawPkgSFTPReadDirOutsideReaddir verifies AB9-M1 architecturally:
// no production file in core/sftp outside readdir.go may call ReadDir or
// ReadDirContext on any receiver other than os.
func TestP7W9a_NoRawPkgSFTPReadDirOutsideReaddir(t *testing.T) {
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
		if name == "readdir.go" {
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
			t.Errorf("forbidden raw %s call outside core/sftp/readdir.go at %s:%d", sel.Sel.Name, name, pos.Line)
			return true
		})
	}
}

// TestP7W9a_DownloadTransferSizeSaturatingInt64 verifies AB9-L2:
// saturatingAddInt64 and Client.DownloadTransferSize clamp negative sizes to 0
// and saturate at math.MaxInt64 instead of wrapping around on hostile
// SSH_FILEXFER_ATTR_SIZE totals (math.MaxInt64 + math.MaxInt64 + 1).
func TestP7W9a_DownloadTransferSizeSaturatingInt64(t *testing.T) {
	t.Run("saturatingAddInt64_unit_cases", func(t *testing.T) {
		cases := []struct {
			a, b, want int64
		}{
			{0, 0, 0},
			{10, 20, 30},
			{10, -5, 10},
			{-5, 10, 10},
			{-5, -10, 0},
			{10, math.MinInt64, 10},
			{math.MinInt64, math.MinInt64, 0},
			{math.MaxInt64, 1, math.MaxInt64},
			{math.MaxInt64, math.MaxInt64, math.MaxInt64},
			{math.MaxInt64 - 10, 10, math.MaxInt64},
			{math.MaxInt64 - 10, 11, math.MaxInt64},
		}
		for _, tc := range cases {
			if got := saturatingAddInt64(tc.a, tc.b); got != tc.want {
				t.Errorf("saturatingAddInt64(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		}
	})

	t.Run("hostile_dir_sizes_saturate_never_wrap_negative", func(t *testing.T) {
		h := newW8aHostileTrackingHandler()
		h.stats["/huge"] = syntheticFileInfo{name: "huge", mode: os.ModeDir | 0o755}
		h.dirLists["/huge"] = []os.FileInfo{
			syntheticFileInfo{name: "a.bin", size: math.MaxInt64, mode: 0o644},
			syntheticFileInfo{name: "b.bin", size: math.MaxInt64, mode: 0o644},
			syntheticFileInfo{name: "c.bin", size: 1, mode: 0o644},
			syntheticFileInfo{name: "link", mode: os.ModeSymlink | 0o777},
		}
		h.readLinks["/huge/link"] = "target_path"

		client := newTestSFTPClientWithHandlers(t, h.handlers())
		root, err := ParseRemotePath("/huge")
		if err != nil {
			t.Fatal(err)
		}
		got, err := client.DownloadTransferSize(t.Context(), root)
		if err != nil {
			t.Fatalf("DownloadTransferSize(/huge) err = %v", err)
		}
		if got != math.MaxInt64 {
			t.Fatalf("DownloadTransferSize(/huge) = %d, want math.MaxInt64 (%d)", got, int64(math.MaxInt64))
		}
	})

	t.Run("negative_sizes_clamped_to_zero", func(t *testing.T) {
		h := newW8aHostileTrackingHandler()
		h.stats["/neg"] = syntheticFileInfo{name: "neg", mode: os.ModeDir | 0o755}
		h.dirLists["/neg"] = []os.FileInfo{
			syntheticFileInfo{name: "neg1.bin", size: -42, mode: 0o644},
			syntheticFileInfo{name: "neg2.bin", size: math.MinInt64, mode: 0o644},
			syntheticFileInfo{name: "ok.bin", size: 123, mode: 0o644},
		}
		h.stats["/single_neg"] = syntheticFileInfo{name: "single_neg", size: -99, mode: 0o644}

		client := newTestSFTPClientWithHandlers(t, h.handlers())

		negDir, err := ParseRemotePath("/neg")
		if err != nil {
			t.Fatal(err)
		}
		gotDir, err := client.DownloadTransferSize(t.Context(), negDir)
		if err != nil {
			t.Fatalf("DownloadTransferSize(/neg) err = %v", err)
		}
		if gotDir != 123 {
			t.Fatalf("DownloadTransferSize(/neg) = %d, want 123", gotDir)
		}

		singleNeg, err := ParseRemotePath("/single_neg")
		if err != nil {
			t.Fatal(err)
		}
		gotSingle, err := client.DownloadTransferSize(t.Context(), singleNeg)
		if err != nil {
			t.Fatalf("DownloadTransferSize(/single_neg) err = %v", err)
		}
		if gotSingle != 0 {
			t.Fatalf("DownloadTransferSize(/single_neg) = %d, want 0", gotSingle)
		}
	})
}
