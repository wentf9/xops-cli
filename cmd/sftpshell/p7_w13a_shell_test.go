package sftpshell

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/core/sftp"
)

type w13aStatVFSCmder struct {
	pkgsftp.FileCmder
	vfs *pkgsftp.StatVFS
}

func (c w13aStatVFSCmder) StatVFS(*pkgsftp.Request) (*pkgsftp.StatVFS, error) {
	return c.vfs, nil
}

// TestP7W13a_AB13L1_DisplayFormattingNeverNegative verifies AB13-L1:
//   - formatBytes clamps negative int64 inputs cleanly and never prints negative sizes.
//   - sftp.FormatByteSize formats full uint64 range (including >= 1<<63 and MaxUint64)
//     without sign wraparound or suffix bounds panic.
//   - listRemoteOne formats negative wire FileInfo.Size() (uint64 >= 1<<63) as
//     unsigned byte counts, never misleading negative strings.
//   - checkRemoteStorageSpace formats high-bit uint64 StatVFS free/total values
//     via sftp.FormatByteSize without int64 wraparound.
func TestP7W13a_AB13L1_DisplayFormattingNeverNegative(t *testing.T) {
	t.Run("formatBytes_and_FormatByteSize_boundaries", testP7W13aFormatByteBoundaries)
	t.Run("listRemoteOne_unsigned_formatting_for_negative_wire_sizes", testP7W13aListRemoteOneNegativeSize)
	t.Run("checkRemoteStorageSpace_high_bit_uint64_statvfs", testP7W13aCheckRemoteStorageSpaceHighBit)
}

func testP7W13aFormatByteBoundaries(t *testing.T) {
	for _, tc := range []struct {
		in   int64
		want string
	}{
		{math.MinInt64, "0 B"},
		{-50, "0 B"},
		{-1, "0 B"},
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{math.MaxInt64, "8.0 EB"},
	} {
		got := formatBytes(tc.in)
		if got != tc.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
		if strings.HasPrefix(got, "-") {
			t.Errorf("formatBytes(%d) returned negative string %q", tc.in, got)
		}
	}

	for _, tc := range []struct {
		in   uint64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1 << 60, "1.0 EB"},
		{1 << 63, "8.0 EB"},
		{math.MaxUint64, "16.0 EB"},
	} {
		got := sftp.FormatByteSize(tc.in)
		if got != tc.want {
			t.Errorf("sftp.FormatByteSize(%d) = %q, want %q", tc.in, got, tc.want)
		}
		if strings.HasPrefix(got, "-") {
			t.Errorf("sftp.FormatByteSize(%d) returned negative string %q", tc.in, got)
		}
	}
}

func testP7W13aListRemoteOneNegativeSize(t *testing.T) {
	h := newW8aShellTrackingHandler()
	h.stats["/remote"] = p7ReproFileInfo{name: "remote", mode: os.ModeDir | 0o755}
	h.dirLists["/remote"] = []os.FileInfo{
		p7ReproFileInfo{name: "maxuint.bin", size: -1, mode: 0o644},
		p7ReproFileInfo{name: "highbit.bin", size: math.MinInt64, mode: 0o644},
		p7ReproFileInfo{name: "normal.bin", size: 2048, mode: 0o644},
	}
	h.stats["/remote/single_neg.bin"] = p7ReproFileInfo{name: "single_neg.bin", size: -50, mode: 0o644}

	sh := newP7W7bShellWithHandlers(t, h.handlers(), "/", t.TempDir())
	var stdout, stderr bytes.Buffer
	sh.stdout = &stdout
	sh.stderr = &stderr

	if err := sh.listRemoteOne(t.Context(), "/remote", true); err != nil {
		t.Fatalf("listRemoteOne(/remote, long=true) err = %v", err)
	}
	dirOut := stdout.String()
	if strings.Contains(dirOut, "-1 B") || strings.Contains(dirOut, "-9223372036854775808") {
		t.Fatalf("listRemoteOne leaked negative byte size in %q", dirOut)
	}
	if !strings.Contains(dirOut, "16.0 EB") || !strings.Contains(dirOut, "8.0 EB") || !strings.Contains(dirOut, "2.0 KB") {
		t.Fatalf("listRemoteOne output missing expected unsigned sizes: %q", dirOut)
	}

	stdout.Reset()
	if err := sh.listRemoteOne(t.Context(), "/remote/single_neg.bin", true); err != nil {
		t.Fatalf("listRemoteOne(single_neg.bin, long=true) err = %v", err)
	}
	singleOut := stdout.String()
	if strings.Contains(singleOut, "-50 B") {
		t.Fatalf("listRemoteOne(single) leaked negative size in %q", singleOut)
	}
	if !strings.Contains(singleOut, "16.0 EB") {
		t.Fatalf("listRemoteOne(single) output missing expected unsigned size: %q", singleOut)
	}
}

func testP7W13aCheckRemoteStorageSpaceHighBit(t *testing.T) {
	h := newW8aShellTrackingHandler()
	handlers := h.handlers()
	handlers.FileCmd = w13aStatVFSCmder{
		FileCmder: handlers.FileCmd,
		vfs: &pkgsftp.StatVFS{
			Bsize:  4096,
			Frsize: 4096,
			Blocks: math.MaxUint64 / 2048, // saturates TotalStorageSpace to math.MaxUint64 (16.0 EB)
			Bfree:  0,
			Bavail: 0,
		},
	}
	sh := newP7W7bShellWithHandlers(t, handlers, "/", t.TempDir())
	var stdout, stderr bytes.Buffer
	sh.stdout = &stdout
	sh.stderr = &stderr

	sh.checkRemoteStorageSpace(t.Context(), sh.client, "/remote/big.bin", 4096, false)
	out := stdout.String()
	if out == "" {
		t.Fatal("checkRemoteStorageSpace emitted no insufficient-storage warning")
	}
	if strings.Contains(out, "-1 B") || (strings.Contains(out, "-") && strings.Contains(out, " B")) {
		t.Fatalf("checkRemoteStorageSpace emitted negative byte size in %q", out)
	}
	if !strings.Contains(out, "16.0 EB") || !strings.Contains(out, "0 B") {
		t.Fatalf("checkRemoteStorageSpace output = %q, want 0 B free and 16.0 EB total", out)
	}
}

// TestP7W13a_AB13L2_WriteCommandHistoryHandleFirstStaging verifies AB13-L2:
//   - editor_history.go uses handle-first fsx.CreateExclusive (not os.CreateTemp)
//     so Windows applies an explicit SE_DACL_PROTECTED owner-only SD at creation
//     time and Unix creates 0600 O_NOFOLLOW|O_EXCL|O_CLOEXEC staging files.
//   - Staging files are cleaned up on failure without touching an existing
//     destination or leaving .xops-history-* temp files behind.
func TestP7W13a_AB13L2_WriteCommandHistoryHandleFirstStaging(t *testing.T) {
	t.Run("ast_no_os_CreateTemp_and_uses_fsx_CreateExclusive", testP7W13aHistoryASTCheck)
	t.Run("writes_owner_only_and_leaves_no_staging_files", testP7W13aHistoryWriteOwnerOnly)
	t.Run("cleans_up_staging_file_when_rename_fails", testP7W13aHistoryCleanupOnRenameFailure)
}

func testP7W13aHistoryASTCheck(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "editor_history.go", nil, 0)
	if err != nil {
		t.Fatalf("parse editor_history.go: %v", err)
	}
	sawCreateExclusive := false
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if ident.Name == "os" && sel.Sel.Name == "CreateTemp" {
			t.Errorf("editor_history.go still calls os.CreateTemp at line %d", fset.Position(call.Pos()).Line)
		}
		if ident.Name == "fsx" && sel.Sel.Name == "CreateExclusive" {
			sawCreateExclusive = true
		}
		return true
	})
	if !sawCreateExclusive {
		t.Fatal("editor_history.go must stage history files via fsx.CreateExclusive")
	}
}

func testP7W13aHistoryWriteOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	historyPath := filepath.Join(dir, ".xops_sftp_history")
	if err := writeCommandHistory(t.Context(), historyPath, []string{"ls", "pwd"}); err != nil {
		t.Fatalf("writeCommandHistory: %v", err)
	}
	data, err := os.ReadFile(historyPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "ls\npwd\n" {
		t.Fatalf("history content = %q, want %q", string(data), "ls\npwd\n")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Lstat(historyPath)
		if err != nil {
			t.Fatalf("Lstat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != fsx.OwnerOnlyPerm {
			t.Fatalf("history file perm = %04o, want %04o", perm, fsx.OwnerOnlyPerm)
		}
	}
	assertNoLeftoverHistoryStaging(t, dir)
}

func testP7W13aHistoryCleanupOnRenameFailure(t *testing.T) {
	dir := t.TempDir()
	// Make destination a non-empty directory so rename fails on all OSes.
	destDir := filepath.Join(dir, ".xops_sftp_history")
	if err := os.Mkdir(destDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeCommandHistory(t.Context(), destDir, []string{"ls"}); err == nil {
		t.Fatal("writeCommandHistory unexpectedly succeeded over non-empty directory")
	}
	assertNoLeftoverHistoryStaging(t, dir)
}

func assertNoLeftoverHistoryStaging(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".xops-history-") {
			t.Fatalf("leftover staging file: %q", e.Name())
		}
	}
}
