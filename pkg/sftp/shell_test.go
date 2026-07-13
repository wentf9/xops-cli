package sftp

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peterh/liner"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

func TestDispatchCommand(t *testing.T) {
	i18n.Init("zh")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	// liner.NewLiner() 在非 TTY 环境下可能无法正常工作，
	// 但由于 dispatchCommand 及其调用的具体 Handler 并不直接使用 line 成员（Run 和 askConfirmation 除外），
	// 我们可以在测试中使用一个空的 liner 实例或 nil。
	// 为了安全起见，这里创建一个 liner 实例并确保关闭。
	line := liner.NewLiner()
	defer func() { _ = line.Close() }()

	tempDir := t.TempDir()
	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: tempDir,
		line:     line,
		stdout:   &stdout,
		stderr:   &stderr,
	}

	tests := []struct {
		name       string
		cmd        string
		params     []string
		wantExit   bool
		wantErr    bool
		wantOutput string
	}{
		{"exit command", "exit", nil, true, false, ""},
		{"quit command", "quit", nil, true, false, ""},
		{"bye command", "bye", nil, true, false, ""},
		{"pwd command", "pwd", nil, false, false, "/test/remote/dir\n"},
		{"lpwd command", "lpwd", nil, false, false, tempDir},
		{"help command", "help", nil, false, false, "可用命令:"},
		{"lmkdir command", "lmkdir", []string{"test_dir"}, false, false, ""},
		{"lcp command", "lcp", []string{"test_file", "test_file_cp"}, false, false, ""},
		{"lmv command", "lmv", []string{"test_file_cp", "test_file_mv"}, false, false, ""},
		{"lrm command", "lrm", []string{"test_dir"}, false, false, ""},
		{"unknown command", "unknown_cmd", nil, false, false, "未知命令: unknown_cmd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout.Reset()
			stderr.Reset()

			exit, err := s.dispatchCommand(context.Background(), tt.cmd, tt.params)
			if exit != tt.wantExit {
				t.Errorf("dispatchCommand() exit = %v, want %v", exit, tt.wantExit)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("dispatchCommand() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Validate outputs
			out := stdout.String()
			errout := stderr.String()

			if tt.name == "unknown command" {
				if !strings.Contains(errout, tt.wantOutput) {
					t.Errorf("stderr output = %q, want it to contain %q", errout, tt.wantOutput)
				}
			} else if tt.cmd == "pwd" || tt.cmd == "help" || tt.cmd == "lpwd" {
				if !strings.Contains(out, tt.wantOutput) {
					t.Errorf("stdout output = %q, want it to contain %q", out, tt.wantOutput)
				}
			}
		})
	}
}

func TestHandlePut_NonExistentFile(t *testing.T) {
	i18n.Init("zh")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: t.TempDir(),
		stdout:   &stdout,
		stderr:   &stderr,
	}

	exit, err := s.dispatchCommand(context.Background(), "put", []string{"nonexistent_file_xyz_123"})
	if exit {
		t.Error("expected exit to be false")
	}
	if err != nil {
		t.Errorf("expected no error returned, got %v", err)
	}

	errout := stderr.String()
	if !strings.Contains(errout, "上传失败") {
		t.Errorf("expected stderr to contain '上传失败', got %q", errout)
	}
}

// TestLocalLsWildcard 验证 lls 命令支持通配符展开
func TestLocalLsWildcard(t *testing.T) {
	i18n.Init("zh")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	dir := t.TempDir()
	for _, name := range []string{"a.go", "b.go", "c.txt"} {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}

	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: dir,
		stdout:   &stdout,
		stderr:   &stderr,
	}

	// lls *.go 应列出 a.go 和 b.go，不列出 c.txt
	exit, err := s.dispatchCommand(context.Background(), "lls", []string{"*.go"})
	if exit {
		t.Error("expected exit to be false")
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "a.go") || !strings.Contains(out, "b.go") {
		t.Errorf("expected stdout to contain a.go and b.go, got %q", out)
	}
	if strings.Contains(out, "c.txt") {
		t.Errorf("expected stdout NOT to contain c.txt, got %q", out)
	}
}

// TestLocalLsWildcardSingleFile 验证通配符匹配到单个文件时显示文件名而非报错
// (回归测试：此前 ReadDir 对文件路径报 "file does not exist")
func TestLocalLsWildcardSingleFile(t *testing.T) {
	i18n.Init("zh")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "only.go"))
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: dir,
		stdout:   &stdout,
		stderr:   &stderr,
	}

	exit, err := s.dispatchCommand(context.Background(), "lls", []string{"only.go"})
	if exit {
		t.Error("expected exit to be false")
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	out := stdout.String()
	errout := stderr.String()
	if !strings.Contains(out, "only.go") {
		t.Errorf("expected stdout to contain 'only.go', got %q", out)
	}
	if errout != "" {
		t.Errorf("expected empty stderr, got %q", errout)
	}
}

// TestLocalLsWildcardNoMatch 验证无匹配时报错
func TestLocalLsWildcardNoMatch(t *testing.T) {
	i18n.Init("zh")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	dir := t.TempDir()
	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: dir,
		stdout:   &stdout,
		stderr:   &stderr,
	}

	exit, err := s.dispatchCommand(context.Background(), "lls", []string{"*.nomatch"})
	if exit {
		t.Error("expected exit to be false")
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	errout := stderr.String()
	if !strings.Contains(errout, "未找到匹配项") {
		t.Errorf("expected stderr to contain '未找到匹配项', got %q", errout)
	}
}

// TestLocalRmWildcard 验证 lrm 命令支持通配符批量删除
func TestLocalRmWildcard(t *testing.T) {
	i18n.Init("zh")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	dir := t.TempDir()
	for _, name := range []string{"a.tmp", "b.tmp", "keep.go"} {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}

	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: dir,
		stdout:   &stdout,
		stderr:   &stderr,
	}

	exit, err := s.dispatchCommand(context.Background(), "lrm", []string{"*.tmp"})
	if exit {
		t.Error("expected exit to be false")
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// .tmp 文件应被删除，keep.go 应保留
	if _, err := os.Stat(filepath.Join(dir, "a.tmp")); !os.IsNotExist(err) {
		t.Errorf("expected a.tmp to be deleted, got err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "b.tmp")); !os.IsNotExist(err) {
		t.Errorf("expected b.tmp to be deleted, got err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "keep.go")); err != nil {
		t.Errorf("expected keep.go to remain, got err=%v", err)
	}
}

// TestLocalCpWildcard 验证 lcp 命令支持通配符多源复制到目录
func TestLocalCpWildcard(t *testing.T) {
	i18n.Init("zh")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	dir := t.TempDir()
	for _, name := range []string{"a.go", "b.go"} {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	dstDir := filepath.Join(dir, "sub")
	if err := os.Mkdir(dstDir, 0o755); err != nil {
		t.Fatal(err)
	}

	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: dir,
		stdout:   &stdout,
		stderr:   &stderr,
	}

	exit, err := s.dispatchCommand(context.Background(), "lcp", []string{"*.go", "sub"})
	if exit {
		t.Error("expected exit to be false")
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// 验证 sub/a.go 和 sub/b.go 存在
	if _, err := os.Stat(filepath.Join(dstDir, "a.go")); err != nil {
		t.Errorf("expected sub/a.go to exist, got err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "b.go")); err != nil {
		t.Errorf("expected sub/b.go to exist, got err=%v", err)
	}
}

// TestLocalCpWildcardDestNotDir 验证多源时目标非目录报错
func TestLocalCpWildcardDestNotDir(t *testing.T) {
	i18n.Init("zh")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	dir := t.TempDir()
	for _, name := range []string{"a.go", "b.go"} {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}

	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: dir,
		stdout:   &stdout,
		stderr:   &stderr,
	}

	// 多源复制到不存在的路径应报错
	exit, err := s.dispatchCommand(context.Background(), "lcp", []string{"*.go", "nonexistent_dst"})
	if exit {
		t.Error("expected exit to be false")
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	errout := stderr.String()
	if !strings.Contains(errout, "目标必须是已存在的目录") {
		t.Errorf("expected stderr to contain dest_must_be_dir message, got %q", errout)
	}
}

// TestLocalCdWildcardMultiple 验证 lcd 通配符多匹配报错
func TestLocalCdWildcardMultiple(t *testing.T) {
	i18n.Init("zh")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	dir := t.TempDir()
	for _, name := range []string{"sub1", "sub2"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: dir,
		stdout:   &stdout,
		stderr:   &stderr,
	}

	// lcd sub* 匹配两个目录应报错
	exit, err := s.dispatchCommand(context.Background(), "lcd", []string{"sub*"})
	if exit {
		t.Error("expected exit to be false")
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	errout := stderr.String()
	if !strings.Contains(errout, "匹配到") || !strings.Contains(errout, "个路径") {
		t.Errorf("expected stderr to contain multiple match error, got %q", errout)
	}
}
