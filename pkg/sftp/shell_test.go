package sftp

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// TestShellRun_ExitsOnContextCancel 验证连接断开（ctx 被取消）后，
// shell 在下一次用户交互时返回 context.Canceled 而非继续 REPL 循环。
// 测试通过管道替换 os.Stdin 驱动 liner 的 fallback 输入路径
// （go test 环境无 TTY，liner.NewLiner 会置 inputRedirected=true）。
func TestShellRun_ExitsOnContextCancel(t *testing.T) {
	i18n.Init("zh")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	oldStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = oldStdin
		_ = r.Close()
	}()

	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: t.TempDir(),
		line:     liner.NewLiner(),
		stdout:   &bytes.Buffer{},
		stderr:   &bytes.Buffer{},
	}
	defer func() { _ = s.line.Close() }()

	ctx, cancel := context.WithCancel(context.Background())

	runDone := make(chan error, 1)
	go func() {
		runDone <- s.Run(ctx)
	}()

	// 模拟连接断开：watcher 检测到断连后取消 ctx
	cancel()

	// 用户按下回车（下一次交互），shell 应立即返回 context.Canceled
	_, _ = w.WriteString("\n")
	_ = w.Close()

	select {
	case err := <-runDone:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shell.Run did not return within 5s after ctx cancelled and enter pressed")
	}
}

// TestShellRun_ContinuesOnCancelledPromptAbort 验证 Ctrl+C 中断提示时若连接正常，
// shell 继续等待输入而非误退出（回归保护）
func TestShellRun_ContinuesOnCancelledPromptAbort(t *testing.T) {
	i18n.Init("zh")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	oldStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = oldStdin
		_ = r.Close()
	}()

	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: t.TempDir(),
		line:     liner.NewLiner(),
		stdout:   &bytes.Buffer{},
		stderr:   &bytes.Buffer{},
	}
	defer func() { _ = s.line.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- s.Run(ctx)
	}()

	// 连接正常时执行本地命令 lpwd，shell 不应退出
	_, _ = w.WriteString("lpwd\n")
	// 给 REPL 一点时间消费输入
	time.Sleep(200 * time.Millisecond)

	select {
	case err := <-runDone:
		t.Fatalf("shell.Run returned unexpectedly: %v", err)
	default:
		// 预期仍在运行
	}

	// 输入 exit 正常退出，Run 应返回 nil
	_, _ = w.WriteString("exit\n")
	_ = w.Close()

	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("expected nil error on normal exit, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shell.Run did not return within 5s after exit command")
	}
}

func TestParseForceFlag(t *testing.T) {
	tests := []struct {
		args      []string
		wantArgs  []string
		wantForce bool
	}{
		{[]string{"file1"}, []string{"file1"}, false},
		{[]string{"-f", "file1"}, []string{"file1"}, true},
		{[]string{"file1", "-f"}, []string{"file1"}, true},
		{[]string{"file1", "file2", "-f"}, []string{"file1", "file2"}, true},
	}
	for _, tt := range tests {
		gotArgs, gotForce := parseForceFlag(tt.args)
		if len(gotArgs) != len(tt.wantArgs) {
			t.Errorf("parseForceFlag(%v) gotArgs = %v, want %v", tt.args, gotArgs, tt.wantArgs)
		} else {
			for i, v := range gotArgs {
				if v != tt.wantArgs[i] {
					t.Errorf("parseForceFlag(%v) gotArgs[%d] = %q, want %q", tt.args, i, v, tt.wantArgs[i])
				}
			}
		}
		if gotForce != tt.wantForce {
			t.Errorf("parseForceFlag(%v) gotForce = %v, want %v", tt.args, gotForce, tt.wantForce)
		}
	}
}

func TestLocalRmWithConfirmation(t *testing.T) {
	i18n.Init("zh")
	dir := t.TempDir()

	// 1. 测试没有 -f 且拒绝删除
	file1 := filepath.Join(dir, "file1")
	_ = os.WriteFile(file1, []byte("test1"), 0644)

	s := &Shell{
		localCwd: dir,
		stdout:   &bytes.Buffer{},
		stderr:   &bytes.Buffer{},
		askConfirmHook: func(prompt string) bool {
			return false // 拒绝确认
		},
	}
	s.handleLocalRm([]string{"file1"})
	if _, err := os.Stat(file1); os.IsNotExist(err) {
		t.Error("expected file1 to still exist when confirmation is denied")
	}

	// 2. 测试没有 -f 且允许删除
	s.askConfirmHook = func(prompt string) bool {
		return true // 同意确认
	}
	s.handleLocalRm([]string{"file1"})
	if _, err := os.Stat(file1); !os.IsNotExist(err) {
		t.Error("expected file1 to be deleted when confirmation is granted")
	}

	// 3. 测试使用 -f 选项强制执行（无需确认，直接删除）
	file2 := filepath.Join(dir, "file2")
	_ = os.WriteFile(file2, []byte("test2"), 0644)
	s.askConfirmHook = func(prompt string) bool {
		t.Error("askConfirmHook should not be called when -f is provided")
		return false
	}
	s.handleLocalRm([]string{"-f", "file2"})
	if _, err := os.Stat(file2); !os.IsNotExist(err) {
		t.Error("expected file2 to be deleted automatically with -f flag")
	}
}

func TestLocalCpWithConfirmation(t *testing.T) {
	i18n.Init("zh")
	dir := t.TempDir()

	srcFile := filepath.Join(dir, "src")
	_ = os.WriteFile(srcFile, []byte("source_content"), 0644)

	// 1. 目标不存在，不需要询问，直接复制
	dstFile1 := filepath.Join(dir, "dst1")
	s := &Shell{
		localCwd: dir,
		stdout:   &bytes.Buffer{},
		stderr:   &bytes.Buffer{},
		askConfirmHook: func(prompt string) bool {
			t.Error("askConfirmHook should not be called when target does not exist")
			return false
		},
	}
	s.handleLocalCp([]string{"src", "dst1"})
	data, err := os.ReadFile(dstFile1)
	if err != nil || string(data) != "source_content" {
		t.Errorf("failed to copy to non-existent dst1: %v", err)
	}

	// 2. 目标已存在，拒绝确认，不覆盖
	_ = os.WriteFile(dstFile1, []byte("original_dst1"), 0644)
	s.askConfirmHook = func(prompt string) bool {
		return false // 拒绝确认
	}
	s.handleLocalCp([]string{"src", "dst1"})
	data, _ = os.ReadFile(dstFile1)
	if string(data) != "original_dst1" {
		t.Error("expected dst1 content to not be overwritten when confirmation is denied")
	}

	// 3. 目标已存在，同意确认，覆盖
	s.askConfirmHook = func(prompt string) bool {
		return true // 同意确认
	}
	s.handleLocalCp([]string{"src", "dst1"})
	data, _ = os.ReadFile(dstFile1)
	if string(data) != "source_content" {
		t.Error("expected dst1 content to be overwritten when confirmation is granted")
	}

	// 4. 目标已存在，有 -f 选项，直接覆盖且不进行询问
	_ = os.WriteFile(dstFile1, []byte("original_dst1"), 0644)
	s.askConfirmHook = func(prompt string) bool {
		t.Error("askConfirmHook should not be called when -f is provided")
		return false
	}
	s.handleLocalCp([]string{"-f", "src", "dst1"})
	data, _ = os.ReadFile(dstFile1)
	if string(data) != "source_content" {
		t.Error("expected dst1 content to be overwritten with -f flag")
	}
}

func TestLocalMvWithConfirmation(t *testing.T) {
	i18n.Init("zh")
	dir := t.TempDir()

	// 1. 目标不存在，不需要询问，直接移动
	srcFile1 := filepath.Join(dir, "src1")
	_ = os.WriteFile(srcFile1, []byte("content1"), 0644)
	dstFile1 := filepath.Join(dir, "dst1")

	s := &Shell{
		localCwd: dir,
		stdout:   &bytes.Buffer{},
		stderr:   &bytes.Buffer{},
		askConfirmHook: func(prompt string) bool {
			t.Error("askConfirmHook should not be called when target does not exist")
			return false
		},
	}
	s.handleLocalMv([]string{"src1", "dst1"})
	if _, err := os.Stat(srcFile1); !os.IsNotExist(err) {
		t.Error("src1 should be moved")
	}
	data, _ := os.ReadFile(dstFile1)
	if string(data) != "content1" {
		t.Errorf("dst1 has wrong content: %s", string(data))
	}

	// 2. 目标已存在，拒绝确认，不覆盖
	srcFile2 := filepath.Join(dir, "src2")
	_ = os.WriteFile(srcFile2, []byte("content2"), 0644)
	_ = os.WriteFile(dstFile1, []byte("original_dst1"), 0644)
	s.askConfirmHook = func(prompt string) bool {
		return false // 拒绝确认
	}
	s.handleLocalMv([]string{"src2", "dst1"})
	if _, err := os.Stat(srcFile2); err != nil {
		t.Error("src2 should not be moved when confirmation is denied")
	}
	data, _ = os.ReadFile(dstFile1)
	if string(data) != "original_dst1" {
		t.Error("dst1 should not be overwritten when confirmation is denied")
	}

	// 3. 目标已存在，同意确认，覆盖
	s.askConfirmHook = func(prompt string) bool {
		return true // 同意确认
	}
	s.handleLocalMv([]string{"src2", "dst1"})
	if _, err := os.Stat(srcFile2); !os.IsNotExist(err) {
		t.Error("src2 should be moved when confirmation is granted")
	}
	data, _ = os.ReadFile(dstFile1)
	if string(data) != "content2" {
		t.Errorf("dst1 should be overwritten with content2, got: %s", string(data))
	}

	// 4. 目标已存在，有 -f 选项，直接覆盖
	srcFile3 := filepath.Join(dir, "src3")
	_ = os.WriteFile(srcFile3, []byte("content3"), 0644)
	s.askConfirmHook = func(prompt string) bool {
		t.Error("askConfirmHook should not be called when -f is provided")
		return false
	}
	s.handleLocalMv([]string{"-f", "src3", "dst1"})
	if _, err := os.Stat(srcFile3); !os.IsNotExist(err) {
		t.Error("src3 should be moved automatically with -f flag")
	}
	data, _ = os.ReadFile(dstFile1)
	if string(data) != "content3" {
		t.Errorf("dst1 should be overwritten with content3, got: %s", string(data))
	}
}
