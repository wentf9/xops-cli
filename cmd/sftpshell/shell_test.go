package sftpshell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/sftp"
	"github.com/wentf9/xops-cli/pkg/ssh"
	"go.uber.org/goleak"
)

func initTestI18n(t *testing.T) {
	t.Helper()
	if err := i18n.Init("zh"); err != nil {
		t.Fatalf("i18n.Init failed: %v", err)
	}
}

func closeTestResource(t *testing.T, closer io.Closer) {
	t.Helper()
	if err := closer.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		t.Fatalf("close test resource failed: %v", err)
	}
}

// verifyNoShellGoroutineLeak excludes readline's process-global SIGWINCH
// dispatcher. readline starts it once and exposes no shutdown API; every
// project-owned goroutine remains subject to goleak verification.
func verifyNoShellGoroutineLeak(t *testing.T) {
	t.Helper()
	goleak.VerifyNone(t,
		goleak.IgnoreCurrent(),
		goleak.IgnoreTopFunction("github.com/chzyer/readline.DefaultOnWidthChanged.func1.1"),
	)
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write test file failed: %v", err)
	}
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read test file failed: %v", err)
	}
	return data
}

type shellFailingWriter struct {
	err error
}

func (w shellFailingWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestDispatchCommandReturnsDisplayError(t *testing.T) {
	wantErr := errors.New("output unavailable")
	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: t.TempDir(),
		stdout:   shellFailingWriter{err: wantErr},
		stderr:   &bytes.Buffer{},
	}

	exit, err := s.dispatchCommand(context.Background(), "pwd", nil)
	if exit {
		t.Fatal("dispatchCommand() exit = true, want false")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("dispatchCommand() error = %v, want wrapped %v", err, wantErr)
	}
}

func TestDispatchCommand(t *testing.T) {
	initTestI18n(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	tempDir := t.TempDir()
	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: tempDir,
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
		{"lrm command", "lrm", []string{"-f", "test_dir"}, false, false, ""},
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
	initTestI18n(t)

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
	initTestI18n(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	dir := t.TempDir()
	for _, name := range []string{"a.go", "b.go", "c.txt"} {
		writeTestFile(t, filepath.Join(dir, name), nil)
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
	initTestI18n(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "only.go"), nil)

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
	initTestI18n(t)

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
	initTestI18n(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	dir := t.TempDir()
	for _, name := range []string{"a.tmp", "b.tmp", "keep.go"} {
		writeTestFile(t, filepath.Join(dir, name), nil)
	}

	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: dir,
		stdout:   &stdout,
		stderr:   &stderr,
	}

	exit, err := s.dispatchCommand(context.Background(), "lrm", []string{"-f", "*.tmp"})
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

func TestDispatchCommandReturnsConfirmationInputError(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "payload"), nil)
	s := &Shell{
		localCwd: dir,
		stdout:   &bytes.Buffer{},
		stderr:   &bytes.Buffer{},
	}

	exit, err := s.dispatchCommand(t.Context(), "lrm", []string{"payload"})
	if exit {
		t.Fatal("dispatchCommand() exit = true, want false")
	}
	if err == nil || !strings.Contains(err.Error(), "line editor") {
		t.Fatalf("dispatchCommand() error = %v, want line editor error", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "payload")); statErr != nil {
		t.Fatalf("confirmation input failure removed payload: %v", statErr)
	}
}

// TestLocalCpWildcard 验证 lcp 命令支持通配符多源复制到目录
func TestLocalCpWildcard(t *testing.T) {
	initTestI18n(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	dir := t.TempDir()
	for _, name := range []string{"a.go", "b.go"} {
		writeTestFile(t, filepath.Join(dir, name), nil)
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
	initTestI18n(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	dir := t.TempDir()
	for _, name := range []string{"a.go", "b.go"} {
		writeTestFile(t, filepath.Join(dir, name), nil)
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
	initTestI18n(t)

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
// shell 无需等待下一次用户交互便返回 context.Canceled。
func TestShellRun_ExitsOnContextCancel(t *testing.T) {
	defer verifyNoShellGoroutineLeak(t)
	initTestI18n(t)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	defer closeTestResource(t, r)

	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: t.TempDir(),
		stdin:    r,
		stdout:   &bytes.Buffer{},
		stderr:   &bytes.Buffer{},
	}
	ctx, cancel := context.WithCancel(context.Background())

	runDone := make(chan error, 1)
	go func() {
		runDone <- s.Run(ctx)
	}()

	// 等待 Readline 确实阻塞在输入上，再模拟连接断开。
	promptDeadline := time.Now().Add(2 * time.Second)
	for {
		editor := s.currentLineEditor()
		if editor != nil && editor.instance.Terminal.IsReading() {
			break
		}
		if time.Now().After(promptDeadline) {
			t.Fatal("shell did not enter blocking prompt")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()

	select {
	case err := <-runDone:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shell.Run did not return within 5s after ctx cancellation")
	}
	closeTestResource(t, w)
}

// TestShellRun_ContinuesOnCancelledPromptAbort 验证 Ctrl+C 中断提示时若连接正常，
// shell 继续等待输入而非误退出（回归保护）
func TestShellRun_ContinuesOnCancelledPromptAbort(t *testing.T) {
	initTestI18n(t)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	defer closeTestResource(t, r)

	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: t.TempDir(),
		stdin:    r,
		stdout:   &bytes.Buffer{},
		stderr:   &bytes.Buffer{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- s.Run(ctx)
	}()

	// 连接正常时执行本地命令 lpwd，shell 不应退出
	if _, err := w.WriteString("lpwd\n"); err != nil {
		t.Fatalf("write lpwd command failed: %v", err)
	}
	// 给 REPL 一点时间消费输入
	time.Sleep(200 * time.Millisecond)

	select {
	case err := <-runDone:
		t.Fatalf("shell.Run returned unexpectedly: %v", err)
	default:
		// 预期仍在运行
	}

	// 输入 exit 正常退出，Run 应返回 nil
	if _, err := w.WriteString("exit\n"); err != nil {
		t.Fatalf("write exit command failed: %v", err)
	}
	closeTestResource(t, w)

	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("expected nil error on normal exit, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shell.Run did not return within 5s after exit command")
	}
}

func TestShellRun_RejectsConcurrentRun(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create input pipe failed: %v", err)
	}
	defer closeTestResource(t, r)
	defer closeTestResource(t, w)

	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: t.TempDir(),
		stdin:    r,
		stdout:   &bytes.Buffer{},
		stderr:   &bytes.Buffer{},
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- s.Run(ctx)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		editor := s.currentLineEditor()
		if editor != nil && editor.instance.Terminal.IsReading() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first shell run did not enter a prompt")
		}
		time.Sleep(time.Millisecond)
	}

	err = s.Run(t.Context())
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second Run() error = %v, want already running", err)
	}
	cancel()
	select {
	case runErr := <-firstDone:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("first Run() error = %v, want context.Canceled", runErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first shell Run did not return after cancellation")
	}
}

func TestShellClose_CancelsActiveRunAndPreventsRestart(t *testing.T) {
	defer verifyNoShellGoroutineLeak(t)

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create input pipe failed: %v", err)
	}
	defer closeTestResource(t, reader)
	defer closeTestResource(t, writer)

	shell := &Shell{
		cwd:      "/",
		localCwd: t.TempDir(),
		stdin:    reader,
		stdout:   &bytes.Buffer{},
		stderr:   &bytes.Buffer{},
	}
	runDone := make(chan error, 1)
	go func() {
		runDone <- shell.Run(context.Background())
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		editor := shell.currentLineEditor()
		if editor != nil && editor.instance.Terminal.IsReading() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("shell did not enter a prompt")
		}
		time.Sleep(time.Millisecond)
	}

	closeCtx, cancelClose := context.WithTimeout(t.Context(), time.Second)
	defer cancelClose()
	if err := shell.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}
	select {
	case err := <-runDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not return after Close")
	}
	if err := shell.Run(t.Context()); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("Run() after Close error = %v, want closed error", err)
	}
	if err := shell.Close(t.Context()); err != nil {
		t.Fatalf("second Close() error = %v, want nil", err)
	}
}

func TestShellClose_PreventsLazyEditorPublication(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create input pipe failed: %v", err)
	}
	defer closeTestResource(t, reader)
	defer closeTestResource(t, writer)

	editorCreationStarted := make(chan struct{})
	allowEditorCreation := make(chan struct{})
	shell := &Shell{
		cwd:      "/",
		localCwd: t.TempDir(),
		stdin:    reader,
		stdout:   &bytes.Buffer{},
		stderr:   &bytes.Buffer{},
		newLineEditorFn: func(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, historyFile string, shell *Shell) (*lineEditor, error) {
			close(editorCreationStarted)
			<-allowEditorCreation
			return newLineEditor(ctx, stdin, stdout, stderr, historyFile, shell)
		},
	}
	runDone := make(chan error, 1)
	go func() {
		runDone <- shell.Run(context.Background())
	}()
	select {
	case <-editorCreationStarted:
	case <-time.After(time.Second):
		t.Fatal("shell did not begin lazy line-editor creation")
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- shell.Close(t.Context())
	}()
	deadline := time.Now().Add(time.Second)
	for {
		err := shell.Run(t.Context())
		if err != nil && strings.Contains(err.Error(), "closed") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Shell did not become terminal before lazy editor returned, Run() error = %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	close(allowEditorCreation)

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close() error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close() did not finish after lazy editor creation returned")
	}
	select {
	case err := <-runDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not finish after Close")
	}
	if editor := shell.currentLineEditor(); editor != nil {
		t.Fatal("line editor was published after Shell became closed")
	}
}

func TestShellRun_CancelDuringLazyEditorCreationPreventsPublication(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create input pipe failed: %v", err)
	}
	defer closeTestResource(t, reader)
	defer closeTestResource(t, writer)

	creationStarted := make(chan struct{})
	shell := &Shell{
		cwd:      "/",
		localCwd: t.TempDir(),
		stdin:    reader,
		stdout:   &bytes.Buffer{},
		stderr:   &bytes.Buffer{},
		newLineEditorFn: func(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, historyFile string, shell *Shell) (*lineEditor, error) {
			close(creationStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runDone := make(chan error, 1)
	go func() {
		runDone <- shell.Run(ctx)
	}()
	select {
	case <-creationStarted:
	case <-time.After(time.Second):
		t.Fatal("shell did not start line editor creation")
	}
	cancel()
	select {
	case runErr := <-runDone:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("Run() error = %v, want context.Canceled", runErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not return after canceling line editor creation")
	}
	if editor := shell.currentLineEditor(); editor != nil {
		t.Fatal("line editor was published after canceled creation")
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
	initTestI18n(t)
	dir := t.TempDir()

	// 1. 测试没有 -f 且拒绝删除
	file1 := filepath.Join(dir, "file1")
	writeTestFile(t, file1, []byte("test1"))

	s := &Shell{
		localCwd: dir,
		stdout:   &bytes.Buffer{},
		stderr:   &bytes.Buffer{},
		askConfirmHook: func(prompt string) bool {
			return false // 拒绝确认
		},
	}
	s.handleLocalRm(t.Context(), []string{"file1"})
	if _, err := os.Stat(file1); os.IsNotExist(err) {
		t.Error("expected file1 to still exist when confirmation is denied")
	}

	// 2. 测试没有 -f 且允许删除
	s.askConfirmHook = func(prompt string) bool {
		return true // 同意确认
	}
	s.handleLocalRm(t.Context(), []string{"file1"})
	if _, err := os.Stat(file1); !os.IsNotExist(err) {
		t.Error("expected file1 to be deleted when confirmation is granted")
	}

	// 3. 测试使用 -f 选项强制执行（无需确认，直接删除）
	file2 := filepath.Join(dir, "file2")
	writeTestFile(t, file2, []byte("test2"))
	s.askConfirmHook = func(prompt string) bool {
		t.Error("askConfirmHook should not be called when -f is provided")
		return false
	}
	s.handleLocalRm(t.Context(), []string{"-f", "file2"})
	if _, err := os.Stat(file2); !os.IsNotExist(err) {
		t.Error("expected file2 to be deleted automatically with -f flag")
	}
}

func TestLocalCpWithConfirmation(t *testing.T) {
	initTestI18n(t)
	dir := t.TempDir()

	srcFile := filepath.Join(dir, "src")
	writeTestFile(t, srcFile, []byte("source_content"))

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
	s.handleLocalCp(t.Context(), []string{"src", "dst1"})
	data, err := os.ReadFile(dstFile1)
	if err != nil || string(data) != "source_content" {
		t.Errorf("failed to copy to non-existent dst1: %v", err)
	}

	// 2. 目标已存在，拒绝确认，不覆盖
	writeTestFile(t, dstFile1, []byte("original_dst1"))
	s.askConfirmHook = func(prompt string) bool {
		return false // 拒绝确认
	}
	s.handleLocalCp(t.Context(), []string{"src", "dst1"})
	data = readTestFile(t, dstFile1)
	if string(data) != "original_dst1" {
		t.Error("expected dst1 content to not be overwritten when confirmation is denied")
	}

	// 3. 目标已存在，同意确认，覆盖
	s.askConfirmHook = func(prompt string) bool {
		return true // 同意确认
	}
	s.handleLocalCp(t.Context(), []string{"src", "dst1"})
	data = readTestFile(t, dstFile1)
	if string(data) != "source_content" {
		t.Error("expected dst1 content to be overwritten when confirmation is granted")
	}

	// 4. 目标已存在，有 -f 选项，直接覆盖且不进行询问
	writeTestFile(t, dstFile1, []byte("original_dst1"))
	s.askConfirmHook = func(prompt string) bool {
		t.Error("askConfirmHook should not be called when -f is provided")
		return false
	}
	s.handleLocalCp(t.Context(), []string{"-f", "src", "dst1"})
	data = readTestFile(t, dstFile1)
	if string(data) != "source_content" {
		t.Error("expected dst1 content to be overwritten with -f flag")
	}
}

func TestCopyLocal_PreservesSymbolicLinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	writeTestFile(t, target, []byte("target"))

	t.Run("relative link", func(t *testing.T) {
		src := filepath.Join(dir, "relative-link")
		dst := filepath.Join(dir, "relative-copy")
		if err := os.Symlink("target.txt", src); err != nil {
			t.Fatalf("create source symlink: %v", err)
		}
		if err := copyLocal(src, dst); err != nil {
			t.Fatalf("copyLocal failed: %v", err)
		}
		info, err := os.Lstat(dst)
		if err != nil {
			t.Fatalf("lstat copied symlink: %v", err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("copied entry mode %v is not a symlink", info.Mode())
		}
		gotTarget, err := os.Readlink(dst)
		if err != nil {
			t.Fatalf("read copied symlink: %v", err)
		}
		if gotTarget != "target.txt" {
			t.Fatalf("got target %q, want %q", gotTarget, "target.txt")
		}
	})

	t.Run("dangling link in directory", func(t *testing.T) {
		srcDir := filepath.Join(dir, "src-dir")
		dstDir := filepath.Join(dir, "dst-dir")
		if err := os.Mkdir(srcDir, 0o755); err != nil {
			t.Fatalf("create source directory: %v", err)
		}
		if err := os.Symlink("missing.txt", filepath.Join(srcDir, "dangling")); err != nil {
			t.Fatalf("create dangling symlink: %v", err)
		}
		if err := copyLocal(srcDir, dstDir); err != nil {
			t.Fatalf("copyLocal directory failed: %v", err)
		}
		gotTarget, err := os.Readlink(filepath.Join(dstDir, "dangling"))
		if err != nil {
			t.Fatalf("read copied dangling symlink: %v", err)
		}
		if gotTarget != "missing.txt" {
			t.Fatalf("got target %q, want %q", gotTarget, "missing.txt")
		}
	})
}

func TestLocalMvWithConfirmation(t *testing.T) {
	initTestI18n(t)
	dir := t.TempDir()

	// 1. 目标不存在，不需要询问，直接移动
	srcFile1 := filepath.Join(dir, "src1")
	writeTestFile(t, srcFile1, []byte("content1"))
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
	s.handleLocalMv(t.Context(), []string{"src1", "dst1"})
	if _, err := os.Stat(srcFile1); !os.IsNotExist(err) {
		t.Error("src1 should be moved")
	}
	data := readTestFile(t, dstFile1)
	if string(data) != "content1" {
		t.Errorf("dst1 has wrong content: %s", string(data))
	}

	// 2. 目标已存在，拒绝确认，不覆盖
	srcFile2 := filepath.Join(dir, "src2")
	writeTestFile(t, srcFile2, []byte("content2"))
	writeTestFile(t, dstFile1, []byte("original_dst1"))
	s.askConfirmHook = func(prompt string) bool {
		return false // 拒绝确认
	}
	s.handleLocalMv(t.Context(), []string{"src2", "dst1"})
	if _, err := os.Stat(srcFile2); err != nil {
		t.Error("src2 should not be moved when confirmation is denied")
	}
	data = readTestFile(t, dstFile1)
	if string(data) != "original_dst1" {
		t.Error("dst1 should not be overwritten when confirmation is denied")
	}

	// 3. 目标已存在，同意确认，覆盖
	s.askConfirmHook = func(prompt string) bool {
		return true // 同意确认
	}
	s.handleLocalMv(t.Context(), []string{"src2", "dst1"})
	if _, err := os.Stat(srcFile2); !os.IsNotExist(err) {
		t.Error("src2 should be moved when confirmation is granted")
	}
	data = readTestFile(t, dstFile1)
	if string(data) != "content2" {
		t.Errorf("dst1 should be overwritten with content2, got: %s", string(data))
	}

	// 4. 目标已存在，有 -f 选项，直接覆盖
	srcFile3 := filepath.Join(dir, "src3")
	writeTestFile(t, srcFile3, []byte("content3"))
	s.askConfirmHook = func(prompt string) bool {
		t.Error("askConfirmHook should not be called when -f is provided")
		return false
	}
	s.handleLocalMv(t.Context(), []string{"-f", "src3", "dst1"})
	if _, err := os.Stat(srcFile3); !os.IsNotExist(err) {
		t.Error("src3 should be moved automatically with -f flag")
	}
	data = readTestFile(t, dstFile1)
	if string(data) != "content3" {
		t.Errorf("dst1 should be overwritten with content3, got: %s", string(data))
	}
}

// TestEnsureClient_NilSSHClientFailure 验证当 sshClient 为 nil 时 ensureClient 正确返回错误且不 panic
func TestEnsureClient_NilSSHClientFailure(t *testing.T) {
	s := &Shell{
		client:    nil,
		sshClient: nil,
	}

	err := s.ensureClient(context.Background())
	if err == nil {
		t.Fatal("expected error from ensureClient when sshClient is nil")
	}
	if !strings.Contains(err.Error(), "sftp shell SSH client is nil") {
		t.Errorf("expected error message to contain 'sftp shell SSH client is nil', got: %v", err)
	}
}

// TestDispatchCommand_PureLocalWithNilClient 验证即使 client 为 nil 时，纯本地命令和退出命令依然可以正常调度
func TestDispatchCommand_PureLocalWithNilClient(t *testing.T) {
	var stdout, stderr bytes.Buffer
	s := &Shell{
		client:   nil,
		cwd:      "/remote/path",
		localCwd: t.TempDir(),
		stdout:   &stdout,
		stderr:   &stderr,
	}

	// 1. exit / quit 应返回 exit=true, err=nil
	exit, err := s.dispatchCommand(context.Background(), "exit", nil)
	if !exit || err != nil {
		t.Errorf("expected exit=true, err=nil for 'exit', got exit=%v, err=%v", exit, err)
	}

	// 2. lpwd 应该正常输出本地路径
	exit, err = s.dispatchCommand(context.Background(), "lpwd", nil)
	if exit || err != nil {
		t.Errorf("expected exit=false, err=nil for 'lpwd', got exit=%v, err=%v", exit, err)
	}
	if !strings.Contains(stdout.String(), s.localCwd) {
		t.Errorf("expected stdout to contain local cwd %q, got: %s", s.localCwd, stdout.String())
	}

	// 3. help 应该正常输出
	stdout.Reset()
	exit, err = s.dispatchCommand(context.Background(), "help", nil)
	if exit || err != nil {
		t.Errorf("expected exit=false, err=nil for 'help', got exit=%v, err=%v", exit, err)
	}
	if stdout.Len() == 0 {
		t.Error("expected help output on stdout")
	}
}

// TestEnsureClient_ReconnectRetryLifecycle 验证：
// 1. 首次重连失败，s.client 保持 nil，不 panic。
// 2. 第二次重连成功，s.client 正确更新。
// 3. 两次尝试使用完全一致的 TransferConfig，且 noOverwrite 未混入 pkg 配置。
func TestEnsureClient_ReconnectRetryLifecycle(t *testing.T) {
	var callCount int
	var capturedOptions [][]sftp.Option

	expectedConfig := sftp.TransferConfig{
		Force:           true,
		ConcurrentFiles: 5,
		ThreadsPerFile:  3,
		ChunkSize:       64 * 1024,
		EnableResume:    true,
		ResumeMinSize:   1024,
	}

	dummyClient := &sftp.Client{}

	mockFactory := func(ctx context.Context, sshCli *ssh.Client, opts ...sftp.Option) (*sftp.Client, error) {
		callCount++
		capturedOptions = append(capturedOptions, opts)
		if callCount == 1 {
			return nil, errors.New("simulated temporary network timeout")
		}
		return dummyClient, nil
	}

	s := &Shell{
		sshClient:      &ssh.Client{},
		transferConfig: expectedConfig,
		noOverwrite:    true, // presentation-layer only
		newClientFn:    mockFactory,
	}

	// 1. 第一次调用：重连失败
	err1 := s.ensureClient(context.Background())
	if err1 == nil {
		t.Fatal("expected error on 1st reconnect attempt, got nil")
	}
	if !strings.Contains(err1.Error(), "simulated temporary network timeout") {
		t.Errorf("unexpected error: %v", err1)
	}
	if s.client != nil {
		t.Error("expected s.client to remain nil after failed reconnect attempt")
	}

	// 2. 第二次调用：重连成功
	err2 := s.ensureClient(context.Background())
	if err2 != nil {
		t.Fatalf("expected success on 2nd reconnect attempt, got: %v", err2)
	}
	if s.client != dummyClient {
		t.Error("expected s.client to be updated to dummyClient on successful reconnect")
	}

	if callCount != 2 {
		t.Errorf("expected 2 factory calls, got %d", callCount)
	}

	// 4. 断言两次重连尝试传递的 Options 应用后完全等于 expectedConfig
	if len(capturedOptions) != 2 {
		t.Fatalf("expected 2 captured options sets, got %d", len(capturedOptions))
	}
	for i, opts := range capturedOptions {
		evalCli := &sftp.Client{}
		for _, opt := range opts {
			opt(evalCli)
		}
		if evalCli.Config() != expectedConfig {
			t.Errorf("call %d: expected evaluated config %+v, got %+v", i+1, expectedConfig, evalCli.Config())
		}
	}
}

// TestShell_ConcurrentOperations_Race 验证并发执行 completion、重连和 context 更新时无数据竞争
func TestShell_ConcurrentOperations_Race(t *testing.T) {
	dummyClient := &sftp.Client{}
	s := &Shell{
		sshClient: &ssh.Client{},
		newClientFn: func(ctx context.Context, sshCli *ssh.Client, opts ...sftp.Option) (*sftp.Client, error) {
			return dummyClient, nil
		},
	}

	errCh := make(chan error, 30)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := s.ensureClient(context.Background()); err != nil {
				errCh <- err
			}
		}()
		go func() {
			defer wg.Done()
			s.clientMu.RLock()
			cli := s.client
			s.clientMu.RUnlock()
			if cli != nil && cli != dummyClient {
				errCh <- errors.New("unexpected client reference")
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("race test error: %v", err)
	}
}

// TestShell_ConcurrentAcquireAndReconnect 验证并发执行 acquireClient/releaseClient 与 ensureClient 重连时安全无竞态
func TestShell_ConcurrentAcquireAndReconnect(t *testing.T) {
	dummyClient := &sftp.Client{}
	s := &Shell{
		sshClient: &ssh.Client{},
		newClientFn: func(ctx context.Context, sshCli *ssh.Client, opts ...sftp.Option) (*sftp.Client, error) {
			return dummyClient, nil
		},
		cwd: "/remote/test",
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 60)

	for i := 0; i < 20; i++ {
		wg.Add(3)
		// 1. 并发 acquireClient 使用并释放
		go func() {
			defer wg.Done()
			cli, release, err := s.acquireClient(context.Background())
			if err != nil {
				errCh <- err
				return
			}
			defer release()
			_ = cli.Config()
			_ = s.resolvePath("file.txt")
		}()

		// 2. 并发补全
		go func() {
			defer wg.Done()
			_ = s.completeRemotePath(context.Background(), "sub")
		}()

		// 3. 并发重连
		go func() {
			defer wg.Done()
			if err := s.ensureClient(context.Background()); err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent acquire/reconnect error: %v", err)
	}
}

func TestEnsureClient_DoesNotHoldStateLockDuringClientCreation(t *testing.T) {
	createStarted := make(chan struct{})
	allowCreate := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := &Shell{
		sshClient: &ssh.Client{},
		newClientFn: func(ctx context.Context, sshCli *ssh.Client, opts ...sftp.Option) (*sftp.Client, error) {
			close(createStarted)
			select {
			case <-allowCreate:
				return &sftp.Client{}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}

	ensureDone := make(chan error, 1)
	go func() {
		ensureDone <- s.ensureClient(ctx)
	}()
	<-createStarted

	configDone := make(chan struct{})
	go func() {
		_ = s.clientConfig()
		close(configDone)
	}()
	select {
	case <-configDone:
	case <-time.After(time.Second):
		cancel()
		close(allowCreate)
		<-ensureDone
		<-configDone
		t.Fatal("clientConfig blocked while client creation was in progress")
	}

	close(allowCreate)
	if err := <-ensureDone; err != nil {
		t.Fatalf("ensureClient() error = %v", err)
	}
}

func TestShellClose_WaitsForLeasesAndBecomesTerminal(t *testing.T) {
	dummyClient := &sftp.Client{}
	s := &Shell{
		sshClient: &ssh.Client{},
		newClientFn: func(context.Context, *ssh.Client, ...sftp.Option) (*sftp.Client, error) {
			return dummyClient, nil
		},
	}

	_, release, err := s.acquireClient(context.Background())
	if err != nil {
		t.Fatalf("acquireClient() error = %v", err)
	}
	closeCtx, cancelClose := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelClose()
	if err := s.Close(closeCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close() error = %v, want context deadline exceeded", err)
	}

	release()
	if err := s.Close(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close() after releasing lease error = %v, want terminal close error", err)
	}
	if _, _, err := s.acquireClient(context.Background()); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("acquireClient() after Close error = %v, want closed error", err)
	}
}

func TestShellClose_TimeoutDuringClientTransitionBecomesTerminal(t *testing.T) {
	creationStarted := make(chan struct{})
	allowCreationReturn := make(chan struct{})
	s := &Shell{
		sshClient: &ssh.Client{},
		newClientFn: func(context.Context, *ssh.Client, ...sftp.Option) (*sftp.Client, error) {
			close(creationStarted)
			<-allowCreationReturn
			return nil, fmt.Errorf("test client creation stopped")
		},
	}

	ensureDone := make(chan error, 1)
	go func() {
		ensureDone <- s.ensureClient(context.Background())
	}()
	<-creationStarted

	closeCtx, cancelClose := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelClose()
	if err := s.Close(closeCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close() error = %v, want context deadline exceeded", err)
	}
	if _, _, err := s.acquireClient(context.Background()); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("acquireClient() after timed out Close error = %v, want closed error", err)
	}

	close(allowCreationReturn)
	if err := <-ensureDone; err == nil || !strings.Contains(err.Error(), "test client creation stopped") {
		t.Fatalf("ensureClient() error = %v, want client creation error", err)
	}
}

func TestAcquireClient_AllowsConcurrentLeases(t *testing.T) {
	dummyClient := &sftp.Client{}
	s := &Shell{client: dummyClient}

	first, releaseFirst, err := s.acquireClient(context.Background())
	if err != nil {
		t.Fatalf("first acquireClient() error = %v", err)
	}
	second, releaseSecond, err := s.acquireClient(context.Background())
	if err != nil {
		releaseFirst()
		t.Fatalf("second acquireClient() error = %v", err)
	}
	if first != dummyClient || second != dummyClient {
		t.Fatal("concurrent leases did not use the current client")
	}

	s.clientMu.RLock()
	leaseCount := s.clientUses[dummyClient].count
	s.clientMu.RUnlock()
	if leaseCount != 2 {
		t.Fatalf("active lease count = %d, want 2", leaseCount)
	}
	releaseSecond()
	releaseFirst()
}
