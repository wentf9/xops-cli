package sftpshell

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWordCompleter_CommandCompletion 验证命令名补全
func TestWordCompleter_CommandCompletion(t *testing.T) {
	s := &Shell{cwd: "/home/user"}

	// 输入 "ex" 时应补全到 "exec" 和 "exit"
	head, completions, tail := s.wordCompleter(context.Background(), "ex", 2)
	if head != "" {
		t.Errorf("head should be empty for command completion, got %q", head)
	}
	if tail != "" {
		t.Errorf("tail should be empty, got %q", tail)
	}
	found := map[string]bool{}
	for _, c := range completions {
		found[c] = true
	}
	if !found["exec"] {
		t.Error("expected 'exec' in completions")
	}
	if !found["exit"] {
		t.Error("expected 'exit' in completions")
	}
}

// TestWordCompleter_NoCompletionForUnknown 验证未知前缀不返回补全
func TestWordCompleter_NoCompletionForUnknown(t *testing.T) {
	s := &Shell{cwd: "/home/user"}

	_, completions, _ := s.wordCompleter(context.Background(), "zzz", 3)
	if len(completions) != 0 {
		t.Errorf("expected no completions for unknown prefix, got %v", completions)
	}
}

// TestWordCompleter_AllCommandsCompletable 验证所有已知命令均可从空前缀补全
func TestWordCompleter_AllCommandsCompletable(t *testing.T) {
	s := &Shell{cwd: "/home/user"}

	_, completions, _ := s.wordCompleter(context.Background(), "", 0)
	if len(completions) == 0 {
		t.Error("expected completions for empty prefix")
	}
	// 验证一些核心命令在列表中
	found := map[string]bool{}
	for _, c := range completions {
		found[c] = true
	}
	for _, expected := range []string{"ls", "cd", "get", "put", "exit"} {
		if !found[expected] {
			t.Errorf("expected command %q in completions", expected)
		}
	}
}

// TestCompleteLocalPath_BasicPrefix 验证本地路径补全的前缀过滤
func TestCompleteLocalPath_BasicPrefix(t *testing.T) {
	s := &Shell{}

	// 目录 "." 下以不可能存在的前缀过滤，应返回空列表
	candidates := s.completeLocalPath("__nonexistent_prefix_xyz__")
	if len(candidates) > 0 {
		t.Error("expected no candidates for nonexistent prefix")
	}
}

// TestWordCompleter_RuneBytePosition 验证多字节中文输入时 rune/byte 位置处理正确
func TestWordCompleter_RuneBytePosition(t *testing.T) {
	s := &Shell{cwd: "/远程目录"}

	input := "cd 目"
	runeLen := len([]rune(input))
	head, _, tail := s.wordCompleter(context.Background(), input, runeLen)
	// tail 应为空（光标在末尾）
	if tail != "" {
		t.Errorf("tail should be empty when cursor at end, got %q", tail)
	}
	// head 应包含 "cd " 前缀
	if !strings.HasPrefix(head, "cd ") {
		t.Errorf("head should start with 'cd ', got %q", head)
	}
}

// TestCompleteLocalPath_DirSuffix 验证补全时目录带分隔符后缀，文件不带后缀
func TestCompleteLocalPath_DirSuffix(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建一个子目录和普通文件
	subDirName := "subdir_test"
	fileName := "file_test.txt"
	if err := os.Mkdir(filepath.Join(tmpDir, subDirName), 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, fileName), []byte("hello"), 0o644); err != nil {
		t.Fatalf("writeFile failed: %v", err)
	}

	s := &Shell{}
	sep := string(filepath.Separator)
	prefix := filepath.Join(tmpDir, "") + sep

	candidates := s.completeLocalPath(prefix)
	if len(candidates) < 2 {
		t.Fatalf("expected at least 2 candidates in temp dir, got %d: %v", len(candidates), candidates)
	}

	foundDir := false
	foundFile := false
	for _, c := range candidates {
		if strings.Contains(c, subDirName) {
			foundDir = true
			if !strings.HasSuffix(c, sep) {
				t.Errorf("directory candidate %q must end with path separator %q", c, sep)
			}
		}
		if strings.Contains(c, fileName) {
			foundFile = true
			if strings.HasSuffix(c, sep) {
				t.Errorf("file candidate %q must not end with path separator %q", c, sep)
			}
		}
	}

	if !foundDir {
		t.Errorf("expected to find directory %q in candidates %v", subDirName, candidates)
	}
	if !foundFile {
		t.Errorf("expected to find file %q in candidates %v", fileName, candidates)
	}
}

// TestIsPureLocalCmd 验证纯本地命令与远程命令分类正确
func TestIsPureLocalCmd(t *testing.T) {
	localCmds := []string{"exit", "quit", "bye", "help", "?", "pwd", "lpwd", "lls", "lll", "lcd", "lmkdir", "lrm", "lcp", "lmv", "lshell", "lexec"}
	for _, c := range localCmds {
		if !isPureLocalCmd(c) {
			t.Errorf("expected isPureLocalCmd(%q) = true", c)
		}
		if requiresRemote(c) {
			t.Errorf("expected requiresRemote(%q) = false", c)
		}
	}

	remoteCmds := []string{"ls", "ll", "cd", "mkdir", "rm", "cp", "mv", "get", "put", "exec", "shell"}
	for _, c := range remoteCmds {
		if isPureLocalCmd(c) {
			t.Errorf("expected isPureLocalCmd(%q) = false", c)
		}
		if !requiresRemote(c) {
			t.Errorf("expected requiresRemote(%q) = true", c)
		}
	}
}
