package sftpshell

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	pkgsftp "github.com/pkg/sftp"
)

// wordCompleter 计算光标位置对应的命令或路径补全候选
func (s *Shell) wordCompleter(ctx context.Context, line string, pos int) (head string, completions []string, tail string, err error) {
	// line editor 传入的 pos 是 rune 位置，需要转换为字节位置来切分字符串
	runes := []rune(line)
	if pos < 0 || pos > len(runes) {
		return "", nil, "", fmt.Errorf("completion cursor out of range")
	}
	content := string(runes[:pos])
	tail = string(runes[pos:])

	// 场景1：补全命令名（行首无空格）
	if !strings.Contains(content, " ") {
		cmds := []string{"exit", "quit", "bye", "help", "?", "pwd", "lpwd", "ls", "ll", "lls", "lll", "cd", "lcd", "mkdir", "lmkdir", "rm", "lrm", "cp", "lcp", "mv", "lmv", "get", "put", "exec", "lexec", "shell", "lshell"}
		for _, c := range cmds {
			if strings.HasPrefix(c, content) {
				completions = append(completions, c)
			}
		}
		return "", completions, tail, nil
	}

	// 场景2：补全命令参数
	parts := strings.Fields(content)
	if len(parts) < 1 {
		return line, nil, "", nil
	}

	cmd := parts[0]
	var partial string
	if !strings.HasSuffix(content, " ") {
		partial = parts[len(parts)-1]
	}

	// 计算出不参与本次补全的前缀部分
	prefixLen := len(content) - len(partial)
	head = content[:prefixLen]

	switch cmd {
	case "cd", "ls", "ll", "get", "mkdir", "rm", "cp", "mv":
		completions, err = s.completeRemotePath(ctx, partial)
	case "lcd", "lls", "lll", "put", "lmkdir", "lrm", "lcp", "lmv":
		completions, err = s.completeLocalPath(partial)
	}

	return head, completions, tail, err
}

// completeRemotePath 补全远程路径
func (s *Shell) completeRemotePath(ctx context.Context, partial string) ([]string, error) {
	if ctx == nil {
		return nil, fmt.Errorf("completion context is nil")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	cli, release, err := s.acquireClient(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	var dir, prefix string
	if lastSlash := strings.LastIndex(partial, "/"); lastSlash >= 0 {
		dir = partial[:lastSlash+1]
		prefix = partial[lastSlash+1:]
	} else {
		dir = s.cwd
		prefix = partial
	}

	targetDir := dir
	if !strings.HasPrefix(targetDir, "/") {
		targetDir = cli.JoinPath(s.cwd, targetDir)
	}

	var entries []os.FileInfo
	err = cli.Do(ctx, func(c *pkgsftp.Client) error {
		var readErr error
		entries, readErr = c.ReadDir(targetDir)
		return readErr
	})
	if err != nil {
		if isContextError(err) {
			s.invalidateClient(cli)
		}
		return nil, err
	}

	var candidates []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			name := entry.Name()
			if entry.IsDir() {
				name += "/"
			}
			// 拼接上目录前缀供 line editor 替换
			if dir != s.cwd {
				candidates = append(candidates, dir+name)
			} else {
				candidates = append(candidates, name)
			}
		}
	}
	return candidates, nil
}

// completeLocalPath 补全本地路径
func (s *Shell) completeLocalPath(partial string) ([]string, error) {
	var dir, prefix string
	sep := string(filepath.Separator)
	if lastSep := strings.LastIndexAny(partial, "/"+sep); lastSep >= 0 {
		dir = partial[:lastSep+1]
		prefix = partial[lastSep+1:]
	} else {
		dir = "."
		prefix = partial
	}

	targetDir := dir
	if s.localCwd != "" && !filepath.IsAbs(targetDir) {
		targetDir = filepath.Join(s.localCwd, targetDir)
	}
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		return nil, err
	}

	var candidates []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			name := entry.Name()
			if entry.IsDir() {
				name += sep
			}
			if dir != "." {
				candidates = append(candidates, dir+name)
			} else {
				candidates = append(candidates, name)
			}
		}
	}
	return candidates, nil
}

func (s *Shell) completeLine(ctx context.Context, line string, pos int) completionResult {
	head, candidates, tail, err := s.wordCompleter(ctx, line, pos)
	return completionResult{head: head, candidates: candidates, tail: tail, err: err}
}
