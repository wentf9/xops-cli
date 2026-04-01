package sftp

import (
	"os"
	"path/filepath"
	"strings"
)

// wordCompleter 实现 liner.WordCompleter 接口
func (s *Shell) wordCompleter(line string, pos int) (head string, completions []string, tail string) {
	content := line[:pos]

	// 场景1：补全命令名（行首无空格）
	if !strings.Contains(content, " ") {
		cmds := []string{"exit", "quit", "bye", "help", "?", "pwd", "lpwd", "ls", "ll", "lls", "lll", "cd", "lcd", "mkdir", "lmkdir", "rm", "lrm", "cp", "lcp", "mv", "lmv", "get", "put"}
		for _, c := range cmds {
			if strings.HasPrefix(c, content) {
				completions = append(completions, c)
			}
		}
		return "", completions, line[pos:]
	}

	// 场景2：补全命令参数
	parts := strings.Fields(content)
	if len(parts) < 1 {
		return line, nil, ""
	}

	cmd := parts[0]
	var partial string
	if !strings.HasSuffix(content, " ") {
		partial = parts[len(parts)-1]
	}

	// 计算出不参与本次补全的前缀部分
	prefixLen := len(content) - len(partial)
	head = content[:prefixLen]
	tail = line[pos:]

	switch cmd {
	case "cd", "ls", "ll", "get", "mkdir", "rm", "cp", "mv":
		completions = s.completeRemotePath(partial)
	case "lcd", "lls", "lll", "put", "lmkdir", "lrm", "lcp", "lmv":
		completions = s.completeLocalPath(partial)
	}

	return head, completions, tail
}

// completeRemotePath 补全远程路径
func (s *Shell) completeRemotePath(partial string) []string {
	if s.client == nil {
		return nil
	}

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
		targetDir = s.client.JoinPath(s.cwd, targetDir)
	}

	entries, err := s.client.sftpClient.ReadDir(targetDir)
	if err != nil {
		return nil
	}

	var candidates []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			name := entry.Name()
			if entry.IsDir() {
				name += "/"
			}
			// 拼接上目录前缀供 liner 替换
			if dir != s.cwd {
				candidates = append(candidates, dir+name)
			} else {
				candidates = append(candidates, name)
			}
		}
	}
	return candidates
}

// completeLocalPath 补全本地路径
func (s *Shell) completeLocalPath(partial string) []string {
	var dir, prefix string
	sep := string(filepath.Separator)
	if lastSep := strings.LastIndex(partial, sep); lastSep >= 0 {
		dir = partial[:lastSep+1]
		prefix = partial[lastSep+1:]
	} else {
		dir = "."
		prefix = partial
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
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
	return candidates
}
