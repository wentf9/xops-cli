package sftpshell

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

type completionCursor struct {
	cmd               string
	argIndex          int  // 0: 命令名, 1: 第一个参数, 2: 第二个参数...
	isCommand         bool // 是否在补全命令名
	partial           string
	quoteChar         rune // 0: 无引号, '\'': 单引号, '"': 双引号
	head              string
	prefixBeforeQuote string
}

// parseCompletionCursor 词法分析光标前的输入，提取补全上下文
//
//nolint:gocyclo
func parseCompletionCursor(content string) completionCursor {
	runes := []rune(content)
	var tokens []string
	var current strings.Builder
	var inToken bool
	var inQuote rune
	var escaped bool
	tokenStartRune := 0
	quoteStartRune := -1
	prefixBeforeQuote := ""

	for i := 0; i < len(runes); i++ {
		r := runes[i]

		if escaped {
			escaped = false
			inToken = true
			writeEscapedCommandLineRune(r, inQuote, &current)
			continue
		}

		if inQuote == '\'' {
			inToken = true
			if r == '\'' {
				inQuote = 0
				quoteStartRune = -1
				prefixBeforeQuote = ""
			} else {
				current.WriteRune(r)
			}
			continue
		}

		if inQuote == '"' {
			inToken = true
			if r == '\\' {
				escaped = true
				continue
			}
			if r == '"' {
				inQuote = 0
				quoteStartRune = -1
				prefixBeforeQuote = ""
			} else {
				current.WriteRune(r)
			}
			continue
		}

		// 无引号状态
		if r == '\\' {
			escaped = true
			if !inToken {
				inToken = true
				tokenStartRune = i
			}
			continue
		}

		if r == '\'' {
			inQuote = '\''
			quoteStartRune = i
			prefixBeforeQuote = current.String()
			if !inToken {
				inToken = true
				tokenStartRune = i
			}
			continue
		}

		if r == '"' {
			inQuote = '"'
			quoteStartRune = i
			prefixBeforeQuote = current.String()
			if !inToken {
				inToken = true
				tokenStartRune = i
			}
			continue
		}

		if unicode.IsSpace(r) {
			if inToken {
				tokens = append(tokens, current.String())
				current.Reset()
				inToken = false
			}
			continue
		}

		if !inToken {
			inToken = true
			tokenStartRune = i
		}
		current.WriteRune(r)
	}

	if escaped {
		current.WriteRune('\\')
	}

	if !inToken {
		if len(tokens) == 0 {
			return completionCursor{
				cmd:       "",
				argIndex:  0,
				isCommand: true,
				partial:   "",
				quoteChar: 0,
				head:      content,
			}
		}
		return completionCursor{
			cmd:       tokens[0],
			argIndex:  len(tokens),
			isCommand: false,
			partial:   "",
			quoteChar: 0,
			head:      content,
		}
	}

	if len(tokens) == 0 {
		return completionCursor{
			cmd:       current.String(),
			argIndex:  0,
			isCommand: true,
			partial:   current.String(),
			quoteChar: inQuote,
			head:      string(runes[:tokenStartRune]),
		}
	}

	cmd := tokens[0]
	argIndex := len(tokens)
	partial := current.String()
	head := ""
	if inQuote != 0 && quoteStartRune >= 0 {
		head = string(runes[:quoteStartRune+1])
	} else {
		head = string(runes[:tokenStartRune])
		prefixBeforeQuote = ""
	}

	return completionCursor{
		cmd:               cmd,
		argIndex:          argIndex,
		isCommand:         false,
		partial:           partial,
		quoteChar:         inQuote,
		head:              head,
		prefixBeforeQuote: prefixBeforeQuote,
	}
}

// escapeShellArg 在无引号模式下转义反斜杠、引号以及所有 unicode.IsSpace 空白字符，
// 使 splitCommandLine 能够无损还原原始候选路径。
func escapeShellArg(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\\' || r == '\'' || r == '"' || unicode.IsSpace(r) {
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// escapeDoubleQuotedArg 在双引号模式下转义反斜杠和双引号：
// 反斜杠翻倍以避免触发 splitCommandLine 的 Windows 尾部 `\"` 规则，
// 嵌入式双引号通过 `"\""` 跳出再重开双引号以避免后续空白拆分参数。
func escapeDoubleQuotedArg(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`"\""`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// escapeSingleQuotedArg 在单引号模式下通过 POSIX 跳出序列 `'\”` 转义嵌入式单引号。
func escapeSingleQuotedArg(s string) string {
	if !strings.ContainsRune(s, '\'') {
		return s
	}
	return strings.ReplaceAll(s, `'`, `'\''`)
}

// formatCompletionCandidate 格式化补全候选词，作为 splitCommandLine 的无损逆变换：
// 1. 无引号时转义反斜杠、引号和所有 unicode.IsSpace 字符；
// 2. 引号内保留空白并转义嵌入式引号/反斜杠，非目录自动补全闭合引号，目录保留开放以继续补全下一级。
func formatCompletionCandidate(candidate string, quoteChar rune, isDir bool) string {
	switch quoteChar {
	case '\'':
		escaped := escapeSingleQuotedArg(candidate)
		if isDir {
			return escaped
		}
		return escaped + "'"
	case '"':
		escaped := escapeDoubleQuotedArg(candidate)
		if isDir {
			return escaped
		}
		return escaped + `"`
	default:
		return escapeShellArg(candidate)
	}
}

// wordCompleter 计算光标位置对应的命令或路径补全候选
func (s *Shell) wordCompleter(ctx context.Context, line string, pos int) (head string, completions []string, tail string, err error) {
	runes := []rune(line)
	if pos < 0 || pos > len(runes) {
		return "", nil, "", fmt.Errorf("completion cursor out of range")
	}
	content := string(runes[:pos])
	tail = string(runes[pos:])

	cursor := parseCompletionCursor(content)

	if cursor.isCommand {
		cmds := []string{"exit", "quit", "bye", "help", "?", "pwd", "lpwd", "ls", "ll", "lls", "lll", "cd", "lcd", "mkdir", "lmkdir", "rm", "lrm", "cp", "lcp", "mv", "lmv", "get", "put", "exec", "lexec", "shell", "lshell"}
		for _, c := range cmds {
			if strings.HasPrefix(c, cursor.partial) {
				completions = append(completions, c)
			}
		}
		return cursor.head, completions, tail, nil
	}

	var rawCandidates []string
	isRemote := false
	switch cursor.cmd {
	case "cd", "ls", "ll", "mkdir", "rm", "cp", "mv":
		isRemote = true
		rawCandidates, err = s.completeRemotePath(ctx, cursor.partial)
	case "lcd", "lls", "lll", "lmkdir", "lrm", "lcp", "lmv":
		rawCandidates, err = s.completeLocalPath(cursor.partial)
	case "put":
		if cursor.argIndex <= 1 {
			rawCandidates, err = s.completeLocalPath(cursor.partial)
		} else {
			isRemote = true
			rawCandidates, err = s.completeRemotePath(ctx, cursor.partial)
		}
	case "get":
		if cursor.argIndex <= 1 {
			isRemote = true
			rawCandidates, err = s.completeRemotePath(ctx, cursor.partial)
		} else {
			rawCandidates, err = s.completeLocalPath(cursor.partial)
		}
	}

	if err != nil {
		return cursor.head, nil, tail, err
	}

	for _, cand := range rawCandidates {
		if hasTerminalControlRune(cand) {
			continue
		}
		if cursor.prefixBeforeQuote != "" {
			cand = strings.TrimPrefix(cand, cursor.prefixBeforeQuote)
		}
		isDir := strings.HasSuffix(cand, "/")
		if !isRemote {
			isDir = isDir || strings.HasSuffix(cand, string(filepath.Separator))
		}
		completions = append(completions, formatCompletionCandidate(cand, cursor.quoteChar, isDir))
	}

	return cursor.head, completions, tail, nil
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
	hasDirPrefix := false
	if lastSlash := strings.LastIndex(partial, "/"); lastSlash >= 0 {
		dir = partial[:lastSlash+1]
		prefix = partial[lastSlash+1:]
		hasDirPrefix = true
	} else {
		dir = s.cwd
		prefix = partial
	}

	targetDir := dir
	if !strings.HasPrefix(targetDir, "/") {
		targetDir = cli.JoinPath(s.cwd, targetDir)
	}

	entries, err := cli.ReadDir(ctx, targetDir)
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
			if hasDirPrefix {
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
		if hasTerminalControlRune(entry.Name()) {
			continue
		}
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
