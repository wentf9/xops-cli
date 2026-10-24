package sftpshell

import (
	"errors"
	"strings"
	"unicode"
)

var (
	errUnclosedQuote     = errors.New("unclosed quote in command line")
	errTrailingBackslash = errors.New("trailing backslash in command line")
)

// splitCommandLine 将命令行输入解析为参数切片，支持：
// 1. 单引号 '...'：内部内容均为字面量；
// 2. 双引号 "..."：内部内容保留空白；支持 \" 和 \\ 转义；其他字符保留反斜杠；
// 3. 无引号状态：\ 转义空白（空格、制表符等）、单双引号及反斜杠自身；Windows 路径中的普通反斜杠（如 C:\Users）予以保留；
// 4. 引号与普通字符相邻拼接（如 prefix"middle with space"suffix -> prefixmiddle with spacesuffix）；
// 5. 空引号（如 "" 或 ”）作为空字符串参数保留。
func splitCommandLine(input string) ([]string, error) {
	var args []string
	var current strings.Builder
	var inToken bool
	var inQuote rune // 0, '\'', '"'
	var escaped bool

	runes := []rune(input)
	for i := 0; i < len(runes); i++ {
		r := runes[i]

		if escaped {
			escaped = false
			inToken = true
			if inQuote == '"' {
				if r == '"' || r == '\\' {
					current.WriteRune(r)
				} else {
					current.WriteRune('\\')
					current.WriteRune(r)
				}
			} else {
				// inQuote == 0
				switch r {
				case ' ', '\t', '\n', '\r', '\'', '"', '\\':
					current.WriteRune(r)
				default:
					// 保留 Windows 路径的反斜杠，如 C:\Users
					current.WriteRune('\\')
					current.WriteRune(r)
				}
			}
			continue
		}

		if inQuote == '\'' {
			inToken = true
			if r == '\'' {
				inQuote = 0
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
			} else {
				current.WriteRune(r)
			}
			continue
		}

		// 无引号状态
		if r == '\\' {
			escaped = true
			inToken = true
			continue
		}

		if r == '\'' {
			inQuote = '\''
			inToken = true
			continue
		}

		if r == '"' {
			inQuote = '"'
			inToken = true
			continue
		}

		if unicode.IsSpace(r) {
			if inToken {
				args = append(args, current.String())
				current.Reset()
				inToken = false
			}
			continue
		}

		inToken = true
		current.WriteRune(r)
	}

	if escaped {
		return nil, errTrailingBackslash
	}
	if inQuote != 0 {
		return nil, errUnclosedQuote
	}
	if inToken {
		args = append(args, current.String())
	}

	return args, nil
}

// parsePassthroughCommand 检测输入行是否以 exec 或 lexec 命令开头。
// 这些命令直接将后续字符串透传给远端或本地 Shell 执行，
// 因此不应被 splitCommandLine 剥离引号或进行末尾反斜杠语法检查。
func parsePassthroughCommand(input string) (cmd string, rawArgs string, ok bool) {
	trimmed := strings.TrimSpace(input)
	for _, name := range []string{"exec", "lexec"} {
		if trimmed == name {
			return name, "", true
		}
		if strings.HasPrefix(trimmed, name) {
			rest := trimmed[len(name):]
			if len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
				return name, strings.TrimSpace(rest), true
			}
		}
	}
	return "", "", false
}
