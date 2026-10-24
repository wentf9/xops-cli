package sftpshell

import (
	"errors"
	"strings"
	"unicode"
)

var (
	errUnclosedQuote = errors.New("unclosed quote in command line")
)

func writeEscapedCommandLineRune(r rune, inQuote rune, current *strings.Builder) {
	if inQuote == '"' {
		if r == '"' || r == '\\' {
			current.WriteRune(r)
		} else {
			current.WriteRune('\\')
			current.WriteRune(r)
		}
		return
	}
	switch r {
	case ' ', '\t', '\n', '\r', '\'', '"', '\\':
		current.WriteRune(r)
	default:
		current.WriteRune('\\')
		current.WriteRune(r)
	}
}

// splitCommandLine 将命令行输入解析为参数切片，支持：
// 1. 单引号 '...'：内部内容均为字面量；
// 2. 双引号 "..."：内部内容保留空白；支持 \" 和 \\ 转义；其他字符保留反斜杠；
// 3. 无引号状态：\ 转义空白（空格、制表符等）、单双引号及反斜杠自身；Windows 路径中的普通反斜杠（如 C:\Users）予以保留；
// 4. 引号与普通字符相邻拼接（如 prefix"middle with space"suffix -> prefixmiddle with spacesuffix）；
// 5. 空引号（如 "" 或 ”）作为空字符串参数保留。
//
//nolint:gocyclo
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
			writeEscapedCommandLineRune(r, inQuote, &current)
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
				// 若下一个字符是双引号，且处于行尾或紧跟空白，说明是 Windows 路径末尾的反斜杠加闭合双引号（如 "C:\test\" 或 "bin036\"）
				if i+1 < len(runes) && runes[i+1] == '"' {
					if i+1 == len(runes)-1 || unicode.IsSpace(runes[i+2]) {
						current.WriteRune('\\')
						inQuote = 0
						i++ // 消费该闭合双引号
						continue
					}
				}
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
		// 无引号模式下末尾反斜杠保留为字面量（如 Windows 路径 C:\ 或补全目录 bin036\）
		current.WriteRune('\\')
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
