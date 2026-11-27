package priv

import (
	"bytes"
	"strings"

	"github.com/wentf9/xops-cli/core/ports"
)

const (
	sudoRSPromptPrefix   = "[sudo: "
	maxSudoRSSuffixBytes = 64
)

// sudoPromptFeedback 在识别到 sudo-rs 封套提示后抑制紧随其后的回显掩码字节（* / \b / 空格 / \r），
// 遇换行符或首个非掩码诊断字节即停止吞噬，确保后续诊断信息完整透出。
type sudoPromptFeedback bool

func (f *sudoPromptFeedback) consume(data []byte) []byte {
	for *f && len(data) > 0 {
		switch data[0] {
		case '*', '\b', ' ', '\r':
			data = data[1:]
		case '\n':
			data = data[1:]
			*f = false
		default:
			*f = false
		}
	}
	return data
}

// matchPrivilegePrompt 依据提权协议匹配口令质询帧（sudo 精确随机令牌与 sudo-rs 封套、su/doas password 提示）。
func matchPrivilegePrompt(method ports.PrivilegeMethod, promptToken string, data []byte) (start, end int, found, needMore bool) {
	switch method {
	case ports.PrivilegeMethodSudo:
		return matchSudoPrompt(promptToken, data)
	case ports.PrivilegeMethodSu:
		return matchKeywordPrompt(data, "password:")
	case ports.PrivilegeMethodDoas:
		return matchKeywordPrompt(data, "password:")
	default:
		return 0, 0, false, false
	}
}

func matchSudoPrompt(marker string, data []byte) (start, end int, found, needMore bool) {
	idx := bytes.Index(data, []byte(marker))
	if idx < 0 {
		return 0, 0, false, hasPartialTail(data, marker) || hasPartialTail(data, sudoRSPromptPrefix)
	}
	mStart, mEnd := idx, idx+len(marker)
	if !bytes.HasSuffix(data[:mStart], []byte(sudoRSPromptPrefix)) {
		return mStart, mEnd, true, false
	}
	return expandSudoRSEnvelope(data, mStart, mEnd)
}

func expandSudoRSEnvelope(data []byte, start, end int) (int, int, bool, bool) {
	suffix := data[end:]
	if len(suffix) == 0 || (len(suffix) == 1 && suffix[0] == ']') {
		return 0, 0, false, true
	}
	if suffix[0] != ']' || suffix[1] != ' ' {
		return start, end, true, false
	}
	win := suffix[:min(len(suffix), maxSudoRSSuffixBytes)]
	if colonEnd, ok := findPromptColonEnd(win); ok {
		return start - len(sudoRSPromptPrefix), end + colonEnd, true, false
	}
	if len(suffix) < maxSudoRSSuffixBytes && !bytes.ContainsAny(suffix, "\r\n") {
		return 0, 0, false, true
	}
	return start, end, true, false
}

func findPromptColonEnd(win []byte) (int, bool) {
	// 按原始 UTF-8 字节序列匹配本地化 sudo-rs 提示尾部的全角冒号（U+FF1A），避免生产源码出现全角字符字面量。
	fwColon := []byte{0xef, 0xbc, 0x9a}
	for i := 0; i < len(win); i++ {
		if win[i] == '\r' || win[i] == '\n' {
			return 0, false
		}
		if win[i] == ':' {
			return i + 1, true
		}
		if bytes.HasPrefix(win[i:], fwColon) {
			return i + len(fwColon), true
		}
	}
	return 0, false
}

func matchKeywordPrompt(data []byte, keyword string) (start, end int, found, needMore bool) {
	lower := bytes.ToLower(data)
	kw := []byte(keyword)
	if idx := bytes.Index(lower, kw); idx >= 0 {
		endIdx := idx + len(kw)
		if endIdx < len(data) && data[endIdx] == ' ' {
			endIdx++
		}
		return idx, endIdx, true, false
	}
	return 0, 0, false, hasPartialTail(lower, keyword)
}

func hasPartialTail(data []byte, prefix string) bool {
	limit := min(len(prefix)-1, len(data))
	for size := 1; size <= limit; size++ {
		if bytes.HasSuffix(data, []byte(prefix[:size])) {
			return true
		}
	}
	return false
}

func isAuthRejectionDiagnostic(diag string) bool {
	lower := strings.ToLower(diag)
	for _, needle := range [...]string{
		"sorry, try again",
		"incorrect password",
		"authentication failure",
		"a password is required",
		"password is required",
		"not in the sudoers",
		"authentication failed",
		"operation not permitted",
		"permission denied",
		"incorrect passphrase",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}
