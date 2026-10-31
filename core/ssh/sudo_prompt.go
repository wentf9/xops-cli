package ssh

import "bytes"

const sudoRSPromptPrefix = "[sudo: "
const maxSudoRSPromptSuffixBytes = 64

var fullWidthColon = []byte("\xef\xbc\x9a")

// sudo-rs treats -p as the label inside its PAM prompt. Wait for the entire
// envelope before answering; otherwise a fragmented suffix leaks to the user.
// The colon completes the prompt: PAM may omit trailing whitespace. Optional
// spaces, including those in a later packet, are consumed with the feedback.
// Localized prompts may end in English colon ':' or full-width colon '：' (\xef\xbc\x9a).
// Other sudo implementations emit only the supplied random marker.
func expandSudoPrompt(data []byte, match []int) []int {
	start, end := match[0], match[1]
	if !bytes.HasSuffix(data[:start], []byte(sudoRSPromptPrefix)) {
		return match
	}
	suffix := data[end:]
	if len(suffix) == 0 {
		return nil
	}
	if suffix[0] != ']' {
		return match
	}
	if len(suffix) == 1 {
		return nil
	}
	if suffix[1] != ' ' {
		return match
	}

	limit := len(suffix)
	if limit > maxSudoRSPromptSuffixBytes {
		limit = maxSudoRSPromptSuffixBytes
	}
	window := suffix[:limit]

	colonIdx := -1
	colonLen := 0
	for i := 0; i < len(window); {
		if window[i] == '\n' || window[i] == '\r' {
			return match
		}
		if window[i] == ':' {
			colonIdx = i
			colonLen = 1
			break
		}
		if bytes.HasPrefix(window[i:], fullWidthColon) {
			colonIdx = i
			colonLen = len(fullWidthColon)
			break
		}
		i++
	}

	if colonIdx >= 0 {
		colonEnd := colonIdx + colonLen
		return []int{start - len(sudoRSPromptPrefix), end + colonEnd}
	}

	if len(suffix) < maxSudoRSPromptSuffixBytes && bytes.IndexByte(suffix, '\n') < 0 && bytes.IndexByte(suffix, '\r') < 0 {
		return nil
	}
	return match
}

// Do not let a generic fallback (e.g. (?i)password) consume part of our
// fragmented marker or sudo-rs envelope and produce duplicate responses.
func incompleteSudoPrompt(data []byte, marker string) bool {
	for _, prefix := range []string{marker, sudoRSPromptPrefix} {
		for size := 1; size <= len(prefix) && size <= len(data); size++ {
			if bytes.HasSuffix(data, []byte(prefix[:size])) {
				return true
			}
		}
	}
	return false
}

// sudo-rs may render password feedback even with PTY echo disabled. Suppress
// only feedback immediately following our recognized prompt, ending at the
// newline or the first non-feedback byte. Diagnostics remain visible.
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
