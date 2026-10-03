package ssh

import "bytes"

const sudoRSPromptPrefix = "[sudo: "
const sudoRSPromptSuffix = "] Password:"

// sudo-rs treats -p as the label inside its PAM prompt. Wait for the entire
// envelope before answering; otherwise a fragmented suffix leaks to the user.
// The colon completes the prompt: PAM may omit trailing whitespace. Optional
// spaces, including those in a later packet, are consumed with the feedback.
// Other sudo implementations emit only the supplied random marker.
func expandSudoPrompt(data []byte, match []int) []int {
	start, end := match[0], match[1]
	if !bytes.HasSuffix(data[:start], []byte(sudoRSPromptPrefix)) {
		return match
	}
	suffix := data[end:]
	if len(suffix) < len(sudoRSPromptSuffix) && bytes.HasPrefix([]byte(sudoRSPromptSuffix), suffix) {
		return nil
	}
	if bytes.HasPrefix(suffix, []byte(sudoRSPromptSuffix)) {
		return []int{start - len(sudoRSPromptPrefix), end + len(sudoRSPromptSuffix)}
	}
	return match
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
