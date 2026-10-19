package ssh

import (
	"regexp"
	"regexp/syntax"
	"unicode/utf8"
)

// Context belongs to one output copier. It preserves no discarded text, only
// the current physical line's leading-plus classification and regexp boundary
// context. A bounded look-behind must not manufacture a fresh line/text start.
type privilegeLinePrefix uint8

const (
	privilegeLineStart privilegeLinePrefix = iota
	privilegeLinePluses
	privilegeLineXtrace
	privilegeLineOther
)

func advancePrivilegeLine(state privilegeLinePrefix, data []byte) privilegeLinePrefix {
	for _, b := range data {
		switch {
		case b == '\n':
			state = privilegeLineStart
		case state == privilegeLineStart && b == '+':
			state = privilegeLinePluses
		case state == privilegeLinePluses && b == ' ':
			state = privilegeLineXtrace
		case state == privilegeLineStart || (state == privilegeLinePluses && b != '+'):
			state = privilegeLineOther
		}
	}
	return state
}

// Inspect an as-yet undecided leading '+' run even when the regexp includes
// that prefix in its match. Never answer an incomplete potential xtrace prefix.
func privilegeXtraceAt(state privilegeLinePrefix, rest []byte) bool {
	for _, b := range rest {
		if state == privilegeLineXtrace || state == privilegeLineOther || b == '\n' {
			break
		}
		state = advancePrivilegeLine(state, []byte{b})
	}
	return state == privilegeLineXtrace || state == privilegeLinePluses
}

func (w *privilegeFrameWriter) rememberDiscarded(data []byte) {
	if len(data) == 0 {
		return
	}
	w.linePrefix = advancePrivilegeLine(w.linePrefix, data)
	// Go regexp word boundaries use ASCII word characters. A representative
	// byte preserves ^, \A and \b semantics without retaining payload bytes.
	b := data[len(data)-1]
	switch {
	case b == '\n':
		w.regexpPrefix = '\n'
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '_':
		w.regexpPrefix = 'x'
	default:
		w.regexpPrefix = ' '
	}
}

// A recognized prompt/frame, unlike discarded unmatched text, deliberately
// begins a new protocol matching region (including retries without a newline).
func (w *privilegeFrameWriter) consumeFrame(end int) {
	w.pending = w.pending[end:]
	w.regexpPrefix = 0
	w.linePrefix = privilegeLineStart
}

func (w *privilegeFrameWriter) promptSearchData(start int) ([]byte, int) {
	if start > 0 {
		_, size := utf8.DecodeLastRune(w.pending[:start])
		return w.pending[start-size:], size
	}
	if w.regexpPrefix == 0 {
		return w.pending, 0
	}
	data := make([]byte, len(w.pending)+1)
	data[0] = w.regexpPrefix
	copy(data[1:], w.pending)
	return data, 1
}

func (w *privilegeFrameWriter) nextPromptMatch(pattern *regexp.Regexp, start int) []int {
	if start == 0 && w.regexpPrefix == 0 {
		return pattern.FindIndex(w.pending)
	}
	guarded := w.contextPattern(pattern)
	if guarded == nil {
		return nil
	} // Fail closed if a contextual pattern cannot be compiled.
	data, offset := w.promptSearchData(start)
	match := guarded.FindSubmatchIndex(data)
	if match == nil {
		return nil
	}
	return []int{start + match[2] - offset, start + match[3] - offset}
}

// The first rune supplies boundary context but is consumed OUTSIDE the prompt
// capture. Lazy search then finds the leftmost legal prompt, so a match on the
// context byte cannot shadow a real prompt inside it. On resumed searches the
// preceding real rune supplies the same ^/\A/\b semantics without copying data.
func (w *privilegeFrameWriter) contextPattern(pattern *regexp.Regexp) *regexp.Regexp {
	if w.contextPatterns == nil {
		w.contextPatterns = make(map[*regexp.Regexp]*regexp.Regexp, 2)
	}
	if cached, ok := w.contextPatterns[pattern]; ok {
		return cached
	}
	// Normalize through syntax rather than embedding raw text: a valid pattern
	// may end in an open \Q quote, which must not swallow our closing capture.
	expr, err := syntax.Parse(pattern.String(), syntax.Perl)
	var guarded *regexp.Regexp
	if err == nil {
		guarded, _ = regexp.Compile(`(?s:\A..*?)(` + expr.String() + `)`)
	}
	w.contextPatterns[pattern] = guarded
	return guarded
}
