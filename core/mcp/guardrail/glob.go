package guardrail

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

type globTokenKind uint8

const (
	globLiteral globTokenKind = iota
	globAny
	globStar
	globClass
)

type runeRange struct {
	lo rune
	hi rune
}

type globToken struct {
	kind    globTokenKind
	lit     rune
	negated bool
	ranges  []runeRange
}

func (t globToken) matchesRune(r rune) bool {
	switch t.kind {
	case globAny:
		return true
	case globLiteral:
		return r == t.lit
	case globClass:
		matched := false
		for _, rg := range t.ranges {
			if r >= rg.lo && r <= rg.hi {
				matched = true
				break
			}
		}
		if t.negated {
			return !matched
		}
		return matched
	default:
		return false
	}
}

// validateGuardrailGlob validates an OS-independent guardrail glob pattern.
func validateGuardrailGlob(pattern string) error {
	_, err := parseGuardrailGlob(pattern)
	return err
}

// matchGuardrailGlob matches s against pattern using an OS-independent UTF-8
// rune glob engine where '*' matches zero or more runes (including '/', '\',
// newlines, and spaces), '?' matches any single rune, '[...]' supports
// negation ('[^...]' / '[!...]') and ranges ('[a-z]'), and '\' is always a
// literal rune on every operating system.
//
// Matching uses iterative two-pointer backtracking over parsed rune tokens so
// worst-case time complexity is O(|pattern| * |s|) with no recursion blowup.
func matchGuardrailGlob(pattern, s string) (bool, error) {
	tokens, err := parseGuardrailGlob(pattern)
	if err != nil {
		return false, err
	}
	rs := []rune(s)
	ti, si := 0, 0
	starTi, starSi := -1, 0
	for si < len(rs) {
		if ti < len(tokens) && tokens[ti].kind == globStar {
			starTi = ti
			starSi = si
			ti++
			continue
		}
		if ti < len(tokens) && tokens[ti].matchesRune(rs[si]) {
			ti++
			si++
			continue
		}
		if starTi >= 0 {
			starSi++
			si = starSi
			ti = starTi + 1
			continue
		}
		return false, nil
	}
	for ti < len(tokens) && tokens[ti].kind == globStar {
		ti++
	}
	return ti == len(tokens), nil
}

func parseGuardrailGlob(pattern string) ([]globToken, error) {
	if !utf8.ValidString(pattern) {
		return nil, errors.New("invalid UTF-8 in glob pattern")
	}
	runes := []rune(pattern)
	tokens := make([]globToken, 0, len(runes))
	for i := 0; i < len(runes); {
		switch runes[i] {
		case '*':
			if len(tokens) == 0 || tokens[len(tokens)-1].kind != globStar {
				tokens = append(tokens, globToken{kind: globStar})
			}
			i++
		case '?':
			tokens = append(tokens, globToken{kind: globAny})
			i++
		case '[':
			tok, next, err := parseGuardrailCharClass(runes, i+1)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, tok)
			i = next
		default:
			tokens = append(tokens, globToken{kind: globLiteral, lit: runes[i]})
			i++
		}
	}
	return tokens, nil
}

func parseGuardrailCharClass(runes []rune, start int) (globToken, int, error) {
	i := start
	if i >= len(runes) {
		return globToken{}, 0, errors.New("unclosed character class in glob pattern")
	}
	negated := false
	if runes[i] == '^' || runes[i] == '!' {
		negated = true
		i++
	}
	var ranges []runeRange
	closed := false
	for i < len(runes) {
		if runes[i] == ']' && len(ranges) > 0 {
			closed = true
			i++
			break
		}
		lo := runes[i]
		i++
		if i+1 < len(runes) && runes[i] == '-' && runes[i+1] != ']' {
			hi := runes[i+1]
			if hi < lo {
				return globToken{}, 0, fmt.Errorf("invalid character range %q-%q in glob pattern", lo, hi)
			}
			ranges = append(ranges, runeRange{lo: lo, hi: hi})
			i += 2
			continue
		}
		ranges = append(ranges, runeRange{lo: lo, hi: lo})
	}
	if !closed {
		return globToken{}, 0, errors.New("unclosed character class in glob pattern")
	}
	return globToken{
		kind:    globClass,
		negated: negated,
		ranges:  ranges,
	}, i, nil
}
