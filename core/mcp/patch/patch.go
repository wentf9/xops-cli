// Package patch implements a two-stage fault-tolerant search/replace patch
// engine for the MCP file tool.
package patch

import (
	"errors"
	"fmt"
	"strings"
)

// Block represents a single <<<< ... ==== ... >>>> replacement operation.
type Block struct {
	Search  string
	Replace string
}

// ErrInvalidFormat indicates a malformed search/replace patch payload.
var ErrInvalidFormat = errors.New("invalid patch format")

// ErrNoMatch indicates that a search block was not found in the target content.
var ErrNoMatch = errors.New("patch block did not match file content")

// ErrAmbiguousMatch indicates that a search block matched multiple locations.
var ErrAmbiguousMatch = errors.New("ambiguous patch block matched multiple locations")

// Parse extracts one or more search/replace blocks from raw patch text.
// Each block is delimited by lines starting with "<<<<", "====", and ">>>>".
func Parse(raw string) ([]Block, error) {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")

	type state int
	const (
		stateOutside state = iota
		stateSearch
		stateReplace
	)

	curState := stateOutside
	var searchLines []string
	var replaceLines []string
	var blocks []Block

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch curState {
		case stateOutside:
			if isMarker(trimmed, "<<<<") {
				curState = stateSearch
				searchLines = nil
				replaceLines = nil
			} else if trimmed != "" {
				return nil, fmt.Errorf("%w: unexpected text outside <<<< >>>> block: %q", ErrInvalidFormat, line)
			}
		case stateSearch:
			if isMarker(trimmed, "====") {
				curState = stateReplace
			} else {
				searchLines = append(searchLines, line)
			}
		case stateReplace:
			if isMarker(trimmed, ">>>>") {
				search := strings.Join(searchLines, "\n")
				if search == "" {
					return nil, fmt.Errorf("%w: search block must not be empty", ErrInvalidFormat)
				}
				blocks = append(blocks, Block{
					Search:  search,
					Replace: strings.Join(replaceLines, "\n"),
				})
				curState = stateOutside
			} else {
				replaceLines = append(replaceLines, line)
			}
		}
	}

	if curState != stateOutside {
		return nil, fmt.Errorf("%w: unclosed patch block (expected ==== and >>>>)", ErrInvalidFormat)
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("%w: no <<<< ==== >>>> blocks found", ErrInvalidFormat)
	}
	return blocks, nil
}

func isMarker(trimmed, prefix string) bool {
	if !strings.HasPrefix(trimmed, prefix) {
		return false
	}
	rest := strings.TrimLeft(trimmed[len(prefix):], prefix[:1])
	return rest == "" || strings.HasPrefix(rest, " ")
}

// Result reports the outcome of Apply.
type Result struct {
	Content string
	// Blocks is the number of blocks applied.
	Blocks int
	// Fuzzy is the number of blocks that matched only after ignoring leading
	// and trailing whitespace on each line; callers should surface this so the
	// edit can be reviewed.
	Fuzzy int
}

// Apply parses raw patch blocks and applies them sequentially to content.
// Uniform CRLF files keep CRLF; files with mixed line endings are patched
// byte-for-byte without normalization so untouched lines keep their endings.
func Apply(content, rawPatch string) (Result, error) {
	blocks, err := Parse(rawPatch)
	if err != nil {
		return Result{}, err
	}

	crlf := strings.Count(content, "\r\n")
	useCRLF := crlf > 0 && crlf == strings.Count(content, "\n")
	working := content
	if useCRLF {
		working = strings.ReplaceAll(content, "\r\n", "\n")
	}

	result := Result{}
	for idx, block := range blocks {
		var fuzzy bool
		working, fuzzy, err = applyBlock(working, block)
		if err != nil {
			return Result{}, fmt.Errorf("block %d: %w", idx+1, err)
		}
		if fuzzy {
			result.Fuzzy++
		}
	}

	if useCRLF {
		working = strings.ReplaceAll(working, "\n", "\r\n")
	}
	result.Content, result.Blocks = working, len(blocks)
	return result, nil
}

func applyBlock(content string, block Block) (string, bool, error) {
	// Stage 1: Exact substring match.
	exactCount := strings.Count(content, block.Search)
	if exactCount == 1 {
		return strings.Replace(content, block.Search, block.Replace, 1), false, nil
	}
	if exactCount > 1 {
		return "", false, fmt.Errorf("%w: found %d exact matches; include more surrounding context lines", ErrAmbiguousMatch, exactCount)
	}

	// Stage 2: Line-by-line TrimSpace fallback with indentation alignment.
	contentLines := strings.Split(content, "\n")
	searchLines := strings.Split(block.Search, "\n")
	if len(contentLines) < len(searchLines) {
		return "", false, ErrNoMatch
	}

	var matchIndices []int
	maxStart := len(contentLines) - len(searchLines)
	for start := 0; start <= maxStart; start++ {
		if matchesTrimmed(contentLines[start:start+len(searchLines)], searchLines) {
			matchIndices = append(matchIndices, start)
		}
	}

	if len(matchIndices) == 0 {
		return "", false, ErrNoMatch
	}
	if len(matchIndices) > 1 {
		return "", false, fmt.Errorf("%w: found %d whitespace-insensitive matches; include more surrounding context lines", ErrAmbiguousMatch, len(matchIndices))
	}

	start := matchIndices[0]
	matchedSlice := contentLines[start : start+len(searchLines)]
	var replacement []string
	if block.Replace != "" {
		replaceLines := strings.Split(block.Replace, "\n")
		replacement = alignIndentation(matchedSlice, searchLines, replaceLines)
	}

	resultLines := make([]string, 0, len(contentLines)-len(searchLines)+len(replacement))
	resultLines = append(resultLines, contentLines[:start]...)
	resultLines = append(resultLines, replacement...)
	resultLines = append(resultLines, contentLines[start+len(searchLines):]...)
	return strings.Join(resultLines, "\n"), true, nil
}

func matchesTrimmed(candidate, search []string) bool {
	for i := range search {
		if strings.TrimSpace(candidate[i]) != strings.TrimSpace(search[i]) {
			return false
		}
	}
	return true
}

func alignIndentation(actualLines, searchLines, replaceLines []string) []string {
	actualIndent := ""
	searchIndent := ""
	foundAnchor := false
	for i := range searchLines {
		if strings.TrimSpace(searchLines[i]) != "" {
			actualIndent = leadingWhitespace(actualLines[i])
			searchIndent = leadingWhitespace(searchLines[i])
			foundAnchor = true
			break
		}
	}
	if !foundAnchor || actualIndent == searchIndent {
		return replaceLines
	}

	aligned := make([]string, len(replaceLines))
	for i, line := range replaceLines {
		if strings.TrimSpace(line) == "" {
			aligned[i] = line
			continue
		}
		if strings.HasPrefix(line, searchIndent) {
			aligned[i] = actualIndent + line[len(searchIndent):]
		} else {
			aligned[i] = actualIndent + strings.TrimLeft(line, " \t")
		}
	}
	return aligned
}

func leadingWhitespace(s string) string {
	trimmed := strings.TrimLeft(s, " \t")
	return s[:len(s)-len(trimmed)]
}
