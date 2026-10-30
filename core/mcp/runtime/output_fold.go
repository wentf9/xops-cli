package runtime

import (
	"fmt"
	"strings"
)

const (
	successFoldThreshold = 60
	successKeepHead      = 15
	successKeepTail      = 30

	failureFoldThreshold = 100
	failureKeepHead      = 20
	failureKeepTail      = 80
)

// foldTerminalOutput compresses verbose command output according to outcome:
//   - Success and >60 lines: keeps first 15 lines + last 30 lines.
//   - Failure and >100 lines: keeps first 20 lines + last 80 lines so stack traces are preserved.
//
// In both cases the full output is offered to saveFull, whose returned
// location (if any) is referenced in the omission banner.
func foldTerminalOutput(raw string, failed bool, saveFull func(content string) string) (string, bool) {
	if raw == "" {
		return raw, false
	}
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	trimmed := strings.TrimSuffix(normalized, "\n")
	lines := strings.Split(trimmed, "\n")

	threshold, head, tail := successFoldThreshold, successKeepHead, successKeepTail
	if failed {
		threshold, head, tail = failureFoldThreshold, failureKeepHead, failureKeepTail
	}
	if len(lines) <= threshold {
		return raw, false
	}
	omitted := len(lines) - head - tail

	banner := fmt.Sprintf("[... %d lines omitted ...]", omitted)
	if saveFull != nil {
		if logPath := saveFull(raw); logPath != "" {
			banner = fmt.Sprintf("[... %d lines omitted. Full log saved to %s ...]", omitted, logPath)
		}
	}
	var b strings.Builder
	b.WriteString(strings.Join(lines[:head], "\n"))
	b.WriteByte('\n')
	b.WriteString(banner)
	b.WriteByte('\n')
	b.WriteString(strings.Join(lines[len(lines)-tail:], "\n"))
	return b.String(), true
}
