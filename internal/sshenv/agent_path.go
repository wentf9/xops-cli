package sshenv

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	defaultWindowsOpenSSHAgentPipe = `\\.\pipe\openssh-ssh-agent`
	windowsDotPipePrefix           = `\\.\pipe\`
	windowsQuestionPipePrefix      = `\\?\pipe\`
)

// normalizeWindowsAgentPipePath checks whether socket refers to a Windows Named Pipe
// (\\.\pipe\..., \\?\pipe\..., or forward/mixed-slash / uppercase variants) and
// returns its canonical \\.\pipe\<name> form.
func normalizeWindowsAgentPipePath(socket string) (string, bool) {
	pipePath, isPipe, err := parseWindowsAgentPipePath(socket)
	if err != nil || !isPipe {
		return "", false
	}
	return pipePath, true
}

func hasWindowsAgentPipePrefix(slashed string) bool {
	if len(slashed) < len(windowsDotPipePrefix) {
		return false
	}
	prefix := slashed[:len(windowsDotPipePrefix)]
	return strings.EqualFold(prefix, windowsDotPipePrefix) || strings.EqualFold(prefix, windowsQuestionPipePrefix)
}

func hasWindowsAgentControlChar(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return true
		}
	}
	return false
}

func parseWindowsAgentPipePath(socket string) (string, bool, error) {
	trimmed := strings.TrimSpace(socket)
	slashed := strings.ReplaceAll(trimmed, "/", `\`)
	isPipe := hasWindowsAgentPipePrefix(slashed)
	if hasWindowsAgentControlChar(socket) {
		return "", isPipe, fmt.Errorf("windows agent socket path contains invalid control characters")
	}
	if trimmed == "" {
		return "", false, nil
	}
	if !isPipe {
		if strings.HasPrefix(slashed, `\\`) || strings.HasPrefix(slashed, `\??\`) || strings.EqualFold(slashed, `\??`) {
			return "", false, fmt.Errorf("windows agent socket path %q must be a local path or valid named pipe", socket)
		}
		return "", false, nil
	}
	rest := slashed[len(windowsDotPipePrefix):]
	if rest == "" {
		return "", true, fmt.Errorf("windows agent named pipe path %q has empty pipe name", socket)
	}
	if strings.ContainsRune(rest, ':') {
		return "", true, fmt.Errorf("windows agent named pipe path %q contains invalid ':'", socket)
	}
	for _, seg := range strings.Split(rest, `\`) {
		if seg == "" || seg == "." || seg == ".." || strings.TrimRight(seg, ". ") == "" || strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			return "", true, fmt.Errorf("windows agent named pipe path %q contains invalid path segment %q", socket, seg)
		}
	}
	return windowsDotPipePrefix + rest, true, nil
}
