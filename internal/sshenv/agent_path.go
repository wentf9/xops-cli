package sshenv

import "strings"

const (
	defaultWindowsOpenSSHAgentPipe = `\\.\pipe\openssh-ssh-agent`
	windowsDotPipePrefix           = `\\.\pipe\`
	windowsQuestionPipePrefix      = `\\?\pipe\`
)

// normalizeWindowsAgentPipePath checks whether socket refers to a Windows Named Pipe
// (\\.\pipe\..., \\?\pipe\..., or forward/mixed-slash / uppercase variants) and
// returns its canonical \\.\pipe\<name> form.
func normalizeWindowsAgentPipePath(socket string) (string, bool) {
	trimmed := strings.TrimSpace(socket)
	if trimmed == "" {
		return "", false
	}
	slashed := strings.ReplaceAll(trimmed, "/", `\`)
	if len(slashed) <= len(windowsDotPipePrefix) {
		return "", false
	}
	prefix := slashed[:len(windowsDotPipePrefix)]
	if !strings.EqualFold(prefix, windowsDotPipePrefix) && !strings.EqualFold(prefix, windowsQuestionPipePrefix) {
		return "", false
	}
	rest := strings.TrimLeft(slashed[len(windowsDotPipePrefix):], `\`)
	if rest == "" {
		return "", false
	}
	return windowsDotPipePrefix + rest, true
}
