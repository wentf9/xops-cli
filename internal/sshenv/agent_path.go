package sshenv

import "strings"

const defaultWindowsOpenSSHAgentPipe = `\\.\pipe\openssh-ssh-agent`

// normalizeWindowsAgentPipePath checks whether socket refers to a Windows Named Pipe
// (\\.\pipe\... or //./pipe/...) and returns its canonical \\.\pipe\<name> form.
func normalizeWindowsAgentPipePath(socket string) (string, bool) {
	trimmed := strings.TrimSpace(socket)
	if strings.HasPrefix(trimmed, `\\.\pipe\`) {
		rest := strings.ReplaceAll(trimmed[len(`\\.\pipe\`):], "/", `\`)
		if rest == "" {
			return "", false
		}
		return `\\.\pipe\` + rest, true
	}
	if strings.HasPrefix(trimmed, `//./pipe/`) {
		rest := strings.ReplaceAll(trimmed[len(`//./pipe/`):], "/", `\`)
		if rest == "" {
			return "", false
		}
		return `\\.\pipe\` + rest, true
	}
	return "", false
}
