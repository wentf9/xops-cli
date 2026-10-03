package guardrail

import (
	"regexp"
	"strings"
)

// blocked patterns are always denied — no approval can override them.
var blockedPatterns = []*regexp.Regexp{
	regexp.MustCompile(`rm\s+(-[^\s]*\s+)*/([\s;|&]|$)`),     // rm targeting root
	regexp.MustCompile(`mkfs(\.\w+)?\s+`),                    // format filesystem
	regexp.MustCompile(`dd\s+.*if=/dev/`),                    // raw disk read
	regexp.MustCompile(`dd\s+.*of=/dev/`),                    // raw disk write
	regexp.MustCompile(`>\s*/dev/sd`),                        // write to block device
	regexp.MustCompile(`:\(\)\s*\{\s*:\|:\s*&\s*\}\s*;\s*:`), // fork bomb
	regexp.MustCompile(`chmod\s+(-[^\s]+\s+)*777\s+/($|\s)`), // chmod 777 on root
	regexp.MustCompile(`echo\s+.*>\s*/proc/`),                // write to /proc
}

// dangerous command patterns that elevate risk to Dangerous.
var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`rm\s+(-[^\s]*\s+)*-?r`), // recursive delete
	regexp.MustCompile(`\b(shutdown|reboot|halt|poweroff|init\s+[06])\b`),
	regexp.MustCompile(`\bsystemctl\s+(stop|disable|mask)\b`),
	regexp.MustCompile(`\bkill\s+-9\b`),
	regexp.MustCompile(`\bkillall\b`),
	regexp.MustCompile(`\biptables\s+-F\b`), // flush iptables
	regexp.MustCompile(`\bnft\s+flush\b`),
	regexp.MustCompile(`\bufw\s+disable\b`),
	regexp.MustCompile(`>\s*/etc/`), // overwrite /etc files
	regexp.MustCompile(`\bchown\s+(-[^\s]+\s+)*root\b`),
	regexp.MustCompile(`\bcurl\b.*\|\s*(ba)?sh`), // pipe-to-shell
	regexp.MustCompile(`\bwget\b.*\|\s*(ba)?sh`),
}

// safeCommandPrefixes identify read-only commands (when not piped or chained).
var safeCommandPrefixes = []string{
	"ls", "cat", "head", "tail", "less", "more",
	"whoami", "hostname", "uname", "id",
	"df", "free", "uptime", "ps", "top",
	"date", "cal", "echo", "pwd", "which", "type",
	"wc", "file", "stat", "find", "grep", "awk", "sed",
	"ip addr", "ip route", "ss", "netstat",
	"systemctl status", "journalctl",
}

// IsBlocked returns true if the command matches a hard-blocked pattern.
func IsBlocked(cmd string) bool {
	normalized := strings.TrimSpace(cmd)
	for _, pat := range blockedPatterns {
		if pat.MatchString(normalized) {
			return true
		}
	}
	return false
}

// AnalyzeCommand returns the risk level for an ssh_run command string.
func AnalyzeCommand(cmd string) RiskLevel {
	if cmd == "" {
		return Safe
	}
	normalized := strings.TrimSpace(cmd)

	if IsBlocked(normalized) {
		return Dangerous
	}

	for _, pat := range dangerousPatterns {
		if pat.MatchString(normalized) {
			return Dangerous
		}
	}

	if containsChaining(normalized) {
		return Moderate
	}

	firstWord := extractFirstWord(normalized)
	for _, prefix := range safeCommandPrefixes {
		parts := strings.Fields(prefix)
		if len(parts) == 1 && firstWord == parts[0] {
			return Safe
		}
		if len(parts) > 1 && strings.HasPrefix(normalized, prefix) {
			return Safe
		}
	}

	return Moderate
}

// sensitivePaths that elevate risk when targeted.
var sensitivePaths = []string{
	"/etc", "/boot", "/usr", "/sbin",
	"/var/lib", "/root", "/proc", "/sys",
}

// AnalyzePaths returns the highest risk level implied by the given paths.
func AnalyzePaths(paths []string) RiskLevel {
	level := Safe
	for _, p := range paths {
		cleaned := strings.TrimRight(p, "/")
		if cleaned == "" || cleaned == "/" {
			return Dangerous
		}
		for _, sensitive := range sensitivePaths {
			if cleaned == sensitive || strings.HasPrefix(cleaned, sensitive+"/") {
				if level < Moderate {
					level = Moderate
				}
			}
		}
	}
	return level
}

func containsChaining(cmd string) bool {
	for _, sep := range []string{"&&", "||", "|", ";", ">>", ">"} {
		if strings.Contains(cmd, sep) {
			return true
		}
	}
	return false
}

func extractFirstWord(cmd string) string {
	// skip leading env vars like VAR=val
	for {
		parts := strings.SplitN(cmd, " ", 2)
		if len(parts) == 0 {
			return ""
		}
		if strings.Contains(parts[0], "=") && len(parts) > 1 {
			cmd = strings.TrimSpace(parts[1])
			continue
		}
		return parts[0]
	}
}
