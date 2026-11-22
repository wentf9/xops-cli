package guardrail

import (
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"
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

// These commands have no mutation or program-execution argument modes.
// Mixed-purpose utilities (find, sed, awk, file, ss, journalctl, pagers, etc.)
// require at least Moderate risk even when their name looks read-only.
var readOnlyCommands = []string{
	"ls", "cat", "head", "tail", "whoami", "uname", "id",
	"df", "free", "uptime", "ps", "cal", "echo", "pwd",
	"which", "type", "wc", "stat", "grep", "netstat",
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

// AnalyzeCommand returns the risk level for an ssh_run command string under POSIX dialect.
func AnalyzeCommand(cmd string) RiskLevel {
	return AnalyzeCommandWithDialect(cmd, "posix")
}

// AnalyzeCommandWithDialect returns the risk level for an ssh_run command string under a specified launch dialect.
// If the launch dialect is unknown or non-POSIX, POSIX safe prefixes cannot be trusted,
// and the command is treated as at least Moderate.
func AnalyzeCommandWithDialect(cmd string, dialect string) RiskLevel {
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

	// Unknown or non-POSIX dialects cannot safely assume POSIX commands/builtins.
	if dialect != "" && dialect != "posix" {
		return Moderate
	}

	if isReadOnlyInvocation(cmd) {
		return Safe
	}

	return Moderate
}

func isReadOnlyInvocation(command string) bool {
	// Do not infer argv through shell quoting, escaping, globbing or environment
	// assignments. Unknown forms stay Moderate instead of hiding option names or
	// changing how an otherwise read-only executable is loaded.
	if strings.ContainsAny(command, "\\'\"=*?[]{}!~#") {
		return false
	}
	// POSIX shell token separators are ASCII; Unicode whitespace must not make
	// a different executable name look like one of the read-only commands.
	words := strings.FieldsFunc(command, func(character rune) bool {
		return character == ' ' || character == '\t'
	})
	if len(words) == 0 {
		return false
	}
	switch words[0] {
	case "hostname":
		return len(words) == 1 || (len(words) == 2 && slices.Contains([]string{"-f", "--fqdn", "-s", "--short", "-d", "--domain", "-i", "--ip-address", "-I", "--all-ip-addresses"}, words[1]))
	case "date":
		return len(words) == 1 || (len(words) == 2 && strings.HasPrefix(words[1], "+"))
	case "ip":
		return (len(words) == 2 || (len(words) == 3 && words[2] == "show")) && (words[1] == "addr" || words[1] == "route")
	case "systemctl":
		return isSystemctlStatusQuery(words[1:])
	default:
		return slices.Contains(readOnlyCommands, words[0])
	}
}

func isSystemctlStatusQuery(arguments []string) bool {
	if len(arguments) == 0 || arguments[0] != "status" {
		return false
	}
	for _, argument := range arguments[1:] {
		if strings.HasPrefix(argument, "-") && !slices.Contains([]string{"--no-pager", "--full", "-l", "--plain"}, argument) {
			return false
		}
	}
	return true
}

// sensitivePaths that elevate risk when targeted.
var sensitivePaths = []string{
	"/etc", "/boot", "/usr", "/sbin",
	"/var/lib", "/root", "/proc", "/sys",
}

// sensitiveWindowsPaths elevate risk when targeted on Windows filesystems.
var sensitiveWindowsPaths = []string{
	"/windows/system32/config",
	"/windows/repair",
}

func isAlpha(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func parseDrivePath(p string) (drive string, rest string, ok bool) {
	if len(p) >= 2 && isAlpha(p[0]) && p[1] == ':' && (len(p) == 2 || p[2] == '/' || p[2] == '\\') {
		return strings.ToUpper(string(p[0])), p[2:], true
	}
	trimmed := strings.TrimLeft(p, "/")
	if len(trimmed) < len(p) && len(trimmed) >= 2 && isAlpha(trimmed[0]) && trimmed[1] == ':' && (len(trimmed) == 2 || trimmed[2] == '/' || trimmed[2] == '\\') {
		return strings.ToUpper(string(trimmed[0])), trimmed[2:], true
	}
	return "", "", false
}

// canonicalDrivePath detects Windows drive paths (C:..., /C:..., //C:..., or
// absolute paths collapsing via ".." to /C:...) and returns the uppercase drive
// letter together with the POSIX-cleaned path beneath that drive root.
func canonicalDrivePath(p string) (drive string, cleanRest string, ok bool) {
	if d, rest, matched := parseDrivePath(p); matched {
		return d, cleanDriveRest(rest), true
	}
	if strings.HasPrefix(p, "/") {
		cleaned := path.Clean(p)
		if strings.HasPrefix(cleaned, "/") {
			if d, rest, matched := parseDrivePath(cleaned); matched {
				return d, cleanDriveRest(rest), true
			}
		}
	}
	return "", "", false
}

func cleanDriveRest(rest string) string {
	return path.Clean("/" + strings.ReplaceAll(rest, "\\", "/"))
}

func hasSensitivePrefix(cleaned string) bool {
	for _, sensitive := range sensitivePaths {
		if cleaned == sensitive || strings.HasPrefix(cleaned, sensitive+"/") {
			return true
		}
	}
	lower := strings.TrimRight(strings.ToLower(cleaned), "/")
	for _, sensitive := range sensitiveWindowsPaths {
		if lower == sensitive || strings.HasPrefix(lower, sensitive+"/") {
			return true
		}
	}
	return false
}

// AnalyzePaths returns the highest risk level implied by the given paths.
func AnalyzePaths(paths []string) RiskLevel {
	level := Safe
	for _, p := range paths {
		pathRisk := analyzeSinglePath(p)
		if pathRisk > level {
			level = pathRisk
		}
		if level == Dangerous {
			return Dangerous
		}
	}
	return level
}

func isControlOrLineSep(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
}

func hasControlOrLineSep(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	for _, r := range s {
		if isControlOrLineSep(r) {
			return true
		}
	}
	return false
}

func analyzeSinglePath(p string) RiskLevel {
	if p == "" || hasControlOrLineSep(p) {
		return Dangerous
	}
	if _, cleanRest, ok := canonicalDrivePath(p); ok {
		return analyzeCleanDriveRest(cleanRest)
	}
	return analyzePosixPath(p)
}

func analyzeCleanDriveRest(cleanRest string) RiskLevel {
	if cleanRest == "/" {
		return Dangerous
	}
	if hasSensitivePrefix(cleanRest) {
		return Moderate
	}
	return Safe
}

func analyzeCleanedPosix(cleaned string) RiskLevel {
	if cleaned == "" || cleaned == "/" || cleaned == "." || !strings.HasPrefix(cleaned, "/") {
		return Dangerous
	}
	if _, rest, ok := parseDrivePath(cleaned); ok {
		return analyzeCleanDriveRest(cleanDriveRest(rest))
	}
	if hasSensitivePrefix(cleaned) {
		return Moderate
	}
	return Safe
}

func analyzePosixPath(p string) RiskLevel {
	// Relative paths cannot be proven outside protected directories or root
	// without knowing the working directory; fail closed as Dangerous.
	if !strings.HasPrefix(p, "/") {
		return Dangerous
	}
	level := analyzeCleanedPosix(path.Clean(p))
	if strings.Contains(p, "\\") {
		slashRisk := analyzeCleanedPosix(path.Clean("/" + strings.ReplaceAll(p, "\\", "/")))
		if slashRisk > level {
			level = slashRisk
		}
	}
	return level
}

func containsChaining(cmd string) bool {
	// Safe prefixes do not establish safety when expansions, substitutions or
	// additional shell statements can execute code. Keep quoted/escaped forms
	// conservative rather than attempting a partial parser for several shells.
	if strings.ContainsAny(cmd, "$`()<\n\r&") {
		return true
	}
	for _, sep := range []string{"&&", "||", "|", ";", ">>", ">"} {
		if strings.Contains(cmd, sep) {
			return true
		}
	}
	return false
}
