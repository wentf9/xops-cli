package guardrail

import (
	"net"
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

func parseBareDriveSegment(seg string) (drive string, rest string, ok bool) {
	if len(seg) >= 2 && isAlpha(seg[0]) && seg[1] == ':' && (len(seg) == 2 || seg[2] == '/' || seg[2] == '\\') {
		return strings.ToUpper(string(seg[0])), seg[2:], true
	}
	return "", "", false
}

func parseDrivePath(p string) (drive string, rest string, ok bool) {
	if d, r, matched := parseBareDriveSegment(p); matched {
		return d, r, true
	}
	trimmed := strings.TrimLeft(p, "/")
	if len(trimmed) < len(p) {
		if d, r, matched := parseBareDriveSegment(trimmed); matched {
			return d, r, true
		}
	}
	return "", "", false
}

func isWin32Sep(b byte) bool {
	return b == '/' || b == '\\'
}

func hasCaseInsensitivePrefixSeg(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return "", false
	}
	if len(s) == len(prefix) {
		return "", true
	}
	if isWin32Sep(s[len(prefix)]) {
		return s[len(prefix)+1:], true
	}
	return "", false
}

func isForwardDeviceWin32Namespace(after string) bool {
	if _, _, ok := parseBareDriveSegment(after); ok {
		return true
	}
	for _, ns := range []string{"UNC", "GLOBALROOT", "pipe"} {
		if _, ok := hasCaseInsensitivePrefixSeg(after, ns); ok {
			return true
		}
	}
	lower := strings.ToLower(after)
	if strings.HasPrefix(lower, "volume{") || strings.HasPrefix(lower, "physicaldrive") {
		return true
	}
	return len(lower) >= 3 && lower[:3] == "nul" && (len(lower) == 3 || isWin32Sep(lower[3]) || lower[3] == '.' || lower[3] == ':')
}

func stripRawWin32DevicePrefix(p string) (string, bool) {
	if len(p) < 4 {
		return "", false
	}
	if p[0] == '\\' && p[1] == '?' && p[2] == '?' && isWin32Sep(p[3]) {
		return p[4:], true
	}
	if !isWin32Sep(p[0]) || !isWin32Sep(p[1]) || !isWin32Sep(p[3]) {
		return "", false
	}
	switch p[2] {
	case '?', '.':
		if p[0] == '/' && p[1] == '/' && p[3] == '/' && !isForwardDeviceWin32Namespace(p[4:]) {
			return "", false
		}
		return p[4:], true
	default:
		return "", false
	}
}

func stripGlobalRootPrefix(after string) string {
	rem, matched := hasCaseInsensitivePrefixSeg(after, "GLOBALROOT")
	if !matched {
		return after
	}
	if len(rem) >= 4 && isWin32Sep(rem[0]) && rem[1] == '?' && rem[2] == '?' && isWin32Sep(rem[3]) {
		return rem[4:]
	}
	if len(rem) >= 3 && rem[0] == '?' && rem[1] == '?' && isWin32Sep(rem[2]) {
		return rem[3:]
	}
	return rem
}

func stripWin32DevicePrefix(p string) (rest string, isUNC bool, ok bool) {
	after, matched := stripRawWin32DevicePrefix(p)
	if !matched {
		return "", false, false
	}
	after = stripGlobalRootPrefix(after)
	if rem, isUNCPrefix := hasCaseInsensitivePrefixSeg(after, "UNC"); isUNCPrefix {
		return rem, true, true
	}
	return after, false, true
}

func isWin32PlainUNC(p string) bool {
	if len(p) < 2 || p[0] != '\\' || p[1] != '\\' {
		return false
	}
	_, _, isDevice := stripWin32DevicePrefix(p)
	return !isDevice
}

func isWin32DeviceOrUNCPath(p string) bool {
	if isWin32PlainUNC(p) {
		return true
	}
	_, _, ok := stripWin32DevicePrefix(p)
	return ok
}

type win32UNCPath struct {
	server    string
	share     string
	cleanRest string
}

func canonicalizeWin32SingleSegment(seg string) string {
	if idx := strings.IndexByte(seg, ':'); idx >= 0 {
		seg = seg[:idx]
	}
	return strings.TrimRight(seg, ". ")
}

func parseWin32UNCBody(body string) (win32UNCPath, bool) {
	slash := strings.ReplaceAll(body, `\`, "/")
	if slash == "" || strings.HasPrefix(slash, "/") {
		return win32UNCPath{}, false
	}
	parts := strings.SplitN(slash, "/", 3)
	server := strings.ToLower(strings.TrimRight(parts[0], ". "))
	if server == "" {
		return win32UNCPath{}, false
	}
	if len(parts) == 1 || parts[1] == "" {
		return win32UNCPath{server: server, cleanRest: "/"}, true
	}
	share := strings.ToLower(canonicalizeWin32SingleSegment(parts[1]))
	if share == "" {
		return win32UNCPath{}, false
	}
	rawRest := ""
	if len(parts) == 3 {
		rawRest = "/" + parts[2]
	}
	cleanRest, _ := canonicalizeDriveRest(rawRest)
	return win32UNCPath{server: server, share: share, cleanRest: cleanRest}, true
}

func canonicalUNCPath(p string) (win32UNCPath, bool) {
	if rest, isUNC, ok := stripWin32DevicePrefix(p); ok {
		if !isUNC {
			return win32UNCPath{}, false
		}
		return parseWin32UNCBody(rest)
	}
	if isWin32PlainUNC(p) {
		return parseWin32UNCBody(p[2:])
	}
	return win32UNCPath{}, false
}

func isLoopbackUNCServer(server string) bool {
	trimmed := strings.TrimRight(strings.ToLower(server), ".")
	if trimmed == "localhost" || trimmed == "--1.ipv6-literal.net" || trimmed == "0--1.ipv6-literal.net" {
		return true
	}
	ipStr := strings.TrimPrefix(strings.TrimSuffix(trimmed, "]"), "[")
	if ip := net.ParseIP(ipStr); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func (u win32UNCPath) adminDrive() (drive string, cleanRest string, ok bool) {
	if !isLoopbackUNCServer(u.server) {
		return "", "", false
	}
	if len(u.share) == 2 && isAlpha(u.share[0]) && u.share[1] == '$' {
		return strings.ToUpper(u.share[:1]), u.cleanRest, true
	}
	return "", "", false
}

func canonicalDeviceNamespacePath(p string) (ns string, cleanRest string, ok bool) {
	rest, isUNC, stripped := stripWin32DevicePrefix(p)
	if !stripped || isUNC {
		return "", "", false
	}
	if _, _, matched := extractDrivePath(rest); matched {
		return "", "", false
	}
	slash := strings.ReplaceAll(rest, `\`, "/")
	slash = strings.TrimLeft(slash, "/")
	if slash == "" {
		return "", "", false
	}
	parts := strings.SplitN(slash, "/", 2)
	ns = strings.ToLower(canonicalizeWin32SingleSegment(parts[0]))
	if ns == "" {
		return "", "", false
	}
	rawRest := ""
	if len(parts) == 2 {
		rawRest = "/" + parts[1]
	}
	cleanRest, _ = canonicalizeDriveRest(rawRest)
	return ns, cleanRest, true
}

// extractDrivePath detects Windows drive paths (C:..., /C:..., //C:..., or
// absolute paths collapsing via ".." to /C:...) and returns the uppercase drive
// letter together with the raw (pre-Clean) path remainder beneath that drive
// root so Win32 component anomalies collapsed by ".." are still observable.
func extractDrivePath(p string) (drive string, rawRest string, ok bool) {
	if d, rest, matched := parseDrivePath(p); matched {
		return d, rest, true
	}
	if !strings.HasPrefix(p, "/") {
		return "", "", false
	}
	type segEntry struct {
		seg    string
		rawIdx int
	}
	segs := strings.Split(p, "/")
	stack := make([]segEntry, 0, len(segs))
	for i, seg := range segs {
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			} else if len(stack) == 1 {
				if _, _, isDrive := parseBareDriveSegment(stack[0].seg); !isDrive {
					stack = stack[:0]
				}
			}
		default:
			stack = append(stack, segEntry{seg: seg, rawIdx: i})
		}
	}
	if len(stack) == 0 {
		return "", "", false
	}
	d, rest, matched := parseBareDriveSegment(stack[0].seg)
	if !matched {
		return "", "", false
	}
	if stack[0].rawIdx+1 < len(segs) {
		rest += "/" + strings.Join(segs[stack[0].rawIdx+1:], "/")
	}
	return d, rest, true
}

func hasWin32AmbiguousSegment(slashPath string) bool {
	for _, seg := range strings.Split(slashPath, "/") {
		if seg == "" || seg == "." || seg == ".." {
			continue
		}
		if strings.ContainsRune(seg, ':') || strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			return true
		}
	}
	return false
}

// canonicalizeDriveRest cleans a Windows drive-relative path (after C:),
// returning:
//   - canonicalRest: POSIX-cleaned path beneath the drive root with NTFS ADS
//     (:stream) suffixes and trailing ASCII '.' / ' ' stripped on non-dot
//     navigation segments (matching Win32 RtlDosPathNameToNtPathName semantics).
//   - ambiguous: true if any segment before or after path.Clean carries a
//     secondary ':' (NTFS ADS) or Win32-stripped trailing '.' / ' ' on a
//     non-"."/".." component (including whitespace-only or multi-dot "..."
//     components).
func canonicalizeDriveRest(rest string) (canonicalRest string, ambiguous bool) {
	slashRest := strings.ReplaceAll(rest, "\\", "/")
	ambiguous = hasWin32AmbiguousSegment(slashRest)

	cleaned := path.Clean("/" + slashRest)
	if !ambiguous && hasWin32AmbiguousSegment(cleaned) {
		ambiguous = true
	}

	rawSegs := strings.Split(cleaned, "/")
	canonSegs := make([]string, 0, len(rawSegs))
	for _, seg := range rawSegs {
		if seg == "" {
			continue
		}
		if seg == "." || seg == ".." {
			canonSegs = append(canonSegs, seg)
			continue
		}
		if idx := strings.IndexByte(seg, ':'); idx >= 0 {
			seg = seg[:idx]
		}
		seg = strings.TrimRight(seg, ". ")
		if seg == "" {
			continue
		}
		canonSegs = append(canonSegs, seg)
	}
	canonicalRest = path.Clean("/" + strings.Join(canonSegs, "/"))
	return canonicalRest, ambiguous
}

// canonicalDrivePath detects Windows drive paths (C:..., /C:..., //C:...,
// /tmp/../C:..., Win32 extended/device-prefixed \\?\C:\..., \\.\C:\...,
// \??\C:\..., and loopback administrative drive shares \\localhost\C$\... /
// \\127.0.0.1\C$\...) and returns the uppercase drive letter, Win32-canonicalized
// path beneath that drive root, and whether any segment had NTFS ADS,
// Win32-ambiguous trailing '.' / ' ' characters, or a Win32 device/UNC prefix.
func canonicalDrivePath(p string) (drive string, cleanRest string, ambiguous bool, ok bool) {
	if rest, isUNC, stripped := stripWin32DevicePrefix(p); stripped {
		if isUNC {
			if u, matched := parseWin32UNCBody(rest); matched {
				if d, cr, isAdmin := u.adminDrive(); isAdmin {
					return d, cr, true, true
				}
			}
			return "", "", false, false
		}
		if d, rawRest, matched := extractDrivePath(rest); matched {
			cr, _ := canonicalizeDriveRest(rawRest)
			return d, cr, true, true
		}
		return "", "", false, false
	}
	if isWin32PlainUNC(p) {
		if u, matched := parseWin32UNCBody(p[2:]); matched {
			if d, cr, isAdmin := u.adminDrive(); isAdmin {
				return d, cr, true, true
			}
		}
		return "", "", false, false
	}
	d, rest, matched := extractDrivePath(p)
	if !matched {
		return "", "", false, false
	}
	cleanRest, ambiguous = canonicalizeDriveRest(rest)
	return d, cleanRest, ambiguous, true
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
	if p == "" || hasControlOrLineSep(p) || isWin32DeviceOrUNCPath(p) {
		return Dangerous
	}
	if _, cleanRest, ambiguous, ok := canonicalDrivePath(p); ok {
		return analyzeCleanDriveRest(cleanRest, ambiguous)
	}
	return analyzePosixPath(p)
}

func analyzeCleanDriveRest(cleanRest string, ambiguous bool) RiskLevel {
	if cleanRest == "/" || ambiguous {
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
	if _, cleanRest, ambiguous, ok := canonicalDrivePath(cleaned); ok {
		return analyzeCleanDriveRest(cleanRest, ambiguous)
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
		slashPath := "/" + strings.ReplaceAll(p, "\\", "/")
		var slashRisk RiskLevel
		if _, cleanRest, ambiguous, ok := canonicalDrivePath(slashPath); ok {
			slashRisk = analyzeCleanDriveRest(cleanRest, ambiguous)
		} else {
			slashRisk = analyzeCleanedPosix(path.Clean(slashPath))
		}
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
