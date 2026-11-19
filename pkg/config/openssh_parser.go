package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type sshConfigDoc struct {
	blocks []*sshConfigBlock
}

type sshConfigBlock struct {
	implicit bool
	isMatch  bool
	matchAll bool
	patterns []sshHostPattern
	nodes    []sshConfigNode
}

type sshHostPattern struct {
	raw     string
	pattern string
	negated bool
}

type sshConfigNode interface {
	isSSHConfigNode()
}

type sshConfigDirective struct {
	line     int
	key      string
	lowerKey string
	value    string
	rawValue string
}

func (*sshConfigDirective) isSSHConfigNode() {}

type sshConfigInclude struct {
	line     int
	patterns []string
	files    []includedSSHConfigFile
	system   bool
}

func (*sshConfigInclude) isSSHConfigNode() {}

type includedSSHConfigFile struct {
	path string
	doc  *sshConfigDoc
}

func newSSHHostPattern(raw string) sshHostPattern {
	if strings.HasPrefix(raw, "!") {
		return sshHostPattern{
			raw:     raw,
			pattern: raw[1:],
			negated: true,
		}
	}
	return sshHostPattern{
		raw:     raw,
		pattern: raw,
	}
}

// matchSSHWildcard implements OpenSSH match_pattern: case-sensitive linear
// matching supporting '*' (zero or more bytes) and '?' (one byte) only.
func matchSSHWildcard(pattern, s string) bool {
	pi, si := 0, 0
	starIdx, matchIdx := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			starIdx = pi
			matchIdx = si
			pi++
		case starIdx != -1:
			pi = starIdx + 1
			matchIdx++
			si = matchIdx
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

func (b *sshConfigBlock) matches(alias string) bool {
	if b == nil {
		return false
	}
	if b.implicit || b.matchAll {
		return true
	}
	matched := false
	for _, p := range b.patterns {
		if !matchSSHWildcard(p.pattern, alias) {
			continue
		}
		if p.negated {
			return false
		}
		matched = true
	}
	return matched
}

func (b *sshConfigBlock) matchesConcretePattern(alias string) bool {
	if b == nil || b.implicit || b.isMatch || alias == "" || !b.matches(alias) {
		return false
	}
	for _, p := range b.patterns {
		if !p.negated && isConcreteSSHHost(p.raw) && p.raw == alias {
			return true
		}
	}
	return false
}

func decodeOpenSSHReader(r io.Reader) (*sshConfigDoc, error) {
	var sourcePath string
	if named, ok := r.(interface{ Name() string }); ok && named != nil {
		sourcePath = named.Name()
	}
	return decodeOpenSSHConfig(r, sourcePath)
}

func decodeOpenSSHConfig(r io.Reader, sourcePath string) (*sshConfigDoc, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	active := make(map[string]struct{}, 4)
	if sourcePath != "" {
		active[canonicalIncludePath(sourcePath)] = struct{}{}
	}
	return decodeOpenSSHBytes(b, isSystemSSHConfigPath(sourcePath), 0, active)
}

func decodeOpenSSHFile(path string, system bool, depth int, active map[string]struct{}) (*sshConfigDoc, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decodeOpenSSHBytes(b, system || isSystemSSHConfigPath(path), depth, active)
}

func decodeOpenSSHBytes(b []byte, system bool, depth int, active map[string]struct{}) (*sshConfigDoc, error) {
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	current := &sshConfigBlock{implicit: true, matchAll: true}
	doc := &sshConfigDoc{blocks: []*sshConfigBlock{current}}
	if len(b) == 0 {
		return doc, nil
	}

	lines := strings.Split(string(b), "\n")
	for idx, rawLine := range lines {
		lineNum := idx + 1
		line := strings.TrimSuffix(rawLine, "\r")
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}
		nextBlock, err := parseOpenSSHLine(lineNum, trimmed, current, system, depth, active)
		if err != nil {
			return nil, err
		}
		if nextBlock != nil {
			current = nextBlock
			doc.blocks = append(doc.blocks, current)
		}
	}
	return doc, nil
}

func parseOpenSSHLine(
	lineNum int,
	trimmedLine string,
	current *sshConfigBlock,
	system bool,
	depth int,
	active map[string]struct{},
) (*sshConfigBlock, error) {
	key, rest, ok := splitOpenSSHDirectiveLine(trimmedLine)
	if !ok {
		return nil, fmt.Errorf("line %d: invalid directive syntax", lineNum)
	}
	lowerKey := strings.ToLower(key)
	switch lowerKey {
	case "include":
		patterns, err := parseOpenSSHIncludeArgs(rest)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}
		files, err := loadOpenSSHIncludeFiles(patterns, system, depth, active)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}
		current.nodes = append(current.nodes, &sshConfigInclude{
			line:     lineNum,
			patterns: patterns,
			files:    files,
			system:   system,
		})
		return nil, nil
	case "host":
		return parseOpenSSHHostBlock(lineNum, rest)
	case "match":
		return parseOpenSSHMatchBlock(lineNum, rest)
	default:
		current.nodes = append(current.nodes, parseOpenSSHDirective(lineNum, key, lowerKey, rest))
		return nil, nil
	}
}

func splitOpenSSHDirectiveLine(trimmed string) (key, rest string, ok bool) {
	kEnd := strings.IndexAny(trimmed, " \t=")
	if kEnd < 0 {
		kEnd = len(trimmed)
	}
	key = trimmed[:kEnd]
	if key == "" || strings.ContainsRune(key, '#') {
		return "", "", false
	}
	afterKey := strings.TrimLeft(trimmed[kEnd:], " \t")
	if strings.HasPrefix(afterKey, "=") {
		afterKey = strings.TrimLeft(afterKey[1:], " \t")
	}
	return key, afterKey, true
}

func parseOpenSSHHostBlock(lineNum int, rest string) (*sshConfigBlock, error) {
	argsPart, _, unclosed := splitOpenSSHArgvComment(rest)
	if unclosed {
		return nil, fmt.Errorf("line %d: unterminated quote in Host directive", lineNum)
	}
	rawPatterns, err := splitOpenSSHArgvTokens(argsPart)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid Host directive: %w", lineNum, err)
	}
	patterns := make([]sshHostPattern, 0, len(rawPatterns))
	for _, raw := range rawPatterns {
		patterns = append(patterns, newSSHHostPattern(raw))
	}
	return &sshConfigBlock{patterns: patterns}, nil
}

func parseOpenSSHMatchBlock(lineNum int, rest string) (*sshConfigBlock, error) {
	argsPart, _, unclosed := splitOpenSSHArgvComment(rest)
	if unclosed {
		return nil, fmt.Errorf("line %d: unterminated quote in Match directive", lineNum)
	}
	toks, err := splitOpenSSHArgvTokens(argsPart)
	if err != nil || len(toks) == 0 {
		return nil, fmt.Errorf("line %d: invalid Match directive", lineNum)
	}
	if len(toks) == 1 && strings.EqualFold(toks[0], "all") {
		return &sshConfigBlock{isMatch: true, matchAll: true}, nil
	}
	if !strings.EqualFold(toks[0], "host") || len(toks) < 2 {
		return nil, fmt.Errorf("line %d: unsupported Match directive %q", lineNum, argsPart)
	}
	var patterns []sshHostPattern
	for _, tok := range toks[1:] {
		if isOpenSSHMatchCriterionKeyword(strings.TrimPrefix(tok, "!")) {
			return nil, fmt.Errorf("line %d: unsupported Match criterion %q", lineNum, tok)
		}
		for _, piece := range strings.Split(tok, ",") {
			if piece == "" {
				continue
			}
			patterns = append(patterns, newSSHHostPattern(piece))
		}
	}
	if len(patterns) == 0 {
		return nil, fmt.Errorf("line %d: Match host requires at least one pattern", lineNum)
	}
	return &sshConfigBlock{isMatch: true, patterns: patterns}, nil
}

func isOpenSSHMatchCriterionKeyword(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "all", "canonical", "final", "exec", "localnetwork",
		"host", "originalhost", "tagged", "user", "localuser",
		"sessiontype", "command":
		return true
	default:
		return false
	}
}

func parseOpenSSHDirective(lineNum int, key, lowerKey, rest string) *sshConfigDirective {
	if isOpenSSHWholeLineCommandDirective(lowerKey) {
		trimmed := strings.TrimSpace(rest)
		return &sshConfigDirective{
			line:     lineNum,
			key:      key,
			lowerKey: lowerKey,
			value:    trimmed,
			rawValue: trimmed,
		}
	}
	argsPart, _, unclosed := splitOpenSSHArgvComment(rest)
	rawVal := strings.TrimSpace(argsPart)
	if isOpenSSHRawTokenListDirective(lowerKey) {
		return &sshConfigDirective{
			line:     lineNum,
			key:      key,
			lowerKey: lowerKey,
			value:    rawVal,
			rawValue: rawVal,
		}
	}
	val := rawVal
	if !unclosed {
		if toks, err := splitOpenSSHArgvTokens(argsPart); err == nil && len(toks) == 1 {
			val = toks[0]
		}
	}
	return &sshConfigDirective{
		line:     lineNum,
		key:      key,
		lowerKey: lowerKey,
		value:    val,
		rawValue: rawVal,
	}
}

func isOpenSSHWholeLineCommandDirective(lowerKey string) bool {
	switch lowerKey {
	case "proxycommand", "proxy_command",
		"localcommand", "local_command",
		"remotecommand", "remote_command":
		return true
	default:
		return false
	}
}

func isOpenSSHRawTokenListDirective(lowerKey string) bool {
	switch lowerKey {
	case "setenv", "set_env",
		"sendenv", "send_env",
		"localforward", "local_forward",
		"remoteforward", "remote_forward",
		"dynamicforward", "dynamic_forward":
		return true
	default:
		return false
	}
}

func isOpenSSHArgvEscapable(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '"' || ch == '\'' || ch == '\\'
}

func splitOpenSSHArgvComment(rest string) (argsPart, comment string, unclosedQuote bool) {
	var quote byte
	atWordStart := true
	for i := 0; i < len(rest); {
		ch := rest[i]
		if quote != 0 {
			adv, closed := advanceQuotedByte(rest, i, quote)
			if closed {
				quote = 0
			}
			i += adv
			atWordStart = false
			continue
		}
		if ch == ' ' || ch == '\t' {
			atWordStart = true
			i++
			continue
		}
		if ch == '#' && atWordStart {
			return strings.TrimRight(rest[:i], " \t"), rest[i+1:], false
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			atWordStart = false
			i++
			continue
		}
		if ch == '\\' && i+1 < len(rest) && isOpenSSHArgvEscapable(rest[i+1]) {
			atWordStart = false
			i += 2
			continue
		}
		atWordStart = false
		i++
	}
	return strings.TrimRight(rest, " \t"), "", quote != 0
}

func advanceQuotedByte(s string, i int, quote byte) (advance int, closed bool) {
	ch := s[i]
	if quote == '"' && ch == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
		return 2, false
	}
	if ch == quote {
		return 1, true
	}
	return 1, false
}

func splitOpenSSHArgvTokens(s string) ([]string, error) {
	var tokens []string
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		var sb strings.Builder
		nextIdx, err := consumeOpenSSHArgvToken(s, i, &sb)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, sb.String())
		i = nextIdx
	}
	return tokens, nil
}

func consumeOpenSSHArgvToken(s string, i int, sb *strings.Builder) (int, error) {
	var quote byte
	for i < len(s) {
		ch := s[i]
		if quote != 0 {
			if quote == '"' && ch == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
				sb.WriteByte(s[i+1])
				i += 2
				continue
			}
			if ch == quote {
				quote = 0
				i++
				continue
			}
			sb.WriteByte(ch)
			i++
			continue
		}
		if ch == ' ' || ch == '\t' {
			break
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			i++
			continue
		}
		if ch == '\\' && i+1 < len(s) && isOpenSSHArgvEscapable(s[i+1]) {
			sb.WriteByte(s[i+1])
			i += 2
			continue
		}
		sb.WriteByte(ch)
		i++
	}
	if quote != 0 {
		return i, fmt.Errorf("unterminated %c quote", quote)
	}
	return i, nil
}

func parseOpenSSHIncludeArgs(rest string) ([]string, error) {
	var patterns []string
	for i := 0; i < len(rest); {
		if rest[i] == ' ' || rest[i] == '\t' {
			i++
			continue
		}
		if rest[i] == '#' {
			break
		}
		tok, nextIdx, tokErr := readNextOpenSSHIncludeToken(rest, i)
		if tokErr != nil {
			return nil, tokErr
		}
		patterns = append(patterns, tok)
		i = nextIdx
	}
	if len(patterns) == 0 {
		return nil, errors.New("include directive requires at least one pattern")
	}
	return patterns, nil
}

func readNextOpenSSHIncludeToken(rest string, start int) (string, int, error) {
	var cur strings.Builder
	var quoteChar byte
	i := start
	for i < len(rest) {
		ch := rest[i]
		if quoteChar != 0 {
			if next, adv, closed := consumeOpenSSHIncludeQuotedChar(rest, i, quoteChar); closed {
				quoteChar = 0
				i += adv
			} else {
				cur.WriteByte(next)
				i += adv
			}
			continue
		}
		if ch == ' ' || ch == '\t' {
			break
		}
		if ch == '"' || ch == '\'' {
			quoteChar = ch
			i++
			continue
		}
		b, adv := consumeOpenSSHIncludeUnquotedChar(rest, i)
		cur.WriteByte(b)
		i += adv
	}
	if quoteChar != 0 {
		return "", 0, errors.New("unterminated quote in Include directive")
	}
	if cur.Len() == 0 {
		return "", 0, errors.New("empty pattern in Include directive")
	}
	return cur.String(), i, nil
}

func consumeOpenSSHIncludeQuotedChar(rest string, i int, quoteChar byte) (ch byte, advance int, closed bool) {
	if quoteChar == '"' && rest[i] == '\\' && i+1 < len(rest) {
		if next := rest[i+1]; next == '"' || next == '\\' {
			return next, 2, false
		}
	}
	if rest[i] == quoteChar {
		return 0, 1, true
	}
	return rest[i], 1, false
}

func consumeOpenSSHIncludeUnquotedChar(rest string, i int) (ch byte, advance int) {
	if rest[i] == '\\' && i+1 < len(rest) {
		next := rest[i+1]
		if next == ' ' || next == '\t' || next == '"' || next == '\'' || next == '#' {
			return next, 2
		}
	}
	return rest[i], 1
}

func loadOpenSSHIncludeFiles(
	patterns []string,
	system bool,
	depth int,
	active map[string]struct{},
) ([]includedSSHConfigFile, error) {
	if depth >= maxIncludeDepth || len(patterns) == 0 {
		return nil, nil
	}
	var files []includedSSHConfigFile
	seenPaths := make(map[string]struct{})
	for _, pat := range patterns {
		matches, skip, err := expandAndGlobIncludePattern(pat, system)
		if err != nil {
			return nil, err
		}
		if skip {
			continue
		}
		for _, match := range matches {
			incFile, ok, err := loadSingleIncludedFile(match, system, depth, active, seenPaths)
			if err != nil {
				return nil, err
			}
			if ok {
				files = append(files, incFile)
			}
		}
	}
	return files, nil
}

func expandAndGlobIncludePattern(pat string, system bool) ([]string, bool, error) {
	globPat, skip, err := expandOpenSSHIncludePattern(pat, system)
	if err != nil || skip || globPat == "" {
		return nil, true, err
	}
	matches, err := filepath.Glob(globPat)
	if err != nil {
		return nil, false, fmt.Errorf("expand Include pattern %q: %w", pat, err)
	}
	slices.Sort(matches)
	return matches, false, nil
}

func loadSingleIncludedFile(
	match string,
	system bool,
	depth int,
	active map[string]struct{},
	seenPaths map[string]struct{},
) (includedSSHConfigFile, bool, error) {
	if _, exists := seenPaths[match]; exists {
		return includedSSHConfigFile{}, false, nil
	}
	info, statErr := os.Stat(match)
	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return includedSSHConfigFile{}, false, nil
		}
		return includedSSHConfigFile{}, false, fmt.Errorf("stat included ssh config %q: %w", match, statErr)
	}
	if info.IsDir() {
		return includedSSHConfigFile{}, false, nil
	}
	canonPath := canonicalIncludePath(match)
	if _, inCycle := active[canonPath]; inCycle {
		return includedSSHConfigFile{}, false, nil
	}
	active[canonPath] = struct{}{}
	subDoc, decErr := decodeOpenSSHFile(match, system, depth+1, active)
	delete(active, canonPath)
	if decErr != nil {
		return includedSSHConfigFile{}, false, fmt.Errorf("decode included ssh config %q: %w", match, decErr)
	}
	seenPaths[match] = struct{}{}
	return includedSSHConfigFile{path: match, doc: subDoc}, true, nil
}

func expandOpenSSHIncludePattern(pat string, system bool) (string, bool, error) {
	expanded, skip, err := expandIncludeTokens(pat, pat, system)
	if err != nil || skip {
		return "", skip, err
	}
	combined := expanded
	if strings.HasPrefix(expanded, "~") {
		if system {
			return "", true, nil
		}
		resolved, skipTilde, err := expandHomeDirTilde(expanded, pat)
		if err != nil || skipTilde {
			return "", skipTilde, err
		}
		combined = resolved
	}
	if combined == "" {
		return "", true, nil
	}
	if filepath.IsAbs(combined) {
		return combined, false, nil
	}
	if system {
		return filepath.Join("/etc/ssh", combined), false, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false, fmt.Errorf("expand user ssh dir for Include %q: %w", pat, err)
	}
	return filepath.Join(home, ".ssh", combined), false, nil
}

func expandHomeDirTilde(expanded, pat string) (path string, skip bool, err error) {
	sep := strings.IndexAny(expanded[1:], `/\`)
	var userPart, rest string
	if sep < 0 {
		userPart = expanded[1:]
	} else {
		userPart = expanded[1 : 1+sep]
		rest = expanded[1+sep+1:]
	}
	var prefix string
	if userPart == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", false, fmt.Errorf("expand home dir for Include %q: %w", pat, err)
		}
		prefix = home
	} else {
		u, err := user.Lookup(userPart)
		if err != nil || u == nil || u.HomeDir == "" {
			return "", true, nil
		}
		prefix = u.HomeDir
	}
	if rest != "" {
		return filepath.Join(prefix, rest), false, nil
	}
	return prefix, false, nil
}

func expandIncludeTokens(s, rawPat string, system bool) (string, bool, error) {
	if !strings.ContainsAny(s, "$%") {
		return s, false, nil
	}
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '$' && i+1 < len(s) && s[i+1] == '{' {
			rep, nextIdx, skip, err := expandIncludeEnvVar(s, i, rawPat)
			if err != nil || skip {
				return "", skip, err
			}
			out.WriteString(rep)
			i = nextIdx
			continue
		}
		if ch == '%' {
			if i+1 >= len(s) {
				return "", false, fmt.Errorf("trailing '%%' token in Include %q", rawPat)
			}
			i++
			rep, skip, err := resolveIncludePercentToken(s[i], rawPat, system)
			if err != nil || skip {
				return "", skip, err
			}
			out.WriteString(rep)
			continue
		}
		out.WriteByte(ch)
	}
	return out.String(), false, nil
}

func expandIncludeEnvVar(s string, start int, rawPat string) (string, int, bool, error) {
	closeIdx := strings.IndexByte(s[start+2:], '}')
	if closeIdx < 0 {
		return "", 0, false, fmt.Errorf("unterminated environment variable in Include %q", rawPat)
	}
	name := s[start+2 : start+2+closeIdx]
	if name == "" {
		return "", 0, false, fmt.Errorf("empty environment variable name in Include %q", rawPat)
	}
	val, ok := os.LookupEnv(name)
	if !ok || val == "" {
		return "", 0, true, nil
	}
	return val, start + 2 + closeIdx, false, nil
}

func resolveIncludePercentToken(tok byte, rawPat string, system bool) (string, bool, error) {
	switch tok {
	case '%':
		return "%", false, nil
	case 'd':
		if system {
			return "", true, nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", false, fmt.Errorf("expand %%d for Include %q: %w", rawPat, err)
		}
		return home, false, nil
	case 'u':
		u, err := getCurrentUser()
		if err != nil || u == "" {
			return "", false, fmt.Errorf("expand %%u for Include %q: %w", rawPat, err)
		}
		return u, false, nil
	case 'i':
		uid := os.Getuid()
		if uid < 0 {
			return "", true, nil
		}
		return strconv.Itoa(uid), false, nil
	case 'l':
		hn, err := os.Hostname()
		if err != nil || hn == "" {
			return "", true, nil
		}
		return hn, false, nil
	case 'L':
		hn, err := os.Hostname()
		if err != nil || hn == "" {
			return "", true, nil
		}
		short, _, _ := strings.Cut(hn, ".")
		return short, false, nil
	case 'h', 'n', 'r', 'p', 'C', 'k':
		// Target-dependent OpenSSH tokens are unavailable at config-load time;
		// OpenSSH skips expanding them quietly during Include loading.
		return "", true, nil
	default:
		return "", false, fmt.Errorf("unsupported Include token %%%c in %q", tok, rawPat)
	}
}

func isSystemSSHConfigPath(path string) bool {
	if path == "" {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	return clean == "/etc/ssh" || strings.HasPrefix(clean, "/etc/ssh/")
}

func canonicalIncludePath(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil && resolved != "" {
		return filepath.Clean(resolved)
	}
	if abs, err := filepath.Abs(path); err == nil && abs != "" {
		return filepath.Clean(abs)
	}
	return filepath.Clean(path)
}

func firstSSHConfigKeyValue(doc *sshConfigDoc, host string, keys ...string) string {
	return firstSSHConfigKeyValueRaw(doc, host, false, keys...)
}

func firstSSHConfigKeyValueRaw(doc *sshConfigDoc, host string, preserveRaw bool, keys ...string) string {
	if doc == nil || host == "" || len(keys) == 0 {
		return ""
	}
	var found string
	walkMatchingSSHConfigDirectives(doc, host, func(d *sshConfigDirective) bool {
		for _, candidate := range keys {
			if strings.EqualFold(d.key, candidate) {
				v := d.value
				if preserveRaw {
					v = d.rawValue
				}
				if v != "" {
					found = v
					return false
				}
				break
			}
		}
		return true
	})
	return found
}

func walkMatchingSSHConfigDirectives(doc *sshConfigDoc, alias string, visit func(d *sshConfigDirective) bool) {
	if doc == nil || alias == "" || visit == nil {
		return
	}
	walkMatchingSSHConfigAST(doc, alias, nil, visit)
}

func walkMatchingSSHConfigBlocks(doc *sshConfigDoc, alias string, visit func(block *sshConfigBlock) bool) {
	if doc == nil || alias == "" || visit == nil {
		return
	}
	walkMatchingSSHConfigAST(doc, alias, visit, nil)
}

func walkMatchingSSHConfigAST(
	doc *sshConfigDoc,
	alias string,
	onBlock func(block *sshConfigBlock) bool,
	onDirective func(d *sshConfigDirective) bool,
) {
	active := make(map[*sshConfigDoc]struct{}, 4)
	_ = walkMatchingSSHConfigASTRec(doc, alias, 0, active, onBlock, onDirective)
}

func walkMatchingSSHConfigASTRec(
	doc *sshConfigDoc,
	alias string,
	depth int,
	active map[*sshConfigDoc]struct{},
	onBlock func(block *sshConfigBlock) bool,
	onDirective func(d *sshConfigDirective) bool,
) bool {
	if doc == nil || depth > maxIncludeDepth {
		return true
	}
	if _, seen := active[doc]; seen {
		return true
	}
	active[doc] = struct{}{}
	defer delete(active, doc)

	for _, block := range doc.blocks {
		if block == nil || !block.matches(alias) {
			continue
		}
		if onBlock != nil && !onBlock(block) {
			return false
		}
		if !walkMatchingBlockNodes(block.nodes, alias, depth, active, onBlock, onDirective) {
			return false
		}
	}
	return true
}

func walkMatchingBlockNodes(
	nodes []sshConfigNode,
	alias string,
	depth int,
	active map[*sshConfigDoc]struct{},
	onBlock func(block *sshConfigBlock) bool,
	onDirective func(d *sshConfigDirective) bool,
) bool {
	for _, node := range nodes {
		switch n := node.(type) {
		case *sshConfigDirective:
			if n != nil && onDirective != nil && !onDirective(n) {
				return false
			}
		case *sshConfigInclude:
			if n == nil || len(n.files) == 0 || depth >= maxIncludeDepth {
				continue
			}
			for _, inc := range n.files {
				if !walkMatchingSSHConfigASTRec(inc.doc, alias, depth+1, active, onBlock, onDirective) {
					return false
				}
			}
		}
	}
	return true
}

func walkConcreteSSHHostNames(doc *sshConfigDoc, visit func(name string) bool) {
	if doc == nil || visit == nil {
		return
	}
	seen := make(map[string]struct{})
	active := make(map[*sshConfigDoc]struct{}, 4)
	_ = walkConcreteSSHHostNamesRec(doc, nil, 0, active, seen, visit)
}

func walkConcreteSSHHostNamesRec(
	doc *sshConfigDoc,
	enclosing []*sshConfigBlock,
	depth int,
	active map[*sshConfigDoc]struct{},
	seen map[string]struct{},
	visit func(name string) bool,
) bool {
	if doc == nil || depth > maxIncludeDepth {
		return true
	}
	if _, ok := active[doc]; ok {
		return true
	}
	active[doc] = struct{}{}
	defer delete(active, doc)

	for _, block := range doc.blocks {
		if block == nil {
			continue
		}
		if !block.implicit && !block.isMatch {
			for _, pat := range block.patterns {
				if pat.negated || !isConcreteSSHHost(pat.raw) {
					continue
				}
				if _, dup := seen[pat.raw]; dup {
					continue
				}
				if !block.matchesConcretePattern(pat.raw) || !allSSHConfigBlocksMatch(enclosing, pat.raw) {
					continue
				}
				seen[pat.raw] = struct{}{}
				if !visit(pat.raw) {
					return false
				}
			}
		}
		if !walkConcreteIncludedFiles(block, enclosing, depth, active, seen, visit) {
			return false
		}
	}
	return true
}

func walkConcreteIncludedFiles(
	block *sshConfigBlock,
	enclosing []*sshConfigBlock,
	depth int,
	active map[*sshConfigDoc]struct{},
	seen map[string]struct{},
	visit func(name string) bool,
) bool {
	if depth >= maxIncludeDepth {
		return true
	}
	nextEnclosing := append(slices.Clip(enclosing), block)
	for _, node := range block.nodes {
		inc, ok := node.(*sshConfigInclude)
		if !ok || inc == nil || len(inc.files) == 0 {
			continue
		}
		for _, f := range inc.files {
			if !walkConcreteSSHHostNamesRec(f.doc, nextEnclosing, depth+1, active, seen, visit) {
				return false
			}
		}
	}
	return true
}

func allSSHConfigBlocksMatch(blocks []*sshConfigBlock, alias string) bool {
	for _, b := range blocks {
		if b == nil || !b.matches(alias) {
			return false
		}
	}
	return true
}
