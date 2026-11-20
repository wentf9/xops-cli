package ssh

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corelog "github.com/wentf9/xops-cli/core/log"
	cryptoSSH "golang.org/x/crypto/ssh"
)

const (
	// MaxSessionEnvVars caps the total number of environment variables sent per SSH session.
	MaxSessionEnvVars = 128
	// MaxSessionEnvEntryBytes caps the combined "NAME=VALUE" byte length of a single session environment variable.
	MaxSessionEnvEntryBytes = 32 * 1024
)

// EnvVar represents a resolved environment variable name and value to send on an SSH session.
type EnvVar struct {
	Name  string
	Value string
}

type sendEnvRule struct {
	pattern string
	negate  bool
}

func isEnvIdentStart(ch byte) bool {
	return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '_'
}

func isEnvIdentCont(ch byte) bool {
	return isEnvIdentStart(ch) || (ch >= '0' && ch <= '9')
}

// isValidEnvVarName reports whether name matches ^[A-Za-z_][A-Za-z0-9_]*$.
func isValidEnvVarName(name string) bool {
	if name == "" || !isEnvIdentStart(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !isEnvIdentCont(name[i]) {
			return false
		}
	}
	return true
}

// isDeniedSendEnvName enforces the non-bypassable denylist when matching host environment
// variables via SendEnv (and filtering SetEnv) so wildcard patterns or explicit directives
// never leak local secrets or dynamic linker injection variables.
func isDeniedSendEnvName(name string) bool {
	upper := strings.ToUpper(name)
	switch upper {
	case "SSH_AUTH_SOCK",
		"SSH_AGENT_PID",
		"KRB5CCNAME",
		"GITHUB_TOKEN",
		"GH_TOKEN",
		"GITLAB_TOKEN",
		"VAULT_TOKEN",
		"NPM_TOKEN",
		"AWS_SESSION_TOKEN",
		"AWS_ACCESS_KEY_ID":
		return true
	}
	return strings.HasPrefix(upper, "XOPS_") ||
		strings.HasPrefix(upper, "SSH_ASKPASS") ||
		strings.HasPrefix(upper, "LD_") ||
		strings.HasPrefix(upper, "DYLD_") ||
		strings.HasPrefix(upper, "AWS_SECRET_")
}

// matchOpenSSHPattern matches s against an OpenSSH pattern supporting '*' (zero or more
// arbitrary characters) and '?' (any single byte/character) in bounded O(len(p)*len(s)) time.
func matchOpenSSHPattern(pattern, s string) bool {
	px, sx := 0, 0
	nextPx, nextSx := 0, 0
	for px < len(pattern) || sx < len(s) {
		if px < len(pattern) {
			switch pattern[px] {
			case '?':
				if sx < len(s) {
					px++
					sx++
					continue
				}
			case '*':
				nextPx = px
				nextSx = sx + 1
				px++
				continue
			default:
				if sx < len(s) && s[sx] == pattern[px] {
					px++
					sx++
					continue
				}
			}
		}
		if nextSx > 0 && nextSx <= len(s) {
			px = nextPx
			sx = nextSx
			continue
		}
		return false
	}
	return true
}

func validateSendEnvToken(tok string) error {
	if tok == "" {
		return errors.New("pattern cannot be empty")
	}
	if tok == "-" {
		return errors.New("negative SendEnv pattern '-' is missing pattern body")
	}
	if strings.ContainsRune(tok, '=') {
		return fmt.Errorf("SendEnv pattern %q must not contain '=' (use SetEnv for KEY=VALUE)", tok)
	}
	if hasControlOrLineSepChar(tok) {
		return fmt.Errorf("SendEnv pattern %q contains invalid ASCII control character", tok)
	}
	body := strings.TrimPrefix(tok, "-")
	for i := 0; i < len(body); i++ {
		ch := body[i]
		if ch == '*' || ch == '?' {
			continue
		}
		if i == 0 && !isEnvIdentStart(ch) {
			return fmt.Errorf("SendEnv pattern %q has invalid leading variable character %q", tok, ch)
		}
		if i > 0 && !isEnvIdentCont(ch) {
			return fmt.Errorf("SendEnv pattern %q has invalid variable character %q", tok, ch)
		}
	}
	return nil
}

func validateSendEnvOption(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("invalid SendEnv: value cannot be empty")
	}
	var tokens []string
	for line := range strings.SplitSeq(raw, "\n") {
		if hasKnownHostsControlChar(line) {
			return "", fmt.Errorf("invalid SendEnv %q: value contains invalid control character", line)
		}
		item := strings.TrimSpace(line)
		if item == "" {
			continue
		}
		parsed, err := splitQuotedEnvTokens(item)
		if err != nil {
			return "", fmt.Errorf("invalid SendEnv %q: %w", item, err)
		}
		for _, tok := range parsed {
			if err := validateSendEnvToken(tok); err != nil {
				return "", fmt.Errorf("invalid SendEnv %q: %w", tok, err)
			}
			tokens = append(tokens, tok)
		}
	}
	if len(tokens) == 0 {
		return "", errors.New("invalid SendEnv: value cannot be empty")
	}
	return strings.Join(tokens, "\n"), nil
}

func validateSetEnvOption(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("invalid SetEnv: value cannot be empty")
	}
	var lines []string
	for line := range strings.SplitSeq(raw, "\n") {
		if hasKnownHostsControlChar(line) {
			return "", errors.New("invalid SetEnv: value contains invalid control character")
		}
		item := strings.TrimSpace(line)
		if item == "" {
			continue
		}
		parsed, err := parseSetEnvDirective(item)
		if err != nil {
			return "", fmt.Errorf("invalid SetEnv %q: %w", item, err)
		}
		if len(parsed) == 0 {
			return "", fmt.Errorf("invalid SetEnv %q: no KEY=VALUE assignments found", item)
		}
		lines = append(lines, item)
	}
	if len(lines) == 0 {
		return "", errors.New("invalid SetEnv: value cannot be empty")
	}
	return strings.Join(lines, "\n"), nil
}

// parseSetEnvDirective splits a single SetEnv directive into one or more KEY=VALUE pairs,
// honoring single and double quotes around either VALUE or the entire "KEY=VALUE" token.
// Following OpenSSH semantics, all tokens are validated and duplicate variable names
// within the same SetEnv directive retain the first occurrence.
func parseSetEnvDirective(directive string) ([]EnvVar, error) {
	tokens, err := splitQuotedEnvTokens(directive)
	if err != nil {
		return nil, err
	}
	vars := make([]EnvVar, 0, len(tokens))
	seen := make(map[string]struct{}, len(tokens))
	for _, tok := range tokens {
		name, val, ok := strings.Cut(tok, "=")
		if !ok {
			return nil, fmt.Errorf("missing '=' in %q", tok)
		}
		if !isValidEnvVarName(name) {
			return nil, fmt.Errorf("invalid environment variable name %q", name)
		}
		if strings.ContainsRune(val, 0) {
			return nil, fmt.Errorf("environment variable %q value contains null byte", name)
		}
		if len(name)+1+len(val) > MaxSessionEnvEntryBytes {
			return nil, fmt.Errorf("environment variable %q exceeds %d bytes", name, MaxSessionEnvEntryBytes)
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		vars = append(vars, EnvVar{Name: name, Value: val})
	}
	return vars, nil
}

func splitQuotedEnvTokens(s string) ([]string, error) {
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
		var err error
		i, err = consumeQuotedEnvToken(s, i, &sb)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, sb.String())
	}
	return tokens, nil
}

func consumeQuotedEnvToken(s string, i int, sb *strings.Builder) (int, error) {
	var quote byte
	for i < len(s) {
		if quote == 0 {
			var done bool
			i, quote, done = stepUnquotedEnvByte(s, i, sb)
			if done {
				break
			}
			continue
		}
		i, quote = stepQuotedEnvByte(s, i, quote, sb)
	}
	if quote != 0 {
		return i, fmt.Errorf("unclosed %c quote", quote)
	}
	return i, nil
}

func stepUnquotedEnvByte(s string, i int, sb *strings.Builder) (nextIdx int, quote byte, done bool) {
	ch := s[i]
	if ch == ' ' || ch == '\t' {
		return i, 0, true
	}
	if ch == '\'' || ch == '"' {
		return i + 1, ch, false
	}
	if ch == '\\' && i+1 < len(s) && isEscapableUnquotedEnvChar(s[i+1]) {
		sb.WriteByte(s[i+1])
		return i + 2, 0, false
	}
	sb.WriteByte(ch)
	return i + 1, 0, false
}

func isEscapableUnquotedEnvChar(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '"' || ch == '\'' || ch == '\\'
}

func stepQuotedEnvByte(s string, i int, quote byte, sb *strings.Builder) (int, byte) {
	ch := s[i]
	if ch == quote {
		return i + 1, 0
	}
	if quote == '"' && ch == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
		sb.WriteByte(s[i+1])
		return i + 2, quote
	}
	sb.WriteByte(ch)
	return i + 1, quote
}

func buildSendEnvRules(patterns []string) ([]sendEnvRule, bool, error) {
	var rules []sendEnvRule
	for _, entry := range patterns {
		parsed, err := splitQuotedEnvTokens(entry)
		if err != nil {
			return nil, false, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
		}
		for _, tok := range parsed {
			if err := validateSendEnvToken(tok); err != nil {
				return nil, false, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
			}
			if strings.HasPrefix(tok, "-") {
				negPat := tok[1:]
				kept := rules[:0]
				for _, r := range rules {
					if !r.negate && matchOpenSSHPattern(negPat, r.pattern) {
						continue
					}
					kept = append(kept, r)
				}
				rules = append(kept, sendEnvRule{pattern: negPat, negate: true})
				continue
			}
			kept := rules[:0]
			for _, r := range rules {
				if r.negate && r.pattern == tok {
					continue
				}
				kept = append(kept, r)
			}
			rules = append(kept, sendEnvRule{pattern: tok, negate: false})
		}
	}
	hasPositive := false
	for _, r := range rules {
		if !r.negate {
			hasPositive = true
			break
		}
	}
	return rules, hasPositive, nil
}

func shouldSendEnvVar(rules []sendEnvRule, name string) bool {
	send := false
	for _, r := range rules {
		if matchOpenSSHPattern(r.pattern, name) {
			send = !r.negate
		}
	}
	return send
}

// ResolveSessionEnv computes the ordered list of environment variables to transmit on a new SSH
// user session from SendEnv patterns (matched against hostEnviron with non-bypassable denylist
// filtering) and explicit SetEnv KEY=VALUE directives.
//
// Slice entries in opts are processed left-to-right (Tier 4 -> Tier 3 -> Tier 2 -> Tier 1 when
// merged via EffectiveOptions / MergeOptionLayers): '-PATTERN' removes/suppresses previously
// accumulated SendEnv patterns, and later SetEnv directives override earlier SetEnv directives
// as well as SendEnv values.
func ResolveSessionEnv(opts *Options, hostEnviron func() []string) ([]EnvVar, error) {
	return resolveSessionEnvWithLogger(opts, hostEnviron, corelog.NopLogger)
}

func resolveSessionEnvWithLogger(opts *Options, hostEnviron func() []string, log corelog.DebugLogger) ([]EnvVar, error) {
	if opts.IsEmpty() {
		return nil, nil
	}
	if log == nil {
		log = corelog.NopLogger
	}

	rules, hasPositiveSendEnv, err := buildSendEnvRules(opts.SendEnvPatterns())
	if err != nil {
		return nil, err
	}

	setEnvPairs, setEnvNames, err := collectValidatedSetEnv(opts.SetEnvDirectives(), log)
	if err != nil {
		return nil, err
	}

	acc := newSessionEnvAccumulator()
	if hasPositiveSendEnv && hostEnviron != nil {
		acc.addMatchingHostEnv(hostEnviron(), rules, setEnvNames, log)
	}

	for _, ev := range setEnvPairs {
		if err := acc.upsert(ev); err != nil {
			return nil, err
		}
	}

	if len(acc.resolved) == 0 {
		return nil, nil
	}
	return acc.resolved, nil
}

func collectValidatedSetEnv(directives []string, log corelog.DebugLogger) ([]EnvVar, map[string]struct{}, error) {
	if len(directives) == 0 {
		return nil, nil, nil
	}
	var pairs []EnvVar
	uniqueNames := make(map[string]struct{})
	for _, directive := range directives {
		parsed, err := parseSetEnvDirective(directive)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: invalid SetEnv %q: %w", ErrSSHOptionsValidation, directive, err)
		}
		for _, ev := range parsed {
			if isDeniedSendEnvName(ev.Name) {
				log.Debugf("SetEnv %q blocked by denylist", ev.Name)
				continue
			}
			uniqueNames[ev.Name] = struct{}{}
			if len(uniqueNames) > MaxSessionEnvVars {
				return nil, nil, fmt.Errorf("%w: session environment exceeds maximum of %d variables", ErrSSHOptionsValidation, MaxSessionEnvVars)
			}
			pairs = append(pairs, ev)
		}
	}
	return pairs, uniqueNames, nil
}

type sessionEnvAccumulator struct {
	resolved    []EnvVar
	indexByName map[string]int
}

func newSessionEnvAccumulator() *sessionEnvAccumulator {
	return &sessionEnvAccumulator{indexByName: make(map[string]int)}
}

func (a *sessionEnvAccumulator) upsert(ev EnvVar) error {
	if len(ev.Name)+1+len(ev.Value) > MaxSessionEnvEntryBytes {
		return fmt.Errorf("%w: environment variable %q exceeds %d bytes", ErrSSHOptionsValidation, ev.Name, MaxSessionEnvEntryBytes)
	}
	if idx, exists := a.indexByName[ev.Name]; exists {
		a.resolved[idx].Value = ev.Value
		return nil
	}
	if len(a.resolved) >= MaxSessionEnvVars {
		return fmt.Errorf("%w: session environment exceeds maximum of %d variables", ErrSSHOptionsValidation, MaxSessionEnvVars)
	}
	a.indexByName[ev.Name] = len(a.resolved)
	a.resolved = append(a.resolved, ev)
	return nil
}

func (a *sessionEnvAccumulator) addMatchingHostEnv(
	environ []string,
	rules []sendEnvRule,
	reservedSetEnv map[string]struct{},
	log corelog.DebugLogger,
) {
	maxSendEnvOnly := MaxSessionEnvVars - len(reservedSetEnv)
	sendEnvOnlyCount := 0
	for _, raw := range environ {
		name, val, ok := strings.Cut(raw, "=")
		if !ok || !isValidEnvVarName(name) || strings.ContainsRune(val, 0) {
			continue
		}
		if isDeniedSendEnvName(name) || !shouldSendEnvVar(rules, name) {
			continue
		}
		if entryLen := len(name) + 1 + len(val); entryLen > MaxSessionEnvEntryBytes {
			log.Debugf("SendEnv: skipping host variable %q (%d bytes exceeds %d-byte limit)", name, entryLen, MaxSessionEnvEntryBytes)
			continue
		}
		if idx, exists := a.indexByName[name]; exists {
			a.resolved[idx].Value = val
			continue
		}
		_, overriddenBySetEnv := reservedSetEnv[name]
		if !overriddenBySetEnv {
			if sendEnvOnlyCount >= maxSendEnvOnly {
				log.Debugf("SendEnv: skipping host variable %q (session limit of %d variables reached)", name, MaxSessionEnvVars)
				continue
			}
			sendEnvOnlyCount++
		}
		a.indexByName[name] = len(a.resolved)
		a.resolved = append(a.resolved, EnvVar{Name: name, Value: val})
	}
}

func (c *Client) resolveClientSessionEnv() ([]EnvVar, error) {
	if c == nil {
		return nil, nil
	}
	connCfg := c.ConnectionConfig()
	if connCfg.Options.IsEmpty() {
		return nil, nil
	}
	return resolveSessionEnvWithLogger(connCfg.Options, c.environment.Environ, c.getLogger())
}

func isProtocolSetenvRejected(err error) bool {
	return err != nil && err.Error() == "ssh: setenv failed"
}

// applySessionEnv sends resolved SendEnv/SetEnv variables on a newly created session before
// PTY/shell/exec/subsystem requests. Server-side protocol rejection ("ssh: setenv failed" when
// sshd AcceptEnv does not permit a variable) is logged at Debugf level and does not abort the
// session; context cancellation, timeout, or transport errors fail closed.
func (c *Client) applySessionEnv(ctx context.Context, session *cryptoSSH.Session) error {
	vars, err := c.resolveClientSessionEnv()
	if err != nil {
		return err
	}
	if len(vars) == 0 {
		return nil
	}
	for _, ev := range vars {
		if err := c.sendBoundedSetenv(ctx, session, ev); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) sendBoundedSetenv(ctx context.Context, session *cryptoSSH.Session, ev EnvVar) error {
	if ctx == nil {
		return errors.New("SSH env request context is nil")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("SSH env request canceled: %w", err)
	}
	c.observeSession(corelog.SessionRequest, 2, "env", "sending")
	work, cancel := withTimeoutOrDefault(ctx, c.handshakeTimeout, defaultSSHHandshakeTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- session.Setenv(ev.Name, ev.Value)
	}()
	select {
	case err := <-done:
		if err == nil {
			c.observeSession(corelog.SessionRequest, 2, "env", "accepted")
			return nil
		}
		if work.Err() == nil && isProtocolSetenvRejected(err) {
			c.observeSession(corelog.SessionRequest, 2, "env", "rejected")
			c.getLogger().Debugf("SSH server rejected env variable %q: %v", ev.Name, err)
			return nil
		}
		c.observeSession(corelog.SessionRequest, 2, "env", "failed or interrupted")
		return fmt.Errorf("SSH env request failed: %w", err)
	case <-work.Done():
		c.observeSession(corelog.SessionRequest, 2, "env", "failed or interrupted")
		return fmt.Errorf("SSH env request interrupted: %w", c.closeCanceledSession(work, session, done))
	}
}
