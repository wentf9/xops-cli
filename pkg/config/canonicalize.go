package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/wentf9/xops-cli/core/ssh"
)

const (
	defaultCanonicalizeMaxDots = 1
	maxCanonicalProbeTimeout   = 5 * time.Second
)

// ErrCanonicalizeFailed is returned when hostname canonicalization was attempted,
// no CanonicalDomains candidate resolved, and CanonicalizeFallbackLocal is disabled.
var ErrCanonicalizeFailed = errors.New("hostname canonicalization failed")

// CanonicalResolver abstracts DNS lookups used during OpenSSH hostname canonicalization
// so unit tests can inject deterministic, zero-network resolvers.
type CanonicalResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

type netCanonicalResolver struct{}

func (netCanonicalResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

func (netCanonicalResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return net.DefaultResolver.LookupCNAME(ctx, host)
}

// CanonicalizeInput describes the Pass 1 inputs to OpenSSH Canonicalize* evaluation.
type CanonicalizeInput struct {
	Provider         ConfigProvider
	Host             string
	RawCLIOptions    []string
	CLIProxyJump     string
	MatchedSavedNode bool
	Resolver         CanonicalResolver
}

// CanonicalizeResult holds the bounded two-pass canonicalization outcome.
type CanonicalizeResult struct {
	OriginalHost  string
	CanonicalHost string
	Canonicalized bool
	// Pass2Options captures the OpenSSHParser options for CanonicalHost; in
	// production CLI/adapter flows, SSHAdapter.ResolveSSHOptions re-evaluates
	// Pass 2 options directly on the canonicalized selector.
	Pass2Options *ssh.Options
}

type canonicalizePolicy struct {
	mode            string // "no", "yes", "always"
	domains         []string
	maxDots         int
	fallbackLocal   bool
	permittedCNAMEs []cnameRule
	hasProxyJump    bool
	hasProxyCommand bool
	timeout         time.Duration
}

type cnameRule struct {
	sourcePatternList string
	targetPatternList string
}

// CanonicalizeHost evaluates OpenSSH CanonicalizeHostname/CanonicalDomains/CanonicalizeMaxDots/
// CanonicalizeFallbackLocal/CanonicalizePermittedCNAMEs in at most two OpenSSHParser passes.
func CanonicalizeHost(ctx context.Context, in CanonicalizeInput) (CanonicalizeResult, error) {
	orig := strings.TrimSpace(in.Host)
	res := CanonicalizeResult{
		OriginalHost:  orig,
		CanonicalHost: orig,
	}
	if orig == "" {
		return res, nil
	}
	var parser *OpenSSHParser
	if src, ok := in.Provider.(openSSHParserSource); ok && src != nil {
		parser = src.GetOpenSSHParser()
	}
	if !in.MatchedSavedNode && parser != nil && parser.Err() != nil {
		return CanonicalizeResult{}, parser.Err()
	}
	if in.MatchedSavedNode || isIPOrLocalhost(orig) {
		return res, nil
	}
	probeTarget := resolveCanonicalEffectiveInputHost(parser, in.RawCLIOptions, orig)
	if isIPOrLocalhost(probeTarget) {
		return res, nil
	}
	policy := resolveCanonicalizePolicy(parser, canonicalProviderTier3Options(in.Provider), orig, in.RawCLIOptions, in.CLIProxyJump)
	if !shouldCanonicalize(probeTarget, policy) {
		return res, nil
	}

	resolver := in.Resolver
	if resolver == nil {
		resolver = netCanonicalResolver{}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return CanonicalizeResult{}, err
	}
	probeCtx, cancel := context.WithTimeout(ctx, policy.timeout)
	defer cancel()

	return executeCanonicalizeProbe(ctx, probeCtx, resolver, parser, policy, probeTarget, res)
}

// CanonicalDomainCandidates returns the ordered FQDN candidates considered for host
// by CanonicalizeHostname/CanonicalDomains without performing DNS I/O.
func CanonicalDomainCandidates(provider ConfigProvider, host string) []string {
	return CanonicalDomainCandidatesWithOptions(provider, host, nil, "")
}

// CanonicalDomainCandidatesWithOptions returns the ordered FQDN candidates
// considered for host while applying explicit CLI -o / -J overrides before
// falling back to ~/.ssh/config and global defaults.
func CanonicalDomainCandidatesWithOptions(provider ConfigProvider, host string, rawCLIOptions []string, cliProxyJump string) []string {
	orig := strings.TrimSpace(host)
	if orig == "" || isIPOrLocalhost(orig) {
		return nil
	}
	var parser *OpenSSHParser
	if src, ok := provider.(openSSHParserSource); ok && src != nil {
		parser = src.GetOpenSSHParser()
	}
	if parser != nil && parser.Err() != nil {
		return nil
	}
	probeTarget := resolveCanonicalEffectiveInputHost(parser, rawCLIOptions, orig)
	if isIPOrLocalhost(probeTarget) || strings.HasSuffix(probeTarget, ".") {
		return nil
	}
	policy := resolveCanonicalizePolicy(parser, canonicalProviderTier3Options(provider), orig, rawCLIOptions, cliProxyJump)
	if !shouldProbeCanonicalDomains(probeTarget, policy) {
		return nil
	}
	out := make([]string, 0, len(policy.domains))
	for _, domain := range policy.domains {
		fqdn := probeTarget + "." + domain
		if !slices.Contains(out, fqdn) {
			out = append(out, fqdn)
		}
	}
	return out
}

func canonicalProviderTier3Options(provider ConfigProvider) *ssh.Options {
	if provider == nil {
		return nil
	}
	if snap := provider.Snapshot(); snap != nil {
		return snap.SSHOptions
	}
	return nil
}

func executeCanonicalizeProbe(
	parentCtx context.Context,
	probeCtx context.Context,
	resolver CanonicalResolver,
	parser *OpenSSHParser,
	policy canonicalizePolicy,
	probeTarget string,
	res CanonicalizeResult,
) (CanonicalizeResult, error) {
	if parentCtx != nil && parentCtx.Err() != nil {
		return CanonicalizeResult{}, parentCtx.Err()
	}
	trailingDot := strings.HasSuffix(probeTarget, ".")
	dotCount := canonicalDotCount(probeTarget)
	if !trailingDot && dotCount <= policy.maxDots && len(policy.domains) > 0 {
		chosen, ok, pErr := probeCanonicalDomains(parentCtx, probeCtx, resolver, probeTarget, policy)
		if pErr != nil {
			return CanonicalizeResult{}, pErr
		}
		if ok {
			res.CanonicalHost = chosen
			res.Canonicalized = !strings.EqualFold(chosen, res.OriginalHost)
			if res.Canonicalized {
				res.Pass2Options = pass2OpenSSHOptionsWithCanonical(parser, res.OriginalHost, chosen)
			} else {
				res.Pass2Options = pass2OpenSSHOptions(parser, chosen)
			}
			return res, nil
		}
		if parentCtx != nil && parentCtx.Err() != nil {
			return CanonicalizeResult{}, parentCtx.Err()
		}
		if !policy.fallbackLocal {
			return res, fmt.Errorf("%w: %s", ErrCanonicalizeFailed, probeTarget)
		}
	}

	return probeLocalCanonicalCNAME(parentCtx, probeCtx, resolver, parser, policy, probeTarget, res)
}

func probeLocalCanonicalCNAME(
	parentCtx context.Context,
	probeCtx context.Context,
	resolver CanonicalResolver,
	parser *OpenSSHParser,
	policy canonicalizePolicy,
	probeTarget string,
	res CanonicalizeResult,
) (CanonicalizeResult, error) {
	if parentCtx != nil && parentCtx.Err() != nil {
		return CanonicalizeResult{}, parentCtx.Err()
	}
	if len(policy.permittedCNAMEs) == 0 {
		return res, nil
	}
	if addrs, err := resolver.LookupHost(probeCtx, probeTarget); err == nil && len(addrs) > 0 {
		chosen, cErr := resolveCanonicalCNAME(parentCtx, probeCtx, resolver, probeTarget, probeTarget, policy.permittedCNAMEs)
		if cErr != nil {
			return CanonicalizeResult{}, cErr
		}
		if !strings.EqualFold(chosen, probeTarget) {
			res.CanonicalHost = chosen
			res.Canonicalized = true
			res.Pass2Options = pass2OpenSSHOptionsWithCanonical(parser, res.OriginalHost, chosen)
		}
	} else if parentCtx != nil && parentCtx.Err() != nil {
		return CanonicalizeResult{}, parentCtx.Err()
	}
	return res, nil
}

func resolveCanonicalEffectiveInputHost(parser *OpenSSHParser, rawCLI []string, orig string) string {
	for _, raw := range rawCLI {
		k, v, ok := splitCanonicalOptionKV(raw)
		if !ok || ssh.CanonicalOptionKey(k) != ssh.OptionHostName {
			continue
		}
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		if expanded, err := ssh.ExpandHostName(trimmed, orig); err == nil {
			clean := unwrapExpandedHostName(trimmed, expanded)
			if clean != "" {
				return clean
			}
		}
		return orig
	}
	if parser != nil && parser.cfg != nil {
		if hn, err := resolveOpenSSHHostName(parser.cfg, orig); err == nil && hn != "" {
			return hn
		}
	}
	return orig
}

func isRealNetCanonicalResolver(resolver CanonicalResolver) bool {
	switch r := resolver.(type) {
	case netCanonicalResolver, *netCanonicalResolver:
		return true
	case *net.Resolver:
		return r != nil
	default:
		return false
	}
}

func canonicalDomainProbeName(resolver CanonicalResolver, fqdn string) string {
	if isRealNetCanonicalResolver(resolver) && !strings.HasSuffix(fqdn, ".") {
		return fqdn + "."
	}
	return fqdn
}

func probeCanonicalDomains(parentCtx, probeCtx context.Context, resolver CanonicalResolver, orig string, policy canonicalizePolicy) (string, bool, error) {
	for _, domain := range policy.domains {
		if parentCtx != nil && parentCtx.Err() != nil {
			return "", false, parentCtx.Err()
		}
		fqdn := orig + "." + domain
		lookupHost := canonicalDomainProbeName(resolver, fqdn)
		addrs, err := resolver.LookupHost(probeCtx, lookupHost)
		if err != nil || len(addrs) == 0 {
			if parentCtx != nil && parentCtx.Err() != nil {
				return "", false, parentCtx.Err()
			}
			continue
		}
		chosen, cErr := resolveCanonicalCNAME(parentCtx, probeCtx, resolver, fqdn, lookupHost, policy.permittedCNAMEs)
		if cErr != nil {
			return "", false, cErr
		}
		return chosen, true, nil
	}
	return "", false, nil
}

func pass2OpenSSHOptionsWithCanonical(parser *OpenSSHParser, origAlias, canonicalHost string) *ssh.Options {
	if parser == nil {
		return nil
	}
	var (
		opts *ssh.Options
		err  error
	)
	if strings.TrimSpace(origAlias) != "" {
		opts, err = parser.GetSSHOptionsWithCanonical(origAlias, canonicalHost)
	} else {
		opts, err = parser.GetSSHOptions(canonicalHost)
	}
	if err != nil {
		return nil
	}
	return opts
}

func pass2OpenSSHOptions(parser *OpenSSHParser, host string) *ssh.Options {
	if parser == nil {
		return nil
	}
	opts, err := parser.GetSSHOptions(host)
	if err != nil {
		return nil
	}
	return opts
}

func resolveCanonicalCNAME(parentCtx, probeCtx context.Context, resolver CanonicalResolver, host, lookupHost string, rules []cnameRule) (string, error) {
	if parentCtx != nil && parentCtx.Err() != nil {
		return "", parentCtx.Err()
	}
	if len(rules) == 0 {
		return host, nil
	}
	cname, err := resolver.LookupCNAME(probeCtx, lookupHost)
	if err != nil {
		if parentCtx != nil && parentCtx.Err() != nil {
			return "", parentCtx.Err()
		}
		return host, nil
	}
	if hasControlOrWhitespace(cname) {
		return host, nil
	}
	normHost := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	normCNAME := strings.TrimSuffix(strings.ToLower(cname), ".")
	if !isValidRFC1123CanonicalCNAME(normCNAME) {
		return host, nil
	}
	if normCNAME != normHost && isPermittedCNAME(normHost, normCNAME, rules) {
		return normCNAME, nil
	}
	return host, nil
}

func hasControlOrWhitespace(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == '\u2028' || r == '\u2029' {
			return true
		}
	}
	return false
}

func isValidRFC1123CanonicalCNAME(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return false
	}
	if strings.HasPrefix(name, OpenSSHNodePrefix) {
		return false
	}
	if isIPOrLocalhost(name) {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func canonicalDotCount(host string) int {
	return strings.Count(strings.TrimSuffix(host, "."), ".")
}

func canCanonicalizePolicy(policy canonicalizePolicy) bool {
	if policy.mode != "yes" && policy.mode != "always" {
		return false
	}
	if (policy.hasProxyJump || policy.hasProxyCommand) && policy.mode != "always" {
		return false
	}
	return true
}

func shouldProbeCanonicalDomains(host string, policy canonicalizePolicy) bool {
	if !canCanonicalizePolicy(policy) || len(policy.domains) == 0 {
		return false
	}
	if strings.HasSuffix(host, ".") {
		return false
	}
	return canonicalDotCount(host) <= policy.maxDots
}

func shouldCanonicalize(host string, policy canonicalizePolicy) bool {
	if !canCanonicalizePolicy(policy) {
		return false
	}
	trailingDot := strings.HasSuffix(host, ".")
	dotCount := canonicalDotCount(host)
	return (!trailingDot && dotCount <= policy.maxDots && len(policy.domains) > 0) || len(policy.permittedCNAMEs) > 0
}

func isIPOrLocalhost(host string) bool {
	trimmed := StripHostBrackets(host)
	if _, err := netip.ParseAddr(trimmed); err == nil {
		return true
	}
	lower := strings.TrimSuffix(strings.ToLower(trimmed), ".")
	return lower == "localhost"
}

func resolveCanonicalizePolicy(parser *OpenSSHParser, tier3Opts *ssh.Options, host string, rawCLI []string, cliProxyJump string) canonicalizePolicy {
	policy := canonicalizePolicy{
		mode:          "no",
		maxDots:       defaultCanonicalizeMaxDots,
		fallbackLocal: true,
		timeout:       maxCanonicalProbeTimeout,
	}
	if parser != nil && parser.cfg != nil {
		applySSHConfigCanonicalDirectives(&policy, parser.cfg, host)
	}
	if tier3Opts != nil {
		applySSHOptionsCanonicalDirectives(&policy, tier3Opts)
	}
	applyCLICanonicalDirectives(&policy, rawCLI, cliProxyJump)
	if policy.hasProxyJump {
		policy.hasProxyCommand = false
	}
	return policy
}

func applySSHConfigCanonicalDirectives(policy *canonicalizePolicy, doc *sshConfigDoc, host string) {
	if v := firstSSHConfigKeyValue(doc, host, "canonicalizehostname"); v != "" {
		policy.setMode(v)
	}
	if v := firstSSHConfigKeyValue(doc, host, "canonicaldomains"); v != "" {
		policy.setDomains(v)
	}
	if v := firstSSHConfigKeyValue(doc, host, "canonicalizemaxdots"); v != "" {
		policy.setMaxDots(v)
	}
	if v := firstSSHConfigKeyValue(doc, host, "canonicalizefallbacklocal"); v != "" {
		policy.setFallbackLocal(v)
	}
	if v := firstSSHConfigKeyValue(doc, host, "canonicalizepermittedcnames"); v != "" {
		policy.setPermittedCNAMEs(v)
	}
	winner, _, cmdVal := firstMatchingOpenSSHProxy(doc, host)
	switch winner {
	case "proxyjump":
		if v := firstSSHConfigKeyValue(doc, host, "proxyjump"); v != "" {
			policy.setProxyJump(v)
		}
	case "proxycommand", "none":
		if cmdVal != "" {
			policy.setProxyCommand(cmdVal)
		}
	default:
		if v := firstSSHConfigKeyValue(doc, host, "proxyjump"); ssh.IsDisabledProxyJump(v) {
			policy.setProxyJump("none")
		}
	}
	if v := firstSSHConfigKeyValue(doc, host, "connecttimeout"); v != "" {
		policy.setTimeoutSeconds(v)
	}
}

func applySSHOptionsCanonicalDirectives(policy *canonicalizePolicy, opts *ssh.Options) {
	if opts == nil {
		return
	}
	if v := strings.TrimSpace(opts.Get(ssh.OptionCanonicalizeHostname)); v != "" {
		policy.setMode(v)
	}
	if rawDomains := strings.TrimSpace(opts.Get(ssh.OptionCanonicalDomains)); rawDomains != "" {
		policy.setDomains(rawDomains)
	}
	if maxDots, ok := opts.CanonicalizeMaxDots(); ok {
		policy.maxDots = maxDots
	}
	if fb, ok := opts.CanonicalizeFallbackLocal(); ok {
		policy.fallbackLocal = fb
	}
	if rawCNAMEs := strings.TrimSpace(opts.Get(ssh.OptionCanonicalizePermittedCNAMEs)); rawCNAMEs != "" {
		policy.setPermittedCNAMEs(rawCNAMEs)
	}
	if v := strings.TrimSpace(opts.Get(ssh.OptionProxyCommand)); v != "" {
		policy.setProxyCommand(v)
	}
	if v := strings.TrimSpace(opts.Get(ssh.OptionConnectTimeout)); v != "" {
		policy.setTimeoutSeconds(v)
	}
}

type cliCanonicalTracker struct {
	seenMode           bool
	seenDomains        bool
	seenMaxDots        bool
	seenFallbackLocal  bool
	seenPermittedCNAME bool
	seenTimeout        bool
	seenProxyJump      bool
	seenProxyCmd       bool
	activeCLIJump      bool
}

func (s *cliCanonicalTracker) applyDirective(policy *canonicalizePolicy, key, v string) {
	lookupKey := ssh.CanonicalOptionKey(key)
	switch lookupKey {
	case ssh.OptionProxyJump, ssh.OptionProxyCommand:
		s.applyProxyDirective(policy, lookupKey, v)
	case ssh.OptionCanonicalizeHostname:
		if !s.seenMode {
			s.seenMode = policy.setMode(v)
		}
	case ssh.OptionCanonicalDomains:
		if !s.seenDomains {
			s.seenDomains = policy.setDomains(v)
		}
	case ssh.OptionCanonicalizeMaxDots:
		if !s.seenMaxDots {
			s.seenMaxDots = policy.setMaxDots(v)
		}
	case ssh.OptionCanonicalizeFallbackLocal:
		if !s.seenFallbackLocal {
			s.seenFallbackLocal = policy.setFallbackLocal(v)
		}
	case ssh.OptionCanonicalizePermittedCNAMEs:
		if !s.seenPermittedCNAME {
			s.seenPermittedCNAME = policy.setPermittedCNAMEs(v)
		}
	case ssh.OptionConnectTimeout:
		if !s.seenTimeout {
			s.seenTimeout = policy.setTimeoutSeconds(v)
		}
	}
}

func (s *cliCanonicalTracker) applyProxyDirective(policy *canonicalizePolicy, lowerKey, v string) {
	if v == "" {
		return
	}
	switch lowerKey {
	case ssh.OptionProxyJump:
		if !s.seenProxyJump {
			s.seenProxyJump = true
			active := ssh.HasActiveProxyJump(v)
			if !s.seenProxyCmd || !active {
				s.activeCLIJump = active
				policy.setProxyJump(v)
			}
		}
	case ssh.OptionProxyCommand:
		if !s.seenProxyCmd {
			s.seenProxyCmd = true
			if !s.activeCLIJump {
				policy.setProxyCommand(v)
			}
		}
	}
}

func applyCLICanonicalDirectives(policy *canonicalizePolicy, rawCLI []string, cliProxyJump string) {
	var state cliCanonicalTracker
	if pj := strings.TrimSpace(cliProxyJump); pj != "" {
		state.seenProxyJump = true
		state.activeCLIJump = ssh.HasActiveProxyJump(pj)
		policy.setProxyJump(pj)
	}
	for _, raw := range rawCLI {
		k, v, ok := splitCanonicalOptionKV(raw)
		if !ok {
			continue
		}
		state.applyDirective(policy, k, v)
	}
}

func (p *canonicalizePolicy) setProxyJump(v string) {
	p.hasProxyJump = ssh.HasActiveProxyJump(v)
}

func (p *canonicalizePolicy) setProxyCommand(v string) {
	p.hasProxyCommand = !strings.EqualFold(strings.TrimSpace(v), "none")
}

func normalizeCanonicalOption(key, raw string) (string, bool) {
	spec, ok := ssh.LookupOptionSpec(key)
	if !ok || spec.Normalize == nil {
		return "", false
	}
	norm, err := spec.Normalize(raw)
	if err != nil {
		return "", false
	}
	return norm, true
}

func (p *canonicalizePolicy) setMode(v string) bool {
	norm, ok := normalizeCanonicalOption(ssh.OptionCanonicalizeHostname, v)
	if !ok {
		return false
	}
	p.mode = norm
	return true
}

func (p *canonicalizePolicy) setDomains(v string) bool {
	norm, ok := normalizeCanonicalOption(ssh.OptionCanonicalDomains, v)
	if !ok {
		return false
	}
	if norm == "none" {
		p.domains = nil
		return true
	}
	p.domains = strings.Fields(norm)
	return true
}

func (p *canonicalizePolicy) setMaxDots(v string) bool {
	norm, ok := normalizeCanonicalOption(ssh.OptionCanonicalizeMaxDots, v)
	if !ok {
		return false
	}
	n, err := strconv.Atoi(norm)
	if err != nil {
		return false
	}
	p.maxDots = n
	return true
}

func (p *canonicalizePolicy) setFallbackLocal(v string) bool {
	norm, ok := normalizeCanonicalOption(ssh.OptionCanonicalizeFallbackLocal, v)
	if !ok {
		return false
	}
	p.fallbackLocal = norm == "yes"
	return true
}

func stripTrailingDotFromCanonicalPatternList(list string) string {
	parts := strings.Split(list, ",")
	for i, part := range parts {
		neg := ""
		tok := part
		if strings.HasPrefix(tok, "!") {
			neg = "!"
			tok = tok[1:]
		}
		if len(tok) > 1 && strings.HasSuffix(tok, ".") {
			tok = strings.TrimSuffix(tok, ".")
		}
		parts[i] = neg + tok
	}
	return strings.Join(parts, ",")
}

func (p *canonicalizePolicy) setPermittedCNAMEs(v string) bool {
	norm, ok := normalizeCanonicalOption(ssh.OptionCanonicalizePermittedCNAMEs, v)
	if !ok {
		return false
	}
	if norm == "none" {
		p.permittedCNAMEs = nil
		return true
	}
	fields := strings.Fields(norm)
	rules := make([]cnameRule, 0, len(fields))
	for _, token := range fields {
		srcList, dstList, ok := strings.Cut(token, ":")
		if !ok || srcList == "" || dstList == "" {
			return false
		}
		rules = append(rules, cnameRule{
			sourcePatternList: stripTrailingDotFromCanonicalPatternList(srcList),
			targetPatternList: stripTrailingDotFromCanonicalPatternList(dstList),
		})
	}
	if len(rules) == 0 {
		return false
	}
	p.permittedCNAMEs = rules
	return true
}

var canonicalTimeoutUnitSeconds = map[byte]uint64{
	's': 1, 'S': 1,
	'm': 60, 'M': 60,
	'h': 3600, 'H': 3600,
	'd': 86400, 'D': 86400,
	'w': 604800, 'W': 604800,
}

func parseCanonicalConnectTimeout(raw string) (time.Duration, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, false
	}
	if strings.EqualFold(trimmed, "none") {
		return maxCanonicalProbeTimeout, true
	}
	maxSeconds := uint64(maxCanonicalProbeTimeout / time.Second)
	var totalSeconds uint64
	exceededCap := false
	for i := 0; i < len(trimmed); {
		digitStart := i
		for i < len(trimmed) && trimmed[i] >= '0' && trimmed[i] <= '9' {
			i++
		}
		if i == digitStart {
			return 0, false
		}
		digits := trimmed[digitStart:i]
		mult := uint64(1)
		if i < len(trimmed) {
			unitMult, ok := canonicalTimeoutUnitSeconds[trimmed[i]]
			if !ok {
				return 0, false
			}
			mult = unitMult
			i++
		}
		val, err := strconv.ParseUint(digits, 10, 64)
		if err != nil {
			if errors.Is(err, strconv.ErrRange) {
				exceededCap = true
				continue
			}
			return 0, false
		}
		if val == 0 {
			continue
		}
		if val > maxSeconds/mult || val*mult > maxSeconds-totalSeconds {
			exceededCap = true
			continue
		}
		totalSeconds += val * mult
	}
	if exceededCap || totalSeconds == 0 || totalSeconds >= maxSeconds {
		return maxCanonicalProbeTimeout, true
	}
	return time.Duration(totalSeconds) * time.Second, true
}

func (p *canonicalizePolicy) setTimeoutSeconds(v string) bool {
	if d, ok := parseCanonicalConnectTimeout(v); ok {
		p.timeout = d
		return true
	}
	return false
}

func trimCanonicalHorizontalSpace(s string) string {
	return strings.Trim(s, " \t")
}

func splitCanonicalOptionKV(raw string) (string, string, bool) {
	if hasControlOrLineSepChar(strings.ReplaceAll(raw, "\t", " ")) {
		return "", "", false
	}
	trimmed := trimCanonicalHorizontalSpace(raw)
	if trimmed == "" {
		return "", "", false
	}
	if idx := strings.IndexAny(trimmed, "= \t"); idx >= 0 {
		k := trimCanonicalHorizontalSpace(trimmed[:idx])
		valPart := trimCanonicalHorizontalSpace(trimmed[idx:])
		v := trimCanonicalHorizontalSpace(strings.TrimPrefix(valPart, "="))
		return k, v, k != ""
	}
	return "", "", false
}

func isPermittedCNAME(normFQDN, normCNAME string, rules []cnameRule) bool {
	for _, r := range rules {
		if matchSSHPatternList(r.sourcePatternList, normFQDN) &&
			matchSSHPatternList(r.targetPatternList, normCNAME) {
			return true
		}
	}
	return false
}
