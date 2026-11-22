package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
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
	// production CLI/adapter flows, SSHAdapter.Resolve re-evaluates
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
	if in.MatchedSavedNode {
		return res, nil
	}
	policy, err := resolveCanonicalizePolicy(parser, canonicalProviderTier3Options(in.Provider), orig, in.RawCLIOptions, in.CLIProxyJump)
	if err != nil {
		return CanonicalizeResult{}, err
	}
	if isIPOrLocalhost(orig) {
		return res, nil
	}
	probeTarget := resolveCanonicalEffectiveInputHost(parser, in.RawCLIOptions, orig)
	if isIPOrLocalhost(probeTarget) || !shouldCanonicalize(probeTarget, policy) {
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
	policy, err := resolveCanonicalizePolicy(parser, canonicalProviderTier3Options(provider), orig, rawCLIOptions, cliProxyJump)
	if err != nil || !shouldProbeCanonicalDomains(probeTarget, policy) {
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
			var optErr error
			if res.Canonicalized {
				res.Pass2Options, optErr = pass2OpenSSHOptionsWithCanonical(parser, res.OriginalHost, chosen)
			} else {
				res.Pass2Options, optErr = pass2OpenSSHOptions(parser, chosen)
			}
			if optErr != nil {
				return CanonicalizeResult{}, optErr
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
			pass2Opts, optErr := pass2OpenSSHOptionsWithCanonical(parser, res.OriginalHost, chosen)
			if optErr != nil {
				return CanonicalizeResult{}, optErr
			}
			res.Pass2Options = pass2Opts
		}
	} else if parentCtx != nil && parentCtx.Err() != nil {
		return CanonicalizeResult{}, parentCtx.Err()
	}
	return res, nil
}

func resolveCanonicalEffectiveInputHost(parser *OpenSSHParser, rawCLI []string, orig string) string {
	for _, raw := range rawCLI {
		k, v, err := ssh.SplitOptionKeyValue(raw)
		if err != nil || ssh.CanonicalOptionKey(k) != ssh.OptionHostName {
			continue
		}
		parsed, err := ssh.ParseOption(ssh.OptionHostName, v, ssh.OptionSourceCLI)
		if err != nil {
			continue
		}
		if expanded, err := ssh.ExpandHostName(parsed.Normalized, orig); err == nil {
			clean := unwrapExpandedHostName(parsed.Normalized, expanded)
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

func pass2OpenSSHOptionsWithCanonical(parser *OpenSSHParser, origAlias, canonicalHost string) (*ssh.Options, error) {
	if parser == nil {
		return nil, nil
	}
	if strings.TrimSpace(origAlias) != "" {
		return parser.GetSSHOptionsWithCanonical(origAlias, canonicalHost)
	}
	return parser.GetSSHOptions(canonicalHost)
}

func pass2OpenSSHOptions(parser *OpenSSHParser, host string) (*ssh.Options, error) {
	if parser == nil {
		return nil, nil
	}
	return parser.GetSSHOptions(host)
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
	if hasOpenSSHPrefix(name) {
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

var canonicalOptionKeys = []string{
	ssh.OptionCanonicalizeHostname,
	ssh.OptionCanonicalDomains,
	ssh.OptionCanonicalizeMaxDots,
	ssh.OptionCanonicalizeFallbackLocal,
	ssh.OptionCanonicalizePermittedCNAMEs,
	ssh.OptionConnectTimeout,
}

func isCanonicalOptionKey(key string) bool {
	return slices.Contains(canonicalOptionKeys, key)
}

func parseTier4CanonicalOptions(doc *sshConfigDoc, host string) *ssh.Options {
	if doc == nil {
		return nil
	}
	opts := &ssh.Options{}
	for _, key := range canonicalOptionKeys {
		spec, ok := ssh.LookupOptionSpec(key)
		if !ok {
			continue
		}
		raw := firstMatchingOpenSSHOptionPasses(doc, []string{host}, spec)
		if raw == "" {
			continue
		}
		if parsed, err := ssh.ParseOption(key, raw, ssh.OptionSourceOpenSSHConfig); err == nil && !parsed.IsNoOp {
			_ = opts.Set(key, parsed.Normalized)
		}
	}
	if opts.IsEmpty() {
		return nil
	}
	return opts
}

func parseCLICanonicalLayer(rawCLI []string, cliProxyJump string) (*ssh.Options, ssh.ProxySetting, error) {
	cliOpts := &ssh.Options{}
	cliProxy := ssh.UnsetProxySetting()
	if hasControlOrLineSepChar(cliProxyJump) {
		return nil, ssh.UnsetProxySetting(), fmt.Errorf("%w: invalid ProxyJump %q: contains control character", ssh.ErrSSHOptionsValidation, cliProxyJump)
	}
	if pj := strings.TrimSpace(cliProxyJump); pj != "" {
		ps, err := ssh.ParseProxyJump(pj)
		if err != nil {
			return nil, ssh.UnsetProxySetting(), fmt.Errorf("invalid ProxyJump %q: %w", cliProxyJump, err)
		}
		cliProxy = cliProxy.Merge(ps)
	}
	seen := make(map[string]bool, len(canonicalOptionKeys))
	for _, raw := range rawCLI {
		key, val, err := ssh.SplitOptionKeyValue(raw)
		if err != nil {
			if isRawProxyOptionDirective(raw) {
				return nil, ssh.UnsetProxySetting(), err
			}
			continue
		}
		if key == "" {
			continue
		}
		canonical := ssh.CanonicalOptionKey(key)
		if canonical == ssh.OptionProxyJump || canonical == ssh.OptionProxyCommand {
			parsed, pErr := ssh.ParseOption(canonical, val, ssh.OptionSourceCLI)
			if pErr != nil {
				return nil, ssh.UnsetProxySetting(), pErr
			}
			cliProxy = cliProxy.Merge(parsed.ProxySetting)
			continue
		}
		if !isCanonicalOptionKey(canonical) || seen[canonical] {
			continue
		}
		if parsed, pErr := ssh.ParseOption(canonical, val, ssh.OptionSourceCLI); pErr == nil {
			_ = cliOpts.Set(canonical, parsed.Normalized)
			seen[canonical] = true
		}
	}
	if cliOpts.IsEmpty() {
		cliOpts = nil
	}
	return cliOpts, cliProxy, nil
}

func isRawProxyOptionDirective(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if idx := strings.IndexAny(trimmed, "= \t"); idx > 0 {
		canonical := ssh.CanonicalOptionKey(trimmed[:idx])
		return canonical == ssh.OptionProxyJump || canonical == ssh.OptionProxyCommand
	}
	return false
}

func resolveCanonicalizePolicy(parser *OpenSSHParser, tier3Opts *ssh.Options, host string, rawCLI []string, cliProxyJump string) (canonicalizePolicy, error) {
	var (
		t4Opts  *ssh.Options
		t4Proxy = ssh.UnsetProxySetting()
	)
	if parser != nil && parser.cfg != nil {
		t4Opts = parseTier4CanonicalOptions(parser.cfg, host)
		var err error
		t4Proxy, err = parser.ResolveProxySetting(host)
		if err != nil {
			return canonicalizePolicy{}, err
		}
	}
	t3Proxy := ssh.UnsetProxySetting()
	if tier3Opts != nil {
		t3Proxy = tier3Opts.ProxyCommandSetting()
	}
	cliOpts, cliProxy, err := parseCLICanonicalLayer(rawCLI, cliProxyJump)
	if err != nil {
		return canonicalizePolicy{}, err
	}

	effOpts := ssh.MergeOptions(cliOpts, tier3Opts, t4Opts)
	effProxy := cliProxy.Merge(t3Proxy).Merge(t4Proxy)

	return canonicalizePolicyFromEffective(effOpts, effProxy), nil
}

func canonicalizePolicyFromEffective(effOpts *ssh.Options, effProxy ssh.ProxySetting) canonicalizePolicy {
	policy := canonicalizePolicy{
		mode:          ssh.CanonicalizeHostnameNo,
		maxDots:       defaultCanonicalizeMaxDots,
		fallbackLocal: true,
		timeout:       maxCanonicalProbeTimeout,
	}
	if effOpts != nil {
		if mode := effOpts.CanonicalizeHostname(); mode != "" {
			policy.mode = mode
		}
		policy.domains = effOpts.CanonicalDomains()
		if maxDots, ok := effOpts.CanonicalizeMaxDots(); ok {
			policy.maxDots = maxDots
		}
		if fb, ok := effOpts.CanonicalizeFallbackLocal(); ok {
			policy.fallbackLocal = fb
		}
		if rawRules := effOpts.CanonicalizePermittedCNAMEs(); len(rawRules) > 0 {
			rules := make([]cnameRule, 0, len(rawRules))
			for _, token := range rawRules {
				srcList, dstList, ok := strings.Cut(token, ":")
				if !ok || srcList == "" || dstList == "" {
					continue
				}
				rules = append(rules, cnameRule{
					sourcePatternList: stripTrailingDotFromCanonicalPatternList(srcList),
					targetPatternList: stripTrailingDotFromCanonicalPatternList(dstList),
				})
			}
			policy.permittedCNAMEs = rules
		}
		if d := effOpts.ConnectTimeout(); d > 0 && d < maxCanonicalProbeTimeout {
			policy.timeout = d
		}
	}
	policy.hasProxyJump = effProxy.Kind() == ssh.ProxyJump
	policy.hasProxyCommand = effProxy.Kind() == ssh.ProxyCommand
	return policy
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

func isPermittedCNAME(normFQDN, normCNAME string, rules []cnameRule) bool {
	for _, r := range rules {
		if matchSSHPatternList(r.sourcePatternList, normFQDN) &&
			matchSSHPatternList(r.targetPatternList, normCNAME) {
			return true
		}
	}
	return false
}
