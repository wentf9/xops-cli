package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	sourceGlob string
	targetGlob string
}

// CanonicalizeHost evaluates OpenSSH CanonicalizeHostname/CanonicalDomains/CanonicalizeMaxDots/
// CanonicalizeFallbackLocal/CanonicalizePermittedCNAMEs in at most two OpenSSHParser passes.
func CanonicalizeHost(ctx context.Context, in CanonicalizeInput) (CanonicalizeResult, error) {
	orig := strings.TrimSpace(in.Host)
	res := CanonicalizeResult{
		OriginalHost:  orig,
		CanonicalHost: orig,
	}
	if orig == "" || in.MatchedSavedNode || isIPOrLocalhost(orig) {
		return res, nil
	}
	var parser *OpenSSHParser
	if src, ok := in.Provider.(openSSHParserSource); ok && src != nil {
		parser = src.GetOpenSSHParser()
	}
	var tier3Opts *ssh.Options
	if in.Provider != nil {
		if snap := in.Provider.Snapshot(); snap != nil {
			tier3Opts = snap.SSHOptions
		}
	}
	policy := resolveCanonicalizePolicy(parser, tier3Opts, orig, in.RawCLIOptions, in.CLIProxyJump)
	if !shouldCanonicalize(orig, policy) {
		return res, nil
	}

	resolver := in.Resolver
	if resolver == nil {
		resolver = netCanonicalResolver{}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	probeCtx, cancel := context.WithTimeout(ctx, policy.timeout)
	defer cancel()

	trailingDot := strings.HasSuffix(orig, ".")
	if !trailingDot && len(policy.domains) > 0 {
		if chosen, ok := probeCanonicalDomains(probeCtx, resolver, orig, policy); ok {
			res.CanonicalHost = chosen
			res.Canonicalized = !strings.EqualFold(chosen, orig)
			res.Pass2Options = pass2OpenSSHOptions(parser, chosen)
			return res, nil
		}

		if !policy.fallbackLocal {
			return res, fmt.Errorf("%w: %s", ErrCanonicalizeFailed, orig)
		}
	}

	if addrs, err := resolver.LookupHost(probeCtx, orig); err == nil && len(addrs) > 0 {
		chosen := resolveCanonicalCNAME(probeCtx, resolver, orig, policy.permittedCNAMEs)
		if !strings.EqualFold(chosen, orig) {
			res.CanonicalHost = chosen
			res.Canonicalized = true
			res.Pass2Options = pass2OpenSSHOptions(parser, chosen)
		}
	}
	return res, nil
}

func probeCanonicalDomains(ctx context.Context, resolver CanonicalResolver, orig string, policy canonicalizePolicy) (string, bool) {
	for _, domain := range policy.domains {
		fqdn := orig + "." + domain
		addrs, err := resolver.LookupHost(ctx, fqdn)
		if err != nil || len(addrs) == 0 {
			continue
		}
		return resolveCanonicalCNAME(ctx, resolver, fqdn, policy.permittedCNAMEs), true
	}
	return "", false
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

func resolveCanonicalCNAME(ctx context.Context, resolver CanonicalResolver, host string, rules []cnameRule) string {
	if len(rules) == 0 {
		return host
	}
	cname, err := resolver.LookupCNAME(ctx, host)
	if err != nil {
		return host
	}
	normHost := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	normCNAME := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cname)), ".")
	if normCNAME != "" && normCNAME != normHost && isPermittedCNAME(normHost, normCNAME, rules) {
		return normCNAME
	}
	return host
}

func shouldCanonicalize(host string, policy canonicalizePolicy) bool {
	if policy.mode != "yes" && policy.mode != "always" {
		return false
	}
	if (policy.hasProxyJump || policy.hasProxyCommand) && policy.mode != "always" {
		return false
	}
	if strings.Count(host, ".") > policy.maxDots {
		return false
	}
	return len(policy.domains) > 0 || len(policy.permittedCNAMEs) > 0
}

func isIPOrLocalhost(host string) bool {
	trimmed := strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
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
		if v := firstSSHConfigKeyValue(doc, host, "proxyjump"); strings.EqualFold(v, "none") {
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
	if domains := opts.CanonicalDomains(); len(domains) > 0 {
		policy.domains = domains
	}
	if maxDots, ok := opts.CanonicalizeMaxDots(); ok {
		policy.maxDots = maxDots
	}
	if fb, ok := opts.CanonicalizeFallbackLocal(); ok {
		policy.fallbackLocal = fb
	}
	if cnames := opts.CanonicalizePermittedCNAMEs(); len(cnames) > 0 {
		policy.setPermittedCNAMEs(strings.Join(cnames, " "))
	}
	if v := strings.TrimSpace(opts.Get("proxy_command")); v != "" {
		policy.setProxyCommand(v)
	}
	if v := strings.TrimSpace(opts.Get("proxy_jump")); v != "" {
		policy.setProxyJump(v)
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
	switch strings.ToLower(key) {
	case "proxyjump", "proxycommand":
		s.applyProxyDirective(policy, strings.ToLower(key), v)
	case "canonicalizehostname":
		if !s.seenMode {
			s.seenMode = true
			policy.setMode(v)
		}
	case "canonicaldomains":
		if !s.seenDomains {
			s.seenDomains = true
			policy.setDomains(v)
		}
	case "canonicalizemaxdots":
		if !s.seenMaxDots {
			s.seenMaxDots = true
			policy.setMaxDots(v)
		}
	case "canonicalizefallbacklocal":
		if !s.seenFallbackLocal {
			s.seenFallbackLocal = true
			policy.setFallbackLocal(v)
		}
	case "canonicalizepermittedcnames":
		if !s.seenPermittedCNAME {
			s.seenPermittedCNAME = true
			policy.setPermittedCNAMEs(v)
		}
	case "connecttimeout":
		if !s.seenTimeout {
			s.seenTimeout = true
			policy.setTimeoutSeconds(v)
		}
	}
}

func (s *cliCanonicalTracker) applyProxyDirective(policy *canonicalizePolicy, lowerKey, v string) {
	if v == "" {
		return
	}
	switch lowerKey {
	case "proxyjump":
		if !s.seenProxyJump {
			s.seenProxyJump = true
			if !s.seenProxyCmd {
				s.activeCLIJump = !strings.EqualFold(strings.TrimSpace(v), "none")
				policy.setProxyJump(v)
			}
		}
	case "proxycommand":
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
		state.activeCLIJump = !strings.EqualFold(pj, "none")
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
	p.hasProxyJump = !strings.EqualFold(strings.TrimSpace(v), "none")
}

func (p *canonicalizePolicy) setProxyCommand(v string) {
	p.hasProxyCommand = !strings.EqualFold(strings.TrimSpace(v), "none")
}

func (p *canonicalizePolicy) setMode(v string) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "always", "no":
		p.mode = strings.ToLower(strings.TrimSpace(v))
	}
}

func (p *canonicalizePolicy) setDomains(v string) {
	if strings.EqualFold(strings.TrimSpace(v), "none") {
		p.domains = nil
		return
	}
	fields := strings.Fields(strings.ReplaceAll(v, ",", " "))
	var out []string
	for _, f := range fields {
		clean := strings.Trim(strings.TrimSpace(f), ".")
		if clean != "" {
			out = append(out, clean)
		}
	}
	p.domains = out
}

func (p *canonicalizePolicy) setMaxDots(v string) {
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 {
		p.maxDots = n
	}
}

func (p *canonicalizePolicy) setFallbackLocal(v string) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true":
		p.fallbackLocal = true
	case "no", "false":
		p.fallbackLocal = false
	}
}

func (p *canonicalizePolicy) setPermittedCNAMEs(v string) {
	if strings.EqualFold(strings.TrimSpace(v), "none") {
		p.permittedCNAMEs = nil
		return
	}
	var rules []cnameRule
	for _, token := range strings.Fields(v) {
		srcList, dstList, ok := strings.Cut(token, ":")
		if !ok || strings.TrimSpace(srcList) == "" || strings.TrimSpace(dstList) == "" {
			continue
		}
		for _, src := range strings.Split(srcList, ",") {
			srcClean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(src)), ".")
			if srcClean == "" {
				continue
			}
			for _, dst := range strings.Split(dstList, ",") {
				dstClean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(dst)), ".")
				if dstClean == "" {
					continue
				}
				rules = append(rules, cnameRule{
					sourceGlob: srcClean,
					targetGlob: dstClean,
				})
			}
		}
	}
	p.permittedCNAMEs = rules
}

func (p *canonicalizePolicy) setTimeoutSeconds(v string) {
	if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs > 0 {
		d := time.Duration(secs) * time.Second
		if d < p.timeout {
			p.timeout = d
		}
	}
}

func splitCanonicalOptionKV(raw string) (string, string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", false
	}
	if idx := strings.IndexAny(trimmed, "= \t"); idx >= 0 {
		k := strings.TrimSpace(trimmed[:idx])
		v := strings.TrimSpace(strings.TrimPrefix(trimmed[idx:], "="))
		return k, v, k != ""
	}
	return "", "", false
}

func isPermittedCNAME(normFQDN, normCNAME string, rules []cnameRule) bool {
	for _, r := range rules {
		srcMatch, srcErr := filepath.Match(r.sourceGlob, normFQDN)
		dstMatch, dstErr := filepath.Match(r.targetGlob, normCNAME)
		if srcErr == nil && dstErr == nil && srcMatch && dstMatch {
			return true
		}
	}
	return false
}
