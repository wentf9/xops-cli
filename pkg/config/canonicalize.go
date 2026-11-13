package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kevinburke/ssh_config"
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
	Pass2Options  *ssh.Options
}

type canonicalizePolicy struct {
	mode            string // "no", "yes", "always"
	domains         []string
	maxDots         int
	fallbackLocal   bool
	permittedCNAMEs []cnameRule
	hasProxy        bool
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

	if chosen, ok := probeCanonicalDomains(probeCtx, resolver, orig, policy); ok {
		res.CanonicalHost = chosen
		res.Canonicalized = !strings.EqualFold(chosen, orig)
		res.Pass2Options = pass2OpenSSHOptions(parser, chosen)
		return res, nil
	}

	if !policy.fallbackLocal {
		return res, fmt.Errorf("%w: %s", ErrCanonicalizeFailed, orig)
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
	if policy.hasProxy && policy.mode != "always" {
		return false
	}
	if strings.Count(host, ".") > policy.maxDots {
		return false
	}
	return len(policy.domains) > 0
}

func isIPOrLocalhost(host string) bool {
	trimmed := strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if net.ParseIP(trimmed) != nil {
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
	return policy
}

func applySSHConfigCanonicalDirectives(policy *canonicalizePolicy, cfg *ssh_config.Config, host string) {
	if v := firstSSHConfigKeyValue(cfg, host, "canonicalizehostname"); v != "" {
		policy.setMode(v)
	}
	if v := firstSSHConfigKeyValue(cfg, host, "canonicaldomains"); v != "" {
		policy.setDomains(v)
	}
	if v := firstSSHConfigKeyValue(cfg, host, "canonicalizemaxdots"); v != "" {
		policy.setMaxDots(v)
	}
	if v := firstSSHConfigKeyValue(cfg, host, "canonicalizefallbacklocal"); v != "" {
		policy.setFallbackLocal(v)
	}
	if v := firstSSHConfigKeyValue(cfg, host, "canonicalizepermittedcnames"); v != "" {
		policy.setPermittedCNAMEs(v)
	}
	if v := firstSSHConfigKeyValue(cfg, host, "proxyjump"); v != "" {
		policy.hasProxy = !strings.EqualFold(v, "none")
	}
	if v := firstSSHConfigKeyValue(cfg, host, "proxycommand"); v != "" && !strings.EqualFold(v, "none") {
		policy.hasProxy = true
	}
	if v := firstSSHConfigKeyValue(cfg, host, "connecttimeout"); v != "" {
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
	if v := strings.TrimSpace(opts.Get("proxy_jump")); v != "" {
		policy.hasProxy = !strings.EqualFold(v, "none")
	}
	if v := strings.TrimSpace(opts.Get("proxy_command")); v != "" && !strings.EqualFold(v, "none") {
		policy.hasProxy = true
	}
	if v := strings.TrimSpace(opts.Get(ssh.OptionConnectTimeout)); v != "" {
		policy.setTimeoutSeconds(v)
	}
}

func applyCLICanonicalDirectives(policy *canonicalizePolicy, rawCLI []string, cliProxyJump string) {
	for _, raw := range rawCLI {
		k, v, ok := splitCanonicalOptionKV(raw)
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "canonicalizehostname":
			policy.setMode(v)
		case "canonicaldomains":
			policy.setDomains(v)
		case "canonicalizemaxdots":
			policy.setMaxDots(v)
		case "canonicalizefallbacklocal":
			policy.setFallbackLocal(v)
		case "canonicalizepermittedcnames":
			policy.setPermittedCNAMEs(v)
		case "proxyjump":
			policy.hasProxy = v != "" && !strings.EqualFold(v, "none")
		case "proxycommand":
			if v != "" && !strings.EqualFold(v, "none") {
				policy.hasProxy = true
			}
		case "connecttimeout":
			policy.setTimeoutSeconds(v)
		}
	}
	if pj := strings.TrimSpace(cliProxyJump); pj != "" {
		policy.hasProxy = !strings.EqualFold(pj, "none")
	}
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

func firstSSHConfigKeyValue(cfg *ssh_config.Config, host, keyLower string) string {
	for _, h := range cfg.Hosts {
		if !h.Matches(host) {
			continue
		}
		for _, node := range h.Nodes {
			kv, ok := node.(*ssh_config.KV)
			if !ok || kv == nil {
				continue
			}
			if strings.ToLower(strings.TrimSpace(kv.Key)) == keyLower {
				return strings.TrimSpace(kv.Value)
			}
		}
	}
	return ""
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
