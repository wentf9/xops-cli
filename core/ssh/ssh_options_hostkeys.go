package ssh

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// validateGlobalKnownHostsFile accepts "none" alone or whitespace-separated
// paths with ~, ${ENV} and % token syntax shared with UserKnownHostsFile.
func validateGlobalKnownHostsFile(raw string) (string, error) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "", errors.New("invalid GlobalKnownHostsFile: value cannot be empty")
	}
	if hasASCIIControlChar(strings.Join(fields, " ")) {
		return "", fmt.Errorf("invalid GlobalKnownHostsFile %q: contains invalid ASCII control character", raw)
	}
	for _, field := range fields {
		if strings.EqualFold(field, "none") {
			if len(fields) != 1 {
				return "", fmt.Errorf("invalid GlobalKnownHostsFile %q: none cannot be combined with paths", raw)
			}
			return "none", nil
		}
		if err := validatePathTokenSyntax(field, "GlobalKnownHostsFile"); err != nil {
			return "", err
		}
	}
	return strings.Join(fields, " "), nil
}

func validateVerifyHostKeyDNS(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "yes", "true":
		return VerifyHostKeyDNSYes, nil
	case "no", "false":
		return VerifyHostKeyDNSNo, nil
	case "ask":
		return VerifyHostKeyDNSAsk, nil
	default:
		return "", fmt.Errorf("invalid VerifyHostKeyDNS option %q (expected yes, no, or ask)", raw)
	}
}

func validateCanonicalizeHostname(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "yes", "true":
		return CanonicalizeHostnameYes, nil
	case "no", "false":
		return CanonicalizeHostnameNo, nil
	case "always":
		return CanonicalizeHostnameAlways, nil
	default:
		return "", fmt.Errorf("invalid CanonicalizeHostname option %q (expected yes, no, or always)", raw)
	}
}

func validateCanonicalizeMaxDots(raw string) (string, error) {
	val, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || val < 0 || val > maxCanonicalizeMaxDots {
		return "", fmt.Errorf("invalid CanonicalizeMaxDots %q: must be an integer between 0 and %d", raw, maxCanonicalizeMaxDots)
	}
	return strconv.Itoa(val), nil
}

// validateCanonicalDomains accepts "none" alone or whitespace-separated DNS
// suffixes. Suffixes are lower-cased, stripped of one trailing dot and deduplicated.
func validateCanonicalDomains(raw string) (string, error) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "", errors.New("invalid CanonicalDomains: value cannot be empty")
	}
	if len(fields) == 1 && strings.EqualFold(fields[0], "none") {
		return "none", nil
	}
	domains := make([]string, 0, len(fields))
	for _, field := range fields {
		domain := strings.ToLower(strings.TrimSuffix(field, "."))
		if !isValidCanonicalDomain(domain) {
			return "", fmt.Errorf("invalid CanonicalDomains entry %q", field)
		}
		if !slices.Contains(domains, domain) {
			domains = append(domains, domain)
		}
	}
	return strings.Join(domains, " "), nil
}

func isValidCanonicalDomain(domain string) bool {
	if domain == "" || len(domain) > 253 || strings.HasPrefix(domain, ".") || strings.Contains(domain, "..") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for i := 0; i < len(label); i++ {
			if !isCanonicalNameChar(label[i], false) {
				return false
			}
		}
	}
	return true
}

func isCanonicalNameChar(c byte, allowPattern bool) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		return true
	case allowPattern && (c == '.' || c == '*' || c == '?' || c == '!'):
		return true
	default:
		return false
	}
}

// validateCanonicalizePermittedCNAMEs accepts "none" alone or whitespace-separated
// "source_patterns:target_patterns" rules, where each side is a comma-separated
// list of hostname glob patterns.
func validateCanonicalizePermittedCNAMEs(raw string) (string, error) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "", errors.New("invalid CanonicalizePermittedCNAMEs: value cannot be empty")
	}
	if len(fields) == 1 && strings.EqualFold(fields[0], "none") {
		return "none", nil
	}
	rules := make([]string, 0, len(fields))
	for _, field := range fields {
		src, dst, ok := strings.Cut(field, ":")
		if !ok || strings.Contains(dst, ":") {
			return "", fmt.Errorf("invalid CanonicalizePermittedCNAMEs rule %q: expected source:target", field)
		}
		normSrc, err := normalizeCNAMEPatternList(src)
		if err != nil {
			return "", fmt.Errorf("invalid CanonicalizePermittedCNAMEs rule %q: %w", field, err)
		}
		normDst, err := normalizeCNAMEPatternList(dst)
		if err != nil {
			return "", fmt.Errorf("invalid CanonicalizePermittedCNAMEs rule %q: %w", field, err)
		}
		rules = append(rules, normSrc+":"+normDst)
	}
	return strings.Join(rules, " "), nil
}

func normalizeCNAMEPatternList(list string) (string, error) {
	if list == "" {
		return "", errors.New("empty pattern list")
	}
	parts := strings.Split(list, ",")
	for i, part := range parts {
		if part == "" {
			return "", errors.New("empty pattern in list")
		}
		for j := 0; j < len(part); j++ {
			if !isCanonicalNameChar(part[j], true) {
				return "", fmt.Errorf("invalid character %q in pattern %q", part[j], part)
			}
		}
		parts[i] = strings.ToLower(part)
	}
	return strings.Join(parts, ","), nil
}

// GlobalKnownHostsFile returns the normalized GlobalKnownHostsFile value
// ("none", whitespace-separated paths), or "" if unset.
func (o *Options) GlobalKnownHostsFile() string {
	return o.Get(OptionGlobalKnownHostsFile)
}

// HashKnownHosts reports whether newly learned known_hosts entries must be hashed.
func (o *Options) HashKnownHosts() bool {
	v, ok := o.boolOption(OptionHashKnownHosts)
	return ok && v
}

// VerifyHostKeyDNS returns the normalized VerifyHostKeyDNS mode, or "" if unset.
func (o *Options) VerifyHostKeyDNS() string {
	return o.Get(OptionVerifyHostKeyDNS)
}

// CanonicalizeHostname returns the normalized CanonicalizeHostname mode, or "" if unset.
func (o *Options) CanonicalizeHostname() string {
	return o.Get(OptionCanonicalizeHostname)
}

// CanonicalDomains returns the configured domain suffixes in order, or nil when
// unset or "none".
func (o *Options) CanonicalDomains() []string {
	v := o.Get(OptionCanonicalDomains)
	if v == "" || v == "none" {
		return nil
	}
	return strings.Fields(v)
}

// CanonicalizeMaxDots returns the configured value and true, or the OpenSSH
// default (1) and false when unset.
func (o *Options) CanonicalizeMaxDots() (int, bool) {
	v := o.Get(OptionCanonicalizeMaxDots)
	if v == "" {
		return DefaultCanonicalizeMaxDots, false
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return DefaultCanonicalizeMaxDots, false
	}
	return n, true
}

// CanonicalizeFallbackLocal returns the configured value and true, or the
// OpenSSH default (true) and false when unset.
func (o *Options) CanonicalizeFallbackLocal() (bool, bool) {
	v, ok := o.boolOption(OptionCanonicalizeFallbackLocal)
	if !ok {
		return true, false
	}
	return v, true
}

// CanonicalizePermittedCNAMEs returns the normalized source:target rules, or nil
// when unset or "none".
func (o *Options) CanonicalizePermittedCNAMEs() []string {
	v := o.Get(OptionCanonicalizePermittedCNAMEs)
	if v == "" || v == "none" {
		return nil
	}
	return strings.Fields(v)
}
