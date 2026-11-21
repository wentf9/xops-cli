package ssh

import (
	"errors"
	"fmt"
	"strings"
)

// IdentityPathKind classifies a parsed IdentityFile or CertificateFile setting
// into mutually exclusive domain states.
type IdentityPathKind uint8

const (
	// IdentityPathUnset indicates no identity path was configured.
	IdentityPathUnset IdentityPathKind = iota
	// IdentityPathDisabled indicates identity loading was explicitly disabled via "none".
	IdentityPathDisabled
	// IdentityPathTemplate indicates a path containing expandable OpenSSH % tokens
	// or ${VAR} environment placeholders.
	IdentityPathTemplate
	// IdentityPathLiteral indicates a concrete identity path without % or ${...} placeholders.
	IdentityPathLiteral
)

// IdentityPathSetting is the typed, parsed representation of an IdentityFile or
// CertificateFile value.
type IdentityPathSetting struct {
	Kind IdentityPathKind
	Raw  string
}

// Unset reports whether no identity path is configured.
func (s IdentityPathSetting) Unset() bool { return s.Kind == IdentityPathUnset }

// Disabled reports whether identity loading is explicitly disabled ("none").
func (s IdentityPathSetting) Disabled() bool { return s.Kind == IdentityPathDisabled }

// Enabled reports whether the setting specifies an active template or literal path.
func (s IdentityPathSetting) Enabled() bool {
	return s.Kind == IdentityPathTemplate || s.Kind == IdentityPathLiteral
}

// IsTemplate reports whether the path contains OpenSSH % tokens or ${VAR} placeholders.
func (s IdentityPathSetting) IsTemplate() bool { return s.Kind == IdentityPathTemplate }

// Persistable reports whether the setting is a concrete non-empty literal path
// safe to persist directly (not unset, not "none", and containing neither % tokens
// nor ${...} environment placeholders).
func (s IdentityPathSetting) Persistable() bool {
	return s.Kind == IdentityPathLiteral &&
		strings.TrimSpace(s.Raw) != "" &&
		!hasIdentityTemplateTokens(s.Raw)
}

func hasIdentityTemplateTokens(s string) bool {
	return strings.ContainsRune(s, '%') || strings.Contains(s, "${")
}

// ParseIdentityPathSetting validates and classifies raw into a typed IdentityPathSetting.
// ASCII control characters and Unicode line separators are rejected before trimming.
// An empty string "" returns IdentityPathUnset; whitespace-only input returns an error.
// When allowNoneSentinel is true, "none" (case-insensitive) returns IdentityPathDisabled.
func ParseIdentityPathSetting(raw string, allowNoneSentinel bool) (IdentityPathSetting, error) {
	if hasControlOrLineSepChar(raw) {
		return IdentityPathSetting{}, fmt.Errorf("invalid identity path %q: contains invalid ASCII control character", raw)
	}
	if raw == "" {
		return IdentityPathSetting{Kind: IdentityPathUnset}, nil
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return IdentityPathSetting{}, errors.New("invalid identity path: value cannot be empty")
	}
	if allowNoneSentinel && IsNoneValue(trimmed) {
		return IdentityPathSetting{Kind: IdentityPathDisabled, Raw: "none"}, nil
	}
	if err := validatePathTokenSyntax(trimmed, "IdentityFile"); err != nil {
		return IdentityPathSetting{}, err
	}
	if hasIdentityTemplateTokens(trimmed) {
		return IdentityPathSetting{Kind: IdentityPathTemplate, Raw: trimmed}, nil
	}
	return IdentityPathSetting{Kind: IdentityPathLiteral, Raw: trimmed}, nil
}

func isSafeFilenameASCII(r rune) bool {
	return (r >= 'A' && r <= 'Z') ||
		(r >= 'a' && r <= 'z') ||
		(r >= '0' && r <= '9') ||
		r == '.' || r == '_' || r == '-'
}

// SanitizeFilenameComponent deterministically converts an arbitrary host or selector
// string into a safe single-segment cross-platform filename stem for Linux, macOS,
// and Windows NTFS (no path separators, NTFS ADS ':', control characters, ".."
// traversal, leading/trailing dots, or Windows reserved device names).
func SanitizeFilenameComponent(raw string) string {
	if raw == "" {
		return "_"
	}
	buf := make([]byte, 0, len(raw))
	for _, r := range raw {
		if isSafeFilenameASCII(r) {
			buf = append(buf, byte(r))
		} else {
			buf = append(buf, '_')
		}
	}
	if len(buf) == 0 {
		return "_"
	}
	// Replace leading dots, trailing dots, and any dot adjacent to another dot so
	// ".", "..", "...", "a..b", and Windows-stripped trailing dots can never survive.
	out := make([]byte, len(buf))
	for i, b := range buf {
		if b == '.' && (i == 0 || i == len(buf)-1 || buf[i-1] == '.' || buf[i+1] == '.') {
			out[i] = '_'
		} else {
			out[i] = b
		}
	}
	s := string(out)
	stem := s
	if dot := strings.IndexByte(s, '.'); dot >= 0 {
		stem = s[:dot]
	}
	if isWindowsReservedDeviceName(stem) {
		return "_" + s
	}
	return s
}

func isWindowsReservedDeviceName(stem string) bool {
	switch len(stem) {
	case 3:
		return strings.EqualFold(stem, "CON") ||
			strings.EqualFold(stem, "PRN") ||
			strings.EqualFold(stem, "AUX") ||
			strings.EqualFold(stem, "NUL")
	case 4:
		d := stem[3]
		if d < '1' || d > '9' {
			return false
		}
		prefix := stem[:3]
		return strings.EqualFold(prefix, "COM") || strings.EqualFold(prefix, "LPT")
	default:
		return false
	}
}
