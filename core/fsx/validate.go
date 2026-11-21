package fsx

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ValidateLocalComponent validates a single local filename component using a
// single portable rule enforced identically on all operating systems (Linux,
// macOS, Windows, and others).
//
// It rejects:
//   - empty names, ".", and ".."
//   - path separators '/' and '\\'
//   - Windows/NTFS forbidden characters ':', '*', '?', '"', '<', '>', '|'
//   - NUL bytes, ASCII control characters (< 0x20, 0x7f), and Unicode control runes
//   - trailing dots '.' or trailing ASCII spaces ' '
//   - volume names / drive prefixes
//   - Windows reserved DOS device stems (case-insensitive, stem before the first
//     '.', trailing ASCII spaces trimmed): CON, PRN, AUX, NUL, COM1-COM9,
//     LPT1-LPT9, and Unicode superscript variants COM¹, COM², COM³, LPT¹, LPT², LPT³.
//
// All rejections wrap ErrInvalidComponent.
func ValidateLocalComponent(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty name", ErrInvalidComponent)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("%w: %q is a traversal component", ErrInvalidComponent, name)
	}
	if filepath.VolumeName(name) != "" {
		return fmt.Errorf("%w: %q contains volume prefix", ErrInvalidComponent, name)
	}
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return fmt.Errorf("%w: %q has trailing dot or space", ErrInvalidComponent, name)
	}
	if err := validateComponentChars(name); err != nil {
		return err
	}
	if hasReservedDeviceStem(name) {
		return fmt.Errorf("%w: %q uses a reserved Windows device name", ErrInvalidComponent, name)
	}
	return nil
}

func validateComponentChars(name string) error {
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b == 0 || b < 0x20 || b == 0x7f {
			return fmt.Errorf("%w: %q contains control or NUL byte", ErrInvalidComponent, name)
		}
		switch b {
		case '/', '\\':
			return fmt.Errorf("%w: %q contains path separator", ErrInvalidComponent, name)
		case ':':
			return fmt.Errorf("%w: %q contains forbidden colon", ErrInvalidComponent, name)
		case '*', '?', '"', '<', '>', '|':
			return fmt.Errorf("%w: %q contains forbidden filename character", ErrInvalidComponent, name)
		}
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %q contains Unicode control character", ErrInvalidComponent, name)
		}
	}
	return nil
}

func hasReservedDeviceStem(name string) bool {
	stem := name
	if dot := strings.IndexByte(stem, '.'); dot >= 0 {
		stem = stem[:dot]
	}
	stem = strings.TrimRight(stem, " ")
	if len(stem) < 3 {
		return false
	}
	if len(stem) == 3 {
		return strings.EqualFold(stem, "CON") ||
			strings.EqualFold(stem, "PRN") ||
			strings.EqualFold(stem, "AUX") ||
			strings.EqualFold(stem, "NUL")
	}
	prefix := stem[:3]
	if !strings.EqualFold(prefix, "COM") && !strings.EqualFold(prefix, "LPT") {
		return false
	}
	rest := stem[3:]
	r, size := utf8.DecodeRuneInString(rest)
	if size != len(rest) {
		return false
	}
	return (r >= '1' && r <= '9') || r == '\u00b9' || r == '\u00b2' || r == '\u00b3'
}
