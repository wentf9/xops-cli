package sftp

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/wentf9/xops-cli/core/fsx"
)

var (
	// ErrInvalidRemotePath indicates a malformed or disallowed POSIX remote path.
	ErrInvalidRemotePath = errors.New("invalid remote path")
	// ErrInvalidRemoteName indicates a malformed or disallowed single remote path segment.
	ErrInvalidRemoteName = errors.New("invalid remote name")
	// ErrInvalidLocalTarget indicates a disallowed or escaping local destination target.
	ErrInvalidLocalTarget = errors.New("invalid local target")
)

// RemotePath is a validated, POSIX-cleaned remote filesystem path.
// Construct exclusively via ParseRemotePath (or RemotePath.Join / Dir).
type RemotePath struct {
	clean string
}

// RemoteName is a validated single POSIX directory entry name: non-empty,
// containing no '/', neither "." nor "..", and free of NUL or control characters.
// Construct exclusively via ParseRemoteName (or RemotePath.Base / RelativeTo).
type RemoteName struct {
	name string
}

// LocalComponentValidator validates a single local filesystem path component
// against portable cross-platform safety rules (matching core/fsx.ValidateLocalComponent).
type LocalComponentValidator interface {
	ValidateLocalComponent(name string) error
}

// LocalComponentValidatorFunc adapts a function with signature func(string) error
// (such as core/fsx.ValidateLocalComponent) to LocalComponentValidator.
type LocalComponentValidatorFunc func(name string) error

// ValidateLocalComponent invokes f(name), failing closed when f is nil.
func (f LocalComponentValidatorFunc) ValidateLocalComponent(name string) error {
	if f == nil {
		return fmt.Errorf("%w: nil local component validator", ErrInvalidLocalTarget)
	}
	return f(name)
}

// defaultLocalComponentValidator delegates to the single portable validator in
// core/fsx so all local filename component validation shares one authority.
var defaultLocalComponentValidator LocalComponentValidator = LocalComponentValidatorFunc(fsx.ValidateLocalComponent)

// LocalTarget is a validated local filesystem destination rooted inside root.
// Construct exclusively via ResolveLocalTarget or ResolveLocalTargetWithValidator.
type LocalTarget struct {
	root string
	rel  string
}

func hasPathControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return true
		}
	}
	return false
}

// ParseRemoteName validates raw as a single POSIX remote path segment (no '/',
// not empty, not "." or "..", and free of NUL or control characters).
func ParseRemoteName(raw string) (RemoteName, error) {
	if raw == "" {
		return RemoteName{}, fmt.Errorf("%w: empty name", ErrInvalidRemoteName)
	}
	if hasPathControlChar(raw) {
		return RemoteName{}, fmt.Errorf("%w: %q contains NUL or control character", ErrInvalidRemoteName, raw)
	}
	if strings.ContainsRune(raw, '/') {
		return RemoteName{}, fmt.Errorf("%w: %q contains '/'", ErrInvalidRemoteName, raw)
	}
	if raw == "." || raw == ".." {
		return RemoteName{}, fmt.Errorf("%w: %q is a dot traversal segment", ErrInvalidRemoteName, raw)
	}
	return RemoteName{name: raw}, nil
}

// IsValid reports whether n was constructed as a valid non-empty RemoteName.
func (n RemoteName) IsValid() bool { return n.name != "" }

// String returns the raw POSIX entry name, or "" for an invalid zero-value RemoteName.
func (n RemoteName) String() string { return n.name }

// Equal reports whether n and other are both valid and equal.
func (n RemoteName) Equal(other RemoteName) bool {
	return n.IsValid() && other.IsValid() && n.name == other.name
}

// ParseRemotePath validates raw as a POSIX remote path (rejecting empty strings,
// NUL, and control characters) and normalizes it with POSIX path.Clean.
func ParseRemotePath(raw string) (RemotePath, error) {
	if raw == "" {
		return RemotePath{}, fmt.Errorf("%w: empty path", ErrInvalidRemotePath)
	}
	if hasPathControlChar(raw) {
		return RemotePath{}, fmt.Errorf("%w: %q contains NUL or control character", ErrInvalidRemotePath, raw)
	}
	return RemotePath{clean: path.Clean(raw)}, nil
}

// IsValid reports whether p was constructed via ParseRemotePath.
func (p RemotePath) IsValid() bool { return p.clean != "" }

// IsAbs reports whether p is an absolute POSIX path (starting with '/').
func (p RemotePath) IsAbs() bool { return p.IsValid() && path.IsAbs(p.clean) }

// String returns the POSIX-cleaned remote path, or "" for an invalid zero-value RemotePath.
func (p RemotePath) String() string { return p.clean }

// Equal reports whether p and other are both valid and have identical cleaned paths.
func (p RemotePath) Equal(other RemotePath) bool {
	return p.IsValid() && other.IsValid() && p.clean == other.clean
}

// Dir returns the POSIX parent directory of p, or an invalid RemotePath if p is invalid.
func (p RemotePath) Dir() RemotePath {
	if !p.IsValid() {
		return RemotePath{}
	}
	return RemotePath{clean: path.Dir(p.clean)}
}

// Base returns the final segment of p using POSIX path.Base (never filepath.Base).
// If p is invalid or its base segment is not a valid RemoteName (such as "/", ".",
// "..", or a path ending in "/.."), Base returns an invalid zero-value RemoteName.
func (p RemotePath) Base() RemoteName {
	if !p.IsValid() {
		return RemoteName{}
	}
	name, err := ParseRemoteName(path.Base(p.clean))
	if err != nil {
		return RemoteName{}
	}
	return name
}

// Join appends a single validated RemoteName to p using POSIX path.Join.
// If either p or name is invalid, Join fails closed by returning an invalid RemotePath.
func (p RemotePath) Join(name RemoteName) RemotePath {
	if !p.IsValid() || !name.IsValid() {
		return RemotePath{}
	}
	return RemotePath{clean: path.Join(p.clean, name.name)}
}

// JoinNames appends zero or more validated RemoteName segments to p.
func (p RemotePath) JoinNames(names ...RemoteName) (RemotePath, error) {
	if !p.IsValid() {
		return RemotePath{}, fmt.Errorf("%w: cannot join onto invalid remote path", ErrInvalidRemotePath)
	}
	cur := p
	for _, name := range names {
		if !name.IsValid() {
			return RemotePath{}, fmt.Errorf("%w: invalid remote name segment", ErrInvalidRemoteName)
		}
		cur = cur.Join(name)
	}
	return cur, nil
}

// RelativeTo expresses p as a slice of validated RemoteName segments relative to
// root. When p equals root, RelativeTo returns (nil, nil). It handles root "."
// and root "/" correctly and rejects any path outside or escaping root.
func (p RemotePath) RelativeTo(root RemotePath) ([]RemoteName, error) {
	if !p.IsValid() {
		return nil, fmt.Errorf("%w: target path is invalid", ErrInvalidRemotePath)
	}
	if !root.IsValid() {
		return nil, fmt.Errorf("%w: root path is invalid", ErrInvalidRemotePath)
	}
	if p.clean == root.clean {
		return nil, nil
	}
	if path.IsAbs(p.clean) != path.IsAbs(root.clean) {
		return nil, fmt.Errorf("%w: remote path %q is outside root %q", ErrInvalidRemotePath, p.clean, root.clean)
	}

	var rel string
	switch root.clean {
	case "/":
		rel = strings.TrimPrefix(p.clean, "/")
	case ".":
		if p.clean == ".." || strings.HasPrefix(p.clean, "../") {
			return nil, fmt.Errorf("%w: remote path %q escapes root %q", ErrInvalidRemotePath, p.clean, root.clean)
		}
		rel = p.clean
	default:
		prefix := root.clean + "/"
		if !strings.HasPrefix(p.clean, prefix) {
			return nil, fmt.Errorf("%w: remote path %q is outside root %q", ErrInvalidRemotePath, p.clean, root.clean)
		}
		rel = strings.TrimPrefix(p.clean, prefix)
	}

	parts := strings.Split(rel, "/")
	out := make([]RemoteName, 0, len(parts))
	for _, part := range parts {
		name, err := ParseRemoteName(part)
		if err != nil {
			return nil, fmt.Errorf("%w: remote path %q relative to %q: %w", ErrInvalidRemotePath, p.clean, root.clean, err)
		}
		out = append(out, name)
	}
	return out, nil
}

// ResolveLocalTarget validates every RemoteName component using the package's
// local component validator and resolves a contained LocalTarget under root.
// Passing zero names resolves to root itself (IsRoot() == true).
func ResolveLocalTarget(root string, names ...RemoteName) (LocalTarget, error) {
	return ResolveLocalTargetWithValidator(root, defaultLocalComponentValidator, names...)
}

// ResolveLocalTargetWithValidator constructs a LocalTarget under root by
// validating every RemoteName segment with validator (such as
// LocalComponentValidatorFunc(fsx.ValidateLocalComponent)) and verifying final
// containment within root. Fails closed if validator is nil or any segment is
// invalid.
func ResolveLocalTargetWithValidator(root string, validator LocalComponentValidator, names ...RemoteName) (LocalTarget, error) {
	if validator == nil {
		return LocalTarget{}, fmt.Errorf("%w: local component validator is required", ErrInvalidLocalTarget)
	}
	if root == "" || strings.TrimSpace(root) == "" {
		return LocalTarget{}, fmt.Errorf("%w: local root cannot be empty", ErrInvalidLocalTarget)
	}
	if hasPathControlChar(root) {
		return LocalTarget{}, fmt.Errorf("%w: local root %q contains NUL or control character", ErrInvalidLocalTarget, root)
	}

	cleanRoot := filepath.Clean(root)
	if len(names) == 0 {
		return LocalTarget{root: cleanRoot, rel: "."}, nil
	}

	segs := make([]string, len(names))
	for i, name := range names {
		if !name.IsValid() {
			return LocalTarget{}, fmt.Errorf("%w: empty or invalid remote name segment at index %d", ErrInvalidLocalTarget, i)
		}
		raw := name.String()
		if err := validator.ValidateLocalComponent(raw); err != nil {
			return LocalTarget{}, fmt.Errorf("%w: %w", ErrInvalidLocalTarget, err)
		}
		segs[i] = raw
	}

	rel := filepath.Join(segs...)
	dest := filepath.Join(cleanRoot, rel)
	if err := ensureLocalDestWithinDir(cleanRoot, dest, false); err != nil {
		return LocalTarget{}, fmt.Errorf("%w: %w", ErrInvalidLocalTarget, err)
	}
	return LocalTarget{root: cleanRoot, rel: rel}, nil
}

// IsValid reports whether t was constructed via ResolveLocalTarget*.
func (t LocalTarget) IsValid() bool { return t.root != "" && t.rel != "" }

// IsRoot reports whether t refers to the root directory itself (rel == ".").
func (t LocalTarget) IsRoot() bool { return t.IsValid() && t.rel == "." }

// Root returns the cleaned local root directory.
func (t LocalTarget) Root() string { return t.root }

// Rel returns the OS-native relative path beneath Root (or "." when IsRoot()).
func (t LocalTarget) Rel() string { return t.rel }

// RelSlash returns the slash-normalized relative path beneath Root (or "." when IsRoot()).
func (t LocalTarget) RelSlash() string {
	if !t.IsValid() {
		return ""
	}
	return filepath.ToSlash(t.rel)
}

// Path returns the resolved OS-native path beneath Root, or "" for an invalid LocalTarget.
func (t LocalTarget) Path() string {
	if !t.IsValid() {
		return ""
	}
	if t.rel == "." {
		return t.root
	}
	return filepath.Join(t.root, t.rel)
}

// String returns the resolved local destination path (identical to Path()).
func (t LocalTarget) String() string { return t.Path() }

// Equal reports whether t and other are both valid and refer to the same root and relative path.
func (t LocalTarget) Equal(other LocalTarget) bool {
	return t.IsValid() && other.IsValid() && t.root == other.root && t.rel == other.rel
}

// Join descends one validated RemoteName beneath t using the default local component validator.
func (t LocalTarget) Join(name RemoteName) (LocalTarget, error) {
	return t.JoinWithValidator(defaultLocalComponentValidator, name)
}

// JoinWithValidator descends one validated RemoteName beneath t using validator.
func (t LocalTarget) JoinWithValidator(validator LocalComponentValidator, name RemoteName) (LocalTarget, error) {
	if !t.IsValid() {
		return LocalTarget{}, fmt.Errorf("%w: cannot join onto invalid local target", ErrInvalidLocalTarget)
	}
	if validator == nil {
		return LocalTarget{}, fmt.Errorf("%w: local component validator is required", ErrInvalidLocalTarget)
	}
	if !name.IsValid() {
		return LocalTarget{}, fmt.Errorf("%w: invalid remote name", ErrInvalidLocalTarget)
	}
	raw := name.String()
	if err := validator.ValidateLocalComponent(raw); err != nil {
		return LocalTarget{}, fmt.Errorf("%w: %w", ErrInvalidLocalTarget, err)
	}
	nextRel := raw
	if !t.IsRoot() {
		nextRel = filepath.Join(t.rel, raw)
	}
	dest := filepath.Join(t.root, nextRel)
	if err := ensureLocalDestWithinDir(t.root, dest, false); err != nil {
		return LocalTarget{}, fmt.Errorf("%w: %w", ErrInvalidLocalTarget, err)
	}
	return LocalTarget{root: t.root, rel: nextRel}, nil
}
