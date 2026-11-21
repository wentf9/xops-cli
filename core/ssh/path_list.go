package ssh

import (
	"fmt"
	"slices"
	"strings"
)

// PathListState classifies a PathList into its three domain states.
type PathListState uint8

const (
	// PathListUnset indicates no paths were specified; default identity fallback is allowed.
	PathListUnset PathListState = iota
	// PathListDisabled indicates identity/certificate loading was explicitly disabled via "none".
	PathListDisabled
	// PathListSet indicates one or more explicit identity/certificate paths are configured.
	PathListSet
)

// String returns the canonical state name ("unset", "disabled", or "set").
func (s PathListState) String() string {
	switch s {
	case PathListUnset:
		return "unset"
	case PathListDisabled:
		return "disabled"
	case PathListSet:
		return "set"
	default:
		return fmt.Sprintf("invalid(%d)", uint8(s))
	}
}

// PathList is an immutable tri-state ordered list of validated IdentityPathSetting
// entries (used by IdentityFile and CertificateFile).
//
// Algebraically, PathList forms a monoid under Merge(higher, lower):
//   - Identity element: Unset (zero value)
//   - Left absorption: Disabled.Merge(x) == Disabled for all x
//   - Associativity: (a.Merge(b)).Merge(c) == a.Merge(b.Merge(c))
//
// To preserve associativity when a higher layer contains concrete items followed
// by a "none" terminator (or merges with a lower Disabled layer), PathList tracks
// an unexported terminated flag so sealed Set lists absorb subsequent lower layers
// without erasing their own concrete items.
//
// Construct exclusively via UnsetPathList, DisabledPathList, NewPathList,
// ParsePathList, or ParsePathListItems.
type PathList struct {
	state      PathListState
	items      []IdentityPathSetting
	terminated bool
}

// UnsetPathList returns the identity element (zero value) of the PathList monoid.
func UnsetPathList() PathList {
	return PathList{}
}

// DisabledPathList returns the explicitly disabled ("none") PathList state.
func DisabledPathList() PathList {
	return PathList{state: PathListDisabled, terminated: true}
}

// NewPathList validates and constructs a PathList from typed IdentityPathSetting
// entries. Unset entries are skipped; a Disabled entry seals the list against
// subsequent entries (still validating their syntax); enabled entries are
// deduplicated preserving first-seen order.
func NewPathList(entries ...IdentityPathSetting) (PathList, error) {
	if len(entries) == 0 {
		return UnsetPathList(), nil
	}
	var items []IdentityPathSetting
	terminated := false
	for _, entry := range entries {
		norm, err := validatePathListEntry(entry)
		if err != nil {
			return PathList{}, err
		}
		if norm.Unset() || terminated {
			continue
		}
		if norm.Disabled() {
			terminated = true
			continue
		}
		if !slices.Contains(items, norm) {
			items = append(items, norm)
		}
	}
	return buildPathList(items, terminated), nil
}

// ParsePathList parses a newline-delimited canonical PathList string.
// An empty string returns PathListUnset. "none" (case-insensitive) seals the
// list: "none" alone yields PathListDisabled, while concrete paths followed by
// "none" yield a terminated PathListSet. Every line is syntax-validated even
// after a "none" terminator.
func ParsePathList(raw string) (PathList, error) {
	if raw == "" {
		return UnsetPathList(), nil
	}
	return ParsePathListItems(strings.Split(raw, "\n"))
}

// ParsePathListItems parses a sequence of raw IdentityFile/CertificateFile lines
// into a validated PathList. An empty slice returns PathListUnset. Empty or
// whitespace-only elements and control characters are rejected.
func ParsePathListItems(rawItems []string) (PathList, error) {
	if len(rawItems) == 0 {
		return UnsetPathList(), nil
	}
	var items []IdentityPathSetting
	terminated := false
	for _, raw := range rawItems {
		if raw == "" {
			return PathList{}, fmt.Errorf("%w: path list entry cannot be empty", ErrSSHOptionsValidation)
		}
		setting, err := ParseIdentityPathSetting(raw, true)
		if err != nil {
			return PathList{}, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
		}
		if setting.Unset() {
			return PathList{}, fmt.Errorf("%w: path list entry cannot be empty", ErrSSHOptionsValidation)
		}
		if terminated {
			continue
		}
		if setting.Disabled() {
			terminated = true
			continue
		}
		if !slices.Contains(items, setting) {
			items = append(items, setting)
		}
	}
	return buildPathList(items, terminated), nil
}

func validatePathListEntry(entry IdentityPathSetting) (IdentityPathSetting, error) {
	switch entry.Kind {
	case IdentityPathUnset:
		if entry.Raw != "" {
			return IdentityPathSetting{}, fmt.Errorf("%w: unset identity path must have empty raw value", ErrSSHOptionsValidation)
		}
		return entry, nil
	case IdentityPathDisabled:
		if entry.Raw != "" && !IsNoneValue(entry.Raw) {
			return IdentityPathSetting{}, fmt.Errorf("%w: disabled identity path has non-none value %q", ErrSSHOptionsValidation, entry.Raw)
		}
		return IdentityPathSetting{Kind: IdentityPathDisabled, Raw: "none"}, nil
	case IdentityPathTemplate, IdentityPathLiteral:
		if entry.Raw == "" {
			return IdentityPathSetting{}, fmt.Errorf("%w: enabled identity path cannot be empty", ErrSSHOptionsValidation)
		}
		parsed, err := ParseIdentityPathSetting(entry.Raw, true)
		if err != nil {
			return IdentityPathSetting{}, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
		}
		if parsed.Disabled() {
			return IdentityPathSetting{}, fmt.Errorf("%w: path %q is the reserved 'none' sentinel; use IdentityPathDisabled", ErrSSHOptionsValidation, entry.Raw)
		}
		if parsed.Kind != entry.Kind {
			return IdentityPathSetting{}, fmt.Errorf("%w: identity path %q kind mismatch (got %d, parsed %d)", ErrSSHOptionsValidation, entry.Raw, entry.Kind, parsed.Kind)
		}
		return parsed, nil
	default:
		return IdentityPathSetting{}, fmt.Errorf("%w: unknown IdentityPathKind %d", ErrSSHOptionsValidation, entry.Kind)
	}
}

func buildPathList(items []IdentityPathSetting, terminated bool) PathList {
	if len(items) == 0 {
		if terminated {
			return DisabledPathList()
		}
		return UnsetPathList()
	}
	return PathList{
		state:      PathListSet,
		items:      items,
		terminated: terminated,
	}
}

// State returns the tri-state classification of p (Unset, Disabled, or Set).
func (p PathList) State() PathListState { return p.state }

// IsUnset reports whether p is in the PathListUnset state.
func (p PathList) IsUnset() bool { return p.state == PathListUnset }

// IsDisabled reports whether p is explicitly disabled ("none").
func (p PathList) IsDisabled() bool { return p.state == PathListDisabled }

// IsSet reports whether p holds one or more explicit paths.
func (p PathList) IsSet() bool { return p.state == PathListSet }

// Terminated reports whether p was sealed by a "none" sentinel (always true for
// Disabled, and true for a Set list followed by "none" or merged over Disabled).
func (p PathList) Terminated() bool {
	return p.state == PathListDisabled || p.terminated
}

// DefaultsAllowed reports whether implicit default identity files (e.g. ~/.ssh/id_*)
// may be expanded. Returns true strictly when p is Unset.
func (p PathList) DefaultsAllowed() bool {
	return p.state == PathListUnset
}

// Items returns a defensive copy of the configured IdentityPathSetting entries
// (nil when Unset or Disabled). Returned items never include the "none" sentinel.
func (p PathList) Items() []IdentityPathSetting {
	if p.state != PathListSet || len(p.items) == 0 {
		return nil
	}
	return slices.Clone(p.items)
}

// RawItems returns the raw path strings of the configured entries in order
// (nil when Unset or Disabled).
func (p PathList) RawItems() []string {
	if p.state != PathListSet || len(p.items) == 0 {
		return nil
	}
	out := make([]string, len(p.items))
	for i, item := range p.items {
		out[i] = item.Raw
	}
	return out
}

func (p PathList) clone() PathList {
	if len(p.items) == 0 {
		return PathList{state: p.state, terminated: p.terminated}
	}
	return PathList{
		state:      p.state,
		items:      slices.Clone(p.items),
		terminated: p.terminated,
	}
}

// Merge combines higher-priority p with lower-priority lower according to the
// PathList monoid:
//   - Unset is the two-sided identity.
//   - Disabled (or any terminated list) absorbs lower.
//   - Otherwise items are appended with first-occurrence deduplication and
//     lower's termination bit is inherited.
func (p PathList) Merge(lower PathList) PathList {
	if p.state == PathListUnset {
		return lower.clone()
	}
	if p.state == PathListDisabled || p.terminated {
		return p.clone()
	}
	if lower.state == PathListUnset {
		return p.clone()
	}
	if lower.state == PathListDisabled {
		return PathList{
			state:      PathListSet,
			items:      slices.Clone(p.items),
			terminated: true,
		}
	}
	merged := make([]IdentityPathSetting, len(p.items), len(p.items)+len(lower.items))
	copy(merged, p.items)
	for _, item := range lower.items {
		if !slices.Contains(merged, item) {
			merged = append(merged, item)
		}
	}
	return PathList{
		state:      PathListSet,
		items:      merged,
		terminated: lower.terminated,
	}
}

// MergePathList merges a higher-priority PathList over a lower-priority PathList.
func MergePathList(higher, lower PathList) PathList {
	return higher.Merge(lower)
}

// MergePathLists folds layers from highest priority to lowest priority.
func MergePathLists(layers ...PathList) PathList {
	acc := UnsetPathList()
	for _, layer := range layers {
		acc = acc.Merge(layer)
	}
	return acc
}

// Equal reports whether p and other represent the exact same monoid element
// (state, ordered items, and termination bit).
func (p PathList) Equal(other PathList) bool {
	return p.state == other.state &&
		p.Terminated() == other.Terminated() &&
		slices.Equal(p.items, other.items)
}

// String formats p losslessly in canonical newline-delimited syntax:
//   - Unset: ""
//   - Disabled: "none"
//   - Set (unterminated): "<path1>\n<path2>"
//   - Set (terminated): "<path1>\n<path2>\nnone"
func (p PathList) String() string {
	switch p.state {
	case PathListUnset:
		return ""
	case PathListDisabled:
		return "none"
	case PathListSet:
		parts := make([]string, 0, len(p.items)+1)
		for _, item := range p.items {
			parts = append(parts, item.Raw)
		}
		if p.terminated {
			parts = append(parts, "none")
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}
