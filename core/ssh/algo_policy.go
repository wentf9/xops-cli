package ssh

import (
	"fmt"
	"slices"
	"strings"
)

// AlgoOp classifies an OpenSSH algorithm list modification operation.
type AlgoOp uint8

const (
	// AlgoOpUnset represents an unspecified algorithm policy (identity for Merge and Resolve).
	AlgoOpUnset AlgoOp = iota
	// AlgoOpReplace replaces the default algorithm list with the specified tokens.
	AlgoOpReplace
	// AlgoOpAppend ('+') appends the specified tokens to the defaults.
	AlgoOpAppend
	// AlgoOpRemove ('-') removes the specified tokens from the defaults.
	AlgoOpRemove
	// AlgoOpPrepend ('^') prepends the specified tokens ahead of the defaults.
	AlgoOpPrepend
	// AlgoOpDefault represents an explicit default-retaining policy (for example
	// an OpenSSH "+algo" or "^algo" modifier whose tokens are unsupported
	// locally): it resolves to unmodified defaults while shadowing lower layers
	// during Merge.
	AlgoOpDefault
)

// String returns the canonical operation name.
func (op AlgoOp) String() string {
	switch op {
	case AlgoOpUnset:
		return "unset"
	case AlgoOpReplace:
		return "replace"
	case AlgoOpAppend:
		return "append"
	case AlgoOpRemove:
		return "remove"
	case AlgoOpPrepend:
		return "prepend"
	case AlgoOpDefault:
		return "default"
	default:
		return fmt.Sprintf("invalid(%d)", uint8(op))
	}
}

// AlgoPolicy is an immutable, validated OpenSSH algorithm policy bound to a
// registered algorithm OptionSpec (Ciphers, MACs, KexAlgorithms, or HostKeyAlgorithms).
//
// Zero value is AlgoOpUnset (identity under Merge; Resolve clones defaults).
// Construct non-unset policies exclusively via ParseAlgoPolicy.
type AlgoPolicy struct {
	optionKey string
	op        AlgoOp
	tokens    []string
}

// UnsetAlgoPolicy returns the zero-value unset AlgoPolicy (identity for Merge).
func UnsetAlgoPolicy() AlgoPolicy {
	return AlgoPolicy{}
}

// DefaultAlgoPolicy returns an explicit default-retaining AlgoPolicy bound to
// optionKey. Unlike UnsetAlgoPolicy (the Merge identity), DefaultAlgoPolicy
// shadows lower-priority layers in Merge while resolving to the unmodified
// default algorithm list.
func DefaultAlgoPolicy(optionKey string) (AlgoPolicy, error) {
	spec, err := lookupAlgorithmOptionSpec(optionKey)
	if err != nil {
		return AlgoPolicy{}, err
	}
	return AlgoPolicy{
		optionKey: spec.CanonicalKey,
		op:        AlgoOpDefault,
	}, nil
}

// ParseAlgoPolicy strictly parses an OpenSSH algorithm specification for
// optionKey (canonical key or OpenSSH name of an algorithm OptionSpec such as
// Ciphers, MACs, KexAlgorithms, or HostKeyAlgorithms).
//
// Bare modifiers ("-", "+", "^"), empty specifications, empty comma-separated
// tokens, invalid algorithm syntax, and unsupported tokens (for replace/+/^,
// checked against OptionSpec.SupportedTokens as the single capability source)
// are all rejected with an error wrapping ErrSSHOptionsValidation.
func ParseAlgoPolicy(optionKey, raw string) (AlgoPolicy, error) {
	spec, err := lookupAlgorithmOptionSpec(optionKey)
	if err != nil {
		return AlgoPolicy{}, err
	}
	if hasControlOrLineSepChar(raw) {
		return AlgoPolicy{}, fmt.Errorf("%w: invalid %s %q: contains invalid control character", ErrSSHOptionsValidation, spec.OpenSSHName, raw)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return AlgoPolicy{}, fmt.Errorf("%w: invalid %s: value cannot be empty", ErrSSHOptionsValidation, spec.OpenSSHName)
	}

	op := AlgoOpReplace
	body := trimmed
	switch trimmed[0] {
	case '+':
		op = AlgoOpAppend
		body = trimmed[1:]
	case '-':
		op = AlgoOpRemove
		body = trimmed[1:]
	case '^':
		op = AlgoOpPrepend
		body = trimmed[1:]
	}

	if strings.TrimSpace(body) == "" {
		return AlgoPolicy{}, fmt.Errorf("%w: invalid %s %q: bare modifier %q without algorithm tokens", ErrSSHOptionsValidation, spec.OpenSSHName, raw, trimmed[:1])
	}

	supported := spec.SupportedTokens()
	var tokens []string
	for part := range strings.SplitSeq(body, ",") {
		tok := strings.TrimSpace(part)
		if tok == "" {
			return AlgoPolicy{}, fmt.Errorf("%w: invalid %s %q: empty algorithm token", ErrSSHOptionsValidation, spec.OpenSSHName, raw)
		}
		if !isValidAlgorithmName(tok) {
			return AlgoPolicy{}, fmt.Errorf("%w: invalid %s %q: invalid algorithm token %q", ErrSSHOptionsValidation, spec.OpenSSHName, raw, tok)
		}
		if op != AlgoOpRemove && !slices.Contains(supported, tok) {
			return AlgoPolicy{}, fmt.Errorf("%w: invalid %s %q: unsupported algorithm %q", ErrSSHOptionsValidation, spec.OpenSSHName, raw, tok)
		}
		if !slices.Contains(tokens, tok) {
			tokens = append(tokens, tok)
		}
	}
	if len(tokens) == 0 {
		return AlgoPolicy{}, fmt.Errorf("%w: invalid %s %q: empty algorithm list", ErrSSHOptionsValidation, spec.OpenSSHName, raw)
	}
	return AlgoPolicy{
		optionKey: spec.CanonicalKey,
		op:        op,
		tokens:    tokens,
	}, nil
}

func lookupAlgorithmOptionSpec(optionKey string) (OptionSpec, error) {
	spec, ok := LookupOptionSpec(optionKey)
	if !ok || spec.SupportedTokens == nil || spec.Class != OptionClassTransport {
		return OptionSpec{}, fmt.Errorf("%w: %q is not a registered algorithm option", ErrSSHOptionsValidation, optionKey)
	}
	return spec, nil
}

// OptionKey returns the canonical snake_case option key (e.g. OptionCiphers),
// or "" when p is unset.
func (p AlgoPolicy) OptionKey() string { return p.optionKey }

// Op returns the algorithm operation (AlgoOpUnset, Replace, Append, Remove, Prepend).
func (p AlgoPolicy) Op() AlgoOp { return p.op }

// IsUnset reports whether p is the unset identity policy.
func (p AlgoPolicy) IsUnset() bool { return p.op == AlgoOpUnset }

// IsDefault reports whether p is an explicit default-retaining policy that
// resolves to unmodified defaults while shadowing lower layers in Merge.
func (p AlgoPolicy) IsDefault() bool { return p.op == AlgoOpDefault }

// Tokens returns a defensive copy of the deduplicated algorithm tokens.
func (p AlgoPolicy) Tokens() []string {
	if p.op == AlgoOpUnset || p.op == AlgoOpDefault || len(p.tokens) == 0 {
		return nil
	}
	return slices.Clone(p.tokens)
}

func (p AlgoPolicy) clone() AlgoPolicy {
	if p.op == AlgoOpUnset {
		return AlgoPolicy{}
	}
	return AlgoPolicy{
		optionKey: p.optionKey,
		op:        p.op,
		tokens:    slices.Clone(p.tokens),
	}
}

// Resolve applies p to defaults and returns the resulting non-empty,
// deduplicated algorithm list. If the resolved list is empty (or p has an
// invalid operation), Resolve returns an error wrapping ErrSSHOptionsValidation.
func (p AlgoPolicy) Resolve(defaults []string) ([]string, error) {
	var result []string
	switch p.op {
	case AlgoOpUnset, AlgoOpDefault:
		result = dedupNonEmpty(defaults)
	case AlgoOpReplace:
		result = slices.Clone(p.tokens)
	case AlgoOpAppend:
		result = dedupNonEmpty(defaults)
		for _, tok := range p.tokens {
			if !slices.Contains(result, tok) {
				result = append(result, tok)
			}
		}
	case AlgoOpPrepend:
		result = slices.Clone(p.tokens)
		for _, tok := range defaults {
			if tok != "" && !slices.Contains(result, tok) {
				result = append(result, tok)
			}
		}
	case AlgoOpRemove:
		for _, tok := range defaults {
			if tok != "" && !slices.Contains(p.tokens, tok) && !slices.Contains(result, tok) {
				result = append(result, tok)
			}
		}
	default:
		return nil, fmt.Errorf("%w: invalid algorithm policy op %d", ErrSSHOptionsValidation, p.op)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("%w: resolved algorithm list is empty", ErrSSHOptionsValidation)
	}
	return result, nil
}

func dedupNonEmpty(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, 0, len(src))
	for _, s := range src {
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// Merge applies OpenSSH first-wins precedence: if higher-priority p is set, it
// absorbs lower; otherwise lower is returned. Forms a monoid with UnsetAlgoPolicy
// as identity.
func (p AlgoPolicy) Merge(lower AlgoPolicy) AlgoPolicy {
	if p.op != AlgoOpUnset {
		return p.clone()
	}
	return lower.clone()
}

// MergeAlgoPolicy merges higher over lower using OpenSSH first-wins semantics.
func MergeAlgoPolicy(higher, lower AlgoPolicy) AlgoPolicy {
	return higher.Merge(lower)
}

// MergeAlgoPolicies folds policies from highest priority to lowest priority.
func MergeAlgoPolicies(layers ...AlgoPolicy) AlgoPolicy {
	acc := UnsetAlgoPolicy()
	for _, layer := range layers {
		acc = acc.Merge(layer)
	}
	return acc
}

// Equal reports whether p and other have the same optionKey, op, and ordered tokens.
func (p AlgoPolicy) Equal(other AlgoPolicy) bool {
	return p.optionKey == other.optionKey &&
		p.op == other.op &&
		slices.Equal(p.tokens, other.tokens)
}

// String formats p in canonical OpenSSH syntax ("" for Unset/Default, or optional
// "+", "-", "^" prefix followed by comma-separated tokens).
func (p AlgoPolicy) String() string {
	switch p.op {
	case AlgoOpUnset, AlgoOpDefault:
		return ""
	case AlgoOpReplace:
		return strings.Join(p.tokens, ",")
	case AlgoOpAppend:
		return "+" + strings.Join(p.tokens, ",")
	case AlgoOpRemove:
		return "-" + strings.Join(p.tokens, ",")
	case AlgoOpPrepend:
		return "^" + strings.Join(p.tokens, ",")
	default:
		return ""
	}
}
