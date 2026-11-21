package verdict

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// Verdict represents a fail-closed security authorization or safety decision.
// Its zero value is Deny; only Allow permits the evaluated action.
type Verdict uint8

const (
	// Deny is the zero-value fail-closed verdict.
	Deny Verdict = iota
	// Allow explicitly permits the evaluated action.
	Allow
)

// ErrInvalidVerdict indicates an unrecognized textual or numeric verdict value.
var ErrInvalidVerdict = errors.New("invalid verdict")

// Allowed reports whether v is explicitly Allow.
// Any zero or unknown Verdict value fails closed and returns false.
func (v Verdict) Allowed() bool {
	return v == Allow
}

// Denied reports whether v does not permit the action (including zero or unknown values).
func (v Verdict) Denied() bool {
	return v != Allow
}

// And returns Allow if and only if both v and other are Allow; otherwise Deny.
func (v Verdict) And(other Verdict) Verdict {
	if v == Allow && other == Allow {
		return Allow
	}
	return Deny
}

// String returns the canonical string representation of v ("allow" or "deny").
// Unknown non-Allow values fail closed as "deny(invalid:<n>)".
func (v Verdict) String() string {
	switch v {
	case Deny:
		return "deny"
	case Allow:
		return "allow"
	default:
		return fmt.Sprintf("deny(invalid:%d)", uint8(v))
	}
}

// ParseVerdict parses a canonical verdict string ("allow" or "deny", case-insensitive).
// Any control character, whitespace-only input, or unrecognized token fails closed
// by returning (Deny, error).
func ParseVerdict(raw string) (Verdict, error) {
	for _, r := range raw {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return Deny, fmt.Errorf("%w: verdict %q contains control character", ErrInvalidVerdict, raw)
		}
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "deny":
		return Deny, nil
	case "allow":
		return Allow, nil
	default:
		return Deny, fmt.Errorf("%w: %q", ErrInvalidVerdict, raw)
	}
}

// Decide evaluates fn and collapses any error, nil function, or non-Allow verdict
// into Deny. Only a nil error paired with Allow returns Allow.
func Decide(fn func() (Verdict, error)) Verdict {
	return DecideWithAudit(fn, nil)
}

// DecideWithAudit evaluates fn like Decide and invokes onDeny whenever the
// resulting verdict is Deny. When fn is nil, returns a non-nil error, or yields
// an unrecognized verdict value, onDeny receives the corresponding error; for a
// clean (Deny, nil) decision, onDeny receives nil.
func DecideWithAudit(fn func() (Verdict, error), onDeny func(reason error)) Verdict {
	if fn == nil {
		if onDeny != nil {
			onDeny(errors.New("nil verdict evaluator"))
		}
		return Deny
	}
	v, err := fn()
	if err != nil {
		if onDeny != nil {
			onDeny(err)
		}
		return Deny
	}
	if v == Allow {
		return Allow
	}
	if onDeny != nil {
		if v == Deny {
			onDeny(nil)
		} else {
			onDeny(fmt.Errorf("%w: %d", ErrInvalidVerdict, uint8(v)))
		}
	}
	return Deny
}
