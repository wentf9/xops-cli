package verdict

import (
	"errors"
	"strings"
	"testing"
)

func TestVerdict_ZeroIsDenyAndFailClosed(t *testing.T) {
	t.Parallel()

	var zero Verdict
	if zero != Deny {
		t.Fatalf("zero value Verdict = %d, want Deny (%d)", zero, Deny)
	}
	if zero.Allowed() || !zero.Denied() {
		t.Fatalf("zero Verdict Allowed=%v Denied=%v, want false/true", zero.Allowed(), zero.Denied())
	}
	if zero.String() != "deny" {
		t.Fatalf("Deny.String() = %q, want %q", zero.String(), "deny")
	}

	if !Allow.Allowed() || Allow.Denied() {
		t.Fatalf("Allow Allowed=%v Denied=%v, want true/false", Allow.Allowed(), Allow.Denied())
	}
	if Allow.String() != "allow" {
		t.Fatalf("Allow.String() = %q, want %q", Allow.String(), "allow")
	}

	// Unknown / corrupted values must fail closed.
	for _, unknown := range []Verdict{Verdict(2), Verdict(42), Verdict(255)} {
		if unknown.Allowed() || !unknown.Denied() {
			t.Fatalf("Verdict(%d) must fail closed: Allowed=%v Denied=%v", unknown, unknown.Allowed(), unknown.Denied())
		}
		if !strings.HasPrefix(unknown.String(), "deny(") {
			t.Fatalf("Verdict(%d).String() = %q, want deny(...)", unknown, unknown.String())
		}
	}
}

func TestVerdict_And(t *testing.T) {
	t.Parallel()

	cases := []struct {
		a, b Verdict
		want Verdict
	}{
		{Deny, Deny, Deny},
		{Deny, Allow, Deny},
		{Allow, Deny, Deny},
		{Allow, Allow, Allow},
		{Allow, Verdict(9), Deny},
		{Verdict(9), Allow, Deny},
	}
	for _, tc := range cases {
		if got := tc.a.And(tc.b); got != tc.want {
			t.Errorf("(%v).And(%v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestVerdict_DecideAndAudit(t *testing.T) {
	t.Parallel()

	boom := errors.New("syscall failed")

	if got := Decide(nil); got != Deny {
		t.Fatalf("Decide(nil) = %v, want Deny", got)
	}
	if got := Decide(func() (Verdict, error) { return Allow, nil }); got != Allow {
		t.Fatalf("Decide(Allow, nil) = %v, want Allow", got)
	}
	if got := Decide(func() (Verdict, error) { return Deny, nil }); got != Deny {
		t.Fatalf("Decide(Deny, nil) = %v, want Deny", got)
	}
	// Crucial fail-closed invariant: non-nil error overrides Allow -> Deny.
	if got := Decide(func() (Verdict, error) { return Allow, boom }); got != Deny {
		t.Fatalf("Decide(Allow, err) = %v, want Deny", got)
	}
	if got := Decide(func() (Verdict, error) { return Verdict(99), nil }); got != Deny {
		t.Fatalf("Decide(Verdict(99), nil) = %v, want Deny", got)
	}

	var audited []error
	audit := func(err error) { audited = append(audited, err) }

	if got := DecideWithAudit(func() (Verdict, error) { return Allow, nil }, audit); got != Allow {
		t.Fatalf("DecideWithAudit(Allow) = %v, want Allow", got)
	}
	if len(audited) != 0 {
		t.Fatalf("Allow must not trigger onDeny audit, got %v", audited)
	}

	if got := DecideWithAudit(func() (Verdict, error) { return Allow, boom }, audit); got != Deny {
		t.Fatalf("DecideWithAudit(Allow, err) = %v, want Deny", got)
	}
	if len(audited) != 1 || !errors.Is(audited[0], boom) {
		t.Fatalf("audited errors = %v, want [%v]", audited, boom)
	}

	if got := DecideWithAudit(func() (Verdict, error) { return Deny, nil }, audit); got != Deny {
		t.Fatalf("DecideWithAudit(Deny, nil) = %v, want Deny", got)
	}
	if len(audited) != 2 || audited[1] != nil {
		t.Fatalf("clean Deny audit = %v, want nil reason", audited)
	}

	if got := DecideWithAudit(func() (Verdict, error) { return Verdict(7), nil }, audit); got != Deny {
		t.Fatalf("DecideWithAudit(Verdict(7), nil) = %v, want Deny", got)
	}
	if len(audited) != 3 || !errors.Is(audited[2], ErrInvalidVerdict) {
		t.Fatalf("invalid verdict audit = %v, want ErrInvalidVerdict", audited)
	}

	if got := DecideWithAudit(nil, audit); got != Deny {
		t.Fatalf("DecideWithAudit(nil) = %v, want Deny", got)
	}
	if len(audited) != 4 || audited[3] == nil {
		t.Fatalf("nil evaluator audit = %v, want non-nil reason", audited)
	}
}

func TestParseVerdict(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		raw  string
		want Verdict
	}{
		{"deny", Deny},
		{"DENY", Deny},
		{"  Deny  ", Deny},
		{"allow", Allow},
		{"ALLOW", Allow},
		{" allow ", Allow},
	} {
		got, err := ParseVerdict(tc.raw)
		if err != nil || got != tc.want {
			t.Errorf("ParseVerdict(%q) = (%v, %v), want (%v, nil)", tc.raw, got, err, tc.want)
		}
	}

	for _, bad := range []string{"", "   ", "yes", "no", "true", "false", "1", "0", "allow\n", "deny\x00", "allow\u2028"} {
		got, err := ParseVerdict(bad)
		if err == nil || !errors.Is(err, ErrInvalidVerdict) || got != Deny {
			t.Errorf("ParseVerdict(%q) = (%v, %v), want (Deny, ErrInvalidVerdict)", bad, got, err)
		}
	}
}

func FuzzParseVerdictRoundTrip(f *testing.F) {
	for _, seed := range []string{"allow", "deny", "ALLOW", "DENY", "", "yes", "allow\n", "\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		v, err := ParseVerdict(raw)
		if err != nil {
			if v != Deny {
				t.Fatalf("ParseVerdict(%q) failed with err=%v but returned non-Deny %v", raw, err, v)
			}
			return
		}
		reparsed, err := ParseVerdict(v.String())
		if err != nil || reparsed != v {
			t.Fatalf("round-trip failed for %q -> %v -> %q -> (%v, %v)", raw, v, v.String(), reparsed, err)
		}
	})
}
