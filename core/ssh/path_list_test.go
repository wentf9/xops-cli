package ssh

import (
	"errors"
	"slices"
	"testing"
)

func TestPathList_UnsetAndDisabledStates(t *testing.T) {
	t.Parallel()

	unset := UnsetPathList()
	var zero PathList
	if !unset.Equal(zero) || !unset.IsUnset() || unset.IsDisabled() || unset.IsSet() || unset.Terminated() {
		t.Fatalf("unexpected Unset state: %+v", unset)
	}
	if !unset.DefaultsAllowed() {
		t.Fatal("Unset PathList must allow defaults")
	}
	if unset.State().String() != "unset" || unset.String() != "" || unset.Items() != nil || unset.RawItems() != nil {
		t.Fatalf("unexpected Unset accessors: state=%q str=%q items=%v", unset.State(), unset.String(), unset.Items())
	}

	disabled := DisabledPathList()
	if !disabled.IsDisabled() || disabled.IsUnset() || disabled.IsSet() || !disabled.Terminated() {
		t.Fatalf("unexpected Disabled state: %+v", disabled)
	}
	if disabled.DefaultsAllowed() {
		t.Fatal("Disabled PathList must NOT allow defaults (H3)")
	}
	if disabled.State().String() != "disabled" || disabled.String() != "none" || disabled.Items() != nil {
		t.Fatalf("unexpected Disabled accessors: state=%q str=%q items=%v", disabled.State(), disabled.String(), disabled.Items())
	}
}

func TestPathList_SetAndSealedStates(t *testing.T) {
	t.Parallel()

	setList, err := ParsePathList("~/.ssh/id_a\n~/.ssh/id_%h\n~/.ssh/id_a")
	if err != nil {
		t.Fatalf("ParsePathList: %v", err)
	}
	if !setList.IsSet() || setList.IsUnset() || setList.IsDisabled() || setList.Terminated() {
		t.Fatalf("unexpected Set state: %+v", setList)
	}
	if setList.DefaultsAllowed() {
		t.Fatal("Set PathList must NOT allow defaults")
	}
	if !slices.Equal(setList.RawItems(), []string{"~/.ssh/id_a", "~/.ssh/id_%h"}) {
		t.Fatalf("RawItems = %v", setList.RawItems())
	}
	items := setList.Items()
	if len(items) != 2 || items[0].Kind != IdentityPathLiteral || items[1].Kind != IdentityPathTemplate {
		t.Fatalf("Items = %+v", items)
	}
	// Mutating returned slice must not mutate PathList.
	items[0].Raw = "/mutated"
	if setList.Items()[0].Raw != "~/.ssh/id_a" {
		t.Fatal("PathList.Items did not return a defensive copy")
	}

	sealed, err := ParsePathList("/k1\nNONE\n/ignored_after_none")
	if err != nil {
		t.Fatalf("ParsePathList sealed: %v", err)
	}
	if !sealed.IsSet() || !sealed.Terminated() || sealed.DefaultsAllowed() {
		t.Fatalf("unexpected sealed state: %+v", sealed)
	}
	if !slices.Equal(sealed.RawItems(), []string{"/k1"}) {
		t.Fatalf("sealed RawItems = %v, want [/k1]", sealed.RawItems())
	}
	if sealed.String() != "/k1\nnone" {
		t.Fatalf("sealed String() = %q, want %q", sealed.String(), "/k1\nnone")
	}
}

func TestPathList_ConstructorsValidation(t *testing.T) {
	t.Parallel()

	// Invalid entries after "none" must still be rejected fail-closed.
	for _, bad := range []string{
		"   ",
		"/k1\n\n/k2",
		"/k1\n   ",
		"none\n~/.ssh/id_%k",
		"/k1\r",
		"/k1\x00",
		"/k1\u2028",
		"${UNCLOSED",
	} {
		if _, err := ParsePathList(bad); !errors.Is(err, ErrSSHOptionsValidation) {
			t.Errorf("ParsePathList(%q) err = %v, want ErrSSHOptionsValidation", bad, err)
		}
	}

	// NewPathList rejects forged/inconsistent IdentityPathSetting values.
	for _, badEntry := range []IdentityPathSetting{
		{Kind: IdentityPathUnset, Raw: "/nonempty"},
		{Kind: IdentityPathDisabled, Raw: "/not-none"},
		{Kind: IdentityPathLiteral, Raw: ""},
		{Kind: IdentityPathLiteral, Raw: "none"},
		{Kind: IdentityPathLiteral, Raw: "~/.ssh/id_%h"}, // actually template
		{Kind: IdentityPathTemplate, Raw: "~/.ssh/id_a"}, // actually literal
		{Kind: IdentityPathLiteral, Raw: "/bad\nkey"},
		{Kind: IdentityPathKind(99), Raw: "/x"},
	} {
		if _, err := NewPathList(badEntry); !errors.Is(err, ErrSSHOptionsValidation) {
			t.Errorf("NewPathList(%+v) err = %v, want ErrSSHOptionsValidation", badEntry, err)
		}
	}

	a, err := ParseIdentityPathSetting("~/.ssh/id_ed25519", true)
	if err != nil {
		t.Fatal(err)
	}
	none, err := ParseIdentityPathSetting("none", true)
	if err != nil {
		t.Fatal(err)
	}
	pl, err := NewPathList(IdentityPathSetting{}, a, none)
	if err != nil || !pl.IsSet() || !pl.Terminated() || !slices.Equal(pl.RawItems(), []string{"~/.ssh/id_ed25519"}) {
		t.Fatalf("NewPathList(unset, a, none) = (%+v, %v)", pl, err)
	}
}

func TestPathList_MonoidLawsTable(t *testing.T) {
	t.Parallel()

	mustParse := func(raw string) PathList {
		t.Helper()
		pl, err := ParsePathList(raw)
		if err != nil {
			t.Fatalf("ParsePathList(%q): %v", raw, err)
		}
		return pl
	}

	universe := []PathList{
		UnsetPathList(),
		DisabledPathList(),
		mustParse("/a"),
		mustParse("/b"),
		mustParse("/a\n/b"),
		mustParse("/b\n/a"),
		mustParse("/a\nnone"),
		mustParse("/b\n/c\nnone"),
	}

	// 1. Identity law: Unset ⊕ x == x and x ⊕ Unset == x.
	for _, x := range universe {
		if got := MergePathList(UnsetPathList(), x); !got.Equal(x) {
			t.Errorf("left identity failed for %q: got %q", x, got)
		}
		if got := MergePathList(x, UnsetPathList()); !got.Equal(x) {
			t.Errorf("right identity failed for %q: got %q", x, got)
		}
	}

	// 2. Disabled left-absorption: Disabled ⊕ x == Disabled for all x.
	for _, x := range universe {
		if got := MergePathList(DisabledPathList(), x); !got.Equal(DisabledPathList()) {
			t.Errorf("Disabled absorption failed for %q: got %q", x, got)
		}
	}

	// 3. Associativity over full Cartesian cube: (a ⊕ b) ⊕ c == a ⊕ (b ⊕ c).
	for _, a := range universe {
		for _, b := range universe {
			for _, c := range universe {
				left := MergePathList(MergePathList(a, b), c)
				right := MergePathList(a, MergePathList(b, c))
				if !left.Equal(right) {
					t.Errorf("associativity violated for (%q, %q, %q): left=%q right=%q", a, b, c, left, right)
				}
				flat := MergePathLists(a, b, c)
				if !flat.Equal(left) {
					t.Errorf("MergePathLists disagreed for (%q, %q, %q): flat=%q left=%q", a, b, c, flat, left)
				}
			}
		}
	}

	// Explicit regression check for MED-7:
	// Higher=[/cli], Mid=Disabled(none), Lower=[/global] must keep [/cli] and drop [/global]
	// under BOTH parenthesizations.
	cli := mustParse("/cli")
	mid := DisabledPathList()
	global := mustParse("/global")
	lhs := MergePathList(MergePathList(cli, mid), global)
	rhs := MergePathList(cli, MergePathList(mid, global))
	if !lhs.Equal(rhs) || !slices.Equal(lhs.RawItems(), []string{"/cli"}) || !lhs.Terminated() {
		t.Fatalf("MED-7 regression: lhs=%q rhs=%q", lhs, rhs)
	}
}

func FuzzPathListRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"",
		"none",
		"NONE",
		"~/.ssh/id_ed25519",
		"/a\n/b",
		"/a\nnone",
		"/a\n/b\nnone\n/c",
		"~/.ssh/id_%h\n${HOME}/.ssh/id_rsa",
		"/bad\x00",
		"   ",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		pl, err := ParsePathList(raw)
		if err != nil {
			return
		}
		if pl.DefaultsAllowed() != (pl.State() == PathListUnset) {
			t.Fatalf("DefaultsAllowed invariant violated for %+v", pl)
		}
		reparsed, err := ParsePathList(pl.String())
		if err != nil {
			t.Fatalf("re-parse of %q (from %q) failed: %v", pl.String(), raw, err)
		}
		if !pl.Equal(reparsed) || reparsed.String() != pl.String() {
			t.Fatalf("round-trip mismatch: first=%q second=%q", pl.String(), reparsed.String())
		}
	})
}

func FuzzPathListMonoidLaws(f *testing.F) {
	f.Add([]byte{0, 1, 2}, []byte{3, 4}, []byte{5, 6})
	f.Add([]byte{2, 0}, []byte{1}, []byte{4, 5})
	f.Add([]byte{1}, []byte{2, 3}, []byte{4})

	pool := []string{
		"none",
		"/k1",
		"/k2",
		"/k3",
		"~/.ssh/id_%h",
		"${HOME}/.ssh/id_ed25519",
	}
	buildFromBytes := func(t *testing.T, data []byte) PathList {
		t.Helper()
		if len(data) == 0 {
			return UnsetPathList()
		}
		n := int(data[0]) % 5
		if n == 0 {
			return UnsetPathList()
		}
		rawItems := make([]string, 0, n)
		for i := 0; i < n; i++ {
			b := data[0]
			if i+1 < len(data) {
				b = data[i+1]
			}
			rawItems = append(rawItems, pool[int(b)%len(pool)])
		}
		pl, err := ParsePathListItems(rawItems)
		if err != nil {
			t.Fatalf("ParsePathListItems(%v): %v", rawItems, err)
		}
		return pl
	}

	f.Fuzz(func(t *testing.T, ba, bb, bc []byte) {
		a := buildFromBytes(t, ba)
		b := buildFromBytes(t, bb)
		c := buildFromBytes(t, bc)

		// Identity
		if !MergePathList(UnsetPathList(), a).Equal(a) || !MergePathList(a, UnsetPathList()).Equal(a) {
			t.Fatalf("identity law failed for %q", a)
		}
		// Disabled left-absorption
		if !MergePathList(DisabledPathList(), a).Equal(DisabledPathList()) {
			t.Fatalf("Disabled absorption failed for %q", a)
		}
		// Associativity
		left := MergePathList(MergePathList(a, b), c)
		right := MergePathList(a, MergePathList(b, c))
		if !left.Equal(right) {
			t.Fatalf("associativity failed for a=%q b=%q c=%q: left=%q right=%q", a, b, c, left, right)
		}
	})
}
