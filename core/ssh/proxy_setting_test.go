package ssh

import (
	"errors"
	"slices"
	"testing"
)

func TestProxySetting_Unset(t *testing.T) {
	t.Parallel()

	unset := UnsetProxySetting()
	if !unset.IsUnset() || unset.IsDisabled() || unset.IsJumpDisabledOnly() || unset.IsActive() || unset.Kind() != ProxyUnset || unset.String() != "" {
		t.Fatalf("unexpected Unset: %+v", unset)
	}
	if targets, ok := unset.JumpTargets(); ok || targets != nil {
		t.Fatalf("Unset.JumpTargets = (%v, %v)", targets, ok)
	}
	if cmd, ok := unset.Command(); ok || cmd != "" {
		t.Fatalf("Unset.Command = (%q, %v)", cmd, ok)
	}
}

func TestProxySetting_DisableVariants(t *testing.T) {
	t.Parallel()

	fullDisabled := DisabledProxySetting()
	if !fullDisabled.IsDisabled() || fullDisabled.IsJumpDisabledOnly() || fullDisabled.IsActive() || fullDisabled.Kind() != ProxyDisabled || fullDisabled.String() != "ProxyCommand=none" {
		t.Fatalf("unexpected DisabledProxySetting: %+v str=%q", fullDisabled, fullDisabled.String())
	}
	jumpDisabled := DisabledProxyJumpSetting()
	if !jumpDisabled.IsDisabled() || !jumpDisabled.IsJumpDisabledOnly() || jumpDisabled.IsActive() || jumpDisabled.Kind() != ProxyDisabled || jumpDisabled.String() != "ProxyJump=none" {
		t.Fatalf("unexpected DisabledProxyJumpSetting: %+v str=%q", jumpDisabled, jumpDisabled.String())
	}
	if fullDisabled.Equal(jumpDisabled) {
		t.Fatal("ProxyCommand=none and ProxyJump=none must be distinct monoid elements")
	}

	for _, fn := range []func() (ProxySetting, error){
		func() (ProxySetting, error) { return ParseProxyCommand("  none  ") },
		func() (ProxySetting, error) { return ParseProxySetting("none") },
		func() (ProxySetting, error) { return ParseProxySetting("ProxyCommand=NONE") },
	} {
		got, err := fn()
		if err != nil || !got.Equal(fullDisabled) {
			t.Fatalf("expected full DisabledProxySetting, got (%+v, %v)", got, err)
		}
	}
	for _, fn := range []func() (ProxySetting, error){
		func() (ProxySetting, error) { return ParseProxyJump("NONE") },
		func() (ProxySetting, error) { return ParseProxySetting("ProxyJump=none") },
	} {
		got, err := fn()
		if err != nil || !got.Equal(jumpDisabled) {
			t.Fatalf("expected DisabledProxyJumpSetting, got (%+v, %v)", got, err)
		}
	}
}

func TestProxySetting_JumpAndShadowedMutualExclusivity(t *testing.T) {
	t.Parallel()

	jump, err := ParseProxyJump("bastion1, user@bastion2:2222")
	if err != nil || jump.Kind() != ProxyJump || !jump.IsActive() {
		t.Fatalf("ParseProxyJump = (%+v, %v)", jump, err)
	}
	targets, ok := jump.JumpTargets()
	if !ok || !slices.Equal(targets, []string{"bastion1", "user@bastion2:2222"}) {
		t.Fatalf("JumpTargets = (%v, %v)", targets, ok)
	}
	if cmd, ok := jump.Command(); ok || cmd != "" {
		t.Fatalf("Jump.Command must be absent, got (%q, %v)", cmd, ok)
	}
	// Defensive copy check.
	targets[0] = "mutated"
	if got, _ := jump.JumpTargets(); got[0] != "bastion1" {
		t.Fatal("JumpTargets did not return defensive copy")
	}

	// Merging Jump over Command keeps observable Kind()==ProxyJump and Command()==("", false).
	cmd, err := NewProxyCommand("ssh -W %h:%p lower")
	if err != nil {
		t.Fatal(err)
	}
	shadowed := MergeProxySetting(jump, cmd)
	if shadowed.Kind() != ProxyJump || !shadowed.IsActive() {
		t.Fatalf("shadowed Kind = %v, want ProxyJump", shadowed.Kind())
	}
	if gotCmd, ok := shadowed.Command(); ok || gotCmd != "" {
		t.Fatalf("shadowed ProxyJump must not leak Command(), got (%q, %v)", gotCmd, ok)
	}
	if gotTargets, ok := shadowed.JumpTargets(); !ok || !slices.Equal(gotTargets, []string{"bastion1", "user@bastion2:2222"}) {
		t.Fatalf("shadowed JumpTargets = (%v, %v)", gotTargets, ok)
	}
	if shadowed.Equal(jump) {
		t.Fatal("Jump with shadowed Command must differ from Jump without shadowed Command for monoid congruence")
	}
	reparsed, err := ParseProxySetting(shadowed.String())
	if err != nil || !reparsed.Equal(shadowed) {
		t.Fatalf("shadowed round-trip failed: wire=%q reparsed=(%+v, %v)", shadowed.String(), reparsed, err)
	}
}

func TestProxySetting_CommandAndInvalidInputs(t *testing.T) {
	t.Parallel()

	cmdSet, err := NewProxyCommand("  nc -X connect %h %p  ")
	if err != nil || cmdSet.Kind() != ProxyCommand || !cmdSet.IsActive() {
		t.Fatalf("NewProxyCommand = (%+v, %v)", cmdSet, err)
	}
	if cmd, ok := cmdSet.Command(); !ok || cmd != "nc -X connect %h %p" {
		t.Fatalf("Command() = (%q, %v)", cmd, ok)
	}
	if targets, ok := cmdSet.JumpTargets(); ok || targets != nil {
		t.Fatalf("Command.JumpTargets must be absent, got (%v, %v)", targets, ok)
	}

	// Reject malformed inputs.
	if _, err := NewProxyJump(); !errors.Is(err, ErrSSHOptionsValidation) {
		t.Errorf("NewProxyJump() err = %v", err)
	}
	for _, bad := range []string{"", "   ", ",", "a,,b", "a,", ",b", "a,none", "bastion\n", "bastion\x00"} {
		if _, err := ParseProxyJump(bad); !errors.Is(err, ErrSSHOptionsValidation) {
			t.Errorf("ParseProxyJump(%q) err = %v, want ErrSSHOptionsValidation", bad, err)
		}
	}
	for _, bad := range []string{"", "   ", "none", "nc %h %p\n", "nc %h %p\x00"} {
		if _, err := NewProxyCommand(bad); !errors.Is(err, ErrSSHOptionsValidation) {
			t.Errorf("NewProxyCommand(%q) err = %v, want ErrSSHOptionsValidation", bad, err)
		}
	}
	for _, bad := range []string{"   ", "ProxyJump=a\n", "\nProxyCommand=nc %h %p", "ProxyJump=a\r\nProxyCommand=b", "Unknown=x"} {
		if _, err := ParseProxySetting(bad); !errors.Is(err, ErrSSHOptionsValidation) {
			t.Errorf("ParseProxySetting(%q) err = %v, want ErrSSHOptionsValidation", bad, err)
		}
	}
}

func TestProxySetting_OpenSSHPrecedenceAndMED8(t *testing.T) {
	t.Parallel()

	jumpNone := DisabledProxyJumpSetting()
	cmdNone := DisabledProxySetting()
	bastion, err := NewProxyJump("bastion")
	if err != nil {
		t.Fatal(err)
	}
	lowerCmd, err := NewProxyCommand("ssh -W %h:%p lower-proxy")
	if err != nil {
		t.Fatal(err)
	}

	// OpenSSH ssh -G oracle cases:
	// 1. ProxyCommand=none over ProxyJump=bastion -> full Disabled (neither).
	if got := MergeProxySetting(cmdNone, bastion); !got.Equal(cmdNone) {
		t.Fatalf("ProxyCommand=none over ProxyJump = %q, want ProxyCommand=none", got)
	}
	// 2. ProxyJump=none over ProxyCommand=lower -> ProxyCommand=lower.
	if got := MergeProxySetting(jumpNone, lowerCmd); !got.Equal(lowerCmd) {
		t.Fatalf("ProxyJump=none over ProxyCommand = %q, want %q", got, lowerCmd)
	}
	// 3. MED-8: -o ProxyJump=none over (Host app: ProxyJump bastion + Host *: ProxyCommand lower)
	//    must expose ProxyCommand=lower under BOTH parenthesizations!
	tier4Combined := MergeProxySetting(bastion, lowerCmd)
	if tier4Combined.Kind() != ProxyJump {
		t.Fatalf("tier4Combined.Kind() = %v, want ProxyJump", tier4Combined.Kind())
	}
	rightAssoc := MergeProxySetting(jumpNone, tier4Combined)
	leftAssoc := MergeProxySetting(MergeProxySetting(jumpNone, bastion), lowerCmd)
	if !rightAssoc.Equal(lowerCmd) || !leftAssoc.Equal(lowerCmd) {
		t.Fatalf("MED-8 parenthesization mismatch: right=%q left=%q want=%q", rightAssoc, leftAssoc, lowerCmd)
	}
	// 4. -o ProxyJump=none over ProxyJump bastion + ProxyCommand none + ProxyCommand lower -> ProxyCommand=none.
	tier4DisabledCmd := MergeProxySettings(bastion, cmdNone, lowerCmd)
	if got := MergeProxySetting(jumpNone, tier4DisabledCmd); !got.Equal(cmdNone) {
		t.Fatalf("ProxyJump=none over (Jump + Cmd=none + Cmd=lower) = %q, want ProxyCommand=none", got)
	}
	// 5. Active ProxyJump over ProxyCommand -> ProxyJump; active ProxyCommand over ProxyJump -> ProxyCommand.
	if got := MergeProxySetting(lowerCmd, bastion); !got.Equal(lowerCmd) {
		t.Fatalf("ProxyCommand over ProxyJump = %q, want %q", got, lowerCmd)
	}
	if got := MergeProxySetting(bastion, lowerCmd); got.Kind() != ProxyJump {
		t.Fatalf("ProxyJump over ProxyCommand Kind = %v, want ProxyJump", got.Kind())
	}
}

func TestProxySetting_MonoidLawsFullCartesian(t *testing.T) {
	t.Parallel()

	unset := UnsetProxySetting()
	jumpNone := DisabledProxyJumpSetting()
	cmdNone := DisabledProxySetting()
	jumpA, err := NewProxyJump("bastion-a")
	if err != nil {
		t.Fatal(err)
	}
	jumpB, err := NewProxyJump("bastion-b", "bastion-c")
	if err != nil {
		t.Fatal(err)
	}
	cmdA, err := NewProxyCommand("nc %h %p")
	if err != nil {
		t.Fatal(err)
	}
	cmdB, err := NewProxyCommand("ssh -W %h:%p gateway")
	if err != nil {
		t.Fatal(err)
	}
	jumpAShadowCmd := MergeProxySetting(jumpA, cmdA)
	jumpBShadowNone := MergeProxySetting(jumpB, cmdNone)

	universe := []ProxySetting{
		unset,
		jumpNone,
		cmdNone,
		jumpA,
		jumpB,
		cmdA,
		cmdB,
		jumpAShadowCmd,
		jumpBShadowNone,
	}

	// Identity + absorption laws.
	for _, x := range universe {
		if !MergeProxySetting(unset, x).Equal(x) || !MergeProxySetting(x, unset).Equal(x) {
			t.Errorf("identity law failed for %q", x)
		}
		if !MergeProxySetting(cmdNone, x).Equal(cmdNone) {
			t.Errorf("ProxyCommand=none full absorption failed for %q", x)
		}
		if !MergeProxySetting(cmdA, x).Equal(cmdA) {
			t.Errorf("ProxyCommand absorption failed for %q", x)
		}
	}

	// Full Cartesian cube associativity (9^3 = 729 triples).
	for _, a := range universe {
		for _, b := range universe {
			for _, c := range universe {
				left := MergeProxySetting(MergeProxySetting(a, b), c)
				right := MergeProxySetting(a, MergeProxySetting(b, c))
				if !left.Equal(right) || !MergeProxySettings(a, b, c).Equal(left) {
					t.Errorf("associativity failed for (%q, %q, %q): left=%q right=%q", a, b, c, left, right)
				}
			}
		}
	}
}

func FuzzProxySettingRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"",
		"none",
		"ProxyJump=bastion",
		"ProxyJump=u@j1:22,j2",
		"ProxyJump=none",
		"ProxyCommand=nc %h %p",
		"ProxyCommand=ProxyJump=fake",
		"ProxyCommand=none",
		"ProxyJump=bastion\nProxyCommand=nc %h %p",
		"ProxyJump=bastion\nProxyCommand=none",
		"ProxyJump=none\nProxyJump=bastion\nProxyCommand=nc %h %p",
		"ProxyJump=",
		"Unknown=foo",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		ps, err := ParseProxySetting(raw)
		if err != nil {
			return
		}
		// Mutual exclusivity invariant on accessors.
		_, hasJump := ps.JumpTargets()
		_, hasCmd := ps.Command()
		if hasJump && hasCmd {
			t.Fatalf("ProxySetting %q violated Jump/Command mutual exclusivity", ps)
		}
		wire := ps.String()
		reparsed, err := ParseProxySetting(wire)
		if err != nil {
			t.Fatalf("re-parse of %q (from %q) failed: %v", wire, raw, err)
		}
		if !ps.Equal(reparsed) || reparsed.String() != wire {
			t.Fatalf("round-trip mismatch: first=%q second=%q", wire, reparsed.String())
		}
	})
}

func FuzzProxySettingMonoidLaws(f *testing.F) {
	f.Add(uint8(0), uint8(1), uint8(2))
	f.Add(uint8(1), uint8(6), uint8(4))
	f.Add(uint8(1), uint8(7), uint8(5))
	f.Add(uint8(2), uint8(5), uint8(1))

	items := []ProxySetting{
		UnsetProxySetting(),
		DisabledProxyJumpSetting(),
		DisabledProxySetting(),
	}
	for _, raw := range []string{
		"ProxyJump=j1",
		"ProxyJump=j1,j2",
		"ProxyCommand=nc %h %p",
		"ProxyCommand=socat - PROXY:%h:%p",
		"ProxyJump=j1\nProxyCommand=nc %h %p",
		"ProxyJump=j2\nProxyCommand=none",
	} {
		ps, err := ParseProxySetting(raw)
		if err != nil {
			f.Fatalf("seed %q: %v", raw, err)
		}
		items = append(items, ps)
	}

	f.Fuzz(func(t *testing.T, ia, ib, ic uint8) {
		a := items[int(ia)%len(items)]
		b := items[int(ib)%len(items)]
		c := items[int(ic)%len(items)]

		if !MergeProxySetting(UnsetProxySetting(), a).Equal(a) || !MergeProxySetting(a, UnsetProxySetting()).Equal(a) {
			t.Fatalf("identity failed for %q", a)
		}
		if !MergeProxySetting(DisabledProxySetting(), a).Equal(DisabledProxySetting()) {
			t.Fatalf("full DisabledProxySetting absorption failed for %q", a)
		}
		left := MergeProxySetting(MergeProxySetting(a, b), c)
		right := MergeProxySetting(a, MergeProxySetting(b, c))
		if !left.Equal(right) {
			t.Fatalf("associativity failed for (%q, %q, %q): left=%q right=%q", a, b, c, left, right)
		}
	})
}
