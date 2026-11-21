package clicontract

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	corepolicy "github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/verdict"
	"gopkg.in/yaml.v3"
)

// TestP7_SecurityTypesZeroValueTable verifies Pillar G's zero-value invariant:
// reflect.Zero(T) for every security-critical configuration, decision, limit,
// and typed value must represent the most restrictive, disabled, or invalid
// fail-closed state.
func TestP7_SecurityTypesZeroValueTable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		typ   reflect.Type
		check func(t *testing.T, zeroVal reflect.Value)
	}{
		{"ssh.MuxServerOptions", reflect.TypeFor[ssh.MuxServerOptions](), assertZeroMuxServerOptions},
		{"policy.Config_YAMLDefaultsEnabled", reflect.TypeFor[corepolicy.Config](), assertZeroPolicyConfig},
		{"guardrail.Decision", reflect.TypeFor[guardrail.Decision](), assertZeroGuardrailDecision},
		{"guardrail.Policy", reflect.TypeFor[guardrail.Policy](), assertZeroGuardrailPolicy},
		{"guardrail.RiskInput", reflect.TypeFor[guardrail.RiskInput](), assertZeroGuardrailRiskInput},
		{"fsx.Limits", reflect.TypeFor[fsx.Limits](), assertZeroFSXLimits},
		{"fsx.LockMode", reflect.TypeFor[fsx.LockMode](), assertZeroFSXLockMode},
		{"verdict.Verdict", reflect.TypeFor[verdict.Verdict](), assertZeroVerdict},
		{"ssh.PathList", reflect.TypeFor[ssh.PathList](), assertZeroPathList},
		{"ssh.AlgoPolicy", reflect.TypeFor[ssh.AlgoPolicy](), assertZeroAlgoPolicy},
		{"ssh.ControlSetting", reflect.TypeFor[ssh.ControlSetting](), assertZeroControlSetting},
		{"ssh.ProxySetting", reflect.TypeFor[ssh.ProxySetting](), assertZeroProxySetting},
		{"ssh.Endpoint", reflect.TypeFor[ssh.Endpoint](), assertZeroEndpoint},
		{"sftp.TypedPaths", reflect.TypeFor[sftp.RemotePath](), assertZeroSFTPPaths},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, reflect.Zero(tc.typ))
		})
	}
}

func assertZeroMuxServerOptions(t *testing.T, rv reflect.Value) {
	t.Helper()
	opts := rv.Interface().(ssh.MuxServerOptions)
	if opts.PeerCheck != ssh.PeerCheckEnforce {
		t.Fatalf("PeerCheck = %v, want PeerCheckEnforce (0)", opts.PeerCheck)
	}
	if ssh.PeerCheckDisabledForTesting == 0 {
		t.Fatal("PeerCheckDisabledForTesting must be non-zero")
	}
	permissive := opts.HasExpectedUID || opts.PersistEnabled || opts.PersistIndefinite ||
		opts.AskConfirmation || opts.GatewayPorts || opts.StreamLocalBindUnlink ||
		opts.HasStreamLocalBindMask || opts.AllowAgentForward
	if permissive {
		t.Fatalf("zero MuxServerOptions enabled permissive flag: %+v", opts)
	}
	if opts.ConfirmSession != nil || opts.DialAgent != nil {
		t.Fatal("zero MuxServerOptions callbacks must be nil (fail-closed)")
	}
}

func assertZeroPolicyConfig(t *testing.T, rv reflect.Value) {
	t.Helper()
	zero := rv.Interface().(corepolicy.Config)
	if zero.AuditLog != "" || zero.ApprovalThreshold != "" || zero.NoElicitFallback != "" {
		t.Fatalf("zero policy.Config has non-empty string fields: %+v", zero)
	}
	if len(zero.BlockedPatterns) != 0 || len(zero.ProtectedPaths) != 0 || len(zero.NodeOverrides) != 0 {
		t.Fatalf("zero policy.Config has populated collections: %+v", zero)
	}
	for _, tc := range []struct {
		doc  string
		want bool
	}{
		{"{}\n", true},
		{"approval_threshold: dangerous\nno_elicit_fallback: deny\n", true},
		{"enabled: true\n", true},
		{"enabled: false\n", false},
	} {
		var cfg corepolicy.Config
		if err := yaml.Unmarshal([]byte(tc.doc), &cfg); err != nil {
			t.Fatalf("yaml.Unmarshal(%q): %v", tc.doc, err)
		}
		if cfg.Enabled != tc.want {
			t.Fatalf("yaml.Unmarshal(%q): Enabled = %v, want %v", tc.doc, cfg.Enabled, tc.want)
		}
	}
}

func assertZeroGuardrailDecision(t *testing.T, rv reflect.Value) {
	t.Helper()
	d := rv.Interface().(guardrail.Decision)
	if d != guardrail.Deny || d.String() != "deny" {
		t.Fatalf("zero guardrail.Decision = %v (%q), want Deny (\"deny\")", d, d.String())
	}
}

func assertZeroGuardrailPolicy(t *testing.T, rv reflect.Value) {
	t.Helper()
	p := rv.Interface().(guardrail.Policy)
	if got := p.Evaluate(guardrail.Safe, guardrail.RiskInput{ToolName: "nodes"}); got != guardrail.Deny {
		t.Fatalf("zero guardrail.Policy.Evaluate() = %v, want Deny", got)
	}
}

func assertZeroGuardrailRiskInput(t *testing.T, rv reflect.Value) {
	t.Helper()
	in := rv.Interface().(guardrail.RiskInput)
	if got := guardrail.Classify(in); got != guardrail.Dangerous {
		t.Fatalf("guardrail.Classify(zero RiskInput) = %v, want Dangerous", got)
	}
}

func assertZeroFSXLimits(t *testing.T, rv reflect.Value) {
	t.Helper()
	lim := rv.Interface().(fsx.Limits)
	if lim.MaxBytes != 0 {
		t.Fatalf("zero fsx.Limits.MaxBytes = %d, want 0", lim.MaxBytes)
	}
	probe := filepath.Join(t.TempDir(), "probe.txt")
	if _, err := fsx.OpenRegular(probe, lim); !errors.Is(err, fsx.ErrInvalidLimit) {
		t.Fatalf("fsx.OpenRegular(zero Limits) err = %v, want ErrInvalidLimit", err)
	}
	if _, err := fsx.ReadAllBounded(probe, lim); !errors.Is(err, fsx.ErrInvalidLimit) {
		t.Fatalf("fsx.ReadAllBounded(zero Limits) err = %v, want ErrInvalidLimit", err)
	}
}

func assertZeroFSXLockMode(t *testing.T, rv reflect.Value) {
	t.Helper()
	mode := rv.Interface().(fsx.LockMode)
	if mode == fsx.LockShared || mode == fsx.LockExclusive {
		t.Fatalf("zero fsx.LockMode = %v, must not be LockShared or LockExclusive", mode)
	}
	if mode.String() != "invalid" {
		t.Fatalf("zero fsx.LockMode.String() = %q, want \"invalid\"", mode.String())
	}
	probe := filepath.Join(t.TempDir(), "lock.txt")
	if _, err := fsx.OpenLocked(probe, mode, false, 0o600); !errors.Is(err, fsx.ErrInvalidLockMode) {
		t.Fatalf("fsx.OpenLocked(zero LockMode) err = %v, want ErrInvalidLockMode", err)
	}
}

func assertZeroVerdict(t *testing.T, rv reflect.Value) {
	t.Helper()
	v := rv.Interface().(verdict.Verdict)
	if v != verdict.Deny || v.Allowed() || !v.Denied() || v.String() != "deny" {
		t.Fatalf("zero verdict.Verdict = %v (%q), want Deny", v, v.String())
	}
	if v.And(verdict.Allow) != verdict.Deny {
		t.Fatal("zero Verdict.And(Allow) must be Deny")
	}
	if got := verdict.Decide(func() (verdict.Verdict, error) { return v, nil }); got != verdict.Deny {
		t.Fatalf("verdict.Decide(zero) = %v, want Deny", got)
	}
	if got := verdict.Decide(func() (verdict.Verdict, error) { return verdict.Allow, errors.New("boom") }); got != verdict.Deny {
		t.Fatalf("verdict.Decide(Allow, err) = %v, want Deny", got)
	}
}

func assertZeroPathList(t *testing.T, rv reflect.Value) {
	t.Helper()
	pl := rv.Interface().(ssh.PathList)
	if pl.State() != ssh.PathListUnset || !pl.IsUnset() || pl.IsSet() || pl.IsDisabled() || pl.Terminated() {
		t.Fatalf("zero ssh.PathList state = %v, want PathListUnset", pl.State())
	}
	if len(pl.Items()) != 0 || len(pl.RawItems()) != 0 {
		t.Fatalf("zero ssh.PathList has non-empty items: %v", pl.RawItems())
	}
	disabled := ssh.DisabledPathList()
	if !pl.Merge(disabled).Equal(disabled) || !disabled.Merge(pl).Equal(disabled) {
		t.Fatal("zero ssh.PathList must act as identity under Merge")
	}
}

func assertZeroAlgoPolicy(t *testing.T, rv reflect.Value) {
	t.Helper()
	ap := rv.Interface().(ssh.AlgoPolicy)
	if ap.Op() != ssh.AlgoOpUnset || !ap.IsUnset() || ap.OptionKey() != "" || len(ap.Tokens()) != 0 {
		t.Fatalf("zero ssh.AlgoPolicy = (%v, %q, %v), want unset empty", ap.Op(), ap.OptionKey(), ap.Tokens())
	}
}

func assertZeroControlSetting(t *testing.T, rv reflect.Value) {
	t.Helper()
	cs := rv.Interface().(ssh.ControlSetting)
	if !cs.IsUnset() || cs.IsEnabled() || cs.IsDisabled() {
		t.Fatalf("zero ssh.ControlSetting = %q (unset=%v enabled=%v disabled=%v), want unset/not-enabled",
			cs.String(), cs.IsUnset(), cs.IsEnabled(), cs.IsDisabled())
	}
	if cs.EffectiveMaster() != ssh.ControlMasterNo {
		t.Fatalf("zero ssh.ControlSetting.EffectiveMaster() = %q, want %q", cs.EffectiveMaster(), ssh.ControlMasterNo)
	}
	if cs.ToControlConfig() != nil {
		t.Fatalf("zero ssh.ControlSetting.ToControlConfig() = %+v, want nil", cs.ToControlConfig())
	}
}

func assertZeroProxySetting(t *testing.T, rv reflect.Value) {
	t.Helper()
	ps := rv.Interface().(ssh.ProxySetting)
	if ps.Kind() != ssh.ProxyUnset || !ps.IsUnset() || ps.IsActive() || ps.IsDisabled() {
		t.Fatalf("zero ssh.ProxySetting kind = %v (active=%v), want ProxyUnset/inactive", ps.Kind(), ps.IsActive())
	}
	if hops, ok := ps.JumpTargets(); ok || len(hops) != 0 {
		t.Fatalf("zero ssh.ProxySetting.JumpTargets() = (%v, %v), want (nil, false)", hops, ok)
	}
	if cmd, ok := ps.Command(); ok || cmd != "" {
		t.Fatalf("zero ssh.ProxySetting.Command() = (%q, %v), want (\"\", false)", cmd, ok)
	}
}

func assertZeroEndpoint(t *testing.T, rv reflect.Value) {
	t.Helper()
	ep := rv.Interface().(ssh.Endpoint)
	if ep.IsValid() || ep.IsIP() || ep.Host() != "" || ep.Port() != 0 || ep.String() != "" {
		t.Fatalf("zero ssh.Endpoint must be invalid, got valid=%v host=%q port=%d", ep.IsValid(), ep.Host(), ep.Port())
	}
	if ep.Equal(ep) {
		t.Fatal("zero ssh.Endpoint.Equal(zero) must be false (fail-closed)")
	}
	if _, err := ep.WithPort(22); !errors.Is(err, ssh.ErrInvalidEndpoint) {
		t.Fatalf("zero ssh.Endpoint.WithPort(22) err = %v, want ErrInvalidEndpoint", err)
	}
}

func assertZeroSFTPPaths(t *testing.T, rv reflect.Value) {
	t.Helper()
	rp := rv.Interface().(sftp.RemotePath)
	rn := reflect.Zero(reflect.TypeFor[sftp.RemoteName]()).Interface().(sftp.RemoteName)
	lt := reflect.Zero(reflect.TypeFor[sftp.LocalTarget]()).Interface().(sftp.LocalTarget)
	ld := reflect.Zero(reflect.TypeFor[sftp.LocalDest]()).Interface().(sftp.LocalDest)
	if rp.IsValid() || rn.IsValid() || lt.IsValid() || ld.IsValid() {
		t.Fatalf("zero sftp path types must be invalid: rp=%v rn=%v lt=%v ld=%v",
			rp.IsValid(), rn.IsValid(), lt.IsValid(), ld.IsValid())
	}
	if _, err := sftp.ResolveLocalTarget(t.TempDir(), rn); !errors.Is(err, sftp.ErrInvalidLocalTarget) {
		t.Fatalf("ResolveLocalTarget(zero RemoteName) err = %v, want ErrInvalidLocalTarget", err)
	}
}
