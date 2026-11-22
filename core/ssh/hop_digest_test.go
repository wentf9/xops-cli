package ssh

import (
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
)

func TestHopDigest_StructTagCompleteness(t *testing.T) {
	t.Parallel()

	// Every struct participating in ClientConfig / Options / ControlConfig must
	// annotate every field with digest:"include" or digest:"exclude,reason=...".
	for _, typ := range []reflect.Type{
		reflect.TypeFor[ClientConfig](),
		reflect.TypeFor[ConnectionConfig](),
		reflect.TypeFor[AdmittedCertificate](),
		reflect.TypeFor[AdmittedKeyDigest](),
		reflect.TypeFor[ExecutionConfig](),
		reflect.TypeFor[Options](),
		reflect.TypeFor[ControlConfig](),
	} {
		if err := ValidateDigestTags(typ); err != nil {
			t.Errorf("ValidateDigestTags(%s) failed: %v", typ.Name(), err)
		}
	}
}

func TestHopDigest_CompletenessRejectsUntaggedAndMalformedTags(t *testing.T) {
	t.Parallel()

	type untaggedExported struct {
		OK      string `digest:"include"`
		Missing string
	}
	type untaggedUnexported struct {
		OK      string `digest:"include"`
		missing string
	}
	type excludeNoReason struct {
		Secret string `digest:"exclude"`
	}
	type excludeBlankReason struct {
		Secret string `digest:"exclude,reason=   "`
	}
	type bogusDirective struct {
		Field string `digest:"skip"`
	}
	type nestedBadChild struct {
		Untagged int
	}
	type nestedParent struct {
		Child *nestedBadChild `digest:"include"`
	}

	for _, tc := range []struct {
		name string
		typ  reflect.Type
	}{
		{"nil_type", nil},
		{"untagged_exported", reflect.TypeFor[untaggedExported]()},
		{"untagged_unexported", reflect.TypeFor[untaggedUnexported]()},
		{"exclude_no_reason", reflect.TypeFor[excludeNoReason]()},
		{"exclude_blank_reason", reflect.TypeFor[excludeBlankReason]()},
		{"bogus_directive", reflect.TypeFor[bogusDirective]()},
		{"nested_untagged_child", reflect.TypeFor[nestedParent]()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateDigestTags(tc.typ); !errors.Is(err, ErrDigestTagIncomplete) {
				t.Errorf("ValidateDigestTags(%s) = %v, want ErrDigestTagIncomplete", tc.name, err)
			}
		})
	}

	// Verify digestStructValue itself fails closed on untagged exported and unexported fields.
	if err := digestStructValue(sha256.New(), reflect.ValueOf(untaggedExported{OK: "a", Missing: "b"})); !errors.Is(err, ErrDigestTagIncomplete) {
		t.Fatalf("digestStructValue(untaggedExported) = %v, want ErrDigestTagIncomplete", err)
	}
	if err := digestStructValue(sha256.New(), reflect.ValueOf(untaggedUnexported{OK: "a", missing: "b"})); !errors.Is(err, ErrDigestTagIncomplete) {
		t.Fatalf("digestStructValue(untaggedUnexported) = %v, want ErrDigestTagIncomplete", err)
	}
}

func TestHopDigest_MerkleChainAndNormalization(t *testing.T) {
	t.Parallel()

	hop1A := &ClientConfig{NodeID: "bastion", Address: "10.0.0.1", Port: 22, User: "ops"}
	hop1B := &ClientConfig{NodeID: "bastion", Address: "10.0.0.1", Port: 2222, User: "ops"}
	hop2 := &ClientConfig{NodeID: "target", Address: "10.0.0.2", Port: 22, User: "app", ProxyJump: "bastion"}

	d1A := DigestClientConfig(hop1A, ZeroHopDigest)
	d1B := DigestClientConfig(hop1B, ZeroHopDigest)
	if d1A.IsZero() || d1A.Equal(d1B) {
		t.Fatalf("expected distinct non-zero root digests: d1A=%s d1B=%s", d1A, d1B)
	}

	// Identical downstream hop2 chained over different upstream hop1 configs must differ (H5).
	d2OverA := DigestClientConfig(hop2, d1A)
	d2OverB := DigestClientConfig(hop2, d1B)
	if d2OverA.Equal(d2OverB) {
		t.Fatal("Merkle HopDigest must change when upstream hop changes")
	}

	// Nil cfg still binds parent digest.
	if DigestClientConfig(nil, d1A).Equal(DigestClientConfig(nil, d1B)) {
		t.Fatal("nil ClientConfig digest must still include parent HopDigest")
	}

	// Canonical equivalences: port 0 == 22, case-folded host, bracketed IPv6, nil vs empty Options,
	// and nil vs zero/disabled ControlConfig.
	eqA := &ClientConfig{
		NodeID:   "n1",
		Address:  "Web.Example.COM",
		BaseHost: "[2001:0DB8::1]",
		Port:     0,
		AuthType: " KEY ",
		Options:  nil,
		Control:  nil,
	}
	eqB := &ClientConfig{
		NodeID:   "n1",
		Address:  "web.example.com",
		BaseHost: "2001:db8::1",
		Port:     22,
		AuthType: "key",
		Options:  &Options{},
		Control:  &ControlConfig{},
	}
	eqC := &ClientConfig{
		NodeID:   "n1",
		Address:  "web.example.com",
		BaseHost: "2001:db8::1",
		Port:     22,
		AuthType: "key",
		Control:  &ControlConfig{Master: ControlMasterNo, Path: "NONE", Persist: "no", ImplicitTier4: true},
	}
	if !DigestClientConfig(eqA, ZeroHopDigest).Equal(DigestClientConfig(eqB, ZeroHopDigest)) {
		t.Fatal("canonically equivalent ClientConfigs produced different HopDigests")
	}
	if !DigestClientConfig(eqA, ZeroHopDigest).Equal(DigestClientConfig(eqC, ZeroHopDigest)) {
		t.Fatal("disabled ControlConfig must hash identically to nil ControlConfig")
	}
}

func TestHopDigest_IncludeSensitivityAndExcludeInvariance(t *testing.T) {
	t.Parallel()

	loginTrue := true
	base := func() *ClientConfig {
		return &ClientConfig{
			KeyRef:                      "ref-1",
			TrustVersion:                "tv-1",
			NodeID:                      "node-1",
			OriginalHost:                "alias-1",
			CanonicalHost:               "node-1.internal",
			Address:                     "10.0.0.1",
			BaseHost:                    "10.0.0.1",
			Port:                        22,
			User:                        "alice",
			AuthType:                    "key",
			Password:                    "secret-1",
			KeyPath:                     "~/.ssh/id_ed25519",
			KeyPaths:                    []string{"~/.ssh/id_a"},
			Passphrase:                  "pass-1",
			AuthUpdateToken:             "auth-tok-1",
			SudoMode:                    SudoModeSudo,
			SuPwd:                       "su-1",
			SudoUpdateToken:             "sudo-tok-1",
			ProxyJump:                   "bastion-1",
			OriginalProxyJump:           "orig-bastion-1",
			HasOriginalProxyJump:        true,
			PasswordPromptPattern:       "password:",
			EnforceAdmittedCertificates: true,
			AdmittedCertificates:        []AdmittedCertificate{{Path: "/c", SHA256: "abc", RawBytes: []byte("cert-v1")}},
			EnforceAdmittedKeyDigests:   true,
			AdmittedKeyDigests:          []AdmittedKeyDigest{{Path: "/k", SHA256: "def"}},
			Execution:                   &ExecutionConfig{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX, Login: &loginTrue},
			Options:                     MustOptions(OptionControlMaster, "auto", OptionControlPath, "~/.ssh/cm-%C", OptionControlPersist, "10m"),
			Control: &ControlConfig{
				Master:        ControlMasterAuto,
				Path:          "~/.ssh/cm-%C",
				LiteralPath:   false,
				Persist:       "10m",
				ImplicitTier4: false,
				AllowReuse:    false,
			},
		}
	}

	baseDigest := DigestClientConfig(base(), ZeroHopDigest)

	// Mutating excluded secret fields must NOT change the digest.
	excl := base()
	excl.Password = "different-password"
	excl.Passphrase = "different-passphrase"
	excl.SuPwd = "different-su-pwd"
	excl.AdmittedCertificates[0].RawBytes = []byte("different-raw-cert-bytes")
	if !DigestClientConfig(excl, ZeroHopDigest).Equal(baseDigest) {
		t.Fatal("mutating digest:\"exclude\" fields must not change HopDigest")
	}

	// Mutating EVERY included field of ClientConfig must change the digest.
	loginFalse := false
	mutations := []struct {
		name   string
		mutate func(*ClientConfig)
	}{
		{"KeyRef", func(c *ClientConfig) { c.KeyRef = "ref-2" }},
		{"TrustVersion", func(c *ClientConfig) { c.TrustVersion = "tv-2" }},
		{"NodeID", func(c *ClientConfig) { c.NodeID = "node-2" }},
		{"OriginalHost", func(c *ClientConfig) { c.OriginalHost = "alias-2" }},
		{"CanonicalHost", func(c *ClientConfig) { c.CanonicalHost = "node-2.internal" }},
		{"Address", func(c *ClientConfig) { c.Address = "10.0.0.2" }},
		{"BaseHost", func(c *ClientConfig) { c.BaseHost = "10.0.0.2" }},
		{"Port", func(c *ClientConfig) { c.Port = 2222 }},
		{"User", func(c *ClientConfig) { c.User = "bob" }},
		{"AuthType", func(c *ClientConfig) { c.AuthType = "password" }},
		{"KeyPath", func(c *ClientConfig) { c.KeyPath = "~/.ssh/id_rsa" }},
		{"KeyPaths", func(c *ClientConfig) { c.KeyPaths = []string{"~/.ssh/id_b"} }},
		{"AuthUpdateToken", func(c *ClientConfig) { c.AuthUpdateToken = "auth-tok-2" }},
		{"SudoMode", func(c *ClientConfig) { c.SudoMode = SudoModeRoot }},
		{"SudoUpdateToken", func(c *ClientConfig) { c.SudoUpdateToken = "sudo-tok-2" }},
		{"ProxyJump", func(c *ClientConfig) { c.ProxyJump = "bastion-2" }},
		{"OriginalProxyJump", func(c *ClientConfig) { c.OriginalProxyJump = "bastion-2" }},
		{"HasOriginalProxyJump", func(c *ClientConfig) { c.HasOriginalProxyJump = false }},
		{"PasswordPromptPattern", func(c *ClientConfig) { c.PasswordPromptPattern = "pass:" }},
		{"EnforceAdmittedCertificates", func(c *ClientConfig) { c.EnforceAdmittedCertificates = false }},
		{"AdmittedCertificates", func(c *ClientConfig) { c.AdmittedCertificates[0].SHA256 = "xyz" }},
		{"EnforceAdmittedKeyDigests", func(c *ClientConfig) { c.EnforceAdmittedKeyDigests = false }},
		{"AdmittedKeyDigests", func(c *ClientConfig) { c.AdmittedKeyDigests[0].SHA256 = "uvw" }},
		{"Execution.Interpreter", func(c *ClientConfig) { c.Execution.Interpreter = InterpreterSh }},
		{"Execution.LaunchDialect", func(c *ClientConfig) { c.Execution.LaunchDialect = LaunchFish }},
		{"Execution.Login", func(c *ClientConfig) { c.Execution.Login = &loginFalse }},
		{"Options.ControlMaster", func(c *ClientConfig) { _ = c.Options.Set(OptionControlMaster, "yes") }},
		{"Options.ControlPath", func(c *ClientConfig) { _ = c.Options.Set(OptionControlPath, "/tmp/alt-%C") }},
		{"Options.ControlPersist", func(c *ClientConfig) { _ = c.Options.Set(OptionControlPersist, "20m") }},
		{"Options.ImplicitTier4", func(c *ClientConfig) { c.Options.ImplicitTier4 = true }},
		{"Options.LiteralControlPath", func(c *ClientConfig) { c.Options.LiteralControlPath = true }},
		{"Control.Master", func(c *ClientConfig) { c.Control.Master = ControlMasterYes }},
		{"Control.Path", func(c *ClientConfig) { c.Control.Path = "/tmp/other-%C" }},
		{"Control.LiteralPath", func(c *ClientConfig) { c.Control.LiteralPath = true }},
		{"Control.Persist", func(c *ClientConfig) { c.Control.Persist = "30m" }},
		{"Control.ImplicitTier4", func(c *ClientConfig) { c.Control.ImplicitTier4 = true }},
		{"Control.AllowReuse", func(c *ClientConfig) { c.Control.AllowReuse = true }},
		{"Control.Disabled", func(c *ClientConfig) { c.Control = nil }},
	}

	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			cand := base()
			tc.mutate(cand)
			if DigestClientConfig(cand, ZeroHopDigest).Equal(baseDigest) {
				t.Fatalf("mutating %s did not change HopDigest", tc.name)
			}
		})
	}
}

func TestHopDigest_CoversEveryRegisteredOptionSpec(t *testing.T) {
	t.Parallel()

	samples := expectedRegisteredOptionSamples()
	baseCfg := &ClientConfig{NodeID: "n1", Address: "10.0.0.1", Port: 22, User: "ops"}
	baseDigest := DigestClientConfig(baseCfg, ZeroHopDigest)

	for _, spec := range RegisteredOptionSpecs() {
		sample, ok := samples[spec.CanonicalKey]
		if !ok {
			t.Fatalf("missing sample for registered option %q", spec.CanonicalKey)
		}
		cfg := *baseCfg
		cfg.Options = MustOptions(spec.CanonicalKey, sample)
		if DigestClientConfig(&cfg, ZeroHopDigest).Equal(baseDigest) {
			t.Errorf("adding registered option %q (%s) did not change HopDigest", spec.CanonicalKey, spec.Class)
		}
	}
}

func FuzzHopDigestRoundTrip(f *testing.F) {
	f.Add(ZeroHopDigest.String())
	f.Add(DigestClientConfig(&ClientConfig{NodeID: "n1", Address: "10.0.0.1"}, ZeroHopDigest).String())
	f.Add("")
	f.Add("deadbeef")
	f.Add("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")

	f.Fuzz(func(t *testing.T, raw string) {
		d, err := ParseHopDigest(raw)
		if err != nil {
			if !d.IsZero() {
				t.Fatalf("ParseHopDigest(%q) returned non-zero digest on error", raw)
			}
			return
		}
		reparsed, err := ParseHopDigest(d.String())
		if err != nil || !d.Equal(reparsed) || reparsed.String() != d.String() {
			t.Fatalf("HopDigest round-trip failed for %q -> %q", raw, d.String())
		}
	})
}
