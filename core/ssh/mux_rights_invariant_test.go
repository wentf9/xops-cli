package ssh

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestWindowsMuxRights_StructuralSecurityInvariants parses mux_rights_windows.go
// on every OS (including Linux CI and isolated core extraction) to guarantee the
// Windows control socket security primitives cannot regress back to no-op stubs.
func TestWindowsMuxRights_StructuralSecurityInvariants(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "mux_rights_windows.go", nil, 0)
	if err != nil {
		t.Fatalf("parse mux_rights_windows.go failed: %v", err)
	}

	funcs := make(map[string]*ast.FuncDecl)
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
			funcs[fn.Name.Name] = fn
		}
	}

	assertCalls := func(fnName string, required ...string) {
		t.Helper()
		fn := funcs[fnName]
		if fn == nil || fn.Body == nil {
			t.Fatalf("missing function %s in mux_rights_windows.go", fnName)
		}
		seen := make(map[string]bool)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				seen[fun.Name] = true
			case *ast.SelectorExpr:
				if pkg, ok := fun.X.(*ast.Ident); ok {
					seen[pkg.Name+"."+fun.Sel.Name] = true
				}
			}
			return true
		})
		for _, req := range required {
			if !seen[req] {
				t.Errorf("%s in mux_rights_windows.go must call %s (seen calls: %v)", fnName, req, seen)
			}
		}
	}

	assertCalls("bindAndLinkSocket",
		"validateWindowsSocketPath",
		"MaxControlPathLength",
		"fsx.ReplaceStaleSocketSlot",
		"fsx.ProbeStaleUnixSocket",
	)
	assertCalls("checkPeerUID",
		"winsec.VerifyAFUnixPeerCurrentUser",
	)
	assertFSXWindowsSocketSecurityCalls(t, fset)

	// Verify checkPeerUID references ErrUnsupportedMuxPlatform when SIO_AF_UNIX_GETPEERPID is unsupported.
	foundUnsupportedSentinel := false
	ast.Inspect(funcs["checkPeerUID"].Body, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && ident.Name == "ErrUnsupportedMuxPlatform" {
			foundUnsupportedSentinel = true
		}
		return true
	})
	if !foundUnsupportedSentinel {
		t.Error("checkPeerUID in mux_rights_windows.go must wrap ErrUnsupportedMuxPlatform on unsupported IOCTL")
	}
}

func assertFSXWindowsSocketSecurityCalls(t *testing.T, fset *token.FileSet) {
	t.Helper()
	fsxFile, fsxErr := parser.ParseFile(fset, "../fsx/fsx_windows.go", nil, 0)
	if fsxErr != nil {
		t.Fatalf("parse ../fsx/fsx_windows.go failed: %v", fsxErr)
	}
	fsxCalls := make(map[string]bool)
	ast.Inspect(fsxFile, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			fsxCalls[fun.Name] = true
		case *ast.SelectorExpr:
			if pkg, ok := fun.X.(*ast.Ident); ok {
				fsxCalls[pkg.Name+"."+fun.Sel.Name] = true
			}
		}
		return true
	})
	for _, req := range []string{
		"winsec.EnsureOwnerOnlyDirectory",
		"winsec.HardenSocketOwnerOnlyByHandle",
		"winsec.VerifyOwnerOnlySocketByHandle",
		"withDirLockOS",
		"acquireWindowsDirLockFile",
		"verifyLockedFileIdentity",
	} {
		if !fsxCalls[req] {
			t.Errorf("core/fsx/fsx_windows.go must call %s (seen calls: %v)", req, fsxCalls)
		}
	}
}

// TestOptionSpecScope_RegistryInvariants enforces the S3 OptionScope boundary:
// all Trust options propagate connection-wide; all Mux/Session/Forward/LocalExec
// options stay TargetOnly so target-specific settings cannot leak across ProxyJump.
func TestOptionSpecScope_RegistryInvariants(t *testing.T) {
	for _, spec := range RegisteredOptionSpecs() {
		switch spec.Class {
		case OptionClassTrust:
			if !spec.IsConnectionWide() {
				t.Errorf("trust option %s must have OptionScopeConnectionWide", spec.CanonicalKey)
			}
		case OptionClassMux, OptionClassForward, OptionClassSession, OptionClassLocalExec:
			if spec.IsConnectionWide() {
				t.Errorf("%s option %s must stay OptionScopeTargetOnly", spec.Class, spec.CanonicalKey)
			}
		}
	}
}

// TestControlTypedSettingsAndSingleProjection verifies that ControlPathSetting,
// PersistSetting, ExpandControlPath, Options.ControlConfig(), and
// Options.ValidatedControlConfig() obey identical domain semantics with zero drift.
func TestControlTypedSettingsAndSingleProjection(t *testing.T) {
	t.Run("expand_control_path_normalizes_none", func(t *testing.T) {
		env := Environment{
			LookupEnv: func(key string) (string, bool) {
				if key == "MUX_NONE" {
					return "  NoNe  ", true
				}
				return "", false
			},
		}
		for _, raw := range []string{"none", "NONE", " None ", "${MUX_NONE}"} {
			got, err := ExpandControlPath(raw, env, TargetContext{Host: "example.com"})
			if err != nil || got != "none" {
				t.Fatalf("ExpandControlPath(%q) = (%q, %v), want (\"none\", nil)", raw, got, err)
			}
		}
	})

	t.Run("control_config_and_validated_control_config_zero_drift", func(t *testing.T) {
		// Cross-layer ControlPath=NONE cleanly disables lower-tier active mux with zero projection drift.
		mergedDisabled, err := MergeEffectiveOptions(
			OptionsFromControl(&ControlConfig{Path: "NONE"}),
			OptionsFromControl(&ControlConfig{Master: ControlMasterYes, Path: "/tmp/cm-%C", Persist: "10m"}),
		)
		if err != nil {
			t.Fatalf("MergeEffectiveOptions(cross-layer NONE) failed: %v", err)
		}
		projA := mergedDisabled.ControlConfig()
		projB, err := mergedDisabled.ValidatedControlConfig()
		if err != nil {
			t.Fatalf("ValidatedControlConfig(cross-layer NONE) failed: %v", err)
		}
		wantDisabled := &ControlConfig{Master: ControlMasterNo, Path: "none", Persist: ""}
		if !projA.Equal(wantDisabled) || !projB.Equal(wantDisabled) {
			t.Fatalf("projection drift between ControlConfig (%+v) and ValidatedControlConfig (%+v)", projA, projB)
		}

		// Same-layer contradictory ControlPath=NONE + ControlMaster=yes/ControlPersist=10m
		// must fail closed in ValidatedControlConfig while lenient ControlConfig stays disabled.
		contradictory := OptionsFromControl(&ControlConfig{
			Master:  ControlMasterYes,
			Path:    "NONE",
			Persist: "10m",
		})
		if got := contradictory.ControlConfig(); !got.Equal(wantDisabled) {
			t.Fatalf("lenient ControlConfig(contradictory NONE) = %+v, want %+v", got, wantDisabled)
		}
		if ctrl, valErr := contradictory.ValidatedControlConfig(); !errors.Is(valErr, ErrSSHOptionsValidation) || ctrl != nil {
			t.Fatalf("ValidatedControlConfig(same-layer contradictory NONE) = (%+v, %v), want (nil, ErrSSHOptionsValidation)", ctrl, valErr)
		}
	})

	t.Run("persist_setting_states", func(t *testing.T) {
		cases := []struct {
			raw            string
			wantKind       PersistKind
			wantExplicit   bool
			wantEnabled    bool
			wantIndefinite bool
		}{
			{"", PersistUnset, false, false, false},
			{"no", PersistNo, true, false, false},
			{"NO", PersistNo, true, false, false},
			{"false", PersistNo, true, false, false},
			{"False", PersistNo, true, false, false},
			{"yes", PersistIndefinite, true, true, true},
			{"true", PersistIndefinite, true, true, true},
			{"0", PersistIndefinite, true, true, true},
			{"5m", PersistDuration, true, true, false},
		}
		for _, tc := range cases {
			got, err := ParsePersistSetting(tc.raw)
			if err != nil {
				t.Fatalf("ParsePersistSetting(%q) failed: %v", tc.raw, err)
			}
			if got.Kind != tc.wantKind || got.Explicit() != tc.wantExplicit ||
				got.Enabled() != tc.wantEnabled || got.Indefinite() != tc.wantIndefinite {
				t.Fatalf("ParsePersistSetting(%q) = %+v, want kind=%v explicit=%v enabled=%v indef=%v",
					tc.raw, got, tc.wantKind, tc.wantExplicit, tc.wantEnabled, tc.wantIndefinite)
			}
		}
	})
}
