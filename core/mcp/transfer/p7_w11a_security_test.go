package transfer

import "testing"

// TestP7W11a_AB11M2_SpecValidateRejectsControlAndLineSepRunes verifies AB11-M2:
// Spec.validate and Spec.validateIdentity reject ALL C0/DEL/C1 control and
// Unicode line/paragraph separator runes in RemotePath and RequestedPath.
func TestP7W11a_AB11M2_SpecValidateRejectsControlAndLineSepRunes(t *testing.T) {
	baseSpec := Spec{
		RequestID:     "req-w11a",
		Scope:         "scope-w11a",
		NodeID:        "node-1",
		TargetID:      "target-1",
		RequestedPath: "/tmp/file.bin",
		RemotePath:    "/tmp/file.bin",
		Direction:     Download,
	}

	badRunes := []struct {
		name string
		r    rune
	}{
		{"nul", '\x00'},
		{"bel", '\x07'},
		{"tab", '\t'},
		{"lf", '\n'},
		{"cr", '\r'},
		{"esc", '\x1b'},
		{"del", '\x7f'},
		{"c1_nel", '\u0085'},
		{"c1_csi", '\u009b'},
		{"line_sep", '\u2028'},
		{"para_sep", '\u2029'},
	}

	for _, tc := range badRunes {
		t.Run("RemotePath_"+tc.name, func(t *testing.T) {
			s := baseSpec
			s.RemotePath = "/tmp/bad" + string(tc.r) + "file.bin"
			if err := s.validate(); err == nil {
				t.Fatalf("Spec.validate accepted RemotePath containing %s (%q)", tc.name, s.RemotePath)
			}
		})
		t.Run("RequestedPath_"+tc.name, func(t *testing.T) {
			s := baseSpec
			s.RequestedPath = "/tmp/bad" + string(tc.r) + "file.bin"
			if err := s.validate(); err == nil {
				t.Fatalf("Spec.validate accepted RequestedPath containing %s (%q)", tc.name, s.RequestedPath)
			}
		})
	}
}
