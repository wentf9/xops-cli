package guardrail

import "testing"

func TestTunnelRiskClassification(t *testing.T) {
	for _, tc := range []struct {
		action, mode, host string
		want               RiskLevel
	}{
		{"create", "local", "127.0.0.1", Moderate},
		{"create", "local", "127.2.3.4", Moderate},
		{"create", "local", "::1", Moderate},
		{"create", "local", "::ffff:127.0.0.1", Moderate},
		{"create", "local", "0.0.0.0", Dangerous},
		{"create", "local", "::", Dangerous},
		{"create", "local", "localhost", Dangerous},
		{"create", "remote", "127.0.0.1", Dangerous},
		{"create", "dynamic", "127.0.0.1", Dangerous},
		{"stop", "", "", Moderate},
		{"list", "", "", Safe},
		{"status", "", "", Safe},
	} {
		t.Run(tc.action+"/"+tc.mode+"/"+tc.host, func(t *testing.T) {
			input := RiskInput{ToolName: "tunnel", Action: tc.action, TunnelMode: tc.mode, ListenHost: tc.host}
			if got := Classify(input); got != tc.want {
				t.Fatalf("risk = %v, want %v", got, tc.want)
			}
			want := Allow
			if tc.want == Dangerous {
				want = NeedApproval
			}
			if got := NewPolicy(defaultTestConfig()).Evaluate(Classify(input), input); got != want {
				t.Fatalf("decision = %v, want %v", got, want)
			}
		})
	}
}
