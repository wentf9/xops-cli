package guardrail

import "testing"

func TestTunnelRiskClassification(t *testing.T) {
	for _, tc := range []struct {
		tool, mode, host string
		want             RiskLevel
	}{
		{"xops_tunnel_create", "local", "127.0.0.1", Moderate},
		{"xops_tunnel_create", "local", "127.2.3.4", Moderate},
		{"xops_tunnel_create", "local", "::1", Moderate},
		{"xops_tunnel_create", "local", "::ffff:127.0.0.1", Moderate},
		{"xops_tunnel_create", "local", "0.0.0.0", Dangerous},
		{"xops_tunnel_create", "local", "::", Dangerous},
		{"xops_tunnel_create", "local", "localhost", Dangerous},
		{"xops_tunnel_create", "remote", "127.0.0.1", Dangerous},
		{"xops_tunnel_create", "dynamic", "127.0.0.1", Dangerous},
		{"xops_tunnel_stop", "", "", Moderate},
		{"xops_tunnel_list", "", "", Safe},
		{"xops_tunnel_status", "", "", Safe},
	} {
		t.Run(tc.tool+"/"+tc.mode+"/"+tc.host, func(t *testing.T) {
			input := RiskInput{ToolName: tc.tool, TunnelMode: tc.mode, ListenHost: tc.host}
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
