package utils

import (
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
)

func TestRememberPolicyPrecedence(t *testing.T) {
	for _, tc := range []struct{ name, override, configured, want string }{
		{"default", "", "", "ask"},
		{"configured never", "", "never", "never"},
		{"configured always", "", "always", "always"},
		{"explicit ask", "ask", "never", "ask"},
		{"explicit never", "never", "always", "never"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Configuration{Credential: &config.CredentialConfig{RememberPrompted: tc.configured}}
			if got := EffectiveRememberPolicy(tc.override, cfg); got != tc.want {
				t.Fatalf("policy = %q, want %q", got, tc.want)
			}
		})
	}
}
