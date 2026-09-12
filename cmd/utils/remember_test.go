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

func TestRememberRequiresWritableDefaultStore(t *testing.T) {
	for _, tc := range []struct {
		name       string
		credential *config.CredentialConfig
		want       bool
	}{
		{"legacy missing", nil, false},
		{"no default", &config.CredentialConfig{Stores: map[string]config.StoreConfig{"pass": {Type: config.StoreTypePass}}}, false},
		{"unknown default", &config.CredentialConfig{DefaultStore: "missing"}, false},
		{"none", &config.CredentialConfig{DefaultStore: "none", Stores: map[string]config.StoreConfig{"none": {Type: config.StoreTypeNone}}}, false},
		{"readonly", &config.CredentialConfig{DefaultStore: "vault", Stores: map[string]config.StoreConfig{"vault": {Type: config.StoreTypeHelper, ReadOnly: true}}}, false},
		{"writable", &config.CredentialConfig{DefaultStore: "pass", Stores: map[string]config.StoreConfig{"pass": {Type: config.StoreTypePass}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Configuration{SchemaVersion: 1, Credential: tc.credential}
			if got := ShouldRememberConfiguredCredential("always", "node", cfg); got != tc.want {
				t.Fatalf("remember=%v, want %v", got, tc.want)
			}
			if !tc.want && ShouldRememberConfiguredCredential("ask", "node", cfg) {
				t.Fatal("disabled persistence must skip confirmation")
			}
		})
	}
}
