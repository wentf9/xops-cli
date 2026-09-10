package main

import (
	"io"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestFixtureComparison(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	for _, tc := range []struct {
		name   string
		value  string
		expiry *time.Time
		want   bool
	}{
		{"original", fixtureValue, nil, true},
		{"missing", "", nil, false},
		{"replacement", "release-drill-after-restore", nil, false},
		{"altered", fixtureValue + "x", nil, false},
		{"unexpected expiry", fixtureValue, &expiry, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := credential.NewSecret([]byte(tc.value))
			defer secret.Zero()
			secret.ExpiresAt = tc.expiry
			if matchesFixture(secret) != tc.want {
				t.Fatal("incorrect fixture comparison")
			}
		})
	}
}

func TestVerifierRequiresConfiguration(t *testing.T) {
	if err := run(nil, io.Discard); err == nil {
		t.Fatal("missing configuration accepted")
	}
}
