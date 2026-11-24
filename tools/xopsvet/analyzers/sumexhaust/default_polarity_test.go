package sumexhaust

import "testing"

func TestPolarityDuality(t *testing.T) {
	cases := []struct {
		name           string
		wantPermissive bool
		wantFailClosed bool
	}{
		{name: "allowRequest", wantPermissive: true, wantFailClosed: false},
		{name: "allowOnError", wantPermissive: true, wantFailClosed: false},
		{name: "allowIfInvalid", wantPermissive: true, wantFailClosed: false},
		{name: "DecisionAllow", wantPermissive: true, wantFailClosed: false},
		{name: "NotAllowedOrAllow", wantPermissive: true, wantFailClosed: false},
		{name: "ErrNotAllowed", wantPermissive: false, wantFailClosed: true},
		{name: "VerdictNotAllowed", wantPermissive: false, wantFailClosed: true},
		{name: "newNotAllowedErr", wantPermissive: false, wantFailClosed: true},
		{name: "nonAllowed", wantPermissive: false, wantFailClosed: true},
		{name: "neverPermit", wantPermissive: false, wantFailClosed: true},
		{name: "withoutApproved", wantPermissive: false, wantFailClosed: true},
		{name: "noGrant", wantPermissive: false, wantFailClosed: true},
		{name: "DecisionDeny", wantPermissive: false, wantFailClosed: true},
		{name: "Disallowed", wantPermissive: false, wantFailClosed: true},
		{name: "Unapproved", wantPermissive: false, wantFailClosed: true},
		{name: "Halted", wantPermissive: false, wantFailClosed: true},
		{name: "Revoked", wantPermissive: false, wantFailClosed: true},
		{name: "Neutral", wantPermissive: false, wantFailClosed: false},
	}
	for _, tc := range cases {
		gotPerm := isPermissiveIdentName(tc.name)
		gotFC := isFailClosedIdentName(tc.name)
		if gotPerm != tc.wantPermissive || gotFC != tc.wantFailClosed {
			t.Errorf("%s: got (permissive=%v, failClosed=%v), want (%v, %v)",
				tc.name, gotPerm, gotFC, tc.wantPermissive, tc.wantFailClosed)
		}
		if gotPerm && gotFC {
			t.Errorf("%s: permissive and failClosed must be mutually exclusive", tc.name)
		}
	}
}
