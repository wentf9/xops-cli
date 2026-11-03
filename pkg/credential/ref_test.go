package credential

import (
	"errors"
	"testing"
	"time"

	coreauth "github.com/wentf9/xops-cli/core/auth"
	"gopkg.in/yaml.v3"
)

func TestKindValidate(t *testing.T) {
	tests := []struct {
		name    string
		kind    Kind
		wantErr bool
	}{
		{"login_password", KindLoginPassword, false},
		{"passphrase", KindPassphrase, false},
		{"privilege_password", KindPrivilegePassword, false},
		{"totp_secret", KindTOTPSecret, false},
		{"challenge_answer", KindChallengeAnswer, false},
		{"empty", "", true},
		{"unknown", "unknown_kind", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.kind.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Kind.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, coreauth.ErrInvalidRef) {
				t.Fatalf("expected coreauth.ErrInvalidRef, got: %v", err)
			}
		})
	}
}

func TestParseRef(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Ref
		wantErr bool
	}{
		{"empty string", "", Ref{}, false},
		{"whitespace only", "   ", Ref{}, false},
		{"valid store and item", "default/item-123", Ref{StoreID: "default", ItemID: "item-123"}, false},
		{"missing slash", "default-item", Ref{}, true},
		{"multiple slashes", "store/sub/item", Ref{}, true},
		{"empty store", "/item-123", Ref{}, true},
		{"empty item", "store/", Ref{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRef(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseRef(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("ParseRef(%q) = %+v, want %+v", tt.input, got, tt.want)
			}
		})
	}
}

func TestTargetValidate(t *testing.T) {
	// Missing nodeID and identityID
	t1 := Target{Kind: KindLoginPassword}
	if err := t1.Validate(); err == nil {
		t.Fatal("expected error for target missing both nodeID and identityID")
	}

	// Challenge answer without RuleName
	t2 := Target{IdentityID: "id1", Kind: KindChallengeAnswer}
	if err := t2.Validate(); err == nil {
		t.Fatal("expected error for challenge_answer without RuleName")
	}

	// Challenge answer with RuleName
	t3 := Target{IdentityID: "id1", Kind: KindChallengeAnswer, RuleName: "otp-rule"}
	if err := t3.Validate(); err != nil {
		t.Fatalf("unexpected error for challenge_answer with RuleName: %v", err)
	}
	if id := t3.TargetIdentifier(); id != "id1#otp-rule" {
		t.Fatalf("expected target identifier 'id1#otp-rule', got: %s", id)
	}

	// Node target identifier without RuleName
	t4 := Target{NodeID: "node1", Kind: KindLoginPassword}
	if id := t4.TargetIdentifier(); id != "node1" {
		t.Fatalf("expected target identifier 'node1', got: %s", id)
	}
}

func TestRefValidate(t *testing.T) {
	tests := []struct {
		name    string
		ref     Ref
		wantErr bool
	}{
		{"empty ref is valid", Ref{}, false},
		{"valid ref", Ref{StoreID: "system", ItemID: "item-123"}, false},
		{"missing itemID", Ref{StoreID: "system"}, true},
		{"missing storeID", Ref{ItemID: "item-123"}, true},
		{"blank storeID", Ref{StoreID: "   ", ItemID: "item-123"}, true},
		{"blank itemID", Ref{StoreID: "system", ItemID: "   "}, true},
		{"storeID with slash", Ref{StoreID: "sys/tem", ItemID: "item-123"}, true},
		{"storeID with backslash", Ref{StoreID: "sys\\tem", ItemID: "item-123"}, true},
		{"itemID with newline", Ref{StoreID: "system", ItemID: "item\n123"}, true},
		{"itemID with spaces", Ref{StoreID: "system", ItemID: "item 123"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ref.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Ref.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, coreauth.ErrInvalidRef) {
				t.Fatalf("expected coreauth.ErrInvalidRef, got: %v", err)
			}
		})
	}
}

func TestRefHelperMethods(t *testing.T) {
	empty := Ref{}
	if !empty.IsEmpty() {
		t.Errorf("expected empty.IsEmpty() to be true")
	}
	if empty.IsComplete() {
		t.Errorf("expected empty.IsComplete() to be false")
	}
	if empty.String() != "" {
		t.Errorf("expected empty.String() == %q, got %q", "", empty.String())
	}

	valid := Ref{StoreID: "pass", ItemID: "node-1-login"}
	if valid.IsEmpty() {
		t.Errorf("expected valid.IsEmpty() to be false")
	}
	if !valid.IsComplete() {
		t.Errorf("expected valid.IsComplete() to be true")
	}
	if valid.String() != "pass/node-1-login" {
		t.Errorf("expected valid.String() == %q, got %q", "pass/node-1-login", valid.String())
	}

	cloned := valid.Clone()
	if cloned == nil || *cloned != valid {
		t.Fatalf("cloned ref mismatch: got %+v, want %+v", cloned, valid)
	}
	cloned.ItemID = "different"
	if valid.ItemID == "different" {
		t.Errorf("mutation of cloned ref affected original")
	}
}

func TestRefYAMLRoundTrip(t *testing.T) {
	type wrapper struct {
		PasswordRef *Ref `yaml:"password_ref,omitempty"`
	}

	orig := wrapper{
		PasswordRef: &Ref{
			StoreID: "system",
			ItemID:  "item-uuid-001",
		},
	}

	data, err := yaml.Marshal(orig)
	if err != nil {
		t.Fatalf("yaml.Marshal failed: %v", err)
	}

	var parsed wrapper
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("yaml.Unmarshal failed: %v", err)
	}

	if parsed.PasswordRef == nil {
		t.Fatalf("parsed password_ref is nil")
	}
	if *parsed.PasswordRef != *orig.PasswordRef {
		t.Fatalf("roundtrip mismatch: got %+v, want %+v", parsed.PasswordRef, orig.PasswordRef)
	}
}

func TestSecretLifecycle(t *testing.T) {
	secretVal := []byte("topsecret123")
	now := time.Now().UTC()
	exp := now.Add(time.Hour)

	sec := NewSecretWithExpiry(secretVal, exp)
	if string(sec.Value) != "topsecret123" {
		t.Fatalf("unexpected secret value: %s", string(sec.Value))
	}
	if sec.IsExpired(now) {
		t.Fatalf("expected secret to not be expired at now")
	}
	if !sec.IsExpired(exp.Add(time.Second)) {
		t.Fatalf("expected secret to be expired after expiry time")
	}

	// 测试 Clone 深拷贝
	cloned := sec.Clone()
	if string(cloned.Value) != string(sec.Value) {
		t.Fatalf("cloned secret value mismatch")
	}
	cloned.Value[0] = 'X'
	if sec.Value[0] == 'X' {
		t.Fatalf("cloned secret mutation affected original value")
	}

	// 测试 Zero
	sec.Zero()
	if sec.Value != nil {
		t.Fatalf("expected sec.Value to be nil after Zero()")
	}
	if sec.ExpiresAt != nil {
		t.Fatalf("expected sec.ExpiresAt to be nil after Zero()")
	}

	// 再次清零不应 panic
	sec.Zero()
	var nilSec *Secret
	nilSec.Zero()
}
