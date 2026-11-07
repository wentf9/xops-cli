package models

import (
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/credential"
	"gopkg.in/yaml.v3"
)

func TestOTPConfig_CloneAndEqual(t *testing.T) {
	var nilOTP *OTPConfig
	if nilOTP.Clone() != nil {
		t.Fatal("expected nil clone for nil OTPConfig")
	}
	if !nilOTP.Equal(nil) {
		t.Fatal("expected nil OTPConfig equal nil")
	}

	orig := &OTPConfig{
		TOTPSecretRef: &credential.Ref{
			StoreID: "store1",
			ItemID:  "item1",
		},
		Command:       "oathtool",
		Args:          []string{"--totp", "-b"},
		Timeout:       10 * time.Second,
		PromptPattern: "^OTP:",
	}

	cloned := orig.Clone()
	if !orig.Equal(cloned) {
		t.Fatal("cloned OTPConfig should equal original")
	}

	// Mutate cloned fields to verify deep copy
	cloned.Args[0] = "--hotp"
	if orig.Equal(cloned) {
		t.Fatal("modifying cloned Args should break equality")
	}
	cloned.Args[0] = "--totp"

	cloned.TOTPSecretRef.ItemID = "item2"
	if orig.Equal(cloned) {
		t.Fatal("modifying cloned TOTPSecretRef should break equality")
	}
	if orig.TOTPSecretRef.ItemID != "item1" {
		t.Fatal("modifying cloned TOTPSecretRef affected original")
	}
}

func TestChallengeRule_CloneAndEqual(t *testing.T) {
	orig := ChallengeRule{
		Name:               "totp-rule",
		PromptPattern:      "Verification Code:",
		InstructionPattern: "Enter MFA",
		Source:             ChallengeSourceSecret,
		SecretRef: &credential.Ref{
			StoreID: "store1",
			ItemID:  "secret1",
		},
		Command: "pass",
		Args:    []string{"show", "mfa"},
		Timeout: 5 * time.Second,
	}

	cloned := orig.Clone()
	if !orig.Equal(cloned) {
		t.Fatal("cloned ChallengeRule should equal original")
	}

	cloned.Args[1] = "mfa2"
	if orig.Equal(cloned) {
		t.Fatal("modifying cloned Args should break equality")
	}
	cloned.Args[1] = "mfa"

	cloned.SecretRef.ItemID = "secret2"
	if orig.Equal(cloned) {
		t.Fatal("modifying cloned SecretRef should break equality")
	}
	if orig.SecretRef.ItemID != "secret1" {
		t.Fatal("modifying cloned SecretRef affected original")
	}
}

func TestKeyboardInteractiveConfig_CloneAndEqual(t *testing.T) {
	var nilKI *KeyboardInteractiveConfig
	if nilKI.Clone() != nil {
		t.Fatal("expected nil clone for nil KeyboardInteractiveConfig")
	}
	if !nilKI.Equal(nil) {
		t.Fatal("expected nil KeyboardInteractiveConfig equal nil")
	}

	orig := &KeyboardInteractiveConfig{
		Rules: []ChallengeRule{
			{
				Name:          "rule1",
				PromptPattern: "Password:",
				Source:        ChallengeSourceLoginPassword,
			},
			{
				Name:          "rule2",
				PromptPattern: "OTP:",
				Source:        ChallengeSourceOTP,
			},
		},
	}

	cloned := orig.Clone()
	if !orig.Equal(cloned) {
		t.Fatal("cloned KeyboardInteractiveConfig should equal original")
	}

	// Mutate cloned slice
	cloned.Rules = append(cloned.Rules, ChallengeRule{Name: "rule3"})
	if orig.Equal(cloned) {
		t.Fatal("modifying cloned Rules length should break equality")
	}
	if len(orig.Rules) != 2 {
		t.Fatal("modifying cloned Rules length affected original")
	}
}

func TestIdentity_CloneAndEqual(t *testing.T) {
	orig := Identity{
		User:           "testuser",
		KeyPath:        "/home/test/.ssh/id_rsa",
		KeyFingerprint: "SHA256:abc",
		AuthType:       "keyboard-interactive",
		LoginPasswordRef: &credential.Ref{
			StoreID: "store1",
			ItemID:  "pwd1",
		},
		PassphraseRef: &credential.Ref{
			StoreID: "store1",
			ItemID:  "pass1",
		},
		OTP: &OTPConfig{
			TOTPSecretRef: &credential.Ref{
				StoreID: "store1",
				ItemID:  "totp1",
			},
		},
		KeyboardInteractive: &KeyboardInteractiveConfig{
			Rules: []ChallengeRule{
				{
					Name:          "rule1",
					PromptPattern: "OTP:",
					Source:        ChallengeSourceOTP,
				},
			},
		},
	}

	cloned := orig.Clone()
	if !orig.Equal(cloned) {
		t.Fatal("cloned Identity should equal original")
	}

	// Mutate nested pointers in clone
	cloned.LoginPasswordRef.ItemID = "pwd2"
	if orig.Equal(cloned) {
		t.Fatal("mutating cloned LoginPasswordRef should break equality")
	}
	if orig.LoginPasswordRef.ItemID != "pwd1" {
		t.Fatal("mutating cloned LoginPasswordRef affected original")
	}
	cloned.LoginPasswordRef.ItemID = "pwd1"

	cloned.OTP.TOTPSecretRef.ItemID = "totp2"
	if orig.Equal(cloned) {
		t.Fatal("mutating cloned OTP should break equality")
	}
	if orig.OTP.TOTPSecretRef.ItemID != "totp1" {
		t.Fatal("mutating cloned OTP affected original")
	}
	cloned.OTP.TOTPSecretRef.ItemID = "totp1"

	cloned.KeyboardInteractive.Rules[0].PromptPattern = "Token:"
	if orig.Equal(cloned) {
		t.Fatal("mutating cloned KeyboardInteractive should break equality")
	}
	if orig.KeyboardInteractive.Rules[0].PromptPattern != "OTP:" {
		t.Fatal("mutating cloned KeyboardInteractive affected original")
	}
}

func TestNode_ControlYAMLSerialization(t *testing.T) {
	// 1. Without Control, field should be omitted in YAML
	nodeWithoutControl := Node{
		HostRef:     "srv1",
		IdentityRef: "admin",
	}
	out, err := yaml.Marshal(nodeWithoutControl)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if strings.Contains(string(out), "control:") {
		t.Fatalf("expected control to be omitted, got: %s", string(out))
	}

	// 2. With Control, field should be marshaled and unmarshaled correctly
	nodeWithControl := Node{
		HostRef:     "srv1",
		IdentityRef: "admin",
		Control: &ssh.ControlConfig{
			Master:  ssh.ControlMasterAuto,
			Path:    "~/.ssh/cm-%r@%h:%p",
			Persist: "10m",
		},
	}
	data, err := yaml.Marshal(nodeWithControl)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if !strings.Contains(string(data), "control:") {
		t.Fatalf("expected control in YAML, got: %s", string(data))
	}

	var unmarshaled Node
	if err := yaml.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if unmarshaled.Control == nil {
		t.Fatal("expected unmarshaled Control to be non-nil")
	}
	if !unmarshaled.Control.Equal(nodeWithControl.Control) {
		t.Fatalf("expected %v, got %v", nodeWithControl.Control, unmarshaled.Control)
	}
}
