package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestIdentitySetSecret_TOTP(t *testing.T) {
	tempDir := setupTestEnvironment(t)
	helperDataFile := filepath.Join(tempDir, "helper_data.json")
	t.Setenv("TEST_IDENTITY_HELPER", "1")
	t.Setenv("TEST_HELPER_DATA_FILE", helperDataFile)

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath failed: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)

	cfg := &config.Configuration{
		SchemaVersion: 2,
		Nodes:         concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:         concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities:    concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Credential: &config.CredentialConfig{
			DefaultStore: "helper-store",
			Stores: map[string]config.StoreConfig{
				"helper-store": {
					Type:    config.StoreTypeHelper,
					Command: os.Args[0],
				},
			},
		},
	}
	cfg.Identities.Set("user1", models.Identity{
		User:     "user1",
		AuthType: "otp",
	})
	if err := store.Save(cfg); err != nil {
		t.Fatalf("failed to save initial config: %v", err)
	}

	// 1. Invalid Base32 secret should fail validation
	cmdInvalid := NewCmdIdentity()
	cmdInvalid.SetIn(strings.NewReader("INVALID_BASE32_!@#$\n"))
	cmdInvalid.SetArgs([]string{"set-secret", "user1", "--kind", "totp_secret", "--password-stdin"})
	if err := cmdInvalid.Execute(); err == nil {
		t.Fatal("expected error for invalid TOTP secret, got nil")
	}

	// 2. Valid Base32 secret should succeed
	cmdValid := NewCmdIdentity()
	cmdValid.SetIn(strings.NewReader("JBSWY3DPEHPK3PXP\n"))
	cmdValid.SetArgs([]string{"set-secret", "user1", "--kind", "totp_secret", "--password-stdin"})
	if err := cmdValid.Execute(); err != nil {
		t.Fatalf("execute set-secret failed: %v", err)
	}

	// Verify TOTPSecretRef was set
	updatedCfg, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load updated config: %v", err)
	}
	id1, ok := updatedCfg.Identities.Get("user1")
	if !ok {
		t.Fatal("identity user1 not found")
	}
	if id1.OTP == nil || id1.OTP.TOTPSecretRef == nil || id1.OTP.TOTPSecretRef.IsEmpty() {
		t.Fatalf("expected TOTPSecretRef to be populated, got %+v", id1.OTP)
	}
	if id1.OTP.TOTPSecretRef.StoreID != "helper-store" {
		t.Errorf("expected StoreID helper-store, got %q", id1.OTP.TOTPSecretRef.StoreID)
	}

	// 3. Deleting totp_secret should cleanly remove empty OTP block and pass Schema V2 validation
	cmdDelete := NewCmdIdentity()
	cmdDelete.SetArgs([]string{"credential", "delete", "user1", "--kind", "totp_secret"})
	if err := cmdDelete.Execute(); err != nil {
		t.Fatalf("execute credential delete totp_secret failed: %v", err)
	}
	deletedCfg, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load config after deleting totp_secret: %v", err)
	}
	id1Deleted, ok := deletedCfg.Identities.Get("user1")
	if !ok {
		t.Fatal("identity user1 not found after delete")
	}
	if id1Deleted.OTP != nil {
		t.Fatalf("expected OTP block to be nil after deleting totp_secret, got %+v", id1Deleted.OTP)
	}
}

func TestIdentitySetSecret_ChallengeAnswer(t *testing.T) {
	tempDir := setupTestEnvironment(t)
	helperDataFile := filepath.Join(tempDir, "helper_data.json")
	t.Setenv("TEST_IDENTITY_HELPER", "1")
	t.Setenv("TEST_HELPER_DATA_FILE", helperDataFile)

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath failed: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)

	cfg := &config.Configuration{
		SchemaVersion: 2,
		Nodes:         concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:         concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities:    concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Credential: &config.CredentialConfig{
			DefaultStore: "helper-store",
			Stores: map[string]config.StoreConfig{
				"helper-store": {
					Type:    config.StoreTypeHelper,
					Command: os.Args[0],
				},
			},
		},
	}
	cfg.Identities.Set("user-ki", models.Identity{
		User:     "user-ki",
		AuthType: "keyboard-interactive",
		KeyboardInteractive: &models.KeyboardInteractiveConfig{
			Rules: []models.ChallengeRule{
				{
					Name:          "rule-pin",
					PromptPattern: "^PIN:",
					Source:        models.ChallengeSourceSecret,
					SecretRef:     &credential.Ref{StoreID: "helper-store", ItemID: "initial-pin"},
				},
			},
		},
	})
	if err := store.Save(cfg); err != nil {
		t.Fatalf("failed to save initial config: %v", err)
	}

	// 1. Missing --rule flag should fail
	cmdNoRule := NewCmdIdentity()
	cmdNoRule.SetIn(strings.NewReader("my-secret-pin\n"))
	cmdNoRule.SetArgs([]string{"credential", "set", "user-ki", "--kind", "challenge_answer", "--password-stdin"})
	if err := cmdNoRule.Execute(); err == nil {
		t.Fatal("expected error when --rule is omitted for challenge_answer, got nil")
	}

	// 2. Non-existent rule name should fail
	cmdWrongRule := NewCmdIdentity()
	cmdWrongRule.SetIn(strings.NewReader("my-secret-pin\n"))
	cmdWrongRule.SetArgs([]string{"credential", "set", "user-ki", "--kind", "challenge_answer", "--rule", "nonexistent-rule", "--password-stdin"})
	if err := cmdWrongRule.Execute(); err == nil {
		t.Fatal("expected error when --rule does not match any existing rule, got nil")
	}

	// 3. Valid rule name should succeed and update rule.SecretRef
	cmdValid := NewCmdIdentity()
	cmdValid.SetIn(strings.NewReader("my-secret-pin\n"))
	cmdValid.SetArgs([]string{"credential", "set", "user-ki", "--kind", "challenge_answer", "--rule", "rule-pin", "--password-stdin"})
	if err := cmdValid.Execute(); err != nil {
		t.Fatalf("expected success for valid challenge_answer rule, got %v", err)
	}

	// Verify rule.SecretRef was set
	updatedCfg, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load updated config: %v", err)
	}
	idKI, ok := updatedCfg.Identities.Get("user-ki")
	if !ok {
		t.Fatal("identity user-ki not found")
	}
	if idKI.KeyboardInteractive == nil || len(idKI.KeyboardInteractive.Rules) == 0 {
		t.Fatal("expected KeyboardInteractive.Rules to exist")
	}
	rule := idKI.KeyboardInteractive.Rules[0]
	if rule.SecretRef == nil || rule.SecretRef.IsEmpty() {
		t.Fatalf("expected rule.SecretRef to be populated, got %+v", rule.SecretRef)
	}
	if rule.SecretRef.StoreID != "helper-store" {
		t.Errorf("expected StoreID helper-store, got %q", rule.SecretRef.StoreID)
	}

	// 4. Rotate operation for challenge_answer rule
	cmdRotate := NewCmdIdentity()
	cmdRotate.SetIn(strings.NewReader("my-new-secret-pin\n"))
	cmdRotate.SetArgs([]string{"credential", "set", "user-ki", "--kind", "challenge_answer", "--rule", "rule-pin", "--password-stdin"})
	if err := cmdRotate.Execute(); err != nil {
		t.Fatalf("expected success rotating challenge_answer rule credential, got %v", err)
	}

	afterRotateCfg, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load config after rotate: %v", err)
	}
	idAfterRotate, _ := afterRotateCfg.Identities.Get("user-ki")
	rotatedRule := idAfterRotate.KeyboardInteractive.Rules[0]
	if rotatedRule.SecretRef == nil || rotatedRule.SecretRef.ItemID == rule.SecretRef.ItemID {
		t.Fatalf("expected rule.SecretRef to be rotated to new ItemID, got %+v", rotatedRule.SecretRef)
	}

	// 5. Delete operation for challenge_answer rule should remove the rule and pass Schema V2 validation
	assertDeleteChallengeAnswerRule(t, store, "user-ki", "rule-pin")
}

func assertDeleteChallengeAnswerRule(t *testing.T, store config.Store, identityName, ruleName string) {
	t.Helper()
	cmdDeleteRule := NewCmdIdentity()
	cmdDeleteRule.SetArgs([]string{"credential", "delete", identityName, "--kind", "challenge_answer", "--rule", ruleName})
	if err := cmdDeleteRule.Execute(); err != nil {
		t.Fatalf("expected success deleting challenge_answer rule credential, got %v", err)
	}
	afterDeleteCfg, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load config after deleting challenge_answer: %v", err)
	}
	idAfterDelete, _ := afterDeleteCfg.Identities.Get(identityName)
	if idAfterDelete.KeyboardInteractive != nil && len(idAfterDelete.KeyboardInteractive.Rules) != 0 {
		t.Fatalf("expected challenge rule to be removed after deleting its secret_ref, got %+v", idAfterDelete.KeyboardInteractive)
	}

	// 6. Setting login_password on a keyboard-interactive identity preserves auth_type: keyboard-interactive
	cmdSetLoginPwd := NewCmdIdentity()
	cmdSetLoginPwd.SetIn(strings.NewReader("pam-login-password\n"))
	cmdSetLoginPwd.SetArgs([]string{"set-secret", identityName, "--kind", "login_password", "--password-stdin"})
	if err := cmdSetLoginPwd.Execute(); err != nil {
		t.Fatalf("expected success setting login_password on keyboard-interactive identity, got %v", err)
	}
	afterLoginPwdCfg, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load config after setting login_password: %v", err)
	}
	idAfterLoginPwd, _ := afterLoginPwdCfg.Identities.Get(identityName)
	if idAfterLoginPwd.AuthType != "keyboard-interactive" {
		t.Fatalf("expected AuthType to remain 'keyboard-interactive', got %q", idAfterLoginPwd.AuthType)
	}
}

func TestIdentityCredentialValidation(t *testing.T) {
	cmd := NewCmdIdentity()
	cmd.SetIn(strings.NewReader("dummy\n"))
	cmd.SetArgs([]string{"credential", "set", "id1", "--kind", "unsupported_kind", "--password-stdin"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected validation error for unsupported credential kind, got nil")
	}
}
