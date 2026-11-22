package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W15c_L4_15_M1_InitRejectsOpenSSHWildcardJumpCycleFailClosed(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	sshConfigPath := filepath.Join(tempDir, "ssh_config")
	sshConfig := []byte(`
Host *.jump.corp
    HostName 10.244.0.200
    User ops
    ProxyJump app

Host app
    HostName 10.244.0.10
    User ops
    ProxyJump gw.jump.corp
`)
	if err := os.WriteFile(sshConfigPath, sshConfig, 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}

	o := &InitOptions{
		ConfigPath:       filepath.Join(tempDir, "xops", "xops_config.yaml"),
		KeyPath:          filepath.Join(tempDir, "xops", "secret.key"),
		SSHConfigPath:    sshConfigPath,
		SSHConfigChanged: true,
	}
	var cycleErr *ssh.ProxyCycleError
	if _, err := o.RunContext(t.Context()); !errors.As(err, &cycleErr) {
		t.Fatalf("InitOptions.RunContext(wildcard jump cycle) = %v, want *ssh.ProxyCycleError", err)
	}
	if _, statErr := os.Stat(o.ConfigPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("xops init created config file despite wildcard ProxyJump cycle: statErr=%v", statErr)
	}
}

func TestP7W15c_L4_15_M2_CredentialDoctorFailsMissingVaultForTOTPAndChallengeRefs(t *testing.T) {
	initCredentialPolicyTestI18n(t)

	cases := []struct {
		name     string
		identity models.Identity
		wantFail bool
	}{
		{
			name: "unreferenced_missing_vault_warns_only",
			identity: models.Identity{
				User:     "ops",
				AuthType: "auto",
			},
			wantFail: false,
		},
		{
			name: "totp_secret_ref_only_missing_vault_fails",
			identity: models.Identity{
				User:     "ops",
				AuthType: "otp",
				OTP: &models.OTPConfig{
					TOTPSecretRef: &credential.Ref{StoreID: "file", ItemID: "totp-item-1"},
				},
			},
			wantFail: true,
		},
		{
			name: "challenge_rule_secret_ref_only_missing_vault_fails",
			identity: models.Identity{
				User:     "ops",
				AuthType: "keyboard-interactive",
				KeyboardInteractive: &models.KeyboardInteractiveConfig{
					Rules: []models.ChallengeRule{
						{
							Name:          "pin",
							PromptPattern: "PIN:",
							Source:        models.ChallengeSourceSecret,
							SecretRef:     &credential.Ref{StoreID: "file", ItemID: "chal-item-1"},
						},
					},
				},
			},
			wantFail: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupTestEnvironment(t)
			cfgPath, keyPath, err := utils.GetConfigFilePath()
			if err != nil {
				t.Fatalf("GetConfigFilePath: %v", err)
			}
			store := config.NewDefaultStore(cfgPath, keyPath)
			cfg := &config.Configuration{
				SchemaVersion: 2,
				Nodes:         concurrent.NewMap[string, models.Node](concurrent.HashString),
				Hosts:         concurrent.NewMap[string, models.Host](concurrent.HashString),
				Identities:    concurrent.NewMap[string, models.Identity](concurrent.HashString),
				Credential: &config.CredentialConfig{
					DefaultStore: "file",
					Stores: map[string]config.StoreConfig{
						"file": {
							Type:    config.StoreTypeEncryptedFile,
							Path:    filepath.Join(dir, "missing-vault"),
							KeyFile: filepath.Join(dir, "missing-vault.key"),
							Unlock:  "key-file",
						},
					},
				},
			}
			cfg.Hosts.Set("10.0.0.1:22", models.Host{Address: "10.0.0.1", Port: 22})
			cfg.Identities.Set("id-mfa", tc.identity)
			cfg.Nodes.Set("ops@10.0.0.1:22", models.Node{
				HostRef:     "10.0.0.1:22",
				IdentityRef: "id-mfa",
				SudoMode:    models.SudoModeAuto,
			})
			if err := store.Save(cfg); err != nil {
				t.Fatalf("store.Save: %v", err)
			}

			var out bytes.Buffer
			cmd := NewCmdCredential()
			cmd.SetOut(&out)
			cmd.SetArgs([]string{"doctor"})
			err = cmd.Execute()
			if tc.wantFail {
				if err == nil {
					t.Fatalf("credential doctor succeeded for %s, want FAIL error\noutput:\n%s", tc.name, out.String())
				}
				if !strings.Contains(out.String(), "Store: file") || !strings.Contains(out.String(), "FAIL") {
					t.Fatalf("credential doctor output missing Store: file FAIL:\n%s", out.String())
				}
			} else {
				if err != nil {
					t.Fatalf("credential doctor failed for %s: %v\noutput:\n%s", tc.name, err, out.String())
				}
				if !strings.Contains(out.String(), "Store: file") || !strings.Contains(out.String(), "WARN") {
					t.Fatalf("credential doctor output missing Store: file WARN:\n%s", out.String())
				}
			}
		})
	}
}
