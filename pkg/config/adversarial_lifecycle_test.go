package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coreauth "github.com/wentf9/xops-cli/core/auth"
	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

// -----------------------------------------------------------------------------
// 1. Zero-Plaintext Penetration Testing
// -----------------------------------------------------------------------------

func TestAdversarial_ZeroPlaintextPermutations(t *testing.T) {
	basePreamble := `schema_version: 2
credential:
  default_store: pass
  stores:
    pass: {type: pass}
hosts:
  h1: {address: 127.0.0.1, port: 22}
nodes:
  n1: {host_ref: h1, identity_ref: dev}
`

	testCases := []struct {
		name        string
		yamlSnippet string
	}{
		// Identity root forbidden fields
		{"id_root_totp_secret", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: otp\n    totp_secret: \"JBSWY3DPEHPK3PXP\"\n"},
		{"id_root_otp_secret", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: otp\n    otp_secret: \"JBSWY3DPEHPK3PXP\"\n"},
		{"id_root_answer", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: keyboard-interactive\n    answer: \"my-secret-answer\"\n"},
		{"id_root_secret", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: keyboard-interactive\n    secret: \"my-secret\"\n"},
		{"id_root_password", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: password\n    password: \"plaintext-password\"\n"},
		{"id_root_passphrase", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: key\n    passphrase: \"plaintext-passphrase\"\n"},

		// Empty/null values for identity root forbidden fields
		{"id_root_totp_secret_empty", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: otp\n    totp_secret: \"\"\n"},
		{"id_root_secret_null", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: keyboard-interactive\n    secret: null\n"},
		{"id_root_answer_tilde", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: keyboard-interactive\n    answer: ~\n"},

		// Inside otp block
		{"otp_block_totp_secret", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: otp\n    otp:\n      totp_secret: \"JBSWY3DPEHPK3PXP\"\n"},
		{"otp_block_otp_secret", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: otp\n    otp:\n      otp_secret: \"JBSWY3DPEHPK3PXP\"\n"},
		{"otp_block_secret", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: otp\n    otp:\n      secret: \"my-secret\"\n"},
		{"otp_block_answer", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: otp\n    otp:\n      answer: \"my-answer\"\n"},

		// Inside keyboard_interactive.rules
		{"rule_answer", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: keyboard-interactive\n    keyboard_interactive:\n      rules:\n        - name: r1\n          prompt_pattern: \"PIN:\"\n          answer: \"123456\"\n"},
		{"rule_secret", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: keyboard-interactive\n    keyboard_interactive:\n      rules:\n        - name: r1\n          prompt_pattern: \"PIN:\"\n          secret: \"123456\"\n"},
		{"rule_totp_secret", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: keyboard-interactive\n    keyboard_interactive:\n      rules:\n        - name: r1\n          prompt_pattern: \"Code:\"\n          totp_secret: \"JBSWY3DPEHPK3PXP\"\n"},
		{"rule_otp_secret", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: keyboard-interactive\n    keyboard_interactive:\n      rules:\n        - name: r1\n          prompt_pattern: \"Code:\"\n          otp_secret: \"JBSWY3DPEHPK3PXP\"\n"},
		{"rule_password", basePreamble + "identities:\n  dev:\n    user: dev\n    auth_type: keyboard-interactive\n    keyboard_interactive:\n      rules:\n        - name: r1\n          prompt_pattern: \"Pass:\"\n          password: \"hunter2\"\n"},

		// Inside nodes: su_pwd
		{"node_su_pwd", `schema_version: 2
credential: {default_store: pass, stores: {pass: {type: pass}}}
hosts: {h1: {address: 127.0.0.1, port: 22}}
identities: {dev: {user: dev, auth_type: key}}
nodes:
  n1:
    host_ref: h1
    identity_ref: dev
    su_pwd: "plaintext_root_pwd"
`},

		// YAML anchor & merge key penetration attempt
		{"yaml_merge_anchor_identity_totp", basePreamble + `
default_secrets: &defs
  totp_secret: "smuggled_totp_secret"
identities:
  dev:
    <<: *defs
    user: dev
    auth_type: otp
`},
		{"yaml_merge_anchor_rule_secret", basePreamble + `
rule_defs: &rdefs
  secret: "smuggled_rule_secret"
identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - <<: *rdefs
          name: smuggled-rule
          prompt_pattern: "Prompt:"
`},

		// Multi-rule list where only 3rd rule contains plaintext
		{"deep_rule_secret", basePreamble + `
identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - name: r1
          prompt_pattern: "P1:"
          source: login_password
        - name: r2
          prompt_pattern: "P2:"
          source: otp
        - name: r3
          prompt_pattern: "P3:"
          answer: "third_rule_leaked_answer"
`},

		// Multi-identity map where second identity leaks secret
		{"multi_identity_leak", basePreamble + `
identities:
  valid-id:
    user: admin
    auth_type: key
  leaked-id:
    user: ops
    auth_type: otp
    otp_secret: "BASE32SECRET3232"
`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := UnmarshalV2([]byte(tc.yamlSnippet))
			if err == nil {
				t.Fatalf("PENETRATION FAILURE: YAML containing forbidden plaintext passed UnmarshalV2:\n%s", tc.yamlSnippet)
			}
			if !errors.Is(err, ErrSchemaValidation) {
				t.Fatalf("expected error wrapping ErrSchemaValidation, got: %v", err)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// 2. Invariant Tests on Regex Patterns and Rule Sources
// -----------------------------------------------------------------------------

func TestAdversarial_RegexPatternValidation(t *testing.T) {
	basePreamble := `schema_version: 2
credential:
  default_store: pass
  stores:
    pass: {type: pass}
hosts:
  h1: {address: 127.0.0.1, port: 22}
nodes:
  n1: {host_ref: h1, identity_ref: dev}
`

	invalidRegexes := []string{
		"[unclosed_bracket",
		"(unclosed_parenthesis",
		"*leading_repetition",
		"+leading_plus",
		"(?P<invalid_group",
		"trailing_backslash\\",
		"a{10,2}", // invalid range min > max
	}

	for i, reg := range invalidRegexes {
		// Test in keyboard_interactive prompt_pattern
		t.Run(fmt.Sprintf("ki_prompt_pattern_%d", i), func(t *testing.T) {
			y := basePreamble + fmt.Sprintf(`identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - name: r1
          prompt_pattern: %q
          source: login_password
`, reg)
			_, err := UnmarshalV2([]byte(y))
			if err == nil || !strings.Contains(err.Error(), "invalid regex") {
				t.Fatalf("expected invalid regex error for prompt_pattern %q, got: %v", reg, err)
			}
		})

		// Test in keyboard_interactive instruction_pattern
		t.Run(fmt.Sprintf("ki_instruction_pattern_%d", i), func(t *testing.T) {
			y := basePreamble + fmt.Sprintf(`identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - name: r1
          prompt_pattern: "^Password:"
          instruction_pattern: %q
          source: login_password
`, reg)
			_, err := UnmarshalV2([]byte(y))
			if err == nil || !strings.Contains(err.Error(), "invalid regex") {
				t.Fatalf("expected invalid regex error for instruction_pattern %q, got: %v", reg, err)
			}
		})

		// Test in otp prompt_pattern
		t.Run(fmt.Sprintf("otp_prompt_pattern_%d", i), func(t *testing.T) {
			y := basePreamble + fmt.Sprintf(`identities:
  dev:
    user: dev
    auth_type: otp
    otp:
      totp_secret_ref: {store_id: pass, item_id: "totp-key"}
      prompt_pattern: %q
`, reg)
			_, err := UnmarshalV2([]byte(y))
			if err == nil || !strings.Contains(err.Error(), "invalid regex") {
				t.Fatalf("expected invalid regex error for otp prompt_pattern %q, got: %v", reg, err)
			}
		})
	}
}

func TestAdversarial_RuleSourceInvariants(t *testing.T) {
	basePreamble := `schema_version: 2
credential:
  default_store: pass
  stores:
    pass: {type: pass}
hosts:
  h1: {address: 127.0.0.1, port: 22}
nodes:
  n1: {host_ref: h1, identity_ref: dev}
`

	testCases := []struct {
		name        string
		yamlSnippet string
		errContains string
	}{
		// source: otp cannot specify secret_ref or command
		{
			name: "source_otp_with_secret_ref",
			yamlSnippet: basePreamble + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - prompt_pattern: "OTP:"
          source: otp
          secret_ref: {store_id: pass, item_id: "sec1"}
`,
			errContains: "cannot specify secret_ref",
		},
		{
			name: "source_otp_with_command",
			yamlSnippet: basePreamble + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - prompt_pattern: "OTP:"
          source: otp
          command: "/usr/bin/otp"
`,
			errContains: "cannot specify command",
		},

		// source: login_password cannot specify secret_ref or command
		{
			name: "source_login_password_with_secret_ref",
			yamlSnippet: basePreamble + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - prompt_pattern: "Password:"
          source: login_password
          secret_ref: {store_id: pass, item_id: "sec1"}
`,
			errContains: "cannot specify secret_ref",
		},
		{
			name: "source_login_password_with_command",
			yamlSnippet: basePreamble + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - prompt_pattern: "Password:"
          source: login_password
          command: "/usr/bin/pwd"
`,
			errContains: "cannot specify command",
		},

		// source: secret requirements
		{
			name: "source_secret_empty_name",
			yamlSnippet: basePreamble + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - prompt_pattern: "PIN:"
          source: secret
          secret_ref: {store_id: pass, item_id: "sec1"}
`,
			errContains: "must specify non-empty name",
		},
		{
			name: "source_secret_missing_ref",
			yamlSnippet: basePreamble + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - name: pin-rule
          prompt_pattern: "PIN:"
          source: secret
`,
			errContains: "must specify secret_ref",
		},
		{
			name: "source_secret_with_command",
			yamlSnippet: basePreamble + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - name: pin-rule
          prompt_pattern: "PIN:"
          source: secret
          secret_ref: {store_id: pass, item_id: "sec1"}
          command: "/usr/bin/pin"
`,
			errContains: "cannot specify command",
		},
		{
			name: "source_secret_unconfigured_store",
			yamlSnippet: basePreamble + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - name: pin-rule
          prompt_pattern: "PIN:"
          source: secret
          secret_ref: {store_id: non_existent_store, item_id: "sec1"}
`,
			errContains: "not configured",
		},

		// source: command requirements
		{
			name: "source_command_missing_command",
			yamlSnippet: basePreamble + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - prompt_pattern: "Token:"
          source: command
`,
			errContains: "must specify non-empty command",
		},
		{
			name: "source_command_with_secret_ref",
			yamlSnippet: basePreamble + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - prompt_pattern: "Token:"
          source: command
          command: "/usr/bin/token"
          secret_ref: {store_id: pass, item_id: "sec1"}
`,
			errContains: "cannot specify secret_ref",
		},

		// Unknown rule source
		{
			name: "unknown_rule_source",
			yamlSnippet: basePreamble + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - prompt_pattern: "Token:"
          source: "magic_authenticator"
`,
			errContains: "unknown source",
		},
		{
			name: "empty_rule_source",
			yamlSnippet: basePreamble + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - prompt_pattern: "Token:"
          source: ""
`,
			errContains: "unknown source",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := UnmarshalV2([]byte(tc.yamlSnippet))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errContains)
			}
			if !strings.Contains(err.Error(), tc.errContains) {
				t.Fatalf("expected error containing %q, got: %v", tc.errContains, err)
			}
		})
	}
}

func TestAdversarial_ShellMetacharactersInCommands(t *testing.T) {
	basePreamble := `schema_version: 2
credential:
  default_store: pass
  stores:
    pass: {type: pass}
hosts:
  h1: {address: 127.0.0.1, port: 22}
nodes:
  n1: {host_ref: h1, identity_ref: dev}
`

	dangerousCommands := []struct {
		name string
		cmd  string
	}{
		{"semicolon", "/usr/bin/get-totp; rm -rf /"},
		{"pipe", "/usr/bin/get-totp | cat"},
		{"ampersand", "/usr/bin/get-totp & bg"},
		{"double_ampersand", "/usr/bin/get-totp && echo ok"},
		{"dollar_expansion", "/usr/bin/get-totp $SECRET"},
		{"dollar_paren", "/usr/bin/get-totp $(id)"},
		{"backticks", "/usr/bin/get-totp `id`"},
		{"newline", "/usr/bin/get-totp\necho hacked"},
	}

	for _, tc := range dangerousCommands {
		// Test shell metacharacters in OTP command
		t.Run("otp_"+tc.name, func(t *testing.T) {
			y := basePreamble + fmt.Sprintf(`identities:
  dev:
    user: dev
    auth_type: otp
    otp:
      command: %q
`, tc.cmd)
			_, err := UnmarshalV2([]byte(y))
			if err == nil || !strings.Contains(err.Error(), "forbidden shell characters") {
				t.Fatalf("expected forbidden shell characters error for command %q, got: %v", tc.cmd, err)
			}
		})

		// Test shell metacharacters in KeyboardInteractive rule command
		t.Run("rule_"+tc.name, func(t *testing.T) {
			y := basePreamble + fmt.Sprintf(`identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - prompt_pattern: "Token:"
          source: command
          command: %q
`, tc.cmd)
			_, err := UnmarshalV2([]byte(y))
			if err == nil || !strings.Contains(err.Error(), "forbidden shell characters") {
				t.Fatalf("expected forbidden shell characters error for command %q, got: %v", tc.cmd, err)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// 3. nodeAuthVersion Sensitivity and CAS Concurrency Stress Testing
// -----------------------------------------------------------------------------

func TestAdversarial_NodeAuthVersionSensitivity(t *testing.T) {
	setupBaseConfig := func() (*Configuration, models.Identity) {
		cfg := &Configuration{
			SchemaVersion: 2,
			Credential: &CredentialConfig{
				DefaultStore: "pass",
				Stores: map[string]StoreConfig{
					"pass":  {Type: StoreTypePass},
					"vault": {Type: StoreTypePass},
				},
			},
			Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
			Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
			Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		}
		cfg.Hosts.Set("h1", models.Host{Address: "10.0.0.1", Port: 22})

		baseID := models.Identity{
			User:     "ops",
			AuthType: "keyboard-interactive",
			OTP: &models.OTPConfig{
				TOTPSecretRef: &credential.Ref{StoreID: "pass", ItemID: "seed-1"},
				PromptPattern: "OTP:",
				Timeout:       5 * time.Second,
				Command:       "/bin/otp-gen",
				Args:          []string{"--profile", "default"},
			},
			KeyboardInteractive: &models.KeyboardInteractiveConfig{
				Rules: []models.ChallengeRule{
					{
						Name:               "r1",
						PromptPattern:      "^Password:",
						InstructionPattern: "Enter password",
						Source:             models.ChallengeSourceLoginPassword,
						Timeout:            3 * time.Second,
					},
					{
						Name:               "r2",
						PromptPattern:      "^PIN:",
						InstructionPattern: "Enter pin",
						Source:             models.ChallengeSourceSecret,
						SecretRef:          &credential.Ref{StoreID: "pass", ItemID: "pin-1"},
						Timeout:            4 * time.Second,
					},
				},
			},
		}

		cfg.Identities.Set("id1", baseID)
		cfg.Nodes.Set("node1", models.Node{HostRef: "h1", IdentityRef: "id1"})
		return cfg, baseID
	}

	cfg, baseID := setupBaseConfig()
	baselineVer, err := nodeAuthVersion(cfg, "node1")
	if err != nil {
		t.Fatalf("initial nodeAuthVersion failed: %v", err)
	}

	mutations := []struct {
		name   string
		mutate func(id *models.Identity)
	}{
		// OTP mutations
		{"otp_store_id", func(id *models.Identity) {
			id.OTP.TOTPSecretRef.StoreID = "vault"
		}},
		{"otp_item_id", func(id *models.Identity) {
			id.OTP.TOTPSecretRef.ItemID = "seed-2"
		}},
		{"otp_prompt_pattern", func(id *models.Identity) {
			id.OTP.PromptPattern = "Code:"
		}},
		{"otp_timeout", func(id *models.Identity) {
			id.OTP.Timeout = 10 * time.Second
		}},
		{"otp_command", func(id *models.Identity) {
			id.OTP.Command = "/usr/local/bin/new-otp"
		}},
		{"otp_args", func(id *models.Identity) {
			id.OTP.Args = append(id.OTP.Args, "--verbose")
		}},
		{"otp_nil", func(id *models.Identity) {
			id.OTP = nil
		}},

		// KeyboardInteractive mutations
		{"ki_rule_name", func(id *models.Identity) {
			id.KeyboardInteractive.Rules[0].Name = "r1_renamed"
		}},
		{"ki_prompt_pattern", func(id *models.Identity) {
			id.KeyboardInteractive.Rules[0].PromptPattern = "^Passcode:"
		}},
		{"ki_instruction_pattern", func(id *models.Identity) {
			id.KeyboardInteractive.Rules[0].InstructionPattern = "Enter secret code"
		}},
		{"ki_source", func(id *models.Identity) {
			id.KeyboardInteractive.Rules[0].Source = models.ChallengeSourceOTP
		}},
		{"ki_rule_secret_store", func(id *models.Identity) {
			id.KeyboardInteractive.Rules[1].SecretRef.StoreID = "vault"
		}},
		{"ki_rule_secret_item", func(id *models.Identity) {
			id.KeyboardInteractive.Rules[1].SecretRef.ItemID = "pin-99"
		}},
		{"ki_rule_timeout", func(id *models.Identity) {
			id.KeyboardInteractive.Rules[0].Timeout = 8 * time.Second
		}},
		{"ki_rule_command", func(id *models.Identity) {
			id.KeyboardInteractive.Rules[0].Command = "/bin/new-cmd"
		}},
		{"ki_rule_args", func(id *models.Identity) {
			id.KeyboardInteractive.Rules[0].Args = []string{"--quiet"}
		}},
		{"ki_rule_reorder", func(id *models.Identity) {
			id.KeyboardInteractive.Rules[0], id.KeyboardInteractive.Rules[1] =
				id.KeyboardInteractive.Rules[1], id.KeyboardInteractive.Rules[0]
		}},
		{"ki_add_rule", func(id *models.Identity) {
			id.KeyboardInteractive.Rules = append(id.KeyboardInteractive.Rules, models.ChallengeRule{
				Name:          "r3",
				PromptPattern: "Token:",
				Source:        models.ChallengeSourceCommand,
				Command:       "/bin/token",
			})
		}},
		{"ki_nil", func(id *models.Identity) {
			id.KeyboardInteractive = nil
		}},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			mutated := baseID.Clone()
			m.mutate(&mutated)

			testCfg, _ := setupBaseConfig()
			testCfg.Identities.Set("id1", mutated)

			newVer, err := nodeAuthVersion(testCfg, "node1")
			if err != nil {
				t.Fatalf("nodeAuthVersion failed: %v", err)
			}
			if newVer == baselineVer {
				t.Fatalf("SENSITIVITY FAILURE: mutation %q did NOT change nodeAuthVersion hash (%x)", m.name, baselineVer)
			}
		})
	}
}

func TestAdversarial_CASConcurrencyStress(t *testing.T) {
	ctx := context.Background()
	repo, initialAuthVer := setupTestRepoWithChallengeAnswer(t)

	// 50 goroutines simultaneously attempt CAS update with the same initialAuthVer
	concurrency := 50
	var successCount atomic.Int32
	var conflictCount atomic.Int32
	var otherErrCount atomic.Int32

	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(workerID int) {
			defer wg.Done()
			ref := credential.Ref{StoreID: "s1", ItemID: fmt.Sprintf("totp-worker-%d", workerID)}
			target := credential.Target{NodeID: "node-1", Kind: credential.KindTOTPSecret}

			outcome, _, err := repo.AsConfigUpdater().ApplyCredentialRefAtVersion(ctx, target, initialAuthVer, &ref)
			if err == nil && outcome.Applied {
				successCount.Add(1)
			} else if errors.Is(err, ErrConfigConflict) || errors.Is(err, coreauth.ErrConfigConflict) {
				conflictCount.Add(1)
			} else {
				otherErrCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	if successCount.Load() != 1 {
		t.Fatalf("CONCURRENCY ANOMALY: expected exactly 1 successful CAS update, got %d", successCount.Load())
	}
	if conflictCount.Load() != int32(concurrency-1) {
		t.Fatalf("CONCURRENCY ANOMALY: expected %d conflict errors, got %d (other errors: %d)",
			concurrency-1, conflictCount.Load(), otherErrCount.Load())
	}

	// Stale CAS attempt must fail
	staleRef := credential.Ref{StoreID: "s1", ItemID: "stale-item"}
	staleTarget := credential.Target{NodeID: "node-1", Kind: credential.KindTOTPSecret}
	_, _, err := repo.AsConfigUpdater().ApplyCredentialRefAtVersion(ctx, staleTarget, initialAuthVer, &staleRef)
	if err == nil || (!errors.Is(err, ErrConfigConflict) && !errors.Is(err, coreauth.ErrConfigConflict)) {
		t.Fatalf("expected ErrConfigConflict on stale auth version, got: %v", err)
	}
}

// -----------------------------------------------------------------------------
// 4. Cascade Deletion and Reference Backup Verification
// -----------------------------------------------------------------------------

func TestAdversarial_CascadeDeletion_OTPAndRules(t *testing.T) {
	cfg := newTestProvider().Snapshot()
	node, _ := cfg.Nodes.Get("web-server")
	identity, _ := cfg.Identities.Get(node.IdentityRef)

	loginRef := credential.Ref{StoreID: "memory", ItemID: "login-001"}
	passphraseRef := credential.Ref{StoreID: "memory", ItemID: "passphrase-001"}
	totpRef := credential.Ref{StoreID: "memory", ItemID: "totp-001"}
	rule1Ref := credential.Ref{StoreID: "memory", ItemID: "rule1-pin-001"}
	rule2Ref := credential.Ref{StoreID: "memory", ItemID: "rule2-key-002"}

	identity.LoginPasswordRef = &loginRef
	identity.PassphraseRef = &passphraseRef
	identity.OTP = &models.OTPConfig{
		TOTPSecretRef: &totpRef,
	}
	identity.KeyboardInteractive = &models.KeyboardInteractiveConfig{
		Rules: []models.ChallengeRule{
			{Name: "r1", PromptPattern: "PIN:", Source: models.ChallengeSourceSecret, SecretRef: &rule1Ref},
			{Name: "r2", PromptPattern: "Key:", Source: models.ChallengeSourceSecret, SecretRef: &rule2Ref},
			{Name: "r3", PromptPattern: "Cmd:", Source: models.ChallengeSourceCommand, Command: "/bin/ans"},
		},
	}
	cfg.Identities.Set(node.IdentityRef, identity)

	// 1. Test appendIdentityCredentialRefs gathering
	gathered := appendIdentityCredentialRefs(nil, identity)
	if len(gathered) != 5 {
		t.Fatalf("expected 5 credential refs gathered, got %d", len(gathered))
	}
	expectedRefs := []credential.Ref{loginRef, passphraseRef, totpRef, rule1Ref, rule2Ref}
	for _, exp := range expectedRefs {
		if !slices.Contains(gathered, exp) {
			t.Fatalf("gathered refs missing expected ref: %+v", exp)
		}
	}

	// 2. Cascade delete execution via DeleteNodesWithCredentialsContext
	persistent := &memoryPersistStore{cfg: cfg, result: &PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(cfg, persistent)
	if err != nil {
		t.Fatal(err)
	}

	storeData := map[string][]byte{
		"login-001":      []byte("pwd"),
		"passphrase-001": []byte("phrase"),
		"totp-001":       []byte("totp-seed"),
		"rule1-pin-001":  []byte("pin-1234"),
		"rule2-key-002":  []byte("key-5678"),
	}
	store := &inMemoryCredStore{data: storeData}
	registry := credential.NewRegistry()
	if err := registry.Register("memory", store); err != nil {
		t.Fatal(err)
	}
	journal, err := credential.NewJournalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc, err := credential.NewService(registry, journal, repo.AsConfigUpdater(), nil)
	if err != nil {
		t.Fatal(err)
	}

	ref := repo.View().NodeRefs["web-server"]
	err = repo.DeleteNodesWithCredentialsContext(t.Context(), []NodeRef{ref}, svc)
	if err != nil {
		t.Fatalf("DeleteNodesWithCredentialsContext failed: %v", err)
	}

	// All 5 credential items should be purged from store
	if len(store.data) != 0 {
		t.Fatalf("CASCADE DELETION FAILURE: expected 0 items remaining in credential store, got: %v", store.data)
	}
}

func TestAdversarial_BackupReferences_OTPAndRules(t *testing.T) {
	tempDir := t.TempDir()
	backupPath := filepath.Join(tempDir, "config.yaml.v2.backup")

	backupYAML := `schema_version: 2
credential:
  default_store: enc1
  stores:
    enc1:
      type: encrypted-file
      unlock: key-file
      path: ` + filepath.Join(tempDir, "store.enc") + `
      key_file: ` + filepath.Join(tempDir, "store.key") + `
    sys1:
      type: system
hosts:
  h1: {address: 127.0.0.1, port: 22}
identities:
  ops:
    user: ops
    auth_type: keyboard-interactive
    key_fingerprint: "SHA256:abcd1234efgh5678"
    login_password_ref:
      store_id: enc1
      item_id: enc-pwd-1
    passphrase_ref:
      store_id: sys1
      item_id: sys-phrase-1
    otp:
      totp_secret_ref:
        store_id: enc1
        item_id: enc-totp-1
    keyboard_interactive:
      rules:
        - name: r1
          prompt_pattern: "PIN:"
          source: secret
          secret_ref:
            store_id: enc1
            item_id: enc-rule-pin-1
        - name: r2
          prompt_pattern: "SysCode:"
          source: secret
          secret_ref:
            store_id: sys1
            item_id: sys-rule-code-2
nodes:
  n1:
    host_ref: h1
    identity_ref: ops
    privilege_password_ref:
      store_id: enc1
      item_id: enc-priv-1
`
	if err := os.WriteFile(backupPath, []byte(backupYAML), 0600); err != nil {
		t.Fatal(err)
	}

	// BackupReferences targeting "enc1"
	refs, err := BackupReferences(backupPath, "enc1")
	if err != nil {
		t.Fatalf("BackupReferences failed: %v", err)
	}

	// Expected refs in enc1: enc-pwd-1, enc-totp-1, enc-rule-pin-1, enc-priv-1
	expected := map[string]bool{
		"enc-pwd-1":      false,
		"enc-totp-1":     false,
		"enc-rule-pin-1": false,
		"enc-priv-1":     false,
	}

	if len(refs) != len(expected) {
		t.Fatalf("expected %d refs from enc1, got %d: %+v", len(expected), len(refs), refs)
	}

	for _, r := range refs {
		if r.StoreID != "enc1" {
			t.Fatalf("unexpected storeID in backup refs: %+v", r)
		}
		if _, ok := expected[r.ItemID]; !ok {
			t.Fatalf("unexpected itemID in backup refs: %+v", r)
		}
		expected[r.ItemID] = true
	}

	for itemID, found := range expected {
		if !found {
			t.Fatalf("BACKUP REFERENCE MISSING: %q was not extracted from backup", itemID)
		}
	}

	// BackupReferences targeting non-encrypted-file store "sys1" must fail
	_, err = BackupReferences(backupPath, "sys1")
	if err == nil || !strings.Contains(err.Error(), "encrypted-file StoreID") {
		t.Fatalf("expected error for non-encrypted-file store, got: %v", err)
	}
}
