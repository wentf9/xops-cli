package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP6_FormIdentityKeyPath_PreservesTemplatesAndNoneWhileExpandingLiterals(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "openssh_percent_d_template_preserved",
			input: "%d/.ssh/id_ed25519",
			want:  "%d/.ssh/id_ed25519",
		},
		{
			name:  "openssh_percent_tokens_trimmed_and_preserved",
			input: "  %d/.ssh/id_%h_%r  ",
			want:  "%d/.ssh/id_%h_%r",
		},
		{
			name:  "env_placeholder_preserved",
			input: "${SSH_KEY_DIR}/id_ed25519",
			want:  "${SSH_KEY_DIR}/id_ed25519",
		},
		{
			name:  "none_sentinel_preserved",
			input: "none",
			want:  "none",
		},
		{
			name:  "none_sentinel_uppercase_normalized",
			input: "  NONE  ",
			want:  "none",
		},
		{
			name:  "unresolved_tilde_user_not_cwd_mangled",
			input: "~nonexistent_xops_user_p6_999/id_ed25519",
			want:  "~nonexistent_xops_user_p6_999/id_ed25519",
		},
		{
			name:  "tilde_literal_expanded",
			input: "~/.ssh/id_ed25519",
			want:  filepath.Join(homeDir, ".ssh", "id_ed25519"),
		},
		{
			name:  "relative_literal_expanded",
			input: "./id_rsa",
			want:  filepath.Join(cwd, "id_rsa"),
		},
		{
			name:  "absolute_literal_preserved",
			input: filepath.Join(homeDir, "abs_key"),
			want:  filepath.Join(homeDir, "abs_key"),
		},
	}

	for _, tc := range cases {
		t.Run("create_"+tc.name, func(t *testing.T) {
			cfg := &config.Configuration{
				Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
				Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
				Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
			}
			repo := newTestRepository(t, cfg)
			m := Model{
				repository: repo,
				formState: &nodeFormState{
					isEdit:           false,
					skipVerify:       true,
					user:             "ops",
					address:          "192.0.2.50",
					port:             "22",
					authType:         "key",
					keyPath:          tc.input,
					passphraseAction: "keep",
					sudoMode:         string(models.SudoModeAuto),
				},
			}
			if err := m.validateFormState(); err != nil {
				t.Fatalf("validateFormState(%q) unexpected error: %v", tc.input, err)
			}
			completeConfigurationMutation(t, &m, m.saveFormCmd())

			snap, err := repo.ResolveConnection("ops@192.0.2.50:22")
			if err != nil {
				t.Fatalf("ResolveConnection: %v", err)
			}
			if snap.Identity.AuthType != "key" {
				t.Fatalf("AuthType = %q, want key", snap.Identity.AuthType)
			}
			if snap.Identity.KeyPath != tc.want {
				t.Fatalf("Identity.KeyPath = %q, want %q", snap.Identity.KeyPath, tc.want)
			}
		})

		t.Run("edit_"+tc.name, func(t *testing.T) {
			cfg := newFormCredentialTestConfiguration("")
			repo := newTestRepository(t, cfg)
			m := &Model{
				repository: repo,
				formState: &nodeFormState{
					isEdit:           true,
					originalID:       formCredentialTestNodeID,
					user:             "user",
					address:          "192.168.1.50",
					port:             "22",
					authType:         "key",
					keyPath:          tc.input,
					passphraseAction: "keep",
					sudoMode:         string(models.SudoModeAuto),
				},
			}
			completeConfigurationMutation(t, m, m.saveFormCmd())

			snap, err := repo.ResolveConnection(formCredentialTestNodeID)
			if err != nil {
				t.Fatalf("ResolveConnection: %v", err)
			}
			if snap.Identity.KeyPath != tc.want {
				t.Fatalf("edited Identity.KeyPath = %q, want %q", snap.Identity.KeyPath, tc.want)
			}
		})
	}
}

func TestP6_FormIdentityKeyPath_RejectsInvalidSyntaxFailClosed(t *testing.T) {
	badPaths := []struct {
		name string
		raw  string
	}{
		{"control_newline", "/tmp/bad\nkey"},
		{"control_nul", "/tmp/bad\x00key"},
		{"invalid_percent_token", "%z/.ssh/id_ed25519"},
		{"dangling_percent", "/tmp/id_%"},
		{"whitespace_only", "   "},
	}

	for _, tc := range badPaths {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Configuration{
				Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
				Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
				Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
			}
			repo := newTestRepository(t, cfg)
			m := Model{
				repository: repo,
				formState: &nodeFormState{
					isEdit:           false,
					skipVerify:       true,
					user:             "ops",
					address:          "192.0.2.51",
					port:             "22",
					authType:         "key",
					keyPath:          tc.raw,
					passphraseAction: "keep",
					sudoMode:         string(models.SudoModeAuto),
				},
			}
			if err := m.validateFormState(); err == nil {
				t.Fatalf("validateFormState(%q) = nil, want fail-closed error", tc.raw)
			}
			if cmd := m.saveFormCmd(); cmd != nil {
				t.Fatalf("saveFormCmd(%q) returned non-nil cmd, want fail-closed rejection", tc.raw)
			}
			if strings.TrimSpace(m.status) == "" {
				t.Fatalf("saveFormCmd(%q) did not record error in m.status", tc.raw)
			}
			if repo.Snapshot().Nodes.Count() != 0 {
				t.Fatalf("invalid key path %q unexpectedly mutated repository", tc.raw)
			}
		})
	}
}
