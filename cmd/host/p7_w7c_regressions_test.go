package host

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestP7W7c_DEF7M6_HostAddAndEditFailClosedOnInvalidJump(t *testing.T) {
	t.Run("host_add_rejects_empty_whitespace_and_control_jump_before_verify_or_commit", func(t *testing.T) {
		_, store := setupHostEditJumpTestConfig(t)

		badJumps := []string{
			"",
			"   ",
			"\n",
			"\t",
			"\r\n",
			"\u0085",
			"\v",
			"\f",
			"\u2028",
			"\u2029",
			"bastion\n",
			"none\n",
			",",
			"bastion,none",
		}

		verifyCalls := 0
		fakeVerify := func(_ context.Context, _ *config.Repository, _ string, _ *inventoryVerification) error {
			verifyCalls++
			return nil
		}

		for _, bad := range badJumps {
			addCmd := newCmdInventoryAdd(fakeVerify)
			addCmd.SilenceErrors = true
			addCmd.SilenceUsage = true
			addCmd.SetOut(&bytes.Buffer{})
			addCmd.SetErr(&bytes.Buffer{})
			addCmd.SetArgs([]string{"new-app", "ops@10.0.0.50:22", "--jump", bad})
			err := addCmd.Execute()
			if !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("host add --jump %q err = %v, want ErrSSHOptionsValidation", bad, err)
			}
		}

		if verifyCalls != 0 {
			t.Fatalf("verifier was called %d times on invalid --jump inputs, want 0", verifyCalls)
		}

		cfg, err := store.Load()
		if err != nil {
			t.Fatalf("store.Load: %v", err)
		}
		if _, exists := cfg.Nodes.Get("ops@10.0.0.50:22"); exists {
			t.Fatal("failed host add with invalid --jump persisted node ops@10.0.0.50:22")
		}

		// Valid --jump none (explicitly disabling jump) and unset --jump must succeed.
		for _, tc := range []struct {
			name     string
			args     []string
			nodeID   string
			wantJump string
		}{
			{
				name:     "unset_jump",
				args:     []string{"clean-unset", "ops@10.0.0.51:22", "--skip-verify"},
				nodeID:   "ops@10.0.0.51:22",
				wantJump: "",
			},
			{
				name:     "explicit_none_jump",
				args:     []string{"clean-none", "ops@10.0.0.52:22", "--jump", "none", "--skip-verify"},
				nodeID:   "ops@10.0.0.52:22",
				wantJump: "",
			},
			{
				name:     "valid_bastion_jump",
				args:     []string{"clean-jump", "ops@10.0.0.53:22", "--jump", "bastion", "--skip-verify"},
				nodeID:   "ops@10.0.0.53:22",
				wantJump: "jump@10.0.0.1:22",
			},
		} {
			addCmd := NewCmdInventoryAdd()
			addCmd.SilenceErrors = true
			addCmd.SilenceUsage = true
			addCmd.SetOut(&bytes.Buffer{})
			addCmd.SetErr(&bytes.Buffer{})
			addCmd.SetArgs(tc.args)
			if err := addCmd.Execute(); err != nil {
				t.Fatalf("host add (%s) unexpected error: %v", tc.name, err)
			}
			loaded, err := store.Load()
			if err != nil {
				t.Fatalf("store.Load(%s): %v", tc.name, err)
			}
			node, ok := loaded.Nodes.Get(tc.nodeID)
			if !ok || node.ProxyJump != tc.wantJump {
				t.Fatalf("node %q = (%+v, %v), want ProxyJump=%q", tc.nodeID, node, ok, tc.wantJump)
			}
		}
	})

	t.Run("host_edit_rejects_whitespace_and_control_jump_while_preserving_exact_empty_clear", func(t *testing.T) {
		_, store := setupHostEditJumpTestConfig(t)

		if err := runHostEditCLI("app-a", "--jump", "bastion"); err != nil {
			t.Fatalf("host edit app-a --jump bastion failed: %v", err)
		}

		badJumps := []string{
			"   ",
			"\n",
			"\t",
			"\r\n",
			"\u0085",
			"\v",
			"\f",
			"\u2028",
			"\u2029",
			"bastion\n",
			"none\n",
		}
		for _, bad := range badJumps {
			err := runHostEditCLI("app-a", "--jump", bad)
			if !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("host edit app-a --jump %q err = %v, want ErrSSHOptionsValidation", bad, err)
			}
		}

		// Stored ProxyJump must remain intact after every rejected edit.
		cfg, err := store.Load()
		if err != nil {
			t.Fatalf("store.Load after rejected edits: %v", err)
		}
		if n, _ := cfg.Nodes.Get("ops@10.0.0.10:22"); n.ProxyJump != "jump@10.0.0.1:22" {
			t.Fatalf("app-a ProxyJump was mutated by invalid --jump: got %q, want %q", n.ProxyJump, "jump@10.0.0.1:22")
		}

		// Exact --jump "" remains an intentional clear.
		if err := runHostEditCLI("app-a", "--jump", ""); err != nil {
			t.Fatalf("host edit app-a --jump '' failed: %v", err)
		}
		cfg, err = store.Load()
		if err != nil {
			t.Fatalf("store.Load after --jump '': %v", err)
		}
		if n, _ := cfg.Nodes.Get("ops@10.0.0.10:22"); n.ProxyJump != "" {
			t.Fatalf("app-a ProxyJump after --jump '' = %q, want empty", n.ProxyJump)
		}
	})
}
