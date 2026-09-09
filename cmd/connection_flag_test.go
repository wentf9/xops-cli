package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	cmdutils "github.com/wentf9/xops-cli/cmd/utils"
)

func TestConnectionFlagsRegistration(t *testing.T) {
	commands := []struct {
		name string
		cmd  *cobra.Command
	}{
		{"ssh", NewCmdSsh()},
		{"exec", NewCmdExec()},
		{"sftp", NewCmdSftp()},
		{"scp", NewCmdScp()},
	}

	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			pwdStdin := tc.cmd.Flags().Lookup("password-stdin")
			if pwdStdin == nil {
				t.Fatalf("%s missing --password-stdin flag", tc.name)
			}
			if pwdStdin.Value.Type() != "bool" {
				t.Errorf("%s --password-stdin type = %q, want bool", tc.name, pwdStdin.Value.Type())
			}

			passStdin := tc.cmd.Flags().Lookup("passphrase-stdin")
			if passStdin == nil {
				t.Fatalf("%s missing --passphrase-stdin flag", tc.name)
			}
			if passStdin.Value.Type() != "bool" {
				t.Errorf("%s --passphrase-stdin type = %q, want bool", tc.name, passStdin.Value.Type())
			}

			remember := tc.cmd.Flags().Lookup("remember")
			if remember == nil {
				t.Fatalf("%s missing --remember flag", tc.name)
			}
			if remember.DefValue != "" {
				t.Errorf("%s --remember default value = %q, want %q", tc.name, remember.DefValue, "inherit configuration")
			}
		})
	}
}

func TestRememberPolicyValidation(t *testing.T) {
	validPolicies := []string{"ask", "always", "never", "ASK", "Always", "NEVER", ""}
	for _, p := range validPolicies {
		if err := cmdutils.ValidateRememberPolicy(p); err != nil {
			t.Errorf("expected policy %q to be valid, got error: %v", p, err)
		}
	}

	invalidPolicies := []string{"yes", "no", "true", "false", "prompt", "forever"}
	for _, p := range invalidPolicies {
		if err := cmdutils.ValidateRememberPolicy(p); err == nil {
			t.Errorf("expected policy %q to be invalid, but got nil", p)
		}
	}
}

func TestShouldRememberCredential(t *testing.T) {
	if !cmdutils.ShouldRememberCredential(cmdutils.RememberPolicyAlways, "host1") {
		t.Errorf("always policy should return true")
	}
	if cmdutils.ShouldRememberCredential(cmdutils.RememberPolicyNever, "host1") {
		t.Errorf("never policy should return false")
	}
	// Empty flags inherit configuration; without configuration they remain ask.
	if got := cmdutils.EffectiveRememberPolicy("", nil); got != "ask" {
		t.Fatalf("default policy = %q", got)
	}

}

func TestFlagsMutuallyExclusive(t *testing.T) {
	// 测试 --password 与 --password-stdin 互斥
	sshCmd := NewCmdSsh()
	sshCmd.SetArgs([]string{"myhost", "--password", "secret", "--password-stdin"})
	if err := sshCmd.Execute(); err == nil {
		t.Errorf("expected error when both --password and --password-stdin are provided, got nil")
	}

	// 测试 --passphrase 与 --passphrase-stdin 互斥
	sftpCmd := NewCmdSftp()
	sftpCmd.SetArgs([]string{"myhost", "--passphrase", "secret", "--passphrase-stdin"})
	if err := sftpCmd.Execute(); err == nil {
		t.Errorf("expected error when both --passphrase and --passphrase-stdin are provided, got nil")
	}
}

func TestWarnFlagDeprecated(t *testing.T) {
	// 验证 WarnFlagDeprecated 不会发生 panic
	cmdutils.WarnFlagDeprecated("password", "--password-stdin")
	cmdutils.WarnFlagDeprecated("passphrase", "--passphrase-stdin")
	cmdutils.WarnFlagDeprecated("suPwd", "secure prompt")
}
