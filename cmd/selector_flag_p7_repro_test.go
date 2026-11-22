package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestP7Repro_MED11_EmptyAndWhitespaceHostFlagsRejected verifies MED-11:
// unified selectorFlag / selectorSliceFlag / RegisterExcludeFlag reject empty
// and whitespace-only values directly in pflag Set() across ssh, sftp, exec,
// scp, and play (including --host, --tag, --exclude, --limit, --ifile, --task).
func TestP7Repro_MED11_EmptyAndWhitespaceHostFlagsRejected(t *testing.T) {
	t.Run("ssh_empty_host_flag_rejected_before_validate", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		if err := cmd.ParseFlags([]string{"--host", ""}); err == nil {
			t.Fatal(`ssh --host "" was not rejected during flag parsing`)
		}
	})

	t.Run("ssh_empty_host_with_positional_fallback", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		if err := cmd.ParseFlags([]string{"--host", "", "target.example.com"}); err == nil {
			t.Fatalf(`ssh --host "" target.example.com succeeded in ParseFlags (Host=%q), want error`, opts.Host)
		}
	})

	t.Run("ssh_empty_host_with_control_command", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		if err := cmd.ParseFlags([]string{"--host", "", "-O", "check", "-S", "/tmp/xops-med11.sock"}); err == nil {
			t.Fatal(`ssh --host "" -O check -S /tmp/xops-med11.sock succeeded in ParseFlags, want error`)
		}
	})

	t.Run("ssh_whitespace_host", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		if err := cmd.ParseFlags([]string{"--host", "   "}); err == nil {
			t.Fatalf(`ssh --host "   " succeeded in ParseFlags (Host=%q), want error`, opts.Host)
		}
	})

	t.Run("sftp_empty_host_flag_rejected_before_validate", func(t *testing.T) {
		opts := NewSftpOptions()
		cmd := newCmdSftpWithOptions(opts)
		if err := cmd.ParseFlags([]string{"--host", ""}); err == nil {
			t.Fatal(`sftp --host "" was not rejected during flag parsing`)
		}
	})

	t.Run("sftp_empty_host_with_positional_fallback", func(t *testing.T) {
		opts := NewSftpOptions()
		cmd := newCmdSftpWithOptions(opts)
		if err := cmd.ParseFlags([]string{"--host", "", "target.example.com"}); err == nil {
			t.Fatalf(`sftp --host "" target.example.com succeeded in ParseFlags (Host=%q), want error`, opts.Host)
		}
	})

	t.Run("sftp_whitespace_host", func(t *testing.T) {
		opts := NewSftpOptions()
		cmd := newCmdSftpWithOptions(opts)
		if err := cmd.ParseFlags([]string{"--host", "   "}); err == nil {
			t.Fatalf(`sftp --host "   " succeeded in ParseFlags (Host=%q), want error`, opts.Host)
		}
	})

	t.Run("all_commands_reject_empty_and_whitespace_selectors_in_Set", func(t *testing.T) {
		cases := []struct {
			name    string
			newCmd  func() *cobra.Command
			flag    string
			badVals []string
		}{
			{"ssh_host", NewCmdSsh, "--host", []string{"", "   ", "\t"}},
			{"ssh_tag", NewCmdSsh, "--tag", []string{"", "   ", ",", "a,,b", `""`, `"   "`, `prod,""`, `prod,"   "`}},
			{"sftp_host", NewCmdSftp, "--host", []string{"", "   "}},
			{"sftp_tag", NewCmdSftp, "--tag", []string{"", "   ", ",", "a,,b", `""`, `"   "`, `prod,""`, `prod,"   "`}},
			{"sftp_task", NewCmdSftp, "--task", []string{"", "   "}},
			{"exec_host", NewCmdExec, "--host", []string{"", "   ", ",", "a,", ",a", "a,,b"}},
			{"exec_tag", NewCmdExec, "--tag", []string{"", "   "}},
			{"exec_ifile", NewCmdExec, "--ifile", []string{"", "   "}},
			{"exec_exclude", NewCmdExec, "--exclude", []string{"", "   ", ",", "web1,,web2"}},
			{"exec_task", NewCmdExec, "--task", []string{"", "   "}},
			{"scp_host", NewCmdScp, "--host", []string{"", "   ", ",", "a,", ",a", "a,,b"}},
			{"scp_tag", NewCmdScp, "--tag", []string{"", "   "}},
			{"scp_ifile", NewCmdScp, "--ifile", []string{"", "   "}},
			{"scp_exclude", NewCmdScp, "--exclude", []string{"", "   ", ",", "web1,,web2"}},
			{"scp_task", NewCmdScp, "--task", []string{"", "   "}},
			{"play_limit", NewCmdPlay, "--limit", []string{"", "   ", ",", "web1,,web2"}},
		}
		for _, tc := range cases {
			for _, bad := range tc.badVals {
				t.Run(tc.name+"_"+bad, func(t *testing.T) {
					c := tc.newCmd()
					if err := c.ParseFlags([]string{tc.flag, bad}); err == nil {
						t.Fatalf("%s %s %q unexpectedly succeeded in ParseFlags", tc.name, tc.flag, bad)
					}
				})
			}
		}
	})

	t.Run("EFG_M4_selector_slice_does_not_mutate_on_quoted_empty_error", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		if err := cmd.ParseFlags([]string{"--tag", "prod"}); err != nil {
			t.Fatalf("ParseFlags(--tag prod): %v", err)
		}
		if err := cmd.Flags().Set("tag", `staging,"   "`); err == nil {
			t.Fatal(`Set(--tag staging,"   ") unexpectedly succeeded`)
		}
		if len(opts.Tags) != 1 || opts.Tags[0] != "prod" {
			t.Fatalf("selectorSliceFlag mutated slice on error: got %v, want [prod]", opts.Tags)
		}
	})

	t.Run("EFG_M4_exec_and_scp_accept_valid_comma_hosts", func(t *testing.T) {
		if err := NewCmdExec().ParseFlags([]string{"--host", "web1,web2"}); err != nil {
			t.Fatalf("exec --host web1,web2: %v", err)
		}
		if err := NewCmdScp().ParseFlags([]string{"--host", "web1,web2"}); err != nil {
			t.Fatalf("scp --host web1,web2: %v", err)
		}
	})

	t.Run("EFG_M4_single_target_ssh_and_sftp_reject_comma_host", func(t *testing.T) {
		for _, badHost := range []string{"a,", ",", "a,b"} {
			sshOpts := NewSshOptions()
			sshOpts.Host = badHost
			if err := sshOpts.Validate(); err == nil {
				t.Errorf("ssh --host %q unexpectedly passed Validate()", badHost)
			}

			sftpOpts := NewSftpOptions()
			sftpOpts.Host = badHost
			if err := sftpOpts.Validate(); err == nil {
				t.Errorf("sftp --host %q unexpectedly passed Validate()", badHost)
			}
		}
	})
}
