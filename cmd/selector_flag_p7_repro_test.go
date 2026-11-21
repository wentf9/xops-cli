//go:build p7repro

package cmd

import "testing"

// TestP7Repro_MED11_EmptyAndWhitespaceHostFlagsRejected reproduces MED-11:
// `ssh --host ""`, `ssh --host "   "`, and `sftp --host ""` (and whitespace) are
// not rejected by flag parsing / Complete / Validate, unlike exec and scp.
func TestP7Repro_MED11_EmptyAndWhitespaceHostFlagsRejected(t *testing.T) {
	t.Run("ssh_empty_host_flag_rejected_before_validate", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		if err := cmd.ParseFlags([]string{"--host", ""}); err != nil {
			return
		}
		if err := opts.Complete(cmd, cmd.Flags().Args()); err != nil {
			return
		}
		t.Fatal(`ssh --host "" was not rejected during flag parsing or Complete`)
	})

	t.Run("ssh_empty_host_with_positional_fallback", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		if err := cmd.ParseFlags([]string{"--host", "", "target.example.com"}); err != nil {
			return
		}
		if err := opts.Complete(cmd, cmd.Flags().Args()); err != nil {
			return
		}
		if err := opts.Validate(); err != nil {
			return
		}
		t.Fatalf(`ssh --host "" target.example.com succeeded through ParseFlags+Complete+Validate (resolved Host=%q), want error rejecting empty --host`, opts.Host)
	})

	t.Run("ssh_empty_host_with_control_command", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		if err := cmd.ParseFlags([]string{"--host", "", "-O", "check", "-S", "/tmp/xops-med11.sock"}); err != nil {
			return
		}
		if err := opts.Complete(cmd, cmd.Flags().Args()); err != nil {
			return
		}
		if err := opts.Validate(); err != nil {
			return
		}
		t.Fatal(`ssh --host "" -O check -S /tmp/xops-med11.sock succeeded through ParseFlags+Complete+Validate, want error rejecting empty --host`)
	})

	t.Run("ssh_whitespace_host", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		if err := cmd.ParseFlags([]string{"--host", "   "}); err != nil {
			return
		}
		if err := opts.Complete(cmd, cmd.Flags().Args()); err != nil {
			return
		}
		if err := opts.Validate(); err != nil {
			return
		}
		t.Fatalf(`ssh --host "   " succeeded through ParseFlags+Complete+Validate (Host=%q Target.Selector=%q), want error rejecting blank --host`, opts.Host, opts.Target.Selector)
	})

	t.Run("sftp_empty_host_flag_rejected_before_validate", func(t *testing.T) {
		opts := NewSftpOptions()
		cmd := newCmdSftpWithOptions(opts)
		if err := cmd.ParseFlags([]string{"--host", ""}); err != nil {
			return
		}
		if err := opts.Complete(cmd, cmd.Flags().Args()); err != nil {
			return
		}
		t.Fatal(`sftp --host "" was not rejected during flag parsing or Complete`)
	})

	t.Run("sftp_empty_host_with_positional_fallback", func(t *testing.T) {
		opts := NewSftpOptions()
		cmd := newCmdSftpWithOptions(opts)
		if err := cmd.ParseFlags([]string{"--host", "", "target.example.com"}); err != nil {
			return
		}
		if err := opts.Complete(cmd, cmd.Flags().Args()); err != nil {
			return
		}
		if err := opts.Validate(); err != nil {
			return
		}
		t.Fatalf(`sftp --host "" target.example.com succeeded through ParseFlags+Complete+Validate (resolved Host=%q), want error rejecting empty --host`, opts.Host)
	})

	t.Run("sftp_whitespace_host", func(t *testing.T) {
		opts := NewSftpOptions()
		cmd := newCmdSftpWithOptions(opts)
		if err := cmd.ParseFlags([]string{"--host", "   "}); err != nil {
			return
		}
		if err := opts.Complete(cmd, cmd.Flags().Args()); err != nil {
			return
		}
		if err := opts.Validate(); err != nil {
			return
		}
		t.Fatalf(`sftp --host "   " succeeded through ParseFlags+Complete+Validate (Host=%q), want error rejecting blank --host`, opts.Host)
	})
}
